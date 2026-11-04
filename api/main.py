"""FastAPI application factory and centralized request/error lifecycle."""

from __future__ import annotations

import logging
import time
import uuid
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy.exc import SQLAlchemyError
from starlette.exceptions import HTTPException as StarletteHTTPException

from api.core.config import Settings
from api.core.errors import ApiError
from api.core.logging import configure_logging
from api.database.session import build_engine, build_session_factory
from api.routes import alerts, analysis, datasets, events, health, jobs, metrics, models, traffic
from api.services.analysis_service import AnalysisService
from api.services.dataset_service import DatasetService
from api.services.event_explanation_service import EventExplanationService
from api.services.job_service import JobService
from api.services.model_service import ModelService

logger = logging.getLogger(__name__)


def create_app(*, settings: Settings | None = None, session_factory: Any | None = None,
               model_service: ModelService | None = None) -> FastAPI:
    settings = settings or Settings.from_env()
    configure_logging(settings.log_level)
    engine = None
    if session_factory is None and settings.database_url:
        engine = build_engine(settings)
        session_factory = build_session_factory(engine)
    dataset_service = DatasetService(settings)
    models_service = model_service or ModelService(settings)
    analysis_service = AnalysisService(settings, models_service)
    job_service = JobService(settings, dataset_service, models_service, analysis_service)
    event_explanation_service = EventExplanationService(settings, dataset_service)
    job_service.configure_session_factory(session_factory)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        settings.upload_dir.mkdir(parents=True, exist_ok=True)
        logger.info("Starting backend environment=%s host=%s", settings.environment, settings.host)
        if session_factory is not None:
            try:
                interrupted = job_service.mark_interrupted_jobs(session_factory)
                if interrupted:
                    logger.warning("Marked %s interrupted in-process analysis jobs as FAILED", interrupted)
            except SQLAlchemyError:
                logger.exception("Database unavailable during startup recovery; liveness remains available")
        yield
        if engine is not None:
            engine.dispose()
        logger.info("Backend shutdown complete")

    app = FastAPI(title=settings.app_name, description="Local REST integration for validated network-flow detectors and alert persistence.",
        version="1.0.0", debug=settings.debug, lifespan=lifespan, docs_url="/docs", redoc_url="/redoc", openapi_url="/openapi.json")
    app.state.settings = settings
    app.state.engine = engine
    app.state.session_factory = session_factory
    app.state.model_service = models_service
    app.state.dataset_service = dataset_service
    app.state.analysis_service = analysis_service
    app.state.job_service = job_service
    app.state.event_explanation_service = event_explanation_service

    if settings.cors_origins:
        app.add_middleware(CORSMiddleware, allow_origins=list(settings.cors_origins), allow_credentials=False,
            allow_methods=["GET", "POST", "PATCH", "OPTIONS"], allow_headers=["Content-Type", "X-Request-ID"])

    @app.middleware("http")
    async def request_context(request: Request, call_next):
        request_id = request.headers.get("x-request-id") or str(uuid.uuid4())
        request.state.request_id = request_id
        content_length = request.headers.get("content-length")
        request_limit = settings.max_upload_bytes + 1024 * 1024 if request.url.path == "/api/v1/datasets" and request.method == "POST" else settings.max_request_bytes
        if content_length and content_length.isdigit() and int(content_length) > request_limit:
            return JSONResponse(status_code=413, content={"error": {"code": "REQUEST_TOO_LARGE", "message": "Request exceeds the configured payload limit.", "request_id": request_id}}, headers={"X-Request-ID": request_id})
        started = time.perf_counter()
        try:
            response = await call_next(request)
        except Exception:
            logger.exception("Unhandled request failure request_id=%s", request_id)
            response = JSONResponse(status_code=500, content={"error": {"code": "INTERNAL_ERROR", "message": "An unexpected internal error occurred.", "request_id": request_id}})
        response.headers["X-Request-ID"] = request_id
        logger.info("HTTP request method=%s path=%s status=%s duration_ms=%.2f request_id=%s", request.method,
            request.url.path, response.status_code, (time.perf_counter() - started) * 1000, request_id)
        return response

    def error_body(request: Request, code: str, message: str, **details: Any) -> dict[str, Any]:
        payload = {"code": code, "message": message, "request_id": getattr(request.state, "request_id", None)}
        if details:
            payload["details"] = details
        return {"error": payload}

    @app.exception_handler(ApiError)
    async def api_error_handler(request: Request, exc: ApiError):
        logger.warning("API error code=%s request_id=%s", exc.code, getattr(request.state, "request_id", None))
        return JSONResponse(status_code=exc.status_code, content=error_body(request, exc.code, exc.message))

    @app.exception_handler(RequestValidationError)
    async def validation_error_handler(request: Request, exc: RequestValidationError):
        details = [{"location": list(item.get("loc", ())), "message": item.get("msg", "Invalid input"), "type": item.get("type", "value_error")} for item in exc.errors()]
        return JSONResponse(status_code=422, content=error_body(request, "VALIDATION_ERROR", "Request validation failed.", fields=details))

    @app.exception_handler(StarletteHTTPException)
    async def http_error_handler(request: Request, exc: StarletteHTTPException):
        code = {404: "NOT_FOUND", 405: "METHOD_NOT_ALLOWED", 413: "REQUEST_TOO_LARGE"}.get(exc.status_code, "HTTP_ERROR")
        message = exc.detail if isinstance(exc.detail, str) else "The request could not be completed."
        return JSONResponse(status_code=exc.status_code, content=error_body(request, code, message), headers=exc.headers)

    @app.exception_handler(SQLAlchemyError)
    async def database_error_handler(request: Request, exc: SQLAlchemyError):
        logger.error("Database operation failed error_type=%s request_id=%s", type(exc).__name__, getattr(request.state, "request_id", None))
        return JSONResponse(status_code=503, content=error_body(request, "DATABASE_ERROR", "Database operation failed."))

    app.include_router(health.router, prefix="/api/v1")
    app.include_router(datasets.router, prefix="/api/v1")
    app.include_router(models.router, prefix="/api/v1")
    app.include_router(analysis.router, prefix="/api/v1")
    app.include_router(jobs.router, prefix="/api/v1")
    app.include_router(events.router, prefix="/api/v1")
    app.include_router(alerts.router, prefix="/api/v1")
    app.include_router(metrics.router, prefix="/api/v1")
    app.include_router(traffic.router, prefix="/api/v1")
    return app


app = create_app()
