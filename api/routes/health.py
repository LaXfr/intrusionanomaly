from fastapi import APIRouter, Depends, Request
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from api.core.errors import ApiError
from api.dependencies import get_model_service, get_session
from api.schemas import HealthResponse, ReadinessResponse

router = APIRouter(tags=["health"])


@router.get("/health", response_model=HealthResponse, summary="Check API liveness")
def health(request: Request):
    return HealthResponse(status="alive", service=request.app.title, version=request.app.version)


@router.get("/ready", response_model=ReadinessResponse, summary="Check backend readiness", responses={503: {"description": "Required service unavailable"}})
def ready(request: Request, session=Depends(get_session), models=Depends(get_model_service)):
    try:
        session.execute(text("SELECT 1"))
    except SQLAlchemyError as exc:
        raise ApiError(503, "DATABASE_UNAVAILABLE", "Database readiness check failed.") from exc
    descriptors, unavailable = models.list_models()
    checks = {"database": "ready", "feature_schema": "ready" if request.app.state.settings.feature_schema_path.is_file() else "unavailable",
              "model_registry": {"ready": sum(item["status"] == "READY" for item in descriptors), "unavailable": unavailable},
              "upload_storage": "ready" if request.app.state.settings.upload_dir.is_dir() else "unavailable"}
    status = "ready" if checks["feature_schema"] == "ready" and checks["upload_storage"] == "ready" and descriptors else "degraded"
    return ReadinessResponse(status=status, checks=checks)
