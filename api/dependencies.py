"""FastAPI dependencies for settings, database sessions, and shared services."""

from __future__ import annotations

from collections.abc import Generator
from typing import TYPE_CHECKING

from fastapi import Request
from sqlalchemy.orm import Session

from api.core.config import Settings
from api.core.errors import ApiError

if TYPE_CHECKING:
    from api.services.analysis_service import AnalysisService
    from api.services.dataset_service import DatasetService
    from api.services.event_explanation_service import EventExplanationService
    from api.services.job_service import JobService
    from api.services.model_service import ModelService


def get_settings(request: Request) -> Settings:
    return request.app.state.settings


def get_session(request: Request) -> Generator[Session, None, None]:
    factory = getattr(request.app.state, "session_factory", None)
    if factory is None:
        raise ApiError(503, "DATABASE_UNAVAILABLE", "Database is not configured.")
    session = factory()
    try:
        yield session
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def get_model_service(request: Request) -> "ModelService":
    return request.app.state.model_service


def get_dataset_service(request: Request) -> "DatasetService":
    return request.app.state.dataset_service


def get_analysis_service(request: Request) -> "AnalysisService":
    return request.app.state.analysis_service


def get_job_service(request: Request) -> "JobService":
    return request.app.state.job_service


def get_event_explanation_service(request: Request) -> "EventExplanationService":
    return request.app.state.event_explanation_service
