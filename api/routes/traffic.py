from datetime import datetime
from typing import Literal
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from api.core.errors import ApiError
from api.dependencies import get_session
from api.schemas import TrafficSummaryResponse
from api.services.metrics_service import MetricsService

router = APIRouter(prefix="/traffic", tags=["traffic"])
service = MetricsService()


@router.get("/summary", response_model=TrafficSummaryResponse, summary="Summarize persisted detection events")
def traffic_summary(dataset_id: UUID | None = None, analysis_job_id: UUID | None = None,
        start: datetime | None = None, end: datetime | None = None,
        group_by: Literal["severity", "event_status", "attack_category", "day"] = "severity",
        detection_status: str | None = Query(None, max_length=48), attack_category: str | None = Query(None, max_length=100),
        limit: int = Query(50, ge=1, le=200), session: Session = Depends(get_session)):
    if start and end and start > end:
        raise ApiError(422, "INVALID_DATE_RANGE", "start must be earlier than or equal to end.")
    result = service.traffic(session, dataset_id=dataset_id, job_id=analysis_job_id, start=start, end=end,
        event_status=detection_status, category=attack_category, group_by=group_by, limit=limit)
    return TrafficSummaryResponse(**result)
