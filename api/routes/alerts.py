from datetime import datetime
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from api.core.errors import ApiError
from api.dependencies import get_session
from api.schemas import AlertDetail, AlertListResponse, AlertStatus, AlertStatusRequest, AlertStatusResponse, AlertSummary
from api.services.alert_service import AlertService

router = APIRouter(prefix="/alerts", tags=["alerts"])
service = AlertService()


def _summary(row):
    return AlertSummary(id=row.id, alert_fingerprint=row.alert_fingerprint, title=row.title, alert_type=row.alert_type,
        severity=row.severity, threat_score=float(row.threat_score), status=row.status,
        predicted_categories=row.predicted_categories, first_seen=row.first_seen, last_seen=row.last_seen,
        event_count=row.event_count, created_at=row.created_at)


@router.get("", response_model=AlertListResponse, summary="Filter and paginate persisted security alerts")
def list_alerts(limit: int = Query(50, ge=1, le=200), offset: int = Query(0, ge=0),
        severity: str | None = Query(None, pattern="^(LOW|MEDIUM|HIGH|CRITICAL|UNSCORED)$"),
        status: AlertStatus | None = None, category: str | None = Query(None, max_length=100),
        start: datetime | None = None, end: datetime | None = None,
        minimum_threat_score: float | None = Query(None, ge=0, le=100),
        sort_by: str = Query("created_at", pattern="^(created_at|threat_score|severity)$"),
        order: str = Query("desc", pattern="^(asc|desc)$"), session: Session = Depends(get_session)):
    if start and end and start > end:
        raise ApiError(422, "INVALID_DATE_RANGE", "start must be earlier than or equal to end.")
    rows, total = service.list(session, limit=limit, offset=offset, severity=severity,
        status=status.value if status else None, category=category, start=start, end=end,
        minimum_score=minimum_threat_score, sort_by=sort_by, order=order)
    return AlertListResponse(items=[_summary(row) for row in rows], total=total, limit=limit, offset=offset)


@router.get("/{alert_id}", response_model=AlertDetail, summary="Get alert evidence and supporting event references")
def get_alert(alert_id: UUID, session: Session = Depends(get_session)):
    row = service.get(session, alert_id)
    events = service.supporting_events(session, alert_id)
    return AlertDetail(**_summary(row).model_dump(), correlation_rule=row.correlation_rule,
        correlation_metadata=row.correlation_metadata, summary=row.summary, explanation=row.explanation,
        supporting_event_ids=[event.id for event in events])


@router.patch("/{alert_id}/status", response_model=AlertStatusResponse, summary="Apply a valid alert lifecycle transition")
def update_alert_status(alert_id: UUID, request: AlertStatusRequest, session: Session = Depends(get_session)):
    row, previous, changed_at = service.update_status(session, alert_id, request.status.value, request.changed_by)
    return AlertStatusResponse(alert=_summary(row), previous_status=previous, status_changed_at=changed_at)
