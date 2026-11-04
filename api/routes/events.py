"""Paginated access to persisted detection events."""

from uuid import UUID

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from api.core.errors import ApiError
from api.database.models import DetectionEvent
from api.dependencies import get_event_explanation_service, get_session
from api.schemas import DetectionEventDetail, DetectionEventList, DetectionEventResponse

router = APIRouter(prefix="/events", tags=["events"])


def _summary(row: DetectionEvent) -> DetectionEventResponse:
    return DetectionEventResponse(
        id=row.id, event_fingerprint=row.event_fingerprint,
        source_record_reference=row.source_record_reference, event_timestamp=row.event_timestamp,
        threat_score=float(row.threat_score) if row.threat_score is not None else None,
        severity=row.severity, event_status=row.event_status,
        detector_evidence={key: value for key, value in {
            "binary": row.binary_evidence, "multiclass": row.multiclass_evidence,
            "anomaly": row.anomaly_evidence}.items() if value is not None},
        scoring_breakdown=row.scoring_breakdown or {},
    )


@router.get("", response_model=DetectionEventList, summary="Filter and paginate persisted detection events")
def list_events(limit: int = Query(50, ge=1, le=200), offset: int = Query(0, ge=0),
        dataset_id: UUID | None = None, analysis_job_id: UUID | None = None,
        event_status: str | None = Query(None, max_length=48),
        severity: str | None = Query(None, pattern="^(LOW|MEDIUM|HIGH|CRITICAL|UNSCORED)$"),
        session: Session = Depends(get_session)):
    conditions = []
    if dataset_id is not None:
        conditions.append(DetectionEvent.dataset_id == dataset_id)
    if analysis_job_id is not None:
        conditions.append(DetectionEvent.analysis_job_id == analysis_job_id)
    if event_status:
        conditions.append(DetectionEvent.event_status == event_status)
    if severity:
        conditions.append(DetectionEvent.severity == severity)
    total = int(session.scalar(select(func.count()).select_from(DetectionEvent).where(*conditions)) or 0)
    rows = list(session.scalars(select(DetectionEvent).where(*conditions)
        .order_by(DetectionEvent.generated_at.desc(), DetectionEvent.id).limit(limit).offset(offset)))
    return DetectionEventList(items=[_summary(row) for row in rows], total=total, limit=limit, offset=offset)


@router.get("/{event_id}", response_model=DetectionEventDetail, summary="Retrieve a persisted detection event")
def get_event(event_id: UUID, session: Session = Depends(get_session)):
    row = session.get(DetectionEvent, event_id)
    if row is None:
        raise ApiError(404, "EVENT_NOT_FOUND", "Detection event was not found.")
    return DetectionEventDetail(**_summary(row).model_dump(), dataset_id=row.dataset_id,
        analysis_job_id=row.analysis_job_id, generated_at=row.generated_at,
        flow_metadata=row.flow_metadata or {}, explanation_references=row.explanation_references or [])


@router.get("/{event_id}/explanation", summary="Compute or retrieve a model-specific SHAP explanation")
def explain_event(event_id: UUID, engine: str = Query(..., pattern="^(binary|multiclass|anomaly)$"),
        service=Depends(get_event_explanation_service), session: Session = Depends(get_session)):
    return service.explain(session, event_id, engine)
