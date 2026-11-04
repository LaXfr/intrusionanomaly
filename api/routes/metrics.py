from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from api.dependencies import get_model_service, get_session
from api.schemas import MetricsResponse
from api.services.metrics_service import MetricsService
from api.database.models import Alert, AnalysisJob, DetectionEvent

router = APIRouter(prefix="/metrics", tags=["metrics"])
service = MetricsService()


@router.get("", response_model=MetricsResponse, summary="Aggregate actual persisted operational metrics")
def metrics(session: Session = Depends(get_session), models=Depends(get_model_service)):
    descriptors, unavailable = models.list_models()
    return MetricsResponse(operational=service.operational(session, models),
        persisted_alerts_by_severity=service.distributions(session, Alert.severity),
        persisted_alerts_by_status=service.distributions(session, Alert.status),
        persisted_events_by_status=service.distributions(session, DetectionEvent.event_status),
        models={"available": [item["model_id"] for item in descriptors], "unavailable": unavailable},
        historical_evaluation={item["model_id"]: item.get("metrics") for item in descriptors if item.get("metrics")})
