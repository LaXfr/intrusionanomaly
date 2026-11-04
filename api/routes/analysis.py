from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from api.core.errors import ApiError
from api.dependencies import get_analysis_service, get_dataset_service, get_session
from api.schemas import AnalysisRequest, AnalysisResponse

router = APIRouter(tags=["analysis"])


@router.post("/analyze", response_model=AnalysisResponse, summary="Analyze bounded network-flow records", responses={503: {"description": "Requested model or database unavailable"}})
def analyze(request: AnalysisRequest, analysis=Depends(get_analysis_service), datasets=Depends(get_dataset_service), session: Session = Depends(get_session)):
    settings = analysis.settings
    if request.records is not None:
        if len(request.records) > settings.max_analysis_records:
            raise ApiError(413, "ANALYSIS_LIMIT_EXCEEDED", "Request exceeds the configured record limit.")
        records = request.records
        dataset_id = None
        truncated = False
    else:
        dataset = datasets.get(session, request.dataset_id)
        records, truncated = datasets.read_bounded_records(dataset, settings.max_analysis_records)
        dataset_id = dataset.id
    result = analysis.analyze_and_persist(session, records, engines=[item.value for item in request.engines],
        model_ids={key.value: value for key, value in request.model_ids.items()},
        anomaly_operating_point=request.anomaly_operating_point, dataset_id=dataset_id)
    result.summary["dataset_scope_truncated"] = truncated
    result.summary["maximum_records"] = settings.max_analysis_records
    return result
