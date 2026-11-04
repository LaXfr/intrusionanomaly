from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from api.dependencies import get_model_service, get_session
from api.schemas import ModelResponse, ModelsResponse

router = APIRouter(prefix="/models", tags=["models"])


@router.get("", response_model=ModelsResponse, summary="List validated local models and availability")
def list_models(service=Depends(get_model_service), session: Session = Depends(get_session)):
    descriptors = service.sync_database_registry(session)
    _, unavailable = service.list_models()
    items = [ModelResponse(model_id=item["model_id"], model_name=item["model_name"], model_version=item["model_version"],
        model_type=item["model_type"], feature_schema_version=item["feature_schema_version"],
        input_feature_count=item["input_feature_count"], class_mapping=item["class_mapping"],
        threshold_configuration=item["threshold_configuration"], status=item["status"],
        supported_prediction_types=item["supported_prediction_types"], evaluation_metadata=item["metrics"]) for item in descriptors]
    return ModelsResponse(items=items, ready_count=len(items), unavailable_count=len(unavailable))
