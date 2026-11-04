from uuid import UUID

from fastapi import APIRouter, BackgroundTasks, Depends
from sqlalchemy.orm import Session

from api.dependencies import get_job_service, get_session
from api.schemas import JobCreateRequest, JobResponse

router = APIRouter(prefix="/analysis-jobs", tags=["analysis-jobs"])


def _response(row):
    return JobResponse(id=row.id, dataset_id=row.dataset_id, status=row.status, requested_engines=row.requested_engines,
        selected_model_versions=row.selected_model_versions, total_records=row.total_records,
        processed_records=row.processed_records, successful_records=row.successful_records,
        failed_records=row.failed_records, alerts_generated=row.alerts_generated,
        error_message=row.error_message, created_at=row.created_at, started_at=row.started_at, completed_at=row.completed_at)


@router.post("", response_model=JobResponse, status_code=202, summary="Queue bounded analysis of a registered dataset")
def create_job(request: JobCreateRequest, background: BackgroundTasks, service=Depends(get_job_service), session: Session = Depends(get_session)):
    return _response(service.create(session, request, background))


@router.get("/{job_id}", response_model=JobResponse, summary="Get persisted analysis-job progress")
def get_job(job_id: UUID, service=Depends(get_job_service), session: Session = Depends(get_session)):
    return _response(service.get(session, job_id))


@router.post("/{job_id}/cancel", response_model=JobResponse, summary="Cancel a queued or running analysis job")
def cancel_job(job_id: UUID, service=Depends(get_job_service), session: Session = Depends(get_session)):
    return _response(service.cancel(session, job_id))
