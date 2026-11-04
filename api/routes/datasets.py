from uuid import UUID

from fastapi import APIRouter, Depends, File, Form, UploadFile
from sqlalchemy.orm import Session

from api.dependencies import get_dataset_service, get_session
from api.schemas import DatasetListResponse, DatasetResponse

router = APIRouter(prefix="/datasets", tags=["datasets"])


def _response(row):
    return DatasetResponse(id=row.id, name=row.name, source_filename=row.source_filename, checksum=row.checksum,
        file_size_bytes=row.file_size_bytes, schema_version=row.schema_version, row_count=row.row_count,
        status=row.status, metadata=row.dataset_metadata, created_at=row.created_at)


@router.post("", response_model=DatasetResponse, status_code=201, summary="Validate and register a bounded CSV dataset")
def upload_dataset(file: UploadFile = File(...), name: str | None = Form(default=None),
                   service=Depends(get_dataset_service), session: Session = Depends(get_session)):
    try:
        return _response(service.register_stream(file.filename, file.file, name, session))
    finally:
        file.file.close()


@router.get("", response_model=DatasetListResponse, summary="List registered datasets")
def list_datasets(limit: int = 50, offset: int = 0, service=Depends(get_dataset_service), session: Session = Depends(get_session)):
    rows, total = service.list(session, limit, offset)
    return DatasetListResponse(items=[_response(row) for row in rows], total=total, limit=limit, offset=offset)


@router.get("/{dataset_id}", response_model=DatasetResponse, summary="Get dataset validation metadata")
def get_dataset(dataset_id: UUID, service=Depends(get_dataset_service), session: Session = Depends(get_session)):
    return _response(service.get(session, dataset_id))
