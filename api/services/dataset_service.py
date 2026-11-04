"""Safe CSV registration, inspection, and configured-storage resolution."""

from __future__ import annotations

import hashlib
import logging
import os
import re
import uuid
from pathlib import Path
from typing import Any, BinaryIO, Iterator

import pandas as pd
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from intrusion_intelligence.feature_engineering import FeatureContract, separate_features_target_metadata
from intrusion_intelligence.ingestion.inspection import inspect_csv_file

from api.core.config import Settings
from api.core.errors import ApiError
from api.database.models import Dataset

logger = logging.getLogger(__name__)
_SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._ -]{0,254}\.csv$", re.IGNORECASE)


class DatasetService:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.contract = FeatureContract.from_file(settings.feature_schema_path)

    def register_stream(self, filename: str | None, stream: BinaryIO, name: str | None, session: Session) -> Dataset:
        if not filename or not _SAFE_NAME.fullmatch(filename) or ".." in filename or "/" in filename or "\\" in filename:
            raise ApiError(400, "INVALID_FILENAME", "Upload filename must be a plain .csv filename without path components.")
        self.settings.upload_dir.mkdir(parents=True, exist_ok=True)
        temporary = self.settings.upload_dir / f"{uuid.uuid4().hex}.part"
        final = temporary.with_suffix(".csv")
        digest = hashlib.sha256()
        byte_count = 0
        try:
            with temporary.open("xb") as output:
                while chunk := stream.read(1024 * 1024):
                    byte_count += len(chunk)
                    if byte_count > self.settings.max_upload_bytes:
                        raise ApiError(413, "UPLOAD_TOO_LARGE", "Uploaded CSV exceeds the configured size limit.")
                    digest.update(chunk)
                    output.write(chunk)
            if byte_count == 0:
                raise ApiError(400, "EMPTY_UPLOAD", "Uploaded CSV is empty.")
            inspection = inspect_csv_file(temporary, label_candidates=(self.contract.target_name, "Label"),
                require_label=False, compute_checksum=False)
            if not inspection.header_readable or inspection.exact_duplicate_columns or inspection.normalized_collisions:
                raise ApiError(422, "INVALID_CSV", "CSV header is unreadable or contains duplicate columns.")
            required = set(self.contract.predictive_features)
            allowed = required | set(self.contract.metadata_fields) | set(self.contract.excluded_fields) | {self.contract.target_name}
            columns = list(inspection.original_columns)
            if not required.issubset(columns) or set(columns) - allowed:
                raise ApiError(422, "FEATURE_SCHEMA_MISMATCH", "CSV columns do not match the approved feature contract.")
            row_count = 0
            try:
                for frame in pd.read_csv(temporary, chunksize=self.settings.job_batch_size, encoding=inspection.detected_encoding):
                    separate_features_target_metadata(frame, self.contract, require_target=False)
                    row_count += len(frame)
            except Exception as exc:
                raise ApiError(422, "INVALID_CSV_ROWS", "CSV data could not be validated against the feature contract.") from exc
            if row_count == 0:
                raise ApiError(422, "EMPTY_DATASET", "CSV has a valid header but contains no data rows.")
            checksum = digest.hexdigest()
            if session.scalar(select(Dataset.id).where(Dataset.checksum == checksum)):
                raise ApiError(409, "DUPLICATE_DATASET", "A dataset with the same content checksum is already registered.")
            os.replace(temporary, final)
            row = Dataset(name=(name or Path(filename).stem)[:240], source_filename=filename,
                storage_uri=str(final.resolve()), checksum=checksum, file_size_bytes=byte_count,
                schema_version=self.contract.schema_version, row_count=row_count, status="VALIDATED",
                dataset_metadata={"header_validation": "passed", "inspection_status": inspection.status,
                    "inspection_warnings": list(inspection.warnings), "label_present": self.contract.target_name in columns,
                    "storage_format": "CSV", "storage_scope": "configured_upload_directory"})
            session.add(row)
            session.commit()
            session.refresh(row)
            logger.info("Registered dataset id=%s rows=%s bytes=%s", row.id, row_count, byte_count)
            return row
        except Exception:
            session.rollback()
            temporary.unlink(missing_ok=True)
            final.unlink(missing_ok=True)
            raise

    def resolve_path(self, row: Dataset) -> Path:
        path = Path(row.storage_uri).resolve()
        try:
            path.relative_to(self.settings.upload_dir.resolve())
        except ValueError as exc:
            raise ApiError(400, "INVALID_STORAGE_REFERENCE", "Registered dataset is outside configured upload storage.") from exc
        if not path.is_file():
            raise ApiError(404, "DATASET_FILE_MISSING", "Registered dataset file is no longer available.")
        return path

    def get(self, session: Session, dataset_id: uuid.UUID) -> Dataset:
        row = session.get(Dataset, dataset_id)
        if row is None:
            raise ApiError(404, "DATASET_NOT_FOUND", "Dataset was not found.")
        return row

    def list(self, session: Session, limit: int, offset: int) -> tuple[list[Dataset], int]:
        total = int(session.scalar(select(func.count()).select_from(Dataset)) or 0)
        rows = list(session.scalars(select(Dataset).order_by(Dataset.created_at.desc()).limit(limit).offset(offset)))
        return rows, total

    def read_bounded_records(self, row: Dataset, maximum: int) -> tuple[list[dict[str, Any]], bool]:
        path = self.resolve_path(row)
        frame = pd.read_csv(path, nrows=maximum)
        X, _, metadata = separate_features_target_metadata(frame, self.contract, require_target=False)
        records = []
        for index in range(len(X)):
            meta = metadata.iloc[index].where(pd.notna(metadata.iloc[index]), None).to_dict()
            meta.update(source_filename=row.source_filename, source_row_number=index + 1,
                flow_record_reference=f"dataset:{row.id}#row={index + 1}")
            records.append({"features": X.iloc[index].where(pd.notna(X.iloc[index]), None).to_dict(), "metadata": meta})
        return records, row.row_count is not None and row.row_count > len(records)

    def iter_batches(self, row: Dataset, batch_size: int, max_rows: int) -> Iterator[pd.DataFrame]:
        path = self.resolve_path(row)
        count = 0
        for frame in pd.read_csv(path, chunksize=batch_size):
            if count >= max_rows:
                break
            if len(frame) + count > max_rows:
                frame = frame.iloc[:max_rows - count]
            separate_features_target_metadata(frame, self.contract, require_target=False)
            count += len(frame)
            yield frame
