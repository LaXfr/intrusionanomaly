"""Coordinate discovery, file inspection, and schema compatibility checks."""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Sequence

from intrusion_intelligence.errors import (
    CSVInspectionError,
    DatasetDiscoveryError,
    DatasetDirectoryError,
)
from intrusion_intelligence.ingestion.discovery import discover_dataset_files
from intrusion_intelligence.ingestion.inspection import inspect_csv_file
from intrusion_intelligence.ingestion.models import (
    DatasetInspectionResult,
    FileInspection,
    SchemaValidationResult,
)
from intrusion_intelligence.ingestion.schema import validate_schemas

logger = logging.getLogger(__name__)


def inspect_dataset(
    dataset_directory: str | Path,
    *,
    dataset_name: str = "CIC-IDS2017",
    source_reference: str = "https://www.unb.ca/cic/datasets/ids-2017.html",
    supported_extensions: Sequence[str] = (".csv",),
    label_candidates: Sequence[str] = ("Label",),
    recursive: bool = True,
    encoding: str = "auto",
    project_root: str | Path | None = None,
    compute_checksums: bool = True,
) -> DatasetInspectionResult:
    """Inspect all discovered files and compare their schemas.

    Inspection reads headers and file bytes for checksums, but does not load or
    count data rows. A missing or empty directory is represented as an
    unavailable result so callers can still write an honest report.
    """
    directory = Path(dataset_directory).expanduser().resolve()
    display_directory = _display_path(directory, project_root)
    timestamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
    logger.info("Starting dataset inspection for %s", dataset_name)

    try:
        files = discover_dataset_files(
            directory,
            supported_extensions=supported_extensions,
            recursive=recursive,
        )
    except (DatasetDirectoryError, DatasetDiscoveryError) as exc:
        safe_error = str(exc).replace(str(directory), display_directory)
        schema = SchemaValidationResult(
            reference_file=None,
            matching_files=(),
            order_only_files=(),
            incompatible_files=(),
            comparisons=(),
            is_compatible=False,
            warnings=(),
            errors=(safe_error,),
        )
        return DatasetInspectionResult(
            dataset_name=dataset_name,
            source_reference=source_reference,
            inspection_timestamp_utc=timestamp,
            dataset_directory=display_directory,
            files=(),
            schema_validation=schema,
            status="unavailable",
            warnings=(),
            errors=(safe_error,),
        )

    inspections: list[FileInspection] = []
    inspection_errors: list[str] = []
    for file_path in files:
        try:
            inspections.append(
                inspect_csv_file(
                    file_path,
                    dataset_directory=directory,
                    label_candidates=label_candidates,
                    encoding=encoding,
                    compute_checksum=compute_checksums,
                )
            )
        except CSVInspectionError as exc:
            inspection_errors.append(f"{file_path.name}: {exc}")
            try:
                file_size = file_path.stat().st_size
                is_empty = file_size == 0
            except OSError:
                file_size = None
                is_empty = False
            resolved_file = file_path.resolve()
            try:
                relative_file = resolved_file.relative_to(directory).as_posix()
            except ValueError:
                relative_file = resolved_file.name
            inspections.append(
                FileInspection(
                    path=resolved_file,
                    relative_path=relative_file,
                    file_name=resolved_file.name,
                    size_bytes=file_size,
                    extension=resolved_file.suffix.lower(),
                    sha256=None,
                    detected_encoding=None,
                    is_empty=is_empty,
                    header_readable=False,
                    original_columns=(),
                    normalized_columns=(),
                    internal_columns=(),
                    exact_duplicate_columns=(),
                    normalized_collisions=(),
                    label_columns=(),
                    label_column_positions=(),
                    schema_fingerprint=None,
                    status="error",
                    warnings=(),
                    errors=(str(exc),),
                )
            )

    schema_validation = validate_schemas(inspections)
    warnings = [warning for item in inspections for warning in item.warnings]
    warnings.extend(schema_validation.warnings)
    errors = [error for item in inspections for error in item.errors]
    errors.extend(schema_validation.errors)
    errors.extend(inspection_errors)
    status = (
        "valid"
        if schema_validation.is_compatible and not inspection_errors
        else "invalid"
    )

    result = DatasetInspectionResult(
        dataset_name=dataset_name,
        source_reference=source_reference,
        inspection_timestamp_utc=timestamp,
        dataset_directory=display_directory,
        files=tuple(inspections),
        schema_validation=schema_validation,
        status=status,
        warnings=tuple(dict.fromkeys(warnings)),
        errors=tuple(dict.fromkeys(errors)),
    )
    logger.info(
        "Dataset inspection complete: status=%s files=%d valid=%d rejected=%d",
        result.status,
        len(result.files),
        sum(item.status == "valid" for item in result.files),
        sum(item.status != "valid" for item in result.files),
    )
    return result


def _display_path(path: Path, project_root: str | Path | None) -> str:
    """Prefer project-relative metadata paths and redact external ancestors."""
    resolved = path.resolve()
    root = (
        Path(project_root).expanduser().resolve()
        if project_root
        else Path.cwd().resolve()
    )
    try:
        return resolved.relative_to(root).as_posix()
    except ValueError:
        return f"<external>/{resolved.name}"
