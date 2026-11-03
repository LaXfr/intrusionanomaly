"""Pandas-based whole-file, preview, and chunked CSV loading strategies."""

from __future__ import annotations

import logging
from collections.abc import Iterator, Sequence
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd

from intrusion_intelligence.errors import (
    CSVInspectionError,
    DataLoadingError,
    DatasetDiscoveryError,
    SchemaValidationError,
)
from intrusion_intelligence.ingestion.discovery import discover_dataset_files
from intrusion_intelligence.ingestion.inspection import inspect_csv_file
from intrusion_intelligence.ingestion.models import (
    DataChunk,
    FileInspection,
    FileLoadStats,
    LoadedDataset,
    LoadingMetadata,
)
from intrusion_intelligence.ingestion.schema import validate_schemas

logger = logging.getLogger(__name__)
_DEFAULT_CHUNK_SIZE = 100_000


def load_dataset(
    dataset_directory: str | Path,
    *,
    files: Sequence[str | Path] | str | Path | None = None,
    supported_extensions: Sequence[str] = (".csv",),
    label_candidates: Sequence[str] = ("Label",),
    encoding: str = "auto",
    recursive: bool = True,
) -> LoadedDataset:
    """Load one or more schema-compatible CSV files into a single DataFrame.

    Headers are inspected before parsing. Source headers are retained in
    inspection metadata; colliding names receive position-specific internal
    aliases. Incompatible files are rejected, and safe order-only differences
    are aligned by internal column name. Label fields are read as strings and
    Pandas NA token conversion is disabled so source label text is retained.
    """
    directory = Path(dataset_directory).expanduser().resolve()
    sources = _resolve_sources(
        directory,
        files,
        supported_extensions=supported_extensions,
        recursive=recursive,
    )
    inspections, canonical_columns = _validate_sources(
        sources,
        directory,
        label_candidates=label_candidates,
        encoding=encoding,
    )

    started_at = _now()
    logger.info(
        "Starting standard CSV loading for %d file(s)",
        len(inspections),
    )
    frames: list[pd.DataFrame] = []
    file_stats: list[FileLoadStats] = []
    for inspection in inspections:
        frame = _read_csv(
            inspection,
            encoding=inspection.detected_encoding or encoding,
        )
        if tuple(frame.columns) != canonical_columns:
            frame = frame.reindex(columns=canonical_columns)
        frames.append(frame)
        file_stats.append(
            FileLoadStats(file=inspection.relative_path, rows_loaded=len(frame))
        )

    data = frames[0] if len(frames) == 1 else pd.concat(
        frames,
        ignore_index=True,
    )
    metadata = LoadingMetadata(
        strategy="standard",
        started_at_utc=started_at,
        completed_at_utc=_now(),
        files=tuple(item.relative_path for item in inspections),
        rows_loaded=len(data),
        columns=tuple(str(column) for column in data.columns),
        file_stats=tuple(file_stats),
        scan_coverage="complete",
    )
    logger.info(
        "Loaded %d row(s) from %d CSV file(s) using standard loading",
        metadata.rows_loaded,
        len(metadata.files),
    )
    return LoadedDataset(data=data, metadata=metadata)


def iter_dataset_chunks(
    dataset_directory: str | Path,
    *,
    files: Sequence[str | Path] | str | Path | None = None,
    chunk_size: int = _DEFAULT_CHUNK_SIZE,
    supported_extensions: Sequence[str] = (".csv",),
    label_candidates: Sequence[str] = ("Label",),
    encoding: str = "auto",
    recursive: bool = True,
) -> Iterator[DataChunk]:
    """Yield DataFrames sequentially without holding a whole dataset in memory."""
    if chunk_size <= 0:
        raise DataLoadingError("Chunk size must be greater than zero.")

    directory = Path(dataset_directory).expanduser().resolve()
    sources = _resolve_sources(
        directory,
        files,
        supported_extensions=supported_extensions,
        recursive=recursive,
    )
    inspections, canonical_columns = _validate_sources(
        sources,
        directory,
        label_candidates=label_candidates,
        encoding=encoding,
    )

    logger.info(
        "Starting chunked CSV loading for %d file(s) with chunk_size=%d",
        len(inspections),
        chunk_size,
    )
    for inspection in inspections:
        offset = 0
        chunk_index = 0
        try:
            reader = pd.read_csv(
                inspection.path,
                encoding=inspection.detected_encoding or encoding,
                header=0,
                names=list(inspection.internal_columns),
                dtype={inspection.internal_label_column: str},
                keep_default_na=False,
                chunksize=chunk_size,
                on_bad_lines="error",
            )
            try:
                for frame in reader:
                    if tuple(frame.columns) != canonical_columns:
                        frame = frame.reindex(columns=canonical_columns)
                    row_count = len(frame)
                    chunk = DataChunk(
                        data=frame,
                        source_file=inspection.relative_path,
                        label_column=inspection.internal_label_column or "",
                        chunk_index=chunk_index,
                        start_row=offset,
                        end_row_exclusive=offset + row_count,
                    )
                    logger.debug(
                        "Read chunk %d from %s: %d row(s)",
                        chunk_index,
                        inspection.relative_path,
                        row_count,
                    )
                    yield chunk
                    offset += row_count
                    chunk_index += 1
            finally:
                reader.close()
        except (OSError, UnicodeError, ValueError, pd.errors.ParserError) as exc:
            raise DataLoadingError(
                f"Unable to read CSV file {inspection.relative_path}: "
                f"{exc.__class__.__name__}."
            ) from exc
    logger.info("Chunked CSV loading completed")


def preview_dataset_file(
    file_path: str | Path,
    *,
    label_candidates: Sequence[str] = ("Label",),
    encoding: str = "auto",
    row_count: int = 10,
) -> pd.DataFrame:
    """Read a bounded preview from one validated CSV file."""
    if row_count <= 0:
        raise DataLoadingError("Preview row count must be greater than zero.")

    path = Path(file_path).expanduser()
    try:
        inspection = inspect_csv_file(
            path,
            label_candidates=label_candidates,
            encoding=encoding,
            compute_checksum=False,
        )
    except CSVInspectionError as exc:
        raise DataLoadingError(str(exc)) from exc
    _require_valid((inspection,))
    return _read_csv(
        inspection,
        encoding=inspection.detected_encoding or encoding,
        nrows=row_count,
    )


def _resolve_sources(
    dataset_directory: Path,
    files: Sequence[str | Path] | str | Path | None,
    *,
    supported_extensions: Sequence[str],
    recursive: bool,
) -> tuple[Path, ...]:
    """Resolve selected file paths or discover the configured file set."""
    if files is None:
        return discover_dataset_files(
            dataset_directory,
            supported_extensions=supported_extensions,
            recursive=recursive,
        )

    if isinstance(files, (str, Path)):
        provided = (files,)
    else:
        provided = tuple(files)
    if not provided:
        raise DatasetDiscoveryError("No CSV files were selected for loading.")

    resolved = tuple(
        (dataset_directory / Path(item)).resolve()
        if not Path(item).is_absolute()
        else Path(item).resolve()
        for item in provided
    )
    allowed_extensions = tuple(extension.lower() for extension in supported_extensions)
    for path in resolved:
        if not path.is_file():
            raise DataLoadingError(f"Selected CSV file does not exist: {path}")
        if not any(
            path.name.lower().endswith(extension)
            for extension in allowed_extensions
        ):
            raise DataLoadingError(
                f"Unsupported dataset file extension: {path.suffix or '(none)'}"
            )
    return resolved


def _validate_sources(
    sources: Sequence[Path],
    dataset_directory: Path,
    *,
    label_candidates: Sequence[str],
    encoding: str,
) -> tuple[list[FileInspection], tuple[str, ...]]:
    """Inspect headers and reject any incompatible source group."""
    try:
        inspections = [
            inspect_csv_file(
                path,
                dataset_directory=dataset_directory,
                label_candidates=label_candidates,
                encoding=encoding,
                compute_checksum=False,
            )
            for path in sources
        ]
    except CSVInspectionError as exc:
        raise SchemaValidationError(str(exc)) from exc

    validation = validate_schemas(inspections)
    _require_valid(inspections, validation.errors)
    if not validation.is_compatible:
        details = "; ".join(validation.errors) or "Schemas are incompatible."
        raise SchemaValidationError(details)

    reference = next(item for item in inspections if item.status == "valid")
    return inspections, reference.internal_columns


def _require_valid(
    inspections: Sequence[FileInspection],
    schema_errors: Sequence[str] = (),
) -> None:
    """Raise a useful error when a selected file fails structural validation."""
    invalid = [item for item in inspections if item.status != "valid"]
    if not invalid:
        return
    details = [
        f"{item.relative_path}: {'; '.join(item.errors) or 'invalid CSV structure'}"
        for item in invalid
    ]
    details.extend(schema_errors)
    raise SchemaValidationError(" ".join(details))


def _read_csv(
    inspection: FileInspection,
    *,
    encoding: str,
    nrows: int | None = None,
) -> pd.DataFrame:
    """Parse a previously inspected CSV while preserving source label text."""
    try:
        return pd.read_csv(
            inspection.path,
            encoding=encoding,
            header=0,
            names=list(inspection.internal_columns),
            dtype={inspection.internal_label_column: str},
            keep_default_na=False,
            on_bad_lines="error",
            nrows=nrows,
        )
    except (OSError, UnicodeError, ValueError, pd.errors.ParserError) as exc:
        raise DataLoadingError(
            f"Unable to read CSV file {inspection.relative_path}: "
            f"{exc.__class__.__name__}."
        ) from exc


def _now() -> str:
    """Return a timezone-aware UTC timestamp."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds")
