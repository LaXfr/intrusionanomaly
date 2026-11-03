"""Typed results shared by the dataset ingestion components."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Literal

if TYPE_CHECKING:
    import pandas as pd


InspectionStatus = Literal["valid", "invalid", "error"]
DatasetStatus = Literal["valid", "invalid", "unavailable"]
ScanCoverage = Literal["metadata_only", "complete", "partial"]


@dataclass(frozen=True, slots=True)
class FileInspection:
    """Header and integrity metadata for one source CSV file."""

    path: Path
    relative_path: str
    file_name: str
    size_bytes: int | None
    extension: str
    sha256: str | None
    detected_encoding: str | None
    is_empty: bool
    header_readable: bool
    original_columns: tuple[str, ...]
    normalized_columns: tuple[str, ...]
    internal_columns: tuple[str, ...]
    exact_duplicate_columns: tuple[str, ...]
    normalized_collisions: tuple[str, ...]
    label_columns: tuple[str, ...]
    label_column_positions: tuple[int, ...]
    schema_fingerprint: str | None
    status: InspectionStatus
    warnings: tuple[str, ...]
    errors: tuple[str, ...]

    @property
    def label_column(self) -> str | None:
        """Return the single identified source label header, if unambiguous."""
        if len(self.label_columns) == 1:
            return self.label_columns[0]
        return None

    @property
    def internal_label_column(self) -> str | None:
        """Return the unique internal name assigned to the source label column."""
        if len(self.label_column_positions) == 1:
            position = self.label_column_positions[0] - 1
            return self.internal_columns[position]
        return None


@dataclass(frozen=True, slots=True)
class SchemaComparison:
    """Schema differences between one file and the selected reference file."""

    file: str
    relation: str
    compatible: bool
    missing_columns: tuple[str, ...]
    additional_columns: tuple[str, ...]
    column_order_differs: bool
    normalized_name_conflicts: tuple[str, ...]
    errors: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class SchemaValidationResult:
    """Dataset-level compatibility summary for inspected CSV headers."""

    reference_file: str | None
    matching_files: tuple[str, ...]
    order_only_files: tuple[str, ...]
    incompatible_files: tuple[str, ...]
    comparisons: tuple[SchemaComparison, ...]
    is_compatible: bool
    warnings: tuple[str, ...]
    errors: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class DatasetInspectionResult:
    """Actual discovery, file inspection, and schema validation results."""

    dataset_name: str
    source_reference: str
    inspection_timestamp_utc: str
    dataset_directory: str
    files: tuple[FileInspection, ...]
    schema_validation: SchemaValidationResult
    status: DatasetStatus
    warnings: tuple[str, ...]
    errors: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class FileLoadStats:
    """Exact row count for one file loaded into a DataFrame."""

    file: str
    rows_loaded: int


@dataclass(frozen=True, slots=True)
class LoadingMetadata:
    """Result metadata for a completed in-memory CSV load."""

    strategy: Literal["standard", "chunked"]
    started_at_utc: str
    completed_at_utc: str
    files: tuple[str, ...]
    rows_loaded: int
    columns: tuple[str, ...]
    file_stats: tuple[FileLoadStats, ...]
    scan_coverage: Literal["complete"]
    chunk_size: int | None = None


@dataclass(frozen=True, slots=True)
class LoadedDataset:
    """DataFrame and exact loading metadata returned by standard loading."""

    data: pd.DataFrame
    metadata: LoadingMetadata


@dataclass(frozen=True, slots=True)
class DataChunk:
    """One manageable DataFrame yielded by chunked loading."""

    data: pd.DataFrame
    source_file: str
    label_column: str
    chunk_index: int
    start_row: int
    end_row_exclusive: int


@dataclass(frozen=True, slots=True)
class LabelCount:
    """A preserved label value and its exact observed count."""

    label: str
    count: int


@dataclass(frozen=True, slots=True)
class LabelSummary:
    """Label counts from a complete or explicitly bounded scan."""

    coverage: Literal["complete", "partial"]
    rows_scanned: int
    files_scanned: tuple[str, ...]
    chunk_size: int
    label_counts: tuple[LabelCount, ...]
    started_at_utc: str
    completed_at_utc: str
