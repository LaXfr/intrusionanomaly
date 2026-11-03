"""Dataset discovery, CSV inspection, validation, and loading interfaces."""

from intrusion_intelligence.ingestion.discovery import discover_dataset_files
from intrusion_intelligence.ingestion.inspection import inspect_csv_file
from intrusion_intelligence.ingestion.loader import (
    DataChunk,
    LoadedDataset,
    iter_dataset_chunks,
    load_dataset,
    preview_dataset_file,
)
from intrusion_intelligence.ingestion.metadata import (
    build_metadata,
    render_ingestion_report,
    write_ingestion_report,
    write_metadata,
)
from intrusion_intelligence.ingestion.models import (
    DatasetInspectionResult,
    FileLoadStats,
    FileInspection,
    LabelSummary,
    LoadingMetadata,
    SchemaValidationResult,
)
from intrusion_intelligence.ingestion.schema import validate_schemas
from intrusion_intelligence.ingestion.service import inspect_dataset
from intrusion_intelligence.ingestion.summary import summarize_labels

__all__ = [
    "DataChunk",
    "DatasetInspectionResult",
    "FileLoadStats",
    "FileInspection",
    "LabelSummary",
    "LoadingMetadata",
    "LoadedDataset",
    "SchemaValidationResult",
    "build_metadata",
    "discover_dataset_files",
    "inspect_csv_file",
    "inspect_dataset",
    "iter_dataset_chunks",
    "load_dataset",
    "preview_dataset_file",
    "render_ingestion_report",
    "summarize_labels",
    "validate_schemas",
    "write_ingestion_report",
    "write_metadata",
]
