"""JSON metadata and readable Markdown reports for actual ingestion runs."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from intrusion_intelligence.errors import MetadataWriteError
from intrusion_intelligence.ingestion.models import (
    DatasetInspectionResult,
    FileInspection,
    LoadingMetadata,
    LabelSummary,
)

logger = logging.getLogger(__name__)


def build_metadata(
    result: DatasetInspectionResult,
    label_summary: LabelSummary | None = None,
    loading_metadata: LoadingMetadata | None = None,
) -> dict[str, Any]:
    """Convert inspection results into JSON-safe metadata without traffic rows."""
    valid_count = sum(item.status == "valid" for item in result.files)
    rejected_count = len(_rejected_files(result))
    unreadable_count = sum(
        item.status == "error" and not item.header_readable
        for item in result.files
    )

    if label_summary is not None:
        scan = {
            "coverage": label_summary.coverage,
            "rows_scanned": label_summary.rows_scanned,
            "files_scanned": list(label_summary.files_scanned),
            "label_category_counts": [
                {"label": item.label, "count": item.count}
                for item in label_summary.label_counts
            ],
            "started_at_utc": label_summary.started_at_utc,
            "completed_at_utc": label_summary.completed_at_utc,
        }
    elif loading_metadata is not None:
        scan = {
            "coverage": loading_metadata.scan_coverage,
            "rows_scanned": loading_metadata.rows_loaded,
            "files_scanned": list(loading_metadata.files),
            "label_category_counts": None,
            "started_at_utc": loading_metadata.started_at_utc,
            "completed_at_utc": loading_metadata.completed_at_utc,
        }
    else:
        scan = {
            "coverage": "metadata_only",
            "rows_scanned": None,
            "files_scanned": [],
            "label_category_counts": None,
        }

    return {
        "dataset_name": result.dataset_name,
        "source_reference": result.source_reference,
        "inspection_timestamp_utc": result.inspection_timestamp_utc,
        "dataset_directory": result.dataset_directory,
        "ingestion_status": result.status,
        "discovery": {
            "discovered_files": len(result.files),
            "successfully_inspected_files": valid_count,
            "rejected_files": rejected_count,
            "unreadable_files": unreadable_count,
        },
        "files": [_file_metadata(item) for item in result.files],
        "schema_validation": {
            "reference_file": result.schema_validation.reference_file,
            "compatible": result.schema_validation.is_compatible,
            "matching_files": list(result.schema_validation.matching_files),
            "order_only_files": list(result.schema_validation.order_only_files),
            "incompatible_files": list(result.schema_validation.incompatible_files),
            "comparisons": [
                {
                    "file": comparison.file,
                    "relation": comparison.relation,
                    "compatible": comparison.compatible,
                    "missing_columns": list(comparison.missing_columns),
                    "additional_columns": list(comparison.additional_columns),
                    "column_order_differs": comparison.column_order_differs,
                    "normalized_name_conflicts": list(
                        comparison.normalized_name_conflicts
                    ),
                    "errors": list(comparison.errors),
                }
                for comparison in result.schema_validation.comparisons
            ],
        },
        "scan": scan,
        "loading": _loading_metadata(loading_metadata),
        "warnings": list(result.warnings),
        "validation_errors": list(result.errors),
    }


def write_metadata(
    result: DatasetInspectionResult,
    output_path: str | Path,
    label_summary: LabelSummary | None = None,
    loading_metadata: LoadingMetadata | None = None,
) -> Path:
    """Write a JSON metadata file from an executed inspection or scan."""
    path = Path(output_path).expanduser()
    payload = build_metadata(result, label_summary, loading_metadata)
    _write_text(path, json.dumps(payload, ensure_ascii=False, indent=2) + "\n")
    logger.info("Wrote dataset metadata to %s", path)
    return path


def render_ingestion_report(
    result: DatasetInspectionResult,
    label_summary: LabelSummary | None = None,
    loading_metadata: LoadingMetadata | None = None,
) -> str:
    """Render concise findings from actual dataset inspection and scans."""
    valid_count = sum(item.status == "valid" for item in result.files)
    rejected_count = len(_rejected_files(result))
    lines = [
        f"# Ingestion report: {result.dataset_name}",
        "",
        f"- **Status:** {result.status}",
        f"- **Source:** {result.source_reference}",
        f"- **Dataset directory:** {result.dataset_directory}",
        f"- **Inspection time (UTC):** {result.inspection_timestamp_utc}",
        f"- **Files discovered:** {len(result.files)}",
        f"- **Files successfully inspected:** {valid_count}",
        f"- **Files rejected:** {rejected_count}",
        "",
        "## File inspection",
        "",
        "| File | Status | Size (bytes) | Columns | Label header | SHA-256 |",
        "|---|---:|---:|---:|---|---|",
    ]
    for item in result.files:
        checksum = item.sha256[:16] + "..." if item.sha256 else "not computed"
        label = ", ".join(item.label_columns) if item.label_columns else "not found"
        lines.append(
            f"| {_escape_cell(item.relative_path)} | {item.status} | "
            f"{item.size_bytes} | {len(item.original_columns)} | "
            f"{_escape_cell(label)} | {checksum} |"
        )
    if not result.files:
        lines.append("| No supported files discovered | unavailable | — | — | — | — |")

    schema = result.schema_validation
    lines.extend(
        [
            "",
            "## Schema compatibility",
            "",
            f"- **Reference file:** {schema.reference_file or 'none'}",
            f"- **Matching files:** {len(schema.matching_files)}",
            f"- **Order-only differences:** {len(schema.order_only_files)}",
            f"- **Incompatible files:** {len(schema.incompatible_files)}",
            "",
        ]
    )
    for comparison in schema.comparisons:
        if comparison.relation in {"reference", "matching"}:
            continue
        lines.append(f"### {comparison.file}: {comparison.relation}")
        if comparison.column_order_differs:
            lines.append("Column names match, but their order differs.")
        if comparison.missing_columns:
            lines.append(
                "Missing columns: "
                + ", ".join(repr(column) for column in comparison.missing_columns)
            )
        if comparison.additional_columns:
            lines.append(
                "Additional columns: "
                + ", ".join(repr(column) for column in comparison.additional_columns)
            )
        for conflict in comparison.normalized_name_conflicts:
            lines.append(f"Normalized header conflict: {conflict}")
        for error in comparison.errors:
            lines.append(f"- {error}")
        lines.append("")

    lines.extend(["## Row and label scan", ""])
    if label_summary is not None:
        lines.extend(
            [
                f"- **Coverage:** {label_summary.coverage}",
                f"- **Exact rows scanned:** {label_summary.rows_scanned}",
                f"- **Chunk size:** {label_summary.chunk_size}",
                "- **Label counts:**",
            ]
        )
        lines.extend(
            f"  - {item.label!r}: {item.count}"
            for item in label_summary.label_counts
        )
        if not label_summary.label_counts:
            lines.append("  - No label values were read.")
    elif loading_metadata is not None:
        lines.extend(
            [
                f"- **Coverage:** {loading_metadata.scan_coverage}",
                f"- **Exact rows loaded:** {loading_metadata.rows_loaded}",
                f"- **Loading strategy:** {loading_metadata.strategy}",
            ]
        )
        if loading_metadata.chunk_size is not None:
            lines.append(f"- **Chunk size:** {loading_metadata.chunk_size}")
        lines.append("- **Label counts:** Not collected during this load.")
    else:
        lines.append("No data rows were scanned; this report is metadata-only.")

    lines.extend(["", "## Warnings", ""])
    lines.extend(f"- {warning}" for warning in result.warnings)
    if not result.warnings:
        lines.append("None.")
    lines.extend(["", "## Validation errors", ""])
    lines.extend(f"- {error}" for error in result.errors)
    if not result.errors:
        lines.append("None.")
    lines.extend(["", "Raw network records are not included in this report.", ""])
    return "\n".join(lines)


def write_ingestion_report(
    result: DatasetInspectionResult,
    output_path: str | Path,
    label_summary: LabelSummary | None = None,
    loading_metadata: LoadingMetadata | None = None,
) -> Path:
    """Write a Markdown report derived from executed inspection results."""
    path = Path(output_path).expanduser()
    _write_text(path, render_ingestion_report(result, label_summary, loading_metadata))
    logger.info("Wrote ingestion report to %s", path)
    return path


def _file_metadata(item: FileInspection) -> dict[str, Any]:
    """Serialize one file inspection without including its absolute path."""
    return {
        "filename": item.file_name,
        "relative_path": item.relative_path,
        "size_bytes": item.size_bytes,
        "extension": item.extension,
        "sha256": item.sha256,
        "detected_encoding": item.detected_encoding,
        "is_empty": item.is_empty,
        "header_readable": item.header_readable,
        "original_columns": list(item.original_columns),
        "normalized_columns": list(item.normalized_columns),
        "internal_columns": list(item.internal_columns),
        "column_bindings": [
            {
                "source_position": position,
                "source_name": source_name,
                "normalized_name": normalized_name,
                "internal_name": internal_name,
            }
            for position, (
                source_name,
                normalized_name,
                internal_name,
            ) in enumerate(
                zip(
                    item.original_columns,
                    item.normalized_columns,
                    item.internal_columns,
                ),
                start=1,
            )
        ],
        "column_count": len(item.original_columns),
        "exact_duplicate_columns": list(item.exact_duplicate_columns),
        "normalized_collisions": list(item.normalized_collisions),
        "label_columns": list(item.label_columns),
        "label_column_positions": list(item.label_column_positions),
        "label_internal_column": item.internal_label_column,
        "schema_fingerprint": item.schema_fingerprint,
        "inspection_status": item.status,
        "warnings": list(item.warnings),
        "errors": list(item.errors),
    }


def _rejected_files(result: DatasetInspectionResult) -> set[str]:
    """Count structural rejects and files incompatible with the reference."""
    rejected = {
        item.relative_path for item in result.files if item.status != "valid"
    }
    rejected.update(result.schema_validation.incompatible_files)
    return rejected


def _loading_metadata(loading: LoadingMetadata | None) -> dict[str, Any] | None:
    """Serialize completed loading counts without storing any flow records."""
    if loading is None:
        return None
    return {
        "strategy": loading.strategy,
        "started_at_utc": loading.started_at_utc,
        "completed_at_utc": loading.completed_at_utc,
        "files": [
            {"file": item.file, "rows_loaded": item.rows_loaded}
            for item in loading.file_stats
        ],
        "rows_loaded": loading.rows_loaded,
        "columns": list(loading.columns),
        "scan_coverage": loading.scan_coverage,
        "chunk_size": loading.chunk_size,
    }


def _write_text(path: Path, contents: str) -> None:
    """Write through a sibling temporary file to avoid partial reports."""
    temporary_path = path.with_name(path.name + ".tmp")
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary_path.write_text(contents, encoding="utf-8", newline="\n")
        temporary_path.replace(path)
    except OSError as exc:
        raise MetadataWriteError(
            f"Unable to write ingestion output: {path.name}"
        ) from exc
    finally:
        try:
            if temporary_path.exists():
                temporary_path.unlink()
        except OSError:
            logger.warning("Could not remove temporary report file %s", temporary_path)


def _escape_cell(value: str) -> str:
    """Escape minimal Markdown table cell syntax."""
    return value.replace("|", "\\|").replace("\n", " ").replace("\r", " ")
