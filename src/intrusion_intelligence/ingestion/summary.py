"""Chunked label-frequency summaries with explicit scan coverage."""

from __future__ import annotations

import logging
from collections import Counter
from collections.abc import Sequence
from datetime import datetime, timezone
from pathlib import Path

from intrusion_intelligence.errors import DataLoadingError
from intrusion_intelligence.ingestion.loader import iter_dataset_chunks
from intrusion_intelligence.ingestion.models import LabelCount, LabelSummary

logger = logging.getLogger(__name__)


def summarize_labels(
    dataset_directory: str | Path,
    *,
    files: Sequence[str | Path] | str | Path | None = None,
    chunk_size: int = 100_000,
    max_rows: int | None = None,
    supported_extensions: Sequence[str] = (".csv",),
    label_candidates: Sequence[str] = ("Label",),
    encoding: str = "auto",
    recursive: bool = True,
) -> LabelSummary:
    """Count observed label values without loading the full dataset at once.

    When max_rows is set, no more than that many rows are counted and coverage
    is marked partial if the bound is reached. Row counts in the result are
    exact observations, not estimates.
    """
    if max_rows is not None and max_rows <= 0:
        raise DataLoadingError("Maximum scan rows must be greater than zero.")
    started_at = _now()
    counts: Counter[str] = Counter()
    rows_scanned = 0
    files_scanned: list[str] = []
    coverage = "complete"

    chunks = iter_dataset_chunks(
        dataset_directory,
        files=files,
        chunk_size=chunk_size,
        supported_extensions=supported_extensions,
        label_candidates=label_candidates,
        encoding=encoding,
        recursive=recursive,
    )
    for chunk in chunks:
        if chunk.source_file not in files_scanned:
            files_scanned.append(chunk.source_file)
        labels = chunk.data[chunk.label_column]
        remaining = max_rows - rows_scanned if max_rows is not None else len(labels)
        selected_labels = labels.iloc[:remaining]
        counts.update(str(value) for value in selected_labels.tolist())
        rows_scanned += len(selected_labels)
        if max_rows is not None and rows_scanned >= max_rows:
            coverage = "partial"
            break

    summary = LabelSummary(
        coverage=coverage,
        rows_scanned=rows_scanned,
        files_scanned=tuple(files_scanned),
        chunk_size=chunk_size,
        label_counts=tuple(
            LabelCount(label=label, count=count)
            for label, count in sorted(counts.items())
        ),
        started_at_utc=started_at,
        completed_at_utc=_now(),
    )
    logger.info(
        "Label summary %s: rows=%d categories=%d",
        summary.coverage,
        summary.rows_scanned,
        len(summary.label_counts),
    )
    return summary


def _now() -> str:
    """Return a timezone-aware UTC timestamp."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds")
