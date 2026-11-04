"""Validated anomaly-detection data inventory and preparation helpers."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re
from typing import Any, Iterable

import numpy as np
import pandas as pd
import pyarrow.parquet as pq

from intrusion_intelligence.feature_engineering import FeatureContract, separate_features_target_metadata
from intrusion_intelligence.multiclass.taxonomy import ClassTaxonomy, TaxonomyError

BENIGN_LABEL = "BENIGN"
CAPTURE_DAYS = ("Monday", "Tuesday", "Wednesday", "Thursday", "Friday")


class AnomalyDataError(ValueError):
    """Raised when anomaly data violates its validated schema or label policy."""


@dataclass(frozen=True, slots=True)
class AnomalyDatasetInventory:
    """Compact, feature-free row inventory aligned to the cleaned Parquet files."""

    files: tuple[Path, ...]
    labels: np.ndarray
    capture_day_codes: np.ndarray
    source_file_codes: np.ndarray
    capture_days: tuple[str, ...]
    source_files: tuple[str, ...]
    class_counts: dict[str, int]
    class_counts_by_day: dict[str, dict[str, int]]
    class_counts_by_source_file: dict[str, dict[str, int]]
    taxonomy: ClassTaxonomy
    feature_names: tuple[str, ...]
    feature_schema_version: str
    metadata_fields_present: tuple[str, ...]
    metadata_fields_unavailable: tuple[str, ...]

    @property
    def benign_count(self) -> int:
        return int(np.count_nonzero(self.labels == BENIGN_LABEL))

    @property
    def attack_count(self) -> int:
        return int(len(self.labels) - self.benign_count)

    def preparation_report(self) -> dict[str, Any]:
        """Summarize validated labels, benign population, features, and groups."""
        return {
            "status": "validated",
            "rows": int(len(self.labels)),
            "benign_label": BENIGN_LABEL,
            "benign_rows": self.benign_count,
            "attack_rows": self.attack_count,
            "label_counts": self.class_counts,
            "labels_missing": 0,
            "labels_blank": 0,
            "unexpected_labels": [],
            "observed_label_count": len(self.taxonomy.labels),
            "feature_count": len(self.feature_names),
            "feature_names": list(self.feature_names),
            "feature_schema_version": self.feature_schema_version,
            "metadata_fields_excluded_from_X": list(self.metadata_fields_present),
            "metadata_fields_unavailable_in_export": list(self.metadata_fields_unavailable),
            "capture_day_counts": {
                day: int(np.count_nonzero(self.capture_day_codes == CAPTURE_DAYS.index(day)))
                for day in self.capture_days
            },
            "source_files": list(self.source_files),
            "grouping_basis": "source filename collection day; source files are also tracked separately",
        }


def validate_original_labels(
    labels: Iterable[Any],
    allowed_labels: Iterable[str],
    *,
    benign_label: str = BENIGN_LABEL,
    require_benign_present: bool = False,
) -> np.ndarray:
    """Validate original labels and return exact strings without remapping."""
    values = np.asarray(list(labels), dtype=object)
    if values.ndim != 1 or not len(values):
        raise AnomalyDataError("Labels must be a non-empty one-dimensional sequence.")
    if pd.isna(values).any():
        raise AnomalyDataError("Missing traffic labels are not allowed; they are never treated as benign.")
    text = np.asarray([str(value) for value in values], dtype=object)
    if any(not value.strip() for value in text):
        raise AnomalyDataError("Blank traffic labels are not allowed; they are never treated as benign.")
    allowed = set(map(str, allowed_labels))
    if benign_label not in allowed:
        raise AnomalyDataError(f"Configured benign label {benign_label!r} is absent from the feature contract.")
    unexpected = sorted(set(text.tolist()) - allowed)
    if unexpected:
        raise AnomalyDataError(f"Unexpected traffic labels are not permitted: {unexpected}.")
    if require_benign_present and benign_label not in set(text.tolist()):
        raise AnomalyDataError(f"The exact benign label {benign_label!r} is absent from the dataset.")
    return text


def prepare_anomaly_frame(
    frame: pd.DataFrame,
    contract: FeatureContract,
    *,
    benign_label: str = BENIGN_LABEL,
) -> tuple[pd.DataFrame, pd.Series, pd.DataFrame, np.ndarray]:
    """Separate features, original labels, metadata, and an evaluation-only mask."""
    try:
        features, labels, metadata = separate_features_target_metadata(frame, contract)
    except (TypeError, ValueError) as exc:
        raise AnomalyDataError(f"Input frame does not satisfy the feature contract: {exc}") from exc
    if labels is None:
        raise AnomalyDataError("A target label column is required for validated anomaly preparation.")
    validated = validate_original_labels(labels.to_numpy(), contract.target_values, benign_label=benign_label)
    return features, pd.Series(validated, index=labels.index, name=labels.name), metadata, validated == benign_label


def capture_day_from_source(source: str | Path) -> str:
    """Read the CIC-IDS2017 collection day encoded in a source filename."""
    name = str(source).replace("\\", "/").rsplit("/", 1)[-1]
    for day in CAPTURE_DAYS:
        if re.match(rf"^{day}(?:[-_]|\b)", name, flags=re.IGNORECASE):
            return day
    raise AnomalyDataError(f"Cannot determine a CIC-IDS2017 collection day from {source!r}.")


def inspect_anomaly_dataset(
    directory: str | Path,
    contract: FeatureContract,
    *,
    benign_label: str = BENIGN_LABEL,
    mapping_version: str = "1.0.0",
) -> AnomalyDatasetInventory:
    """Validate each Phase 04 Parquet schema and inventory labels/groups only."""
    root = Path(directory)
    files = tuple(sorted(root.glob("*.parquet")))
    if not files:
        raise AnomalyDataError(f"No cleaned Parquet files found under {root}.")
    required = set(contract.predictive_features) | {contract.target_name, "__source_file"}
    reference_columns: list[str] | None = None
    label_parts: list[np.ndarray] = []
    day_parts: list[np.ndarray] = []
    source_parts: list[np.ndarray] = []
    source_files: list[str] = []
    day_counts: dict[str, dict[str, int]] = {}
    source_counts: dict[str, dict[str, int]] = {}
    total_counts: dict[str, int] = {}
    observed_labels: list[str] = []
    present_metadata_fields: tuple[str, ...] = ()
    unavailable_metadata_fields = tuple(contract.metadata_fields)
    for file_code, path in enumerate(files):
        parquet_file = pq.ParquetFile(path)
        columns = parquet_file.schema_arrow.names
        if reference_columns is None:
            reference_columns = columns
            present_metadata_fields = tuple(name for name in contract.metadata_fields if name in columns)
            unavailable_metadata_fields = tuple(name for name in contract.metadata_fields if name not in columns)
        elif columns != reference_columns:
            raise AnomalyDataError(f"Parquet schema differs from other files: {path.name}.")
        missing = sorted(required - set(columns))
        if missing:
            raise AnomalyDataError(f"Parquet file {path.name} is missing required columns: {missing}.")
        table = pq.read_table(path, columns=[contract.target_name, "__source_file"]).to_pandas()
        if table["__source_file"].isna().any() or table["__source_file"].nunique(dropna=False) != 1:
            raise AnomalyDataError(f"Source-file provenance is missing or inconsistent in {path.name}.")
        source = str(table["__source_file"].iloc[0])
        day = capture_day_from_source(source)
        labels = validate_original_labels(
            table[contract.target_name].to_numpy(),
            contract.target_values,
            benign_label=benign_label,
        )
        counts = {str(label): int(count) for label, count in pd.Series(labels).value_counts().items()}
        source_files.append(source)
        source_counts[source] = counts
        day_counts.setdefault(day, {})
        for label, count in counts.items():
            total_counts[label] = total_counts.get(label, 0) + count
            day_counts[day][label] = day_counts[day].get(label, 0) + count
        day_parts.append(np.full(len(labels), CAPTURE_DAYS.index(day), dtype=np.uint8))
        source_parts.append(np.full(len(labels), file_code, dtype=np.uint8))
        label_parts.append(labels)
        observed_labels.extend(counts)
    labels_all = np.concatenate(label_parts)
    days_all = np.concatenate(day_parts)
    sources_all = np.concatenate(source_parts)
    try:
        taxonomy = ClassTaxonomy.from_labels(
            observed_labels,
            allowed_labels=contract.target_values,
            version=mapping_version,
        )
    except TaxonomyError as exc:
        raise AnomalyDataError(str(exc)) from exc
    if benign_label not in total_counts:
        raise AnomalyDataError(f"The benign label {benign_label!r} has no rows in the cleaned dataset.")
    # Retain the Phase 05 contract and original strings; taxonomy is for validation only.
    return AnomalyDatasetInventory(
        files=files,
        labels=labels_all,
        capture_day_codes=days_all,
        source_file_codes=sources_all,
        capture_days=tuple(day for day in CAPTURE_DAYS if day in day_counts),
        source_files=tuple(source_files),
        class_counts=total_counts,
        class_counts_by_day=day_counts,
        class_counts_by_source_file=source_counts,
        taxonomy=taxonomy,
        feature_names=tuple(contract.predictive_features),
        feature_schema_version=contract.schema_version,
        metadata_fields_present=present_metadata_fields,
        metadata_fields_unavailable=unavailable_metadata_fields,
    )
