"""Chunked, reproducible exploratory summaries for labelled flow CSV files."""

from __future__ import annotations

import logging
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

from intrusion_intelligence.config import ProjectConfig
from intrusion_intelligence.errors import EDAAnalysisError
from intrusion_intelligence.ingestion import inspect_dataset, iter_dataset_chunks
from intrusion_intelligence.ingestion.models import FileInspection

logger = logging.getLogger(__name__)

_MISSING_TOKENS = {"", "na", "n/a", "nan", "null", "none"}
_FEATURES_FOR_LABEL_COMPARISON = (
    "destination port",
    "flow duration",
    "total fwd packets",
    "flow bytes/s",
    "flow packets/s",
    "packet length mean",
    "flow iat mean",
)
_IDENTIFIER_FIELDS = {
    "flow id": "flow_id",
    "source ip": "source_ip",
    "destination ip": "destination_ip",
    "source port": "source_port",
    "timestamp": "timestamp",
    "protocol": "protocol",
    "destination port": "destination_port",
}


@dataclass(slots=True)
class EDAResult:
    """Full-scan summaries plus bounded samples used for plots and comparisons."""

    summary: dict[str, Any]
    uniform_sample: pd.DataFrame
    stratified_sample: pd.DataFrame
    label_column: str
    numeric_columns: tuple[str, ...]


@dataclass(slots=True)
class _ColumnAccumulator:
    """Mergeable exact counts and moments for one feature column."""

    rows_seen: int = 0
    missing: int = 0
    parseable: int = 0
    invalid_numeric: int = 0
    positive_infinity: int = 0
    negative_infinity: int = 0
    negative: int = 0
    zero: int = 0
    finite_count: int = 0
    mean: float = 0.0
    m2: float = 0.0
    minimum: float | None = None
    maximum: float | None = None
    dtypes: Counter[str] = field(default_factory=Counter)

    def update(self, series: pd.Series) -> np.ndarray:
        """Update exact counts and moments; return this chunk's float values."""
        self.rows_seen += len(series)
        self.dtypes[str(series.dtype)] += 1
        text = series.astype("string").str.strip()
        folded = text.str.casefold()
        missing = text.isna() | folded.isin(_MISSING_TOKENS)
        self.missing += int(missing.sum())

        numeric = pd.to_numeric(series, errors="coerce")
        values = numeric.to_numpy(dtype=np.float64, na_value=np.nan, copy=False)
        nan_values = np.isnan(values)
        self.parseable += int((~nan_values).sum())
        self.invalid_numeric += int((~missing.to_numpy() & nan_values).sum())
        self.positive_infinity += int(np.isposinf(values).sum())
        self.negative_infinity += int(np.isneginf(values).sum())
        finite = values[np.isfinite(values)]
        self.negative += int((finite < 0).sum())
        self.zero += int((finite == 0).sum())

        if finite.size:
            batch_count = int(finite.size)
            batch_mean = float(finite.mean())
            batch_m2 = float(np.square(finite - batch_mean).sum())
            if self.finite_count == 0:
                self.mean = batch_mean
                self.m2 = batch_m2
                self.finite_count = batch_count
            else:
                combined_count = self.finite_count + batch_count
                delta = batch_mean - self.mean
                self.m2 += (
                    batch_m2
                    + delta * delta * self.finite_count * batch_count / combined_count
                )
                self.mean += delta * batch_count / combined_count
                self.finite_count = combined_count
            batch_min = float(finite.min())
            batch_max = float(finite.max())
            self.minimum = (
                batch_min if self.minimum is None else min(self.minimum, batch_min)
            )
            self.maximum = (
                batch_max if self.maximum is None else max(self.maximum, batch_max)
            )
        return values


def label_distribution(labels: pd.Series) -> dict[str, Any]:
    """Return preserved label counts and derived benign/malicious proportions."""
    values = labels.astype("string").fillna("")
    counts = Counter(str(value) for value in values.tolist())
    total = sum(counts.values())
    benign = sum(
        count for label, count in counts.items() if label.strip().casefold() == "benign"
    )
    ordered = dict(sorted(counts.items(), key=lambda item: (-item[1], item[0])))
    return {
        "total_rows": total,
        "counts": ordered,
        "percentages": {
            label: count * 100.0 / total if total else 0.0
            for label, count in ordered.items()
        },
        "benign_malicious": {
            "BENIGN": benign,
            "MALICIOUS": total - benign,
            "benign_percent": benign * 100.0 / total if total else 0.0,
            "malicious_percent": (total - benign) * 100.0 / total if total else 0.0,
        },
    }


def missing_value_summary(frame: pd.DataFrame) -> dict[str, Any]:
    """Count blank and common textual NA tokens without changing the frame."""
    masks = _missing_mask(frame)
    counts = masks.sum(axis=0).astype("int64")
    rows = int(masks.any(axis=1).sum())
    total = len(frame)
    return {
        "rows": total,
        "rows_with_missing": rows,
        "row_percent_with_missing": rows * 100.0 / total if total else 0.0,
        "by_column": {
            str(column): {
                "count": int(count),
                "percent": int(count) * 100.0 / total if total else 0.0,
            }
            for column, count in counts.items()
        },
    }


def numeric_feature_summary(frame: pd.DataFrame) -> dict[str, dict[str, Any]]:
    """Summarize numeric columns, leaving source values untouched."""
    summaries: dict[str, dict[str, Any]] = {}
    for column in frame.columns:
        numeric = pd.to_numeric(frame[column], errors="coerce")
        finite = numeric[np.isfinite(numeric.to_numpy(dtype=float, na_value=np.nan))]
        if finite.empty:
            continue
        values = finite.astype("float64")
        quantiles = values.quantile([0.25, 0.5, 0.75])
        frequencies = values.value_counts(normalize=True, dropna=True)
        summaries[str(column)] = {
            "count": int(values.count()),
            "mean": float(values.mean()),
            "median_sample": float(quantiles.loc[0.5]),
            "std_sample": float(values.std()),
            "min": float(values.min()),
            "q1_sample": float(quantiles.loc[0.25]),
            "q3_sample": float(quantiles.loc[0.75]),
            "max": float(values.max()),
            "iqr_sample": float(quantiles.loc[0.75] - quantiles.loc[0.25]),
            "skew_sample": _finite_float(values.skew()),
            "kurtosis_sample": _finite_float(values.kurt()),
            "zero_percent_sample": float((values == 0).mean() * 100.0),
            "unique_values_sample": int(values.nunique(dropna=True)),
            "dominant_value_percent_sample": (
                float(frequencies.iloc[0] * 100.0) if not frequencies.empty else 0.0
            ),
        }
    return summaries


def correlation_summary(
    frame: pd.DataFrame,
    *,
    columns: tuple[str, ...] | None = None,
    threshold: float = 0.95,
) -> dict[str, Any]:
    """Calculate Pearson and Spearman correlations after masking infinities."""
    chosen = columns or tuple(
        column
        for column in frame.columns
        if pd.to_numeric(frame[column], errors="coerce").notna().any()
    )
    numeric = pd.DataFrame(index=frame.index)
    for column in chosen:
        if column in frame:
            values = pd.to_numeric(frame[column], errors="coerce")
            numeric[column] = values.replace([np.inf, -np.inf], np.nan)
    numeric = numeric.dropna(axis=1, how="all")
    return {
        "columns": list(numeric.columns),
        "pearson_pairs": _high_correlation_pairs(numeric.corr(method="pearson"), threshold),
        "spearman_pairs": _high_correlation_pairs(
            numeric.corr(method="spearman"), threshold
        ),
        "pearson_matrix": numeric.corr(method="pearson"),
    }


def duplicate_summary(
    frame: pd.DataFrame,
    *,
    label_column: str,
    source_column: str = "_eda_source_file",
) -> dict[str, Any]:
    """Measure exact duplicates in a bounded sample, including label conflicts."""
    if label_column not in frame.columns:
        raise ValueError(f"Label column {label_column!r} is not present.")
    feature_columns = [
        column for column in frame.columns if column not in {label_column, source_column}
    ]
    if not feature_columns or frame.empty:
        return {
            "sample_rows": len(frame),
            "duplicate_rows": 0,
            "duplicate_row_percent": 0.0,
            "duplicate_feature_rows": 0,
            "conflicting_label_groups": 0,
            "cross_file_duplicate_groups": 0,
        }
    exact_columns = [column for column in frame.columns if column != source_column]
    exact_mask = frame.duplicated(subset=exact_columns, keep="first")
    feature_mask = frame.duplicated(subset=feature_columns, keep=False)
    duplicate_groups = frame.loc[feature_mask]
    conflicts = 0
    cross_file = 0
    if not duplicate_groups.empty:
        grouped = duplicate_groups.groupby(feature_columns, dropna=False, sort=False)
        conflicts = int((grouped[label_column].nunique(dropna=False) > 1).sum())
        if source_column in duplicate_groups:
            cross_file = int((grouped[source_column].nunique(dropna=False) > 1).sum())
    return {
        "sample_rows": len(frame),
        "duplicate_rows": int(exact_mask.sum()),
        "duplicate_row_percent": (
            float(exact_mask.mean() * 100.0) if len(frame) else 0.0
        ),
        "duplicate_feature_rows": int(feature_mask.sum()),
        "conflicting_label_groups": conflicts,
        "cross_file_duplicate_groups": cross_file,
    }


def analyze_dataset(
    config: ProjectConfig,
    *,
    chunk_size: int | None = None,
    sample_size: int = 20_000,
    max_per_label: int = 1_000,
    seed: int | None = None,
) -> EDAResult:
    """Scan compatible CSVs chunk by chunk and compute reproducible summaries.

    Full-data counts, missingness, infinities, port frequencies, and numeric
    moments are exact. Quantiles, correlations, distributions, and duplicate
    checks use documented deterministic samples.
    """
    if sample_size <= 0:
        raise EDAAnalysisError("The uniform sample size must be greater than zero.")
    if max_per_label <= 0:
        raise EDAAnalysisError("The per-label sample limit must be greater than zero.")
    selected_chunk_size = (
        config.ingestion.chunk_size if chunk_size is None else chunk_size
    )
    if selected_chunk_size <= 0:
        raise EDAAnalysisError("The EDA chunk size must be greater than zero.")
    random_seed = config.experiment.random_seed if seed is None else seed

    logger.info("Starting chunked EDA for %s", config.dataset.name)
    inspection = inspect_dataset(
        config.dataset.directory,
        dataset_name=config.dataset.name,
        source_reference=config.dataset.source_url,
        supported_extensions=config.dataset.supported_extensions,
        label_candidates=config.dataset.label_candidates,
        recursive=config.dataset.recursive_discovery,
        encoding=config.ingestion.csv_encoding,
        project_root=config.project_root,
        compute_checksums=False,
    )
    if inspection.status != "valid" or not inspection.files:
        details = "; ".join(inspection.errors) or "No valid dataset files were found."
        raise EDAAnalysisError(f"EDA requires a valid compatible dataset: {details}")

    valid_files = tuple(item for item in inspection.files if item.status == "valid")
    if len(valid_files) != len(inspection.files):
        raise EDAAnalysisError("EDA stopped because one or more discovered files are invalid.")
    files = tuple(item.path for item in valid_files)
    reference = valid_files[0]
    internal_to_original = dict(zip(reference.internal_columns, reference.original_columns))
    display_names = _display_column_names(reference)
    label_column = reference.internal_label_column
    if label_column is None:
        raise EDAAnalysisError("The dataset does not have one unambiguous label column.")
    feature_columns = tuple(
        column for column in reference.internal_columns if column != label_column
    )
    columns = {column: _ColumnAccumulator() for column in feature_columns}

    row_counts: Counter[str] = Counter()
    label_counts: Counter[str] = Counter()
    per_file_labels: dict[str, Counter[str]] = defaultdict(Counter)
    dtype_profiles: dict[str, Counter[str]] = defaultdict(Counter)
    rows_with_missing = 0
    missing_cells = 0
    all_missing_counts: Counter[str] = Counter()
    port_column = _find_column(reference, "destination port")
    port_counts: Counter[int] = Counter()
    port_by_label: dict[str, Counter[int]] = defaultdict(Counter)
    uniform_sample = pd.DataFrame()
    uniform_keys = np.empty(0, dtype=np.float64)
    stratified_samples: dict[str, pd.DataFrame] = {}
    stratified_keys: dict[str, np.ndarray] = {}
    global_rng = np.random.default_rng(random_seed)
    stratified_rng = np.random.default_rng(random_seed + 1)

    for chunk in iter_dataset_chunks(
        config.dataset.directory,
        files=files,
        chunk_size=selected_chunk_size,
        supported_extensions=config.dataset.supported_extensions,
        label_candidates=config.dataset.label_candidates,
        encoding=config.ingestion.csv_encoding,
        recursive=config.dataset.recursive_discovery,
    ):
        frame = chunk.data
        source = chunk.source_file
        row_counts[source] += len(frame)
        labels = frame[label_column].astype("string").fillna("").astype(str)
        chunk_labels = Counter(labels.value_counts(dropna=False).to_dict())
        label_counts.update(chunk_labels)
        per_file_labels[source].update(chunk_labels)

        row_missing = np.zeros(len(frame), dtype=bool)
        for column in frame.columns:
            dtype_profiles[column][str(frame[column].dtype)] += 1
            text = frame[column].astype("string").str.strip()
            missing_mask = text.isna() | text.str.casefold().isin(_MISSING_TOKENS)
            row_missing |= missing_mask.to_numpy(dtype=bool)
            missing_cells += int(missing_mask.sum())
            all_missing_counts[column] += int(missing_mask.sum())
        for column in feature_columns:
            accumulator = columns[column]
            accumulator.dtypes[str(frame[column].dtype)] += 1
            accumulator.update(frame[column])
        rows_with_missing += int(row_missing.sum())

        if port_column is not None:
            port_values = pd.to_numeric(frame[port_column], errors="coerce").to_numpy(
                dtype=np.float64, na_value=np.nan
            )
            valid_ports = np.isfinite(port_values) & (port_values == np.floor(port_values))
            integer_ports = port_values[valid_ports].astype(np.int64)
            port_counts.update(integer_ports.tolist())
            if integer_ports.size:
                port_frame = pd.DataFrame(
                    {
                        "label": labels.to_numpy()[valid_ports],
                        "port": integer_ports,
                    }
                )
                for (label, port), count in port_frame.groupby(
                    ["label", "port"], sort=False
                ).size().items():
                    port_by_label[str(label)][int(port)] += int(count)

        uniform_sample, uniform_keys = _update_priority_sample(
            uniform_sample,
            uniform_keys,
            frame,
            source=source,
            source_column="_eda_source_file",
            limit=sample_size,
            rng=global_rng,
        )
        for label, label_frame in frame.groupby(label_column, sort=False, dropna=False):
            key = str(label) if not pd.isna(label) else ""
            old_sample = stratified_samples.get(key, pd.DataFrame())
            old_keys = stratified_keys.get(key, np.empty(0, dtype=np.float64))
            new_sample, new_keys = _update_priority_sample(
                old_sample,
                old_keys,
                label_frame,
                source=source,
                source_column="_eda_source_file",
                limit=max_per_label,
                rng=stratified_rng,
            )
            stratified_samples[key] = new_sample
            stratified_keys[key] = new_keys

    rows_scanned = sum(row_counts.values())
    if rows_scanned == 0:
        raise EDAAnalysisError("No data rows were found in the validated CSV files.")
    stratified_sample = (
        pd.concat(stratified_samples.values(), ignore_index=True)
        if stratified_samples
        else pd.DataFrame()
    )

    nonmissing = {
        name: accumulator.rows_seen - accumulator.missing
        for name, accumulator in columns.items()
    }
    numeric_columns = tuple(
        name
        for name, accumulator in columns.items()
        if nonmissing[name] > 0
        and accumulator.parseable / nonmissing[name] >= 0.99
    )
    label_total = sum(label_counts.values())
    ordered_labels = dict(
        sorted(label_counts.items(), key=lambda item: (-item[1], item[0]))
    )
    benign_rows = sum(
        count
        for label, count in label_counts.items()
        if label.strip().casefold() == "benign"
    )
    malicious_rows = label_total - benign_rows
    minimum_class = min(label_counts.values())
    maximum_class = max(label_counts.values())
    label_file_support = {}
    for label, count in ordered_labels.items():
        present = [
            (path, values[label])
            for path, values in per_file_labels.items()
            if values.get(label, 0) > 0
        ]
        dominant_path, dominant_count = max(present, key=lambda item: item[1])
        label_file_support[label] = {
            "files_present": len(present),
            "dominant_file": dominant_path,
            "dominant_file_rows": int(dominant_count),
            "dominant_file_share_percent": dominant_count * 100.0 / count,
        }
    labels_overall = {
        "total_rows": label_total,
        "coverage": "complete",
        "counts": ordered_labels,
        "percentages": {
            label: count * 100.0 / label_total
            for label, count in ordered_labels.items()
        },
        "benign_malicious": {
            "BENIGN": benign_rows,
            "MALICIOUS": malicious_rows,
            "benign_percent": benign_rows * 100.0 / label_total,
            "malicious_percent": malicious_rows * 100.0 / label_total,
        },
        "class_imbalance": {
            "majority_label": max(label_counts, key=label_counts.get),
            "majority_count": maximum_class,
            "minority_label": min(label_counts, key=label_counts.get),
            "minority_count": minimum_class,
            "majority_to_minority_ratio": maximum_class / minimum_class,
            "categories_below_100_rows": {
                label: count for label, count in ordered_labels.items() if count < 100
            },
            "per_label_file_support": label_file_support,
            "non_benign_categories_in_one_file": [
                label
                for label, support in label_file_support.items()
                if label.strip().casefold() != "benign" and support["files_present"] == 1
            ],
        },
        "per_file": {
            path: {
                "rows": int(row_counts[path]),
                "counts": dict(
                    sorted(counts.items(), key=lambda item: (-item[1], item[0]))
                ),
                "percentages": {
                    label: count * 100.0 / row_counts[path]
                    for label, count in counts.items()
                },
            }
            for path, counts in per_file_labels.items()
        },
    }

    sample_numeric = numeric_feature_summary(
        uniform_sample.loc[:, [*numeric_columns]]
    )
    numeric_statistics: list[dict[str, Any]] = []
    for column in numeric_columns:
        accumulator = columns[column]
        finite_count = accumulator.finite_count
        sample_stats = sample_numeric.get(column, {})
        numeric_statistics.append(
            {
                "column": display_names[column],
                "internal_column": column,
                "source_header": internal_to_original[column],
                "finite_count_full": finite_count,
                "mean_full": accumulator.mean if finite_count else None,
                "std_full": (
                    float(np.sqrt(accumulator.m2 / (finite_count - 1)))
                    if finite_count > 1
                    else None
                ),
                "min_full": accumulator.minimum,
                "max_full": accumulator.maximum,
                "zero_count_full": accumulator.zero,
                "zero_percent_full": (
                    accumulator.zero * 100.0 / finite_count if finite_count else 0.0
                ),
                "negative_count_full": accumulator.negative,
                "positive_infinity_full": accumulator.positive_infinity,
                "negative_infinity_full": accumulator.negative_infinity,
                "missing_count_full": accumulator.missing,
                "nonnumeric_count_full": accumulator.invalid_numeric,
                "parseable_nonmissing_percent_full": (
                    accumulator.parseable * 100.0 / nonmissing[column]
                    if nonmissing[column]
                    else 0.0
                ),
                "mean_sample": sample_stats.get("mean"),
                "median_sample": sample_stats.get("median_sample"),
                "q1_sample": sample_stats.get("q1_sample"),
                "q3_sample": sample_stats.get("q3_sample"),
                "iqr_sample": sample_stats.get("iqr_sample"),
                "skew_sample": sample_stats.get("skew_sample"),
                "kurtosis_sample": sample_stats.get("kurtosis_sample"),
                "unique_values_sample": sample_stats.get("unique_values_sample"),
                "dominant_value_percent_sample": sample_stats.get(
                    "dominant_value_percent_sample"
                ),
                "sample_rows": len(uniform_sample),
                "inferred_dtypes": sorted(columns[column].dtypes),
            }
        )

    display_to_internal = {display_names[key]: key for key in numeric_columns}
    pearson = correlation_summary(
        uniform_sample,
        columns=numeric_columns,
        threshold=0.95,
    )
    spearman_corr = _correlation_matrix(uniform_sample, numeric_columns, "spearman")
    correlation_results = {
        "coverage": "deterministic_uniform_sample",
        "sample_rows": len(uniform_sample),
        "sample_seed": random_seed,
        "threshold_absolute": 0.95,
        "pearson_high_pairs": _rename_pairs(pearson["pearson_pairs"], display_names),
        "spearman_high_pairs": _high_correlation_pairs(
            spearman_corr, 0.95, names=display_names
        ),
        "heatmap_features": _heatmap_features(uniform_sample, numeric_columns, 30),
    }

    field_presence = _field_presence(reference)
    destination_port_summary = _port_summary(port_counts, port_by_label)
    duplicate_results = duplicate_summary(
        uniform_sample,
        label_column=label_column,
        source_column="_eda_source_file",
    )
    duplicate_results["coverage"] = "deterministic_uniform_sample"
    duplicate_results["sample_seed"] = random_seed
    quality = _feature_quality(
        columns,
        numeric_columns,
        uniform_sample,
        display_names,
    )
    missing_by_column = [
        {
            "column": display_names.get(column, column),
            "internal_column": column,
            "count_full": all_missing_counts[column],
            "percent_full": all_missing_counts[column] * 100.0 / rows_scanned,
        }
        for column in reference.internal_columns
    ]
    missing_by_column.sort(key=lambda item: (-item["count_full"], item["column"]))
    numeric_issues = [
        {
            "column": display_names[column],
            "positive_infinity_full": columns[column].positive_infinity,
            "negative_infinity_full": columns[column].negative_infinity,
            "nonnumeric_count_full": columns[column].invalid_numeric,
            "negative_count_full": columns[column].negative,
        }
        for column in numeric_columns
        if any(
            (
                columns[column].positive_infinity,
                columns[column].negative_infinity,
                columns[column].invalid_numeric,
                columns[column].negative,
            )
        )
    ]

    file_lookup = {item.relative_path: item for item in valid_files}
    files_summary = []
    for relative_path in sorted(row_counts):
        item = file_lookup[relative_path]
        files_summary.append(
            {
                "file": relative_path,
                "size_bytes": item.size_bytes,
                "rows_full": int(row_counts[relative_path]),
                "columns": len(item.original_columns),
                "dimensions_full": [int(row_counts[relative_path]), len(item.original_columns)],
                "schema_status": item.status,
                "label_counts_full": dict(per_file_labels[relative_path]),
            }
        )

    summary: dict[str, Any] = {
        "dataset_name": config.dataset.name,
        "source_reference": config.dataset.source_url,
        "analysis_timestamp_utc": datetime.now(timezone.utc).isoformat(
            timespec="seconds"
        ),
        "analysis_method": {
            "full_scan": True,
            "chunk_size": selected_chunk_size,
            "sample_size_requested": sample_size,
            "sample_size_actual": len(uniform_sample),
            "sample_seed": random_seed,
            "sample_method": (
                "Uniform priority-key sample across all scanned rows; bounded memory."
            ),
            "stratified_sample_size": len(stratified_sample),
            "stratified_sample_cap_per_label": max_per_label,
            "stratified_sample_method": (
                "Independent deterministic priority-key sample within each original label."
            ),
            "exact_full_scan_metrics": [
                "row and per-file counts",
                "label counts and proportions",
                "blank and common textual NA token counts",
                "row-level missingness counts",
                "numeric finite moments, minima, maxima, zero, negative, and infinity counts",
                "destination-port frequencies when the field is available",
            ],
            "sample_derived_metrics": [
                "quantiles, skewness, kurtosis, and sampled cardinality",
                "Pearson and Spearman correlations",
                "feature distribution and label-comparison plots",
                "duplicate and feature-vector duplicate estimates",
                "near-constant and dominant-value estimates",
            ],
        },
        "dataset_overview": {
            "rows_full": rows_scanned,
            "files_count": len(valid_files),
            "columns_count": len(reference.original_columns),
            "feature_columns_count": len(feature_columns),
            "label_column_source_header": reference.label_column,
            "label_column_internal_name": label_column,
            "numeric_columns_count": len(numeric_columns),
            "non_numeric_or_mixed_columns_count": len(feature_columns) - len(numeric_columns),
            "rows_with_missing_full": rows_with_missing,
            "rows_with_missing_percent_full": rows_with_missing * 100.0 / rows_scanned,
            "missing_cells_full": missing_cells,
            "schema_compatibility": {
                "valid": inspection.schema_validation.is_compatible,
                "matching_files": list(inspection.schema_validation.matching_files),
                "order_only_files": list(inspection.schema_validation.order_only_files),
                "incompatible_files": list(inspection.schema_validation.incompatible_files),
                "source_header_columns": len(reference.original_columns),
            },
            "schema_warnings": list(inspection.warnings),
            "sample_rows_uniform": len(uniform_sample),
            "sample_seed": random_seed,
            "files": files_summary,
            "columns": [
                {
                    "position": index + 1,
                    "source_header": original,
                    "normalized_header": original.strip(),
                    "internal_column": internal,
                    "display_name": display_names[internal],
                    "dtype_by_chunk": sorted(dtype_profiles[internal]),
                }
                for index, (internal, original) in enumerate(
                    zip(reference.internal_columns, reference.original_columns)
                )
            ],
        },
        "label_distribution": labels_overall,
        "data_quality": {
            "coverage": "complete",
            "missing_cells_full": missing_cells,
            "rows_with_missing_full": rows_with_missing,
            "missing_by_column_full": missing_by_column,
            "numeric_value_issues_full": numeric_issues,
            "infinite_value_count_full": sum(
                columns[column].positive_infinity + columns[column].negative_infinity
                for column in feature_columns
            ),
            "negative_numeric_value_count_full": sum(
                columns[column].negative for column in feature_columns
            ),
            "negative_numeric_features_full": sorted(
                [
                    {
                        "column": display_names[column],
                        "count": columns[column].negative,
                        "minimum": columns[column].minimum,
                    }
                    for column in feature_columns
                    if columns[column].negative
                ],
                key=lambda item: (-item["count"], item["column"]),
            ),
            "nonnumeric_token_counts_by_column_full": {
                display_names[column]: columns[column].invalid_numeric
                for column in feature_columns
                if columns[column].invalid_numeric
            },
        },
        "numeric_statistics": numeric_statistics,
        "correlations": correlation_results,
        "feature_relationships": _label_feature_relationships(
            stratified_sample,
            label_column=label_column,
            numeric_columns=numeric_columns,
            display_names=display_names,
        ),
        "network_fields": {
            "presence": field_presence,
            "destination_port": destination_port_summary,
            "protocol_analysis": (
                "Not available: no protocol field is present in these CSV files."
                if not field_presence["protocol"]
                else "Protocol counts are in the full feature summary."
            ),
            "source_port_analysis": (
                "Not available: no standalone source-port field is present."
                if not field_presence["source_port"]
                else "Source-port counts are available."
            ),
        },
        "temporal_analysis": {
            "status": "unavailable",
            "reason": (
                "No timestamp column is present in the MachineLearningCVE CSV schema. "
                "Filenames identify collection-day/scenario groups, but not per-flow time."
            ),
        },
        "duplicate_analysis": duplicate_results,
        "feature_quality": quality,
        "limitations": [
            "No timestamp, protocol, source IP, destination IP, source port, or Flow ID columns are present in this extracted schema.",
            "File identity describes collection-day/scenario provenance and must not be added as a predictive feature without a leakage review.",
            "CIC-IDS2017 is a controlled, short-duration benchmark; observed proportions are not real-world attack prevalence.",
            "Sample-based quantiles, correlations, plots, duplicate estimates, and near-constant indicators are not full-dataset statistics.",
        ],
    }
    summary["key_findings"] = _build_findings(summary)
    logger.info(
        "EDA complete: rows=%d files=%d labels=%d sample=%d",
        rows_scanned,
        len(valid_files),
        len(label_counts),
        len(uniform_sample),
    )
    return EDAResult(
        summary=summary,
        uniform_sample=uniform_sample,
        stratified_sample=stratified_sample,
        label_column=label_column,
        numeric_columns=numeric_columns,
    )


def _missing_mask(frame: pd.DataFrame) -> pd.DataFrame:
    """Return a diagnostic missingness mask without mutating source values."""
    masks = pd.DataFrame(index=frame.index)
    for column in frame.columns:
        text = frame[column].astype("string").str.strip()
        masks[column] = text.isna() | text.str.casefold().isin(_MISSING_TOKENS)
    return masks


def _update_priority_sample(
    existing: pd.DataFrame,
    existing_keys: np.ndarray,
    candidates: pd.DataFrame,
    *,
    source: str,
    source_column: str,
    limit: int,
    rng: np.random.Generator,
) -> tuple[pd.DataFrame, np.ndarray]:
    """Keep the globally lowest random keys, yielding a uniform row sample."""
    if candidates.empty:
        return existing, existing_keys
    candidate_keys = rng.random(len(candidates))
    keep_count = min(limit, len(candidates))
    positions = np.argpartition(candidate_keys, keep_count - 1)[:keep_count]
    new_frame = candidates.iloc[positions].copy()
    new_frame[source_column] = source
    new_keys = candidate_keys[positions]
    combined = pd.concat([existing, new_frame], ignore_index=True)
    combined_keys = np.concatenate([existing_keys, new_keys])
    if len(combined) > limit:
        chosen = np.argpartition(combined_keys, limit - 1)[:limit]
        combined = combined.iloc[chosen].reset_index(drop=True)
        combined_keys = combined_keys[chosen]
    return combined.reset_index(drop=True), combined_keys


def _display_column_names(inspection: FileInspection) -> dict[str, str]:
    """Create readable names while retaining duplicate source positions."""
    names: dict[str, str] = {}
    duplicate_positions = set()
    normalized_counts = Counter(inspection.normalized_columns)
    for position, normalized in enumerate(inspection.normalized_columns, start=1):
        if normalized_counts[normalized] > 1:
            duplicate_positions.add(position)
    for position, (internal, original) in enumerate(
        zip(inspection.internal_columns, inspection.original_columns), start=1
    ):
        display = original.strip() or f"Column {position}"
        if position in duplicate_positions:
            display = f"{display} [source column {position}]"
        names[internal] = display
    return names


def _find_column(inspection: FileInspection, normalized_name: str) -> str | None:
    """Find one field by its whitespace-normalized, case-folded header."""
    matches = [
        internal
        for internal, original in zip(
            inspection.internal_columns, inspection.original_columns
        )
        if original.strip().casefold() == normalized_name.casefold()
    ]
    return matches[0] if len(matches) == 1 else None


def _field_presence(inspection: FileInspection) -> dict[str, bool]:
    """Report common identifiers and network fields available in the schema."""
    normalized = {column.strip().casefold() for column in inspection.original_columns}
    return {
        field_name: name in normalized
        for name, field_name in _IDENTIFIER_FIELDS.items()
    }


def _port_summary(
    counts: Counter[int], by_label: dict[str, Counter[int]]
) -> dict[str, Any]:
    """Render exact full-scan destination-port counts and leading ports by label."""
    return {
        "coverage": "complete" if counts else "unavailable",
        "distinct_values_full": len(counts),
        "top_ports_full": [
            {"port": port, "count": count}
            for port, count in counts.most_common(25)
        ],
        "top_ports_by_label_full": {
            label: [
                {"port": port, "count": count}
                for port, count in counter.most_common(10)
            ]
            for label, counter in sorted(by_label.items())
        },
    }


def _feature_quality(
    accumulators: dict[str, _ColumnAccumulator],
    numeric_columns: tuple[str, ...],
    sample: pd.DataFrame,
    display_names: dict[str, str],
) -> dict[str, Any]:
    """Identify constants exactly and dominant/low-cardinality fields in sample."""
    constants = []
    sampled_flags = []
    for column in numeric_columns:
        accumulator = accumulators[column]
        if (
            accumulator.finite_count
            and accumulator.minimum is not None
            and accumulator.minimum == accumulator.maximum
        ):
            constants.append(display_names[column])
        values = pd.to_numeric(sample[column], errors="coerce")
        finite = values[np.isfinite(values.to_numpy(dtype=float, na_value=np.nan))]
        if finite.empty:
            continue
        frequencies = finite.value_counts(normalize=True)
        dominant = float(frequencies.iloc[0]) if not frequencies.empty else 0.0
        unique = int(finite.nunique())
        flags = []
        if dominant >= 0.99:
            flags.append("dominant_value_at_least_99_percent_sample")
        if unique <= 2:
            flags.append("at_most_two_unique_values_sample")
        if len(finite) and unique / len(finite) >= 0.95:
            flags.append("high_cardinality_sample")
        if flags:
            sampled_flags.append(
                {
                    "column": display_names[column],
                    "sample_unique_values": unique,
                    "sample_dominant_value_percent": dominant * 100.0,
                    "flags": flags,
                }
            )
    return {
        "constant_features_exact_full": constants,
        "sample_coverage": "deterministic_uniform_sample",
        "sample_rows": len(sample),
        "potentially_uninformative_or_high_cardinality_sample": sampled_flags,
    }


def _label_feature_relationships(
    sample: pd.DataFrame,
    *,
    label_column: str,
    numeric_columns: tuple[str, ...],
    display_names: dict[str, str],
) -> dict[str, Any]:
    """Describe selected features by original label in a stratified sample."""
    normalized = {column: display_names[column].strip().casefold() for column in numeric_columns}
    selected = [
        column
        for target in _FEATURES_FOR_LABEL_COMPARISON
        for column in numeric_columns
        if normalized[column] == target
    ]
    selected = list(dict.fromkeys(selected))[:6]
    by_feature: dict[str, dict[str, Any]] = {}
    for column in selected:
        values = pd.to_numeric(sample[column], errors="coerce")
        clean = sample[[label_column]].copy()
        clean["value"] = values.replace([np.inf, -np.inf], np.nan)
        clean = clean.dropna(subset=["value"])
        groups: dict[str, Any] = {}
        for label, group in clean.groupby(label_column, sort=False):
            quantiles = group["value"].quantile([0.25, 0.5, 0.75])
            groups[str(label)] = {
                "sample_rows": len(group),
                "mean_sample": float(group["value"].mean()),
                "median_sample": float(quantiles.loc[0.5]),
                "q1_sample": float(quantiles.loc[0.25]),
                "q3_sample": float(quantiles.loc[0.75]),
            }
        by_feature[display_names[column]] = groups
    return {
        "coverage": "deterministic_stratified_sample",
        "sample_rows": len(sample),
        "features": list(by_feature),
        "per_label_cap": int(sample.groupby(label_column).size().max()) if len(sample) else 0,
        "statistics": by_feature,
        "interpretation_note": (
            "Within-label summaries are from a stratified sample capped per category; "
            "they describe feature shapes, not population prevalence or causal effects."
        ),
    }


def _correlation_matrix(
    frame: pd.DataFrame, columns: tuple[str, ...], method: str
) -> pd.DataFrame:
    """Create a sample correlation matrix after explicit infinity masking."""
    numeric = pd.DataFrame(index=frame.index)
    for column in columns:
        if column in frame:
            series = pd.to_numeric(frame[column], errors="coerce")
            numeric[column] = series.replace([np.inf, -np.inf], np.nan)
    return numeric.corr(method=method)


def _high_correlation_pairs(
    matrix: pd.DataFrame,
    threshold: float,
    *,
    names: dict[str, str] | None = None,
) -> list[dict[str, Any]]:
    """List distinct pairs whose absolute sampled correlation crosses threshold."""
    pairs = []
    columns = list(matrix.columns)
    for left_index, left in enumerate(columns):
        for right in columns[left_index + 1 :]:
            value = matrix.loc[left, right]
            if pd.notna(value) and abs(float(value)) >= threshold:
                pairs.append(
                    {
                        "feature_a": names.get(left, left) if names else left,
                        "feature_b": names.get(right, right) if names else right,
                        "correlation": float(value),
                        "absolute_correlation": abs(float(value)),
                    }
                )
    pairs.sort(key=lambda item: (-item["absolute_correlation"], item["feature_a"]))
    return pairs[:100]


def _rename_pairs(
    pairs: list[dict[str, Any]], names: dict[str, str]
) -> list[dict[str, Any]]:
    """Map internal correlation column names to source-readable names."""
    return [
        {
            **pair,
            "feature_a": names.get(pair["feature_a"], pair["feature_a"]),
            "feature_b": names.get(pair["feature_b"], pair["feature_b"]),
        }
        for pair in pairs
    ]


def _heatmap_features(
    sample: pd.DataFrame, columns: tuple[str, ...], limit: int
) -> list[str]:
    """Select variable columns for a legible correlation heatmap."""
    variances = {}
    for column in columns:
        values = pd.to_numeric(sample[column], errors="coerce").replace(
            [np.inf, -np.inf], np.nan
        )
        variance = values.var()
        if pd.notna(variance):
            variances[column] = float(variance)
    return sorted(variances, key=variances.get, reverse=True)[:limit]


def _build_findings(summary: dict[str, Any]) -> list[str]:
    """Create concise observations only from recorded full or sampled evidence."""
    overview = summary["dataset_overview"]
    labels = summary["label_distribution"]
    findings = [
        (
            f"A complete chunked scan covered {overview['rows_full']:,} rows across "
            f"{overview['files_count']} files with {overview['columns_count']} source columns."
        ),
        (
            f"BENIGN accounts for {labels['benign_malicious']['benign_percent']:.2f}% "
            "of rows; attack labels account for the remainder."
        ),
    ]
    imbalance = labels["class_imbalance"]
    findings.append(
        f"The largest-to-smallest category ratio is "
        f"{imbalance['majority_to_minority_ratio']:,.1f}:1 "
        f"({imbalance['majority_label']} versus {imbalance['minority_label']})."
    )
    confined = imbalance["non_benign_categories_in_one_file"]
    findings.append(
        f"{len(confined)} of {len(labels['counts']) - 1} non-benign categories "
        "occur in only one source file, so file/scenario identity closely tracks labels."
    )
    if overview["missing_cells_full"]:
        findings.append(
            f"The scan found {overview['missing_cells_full']:,} blank or common textual-NA "
            f"cells across {overview['rows_with_missing_full']:,} rows."
        )
    else:
        findings.append("No blank or common textual-NA cells were found in the full scan.")
    if summary["data_quality"]["infinite_value_count_full"]:
        findings.append(
            f"The scan found {summary['data_quality']['infinite_value_count_full']:,} "
            "positive or negative infinite numeric values; no replacements were made."
        )
    else:
        findings.append("No positive or negative infinite numeric values were found.")
    negative_count = summary["data_quality"]["negative_numeric_value_count_full"]
    if negative_count:
        largest = summary["data_quality"]["negative_numeric_features_full"][:3]
        examples = ", ".join(
            f"{item['column']} ({item['count']:,})" for item in largest
        )
        findings.append(
            f"The full scan found {negative_count:,} negative numeric values across "
            f"{len(summary['data_quality']['negative_numeric_features_full'])} fields; "
            f"largest counts include {examples}. EDA flags these for investigation "
            "without assuming they are invalid."
        )
    correlation_pairs = summary["correlations"]["pearson_high_pairs"]
    if correlation_pairs:
        example = correlation_pairs[0]
        findings.append(
            f"The deterministic sample contains strongly associated feature pairs; "
            f"the largest listed Pearson pair is {example['feature_a']} and "
            f"{example['feature_b']} (r={example['correlation']:.3f})."
        )
    else:
        findings.append(
            "No Pearson feature pair crossed the absolute 0.95 threshold in the sample."
        )
    constant_count = len(summary["feature_quality"]["constant_features_exact_full"])
    findings.append(
        f"{constant_count} numeric features are exactly constant across the full scan."
    )
    duplicates = summary["duplicate_analysis"]
    findings.append(
        f"The {duplicates['sample_rows']:,}-row uniform sample contains "
        f"{duplicates['duplicate_rows']:,} exact duplicate rows and "
        f"{duplicates['conflicting_label_groups']:,} repeated-feature groups with "
        "conflicting labels; these duplicate results are sample-based."
    )
    findings.append(
        "The files contain Destination Port but no standalone source port, protocol, "
        "timestamp, source/destination IP, or Flow ID columns."
    )
    findings.append(
        "Collection-day/scenario identity remains available through the source filenames; "
        "it must be kept as analysis provenance and reviewed before any predictive use."
    )
    return findings


def _finite_float(value: Any) -> float | None:
    """Convert finite scalar outputs to JSON-safe floats."""
    if value is None or pd.isna(value):
        return None
    result = float(value)
    return result if np.isfinite(result) else None
