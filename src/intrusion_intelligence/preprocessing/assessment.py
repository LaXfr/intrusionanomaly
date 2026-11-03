"""Chunked full-dataset quality assessment with bounded diagnostics."""

from __future__ import annotations

import hashlib
import logging
import sqlite3
import tempfile
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

from intrusion_intelligence.config import ProjectConfig
from intrusion_intelligence.errors import ProjectError, SchemaValidationError
from intrusion_intelligence.ingestion.service import inspect_dataset

logger = logging.getLogger(__name__)
PROVENANCE_COLUMNS = ("__source_file", "__source_row_number", "__record_id")
CLEANING_METADATA_COLUMNS = (*PROVENANCE_COLUMNS, "__source_label")
MISSING_NULL_TOKENS = {"na", "n/a", "null", "none"}
NAN_TOKENS = {"nan", "+nan", "-nan"}
POSITIVE_INFINITY_TOKENS = {"inf", "+inf", "infinity", "+infinity"}
NEGATIVE_INFINITY_TOKENS = {"-inf", "-infinity"}
POLICY_VERSION = "1.0"


def assess_dataset(
    config: ProjectConfig,
    *,
    dataset_directory: str | Path | None = None,
    chunk_size: int | None = None,
    sample_stride: int = 100,
    compute_duplicates: bool = True,
) -> dict[str, Any]:
    """Scan files sequentially, retaining only counters, hashes, and a sample.

    Counts are full-scan counts. Quantiles, IQR/MAD fences, and sampled
    cardinality are based on deterministic systematic samples and are marked
    as estimates. Source text is never altered.
    """
    selected_chunk_size = chunk_size or config.ingestion.chunk_size
    if selected_chunk_size <= 0 or sample_stride <= 0:
        raise ValueError("chunk_size and sample_stride must be positive.")
    directory = Path(dataset_directory or config.dataset.directory)
    inventory = inspect_dataset(
        directory,
        dataset_name=config.dataset.name,
        source_reference=config.dataset.source_url,
        supported_extensions=config.dataset.supported_extensions,
        label_candidates=config.dataset.label_candidates,
        recursive=config.dataset.recursive_discovery,
        encoding=config.ingestion.csv_encoding,
        project_root=config.project_root,
        compute_checksums=True,
    )
    if not inventory.files:
        raise ProjectError("No supported CSV files were found for quality assessment.")
    if not inventory.schema_validation.is_compatible:
        details = "; ".join(inventory.schema_validation.errors) or "Incompatible CSV schemas."
        raise SchemaValidationError(details)

    file_results: dict[str, dict[str, Any]] = {}
    columns: list[dict[str, Any]] = []
    feature_results: dict[str, dict[str, Any]] = {}
    labels: Counter[str] = Counter()
    label_by_file: dict[str, Counter[str]] = defaultdict(Counter)
    sample_parts: list[pd.DataFrame] = []
    sample_rows = 0
    rows_total = 0
    duplicate_metrics: dict[str, Any] = {
        "computed": False,
        "method": (
            "Two independently keyed 64-bit Pandas row fingerprints are combined "
            "to 128 bits and externally aggregated in SQLite; collision probability "
            "is negligible but not mathematically zero."
        ),
        "records_removed": 0,
    }

    with tempfile.TemporaryDirectory(prefix="nii-quality-") as temporary_directory:
        database = None
        if compute_duplicates:
            database = sqlite3.connect(Path(temporary_directory) / "fingerprints.sqlite")
            database.execute("PRAGMA journal_mode=OFF")
            database.execute("PRAGMA synchronous=OFF")
            database.execute("PRAGMA temp_store=FILE")
            database.execute(
                "CREATE TABLE fingerprints (kind TEXT, digest TEXT, source TEXT, "
                "label TEXT, n INTEGER NOT NULL, "
                "PRIMARY KEY(kind, digest, source, label)) WITHOUT ROWID"
            )

        for inspected in inventory.files:
            source = inspected.relative_path
            if inspected.status != "valid":
                raise ProjectError(
                    f"Cannot assess invalid input {source}: {'; '.join(inspected.errors)}"
                )
            if not inspected.internal_label_column:
                raise ProjectError(f"Could not identify one label column in {source}.")
            label_column = inspected.internal_label_column
            feature_columns = [
                column
                for column in inspected.internal_columns
                if column != label_column and column not in CLEANING_METADATA_COLUMNS
            ]
            for index, (original, internal) in enumerate(
                zip(inspected.original_columns, inspected.internal_columns), start=1
            ):
                if not any(item["source_position"] == index for item in columns):
                    columns.append(
                        {
                            "source_position": index,
                            "source_header": original,
                            "internal_column": internal,
                            "normalized_header": original.strip(),
                            "is_label": internal == label_column,
                        }
                    )
            for internal in feature_columns:
                if internal not in feature_results:
                    original_position = inspected.internal_columns.index(internal)
                    feature_results[internal] = _new_feature_result(
                        inspected.original_columns[original_position],
                        internal,
                        original_position + 1,
                    )
            file_results[source] = {
                "file_name": inspected.file_name,
                "size_bytes": inspected.size_bytes,
                "sha256": inspected.sha256,
                "encoding": inspected.detected_encoding,
                "schema_fingerprint": inspected.schema_fingerprint,
                "rows": 0,
                "label_counts": {},
            }
            row_content_hasher = hashlib.sha256()
            source_rows = 0
            try:
                reader = pd.read_csv(
                    inspected.path,
                    encoding=inspected.detected_encoding or "utf-8",
                    header=0,
                    names=list(inspected.internal_columns),
                    dtype=str,
                    keep_default_na=False,
                    na_filter=False,
                    chunksize=selected_chunk_size,
                    on_bad_lines="error",
                )
                try:
                    for frame in reader:
                        if len(frame.columns) != len(inspected.internal_columns):
                            raise ProjectError(f"Column count changed while reading {source}.")
                        row_count = len(frame)
                        source_rows += row_count
                        rows_total += row_count
                        labels_in_chunk = frame[label_column].astype(str)
                        row_fingerprint = pd.util.hash_pandas_object(
                            frame[[*feature_columns, label_column]],
                            index=False,
                            hash_key="0123456789abcdef",
                        ).to_numpy(dtype=np.uint64)
                        row_content_hasher.update(row_fingerprint.tobytes())
                        label_counts = labels_in_chunk.value_counts(dropna=False)
                        for label, count in label_counts.items():
                            label = str(label)
                            labels[label] += int(count)
                            label_by_file[source][label] += int(count)
                        numeric_rows = {
                            internal: pd.to_numeric(frame[internal], errors="coerce")
                            for internal in feature_columns
                        }
                        for internal, numeric in numeric_rows.items():
                            _update_feature(
                                feature_results[internal],
                                frame[internal],
                                numeric,
                                labels_in_chunk,
                                source,
                            )
                        duration_column = next(
                            (
                                internal
                                for internal in feature_columns
                                if inspected.original_columns[
                                    inspected.internal_columns.index(internal)
                                ].strip().casefold()
                                == "flow duration"
                            ),
                            None,
                        )
                        rate_zero_duration: dict[str, int] = {}
                        if duration_column is not None:
                            duration_values = pd.to_numeric(
                                frame[duration_column], errors="coerce"
                            ).to_numpy(dtype=np.float64, na_value=np.nan)
                            zero_duration = duration_values == 0
                            for internal in feature_columns:
                                header = inspected.original_columns[
                                    inspected.internal_columns.index(internal)
                                ].strip().casefold()
                                if header in {"flow bytes/s", "flow packets/s"}:
                                    values = numeric_rows[internal].to_numpy(
                                        dtype=np.float64, na_value=np.nan
                                    )
                                    infinite = np.isinf(values)
                                    feature_results[internal][
                                        "infinity_with_zero_flow_duration"
                                    ] += int((infinite & zero_duration).sum())
                                    feature_results[internal][
                                        "infinity_with_nonzero_or_missing_flow_duration"
                                    ] += int((infinite & ~zero_duration).sum())

                        if database is not None:
                            _update_fingerprints(
                                database,
                                frame[feature_columns],
                                labels_in_chunk,
                                source,
                            )

                        offset = source_rows - row_count
                        sample_mask = (np.arange(offset, source_rows) % sample_stride) == 0
                        if sample_mask.any():
                            picked = frame.loc[
                                sample_mask, [*feature_columns, label_column]
                            ].copy()
                            picked.insert(0, "__sample_source", source)
                            sample_parts.append(picked)
                            sample_rows += len(picked)
                finally:
                    reader.close()
            except (OSError, UnicodeError, ValueError, pd.errors.ParserError) as exc:
                raise ProjectError(
                    f"Unable to complete the quality scan for {source}: "
                    f"{exc.__class__.__name__}"
                ) from exc
            file_results[source]["rows"] = source_rows
            file_results[source]["label_counts"] = dict(label_by_file[source])
            file_results[source]["row_content_fingerprint_sha256"] = (
                row_content_hasher.hexdigest()
            )
            logger.info("Assessed %s: %d rows", source, source_rows)

        if database is not None:
            database.commit()
            duplicate_metrics = _summarize_fingerprints(database)
            database.close()

    if sample_parts:
        sample = pd.concat(sample_parts, ignore_index=True)
    else:
        sample = pd.DataFrame()
    outlier_summary = _sample_diagnostics(
        sample,
        feature_results,
        label_column=(
            inventory.files[0].internal_label_column
            if inventory.files
            else ""
        ),
        sample_size=sample_rows,
    )
    _finish_feature_results(
        feature_results,
        rows_total,
        outlier_summary,
        file_rows={name: item["rows"] for name, item in file_results.items()},
        label_counts=labels,
    )

    header_groups: dict[tuple[str, ...], list[str]] = defaultdict(list)
    for inspected in inventory.files:
        header_groups[inspected.original_columns].append(inspected.relative_path)
    schema_comparison = {
        "compatible": inventory.schema_validation.is_compatible,
        "matching_files": list(inventory.schema_validation.matching_files),
        "order_only_files": list(inventory.schema_validation.order_only_files),
        "incompatible_files": list(inventory.schema_validation.incompatible_files),
        "distinct_source_header_sequences": len(header_groups),
        "source_header_sequences": [
            {"files": file_names, "columns": list(header)}
            for header, file_names in header_groups.items()
        ],
        "duplicate_source_headers": [
            {
                "source_header": header,
                "positions": [
                    i + 1
                    for i, value in enumerate(inventory.files[0].original_columns)
                    if value == header
                ],
            }
            for header in inventory.files[0].exact_duplicate_columns
        ],
        "whitespace_collisions": [
            {
                "normalized_header": collision,
                "positions": [
                    i + 1
                    for i, value in enumerate(inventory.files[0].normalized_columns)
                    if value == collision
                ],
                "source_headers": [
                    value
                    for i, value in enumerate(inventory.files[0].normalized_columns)
                    if value == collision
                ],
            }
            for collision in inventory.files[0].normalized_collisions
        ],
        "files_have_identical_headers": len(header_groups) == 1,
    }
    report: dict[str, Any] = {
        "report_version": "1.0",
        "dataset_name": config.dataset.name,
        "source_reference": config.dataset.source_url,
        "generated_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "coverage": "complete",
        "method": {
            "chunk_size": selected_chunk_size,
            "sample_method": (
                f"Deterministic systematic sample: every {sample_stride}th "
                "source row per file, beginning at row 1."
            ),
            "sample_rows": sample_rows,
            "full_scan_metrics": [
                "rows, labels, missing token classes, numeric parsing, infinities, "
                "negative values, finite ranges, and constant features",
                "duplicate fingerprint counts when enabled",
            ],
            "sampled_metrics": [
                "quantiles, IQR and MAD outlier fences, sample cardinality, "
                "and sample dominant value percentages"
            ],
            "source_values_modified": False,
            "labels_used_for_cleaning_decisions": False,
        },
        "dataset_overview": {
            "rows": rows_total,
            "files_count": len(file_results),
            "source_columns": len(inventory.files[0].original_columns),
            "feature_columns": len(feature_results),
            "label_column": (
                inventory.files[0].original_columns[
                    inventory.files[0].label_column_positions[0] - 1
                ]
                if inventory.files[0].label_column_positions
                else None
            ),
            "label_counts": dict(sorted(labels.items(), key=lambda item: (-item[1], item[0]))),
            "label_percentages": {
                label: count * 100.0 / rows_total if rows_total else 0.0
                for label, count in sorted(labels.items())
            },
            "label_distribution_by_file": {
                source: dict(sorted(counts.items()))
                for source, counts in label_by_file.items()
            },
        },
        "schema": schema_comparison,
        "files": file_results,
        "features": feature_results,
        "duplicate_analysis": duplicate_metrics,
        "outlier_diagnostics": outlier_summary,
        "policy_version": POLICY_VERSION,
        "limitations": [
            "CSV source text is preserved. Numeric parsing is diagnostic only.",
            "Outlier summaries and cardinality are systematic-sample estimates, not full-data counts.",
            "Duplicate counts use a dual 64-bit row fingerprint. No records are removed.",
            "A feature's physical semantics and CICFlowMeter implementation history do not prove why a specific row is anomalous.",
        ],
    }
    report["quality_summary"] = _quality_summary(report)
    return report


def _new_feature_result(source_header: str, internal: str, position: int) -> dict[str, Any]:
    metrics = (
        "empty_string",
        "explicit_null",
        "nan_token",
        "missing_total",
        "invalid_numeric",
        "positive_infinity",
        "negative_infinity",
        "negative",
        "finite_zero",
        "overflow_or_nonfinite_conversion",
    )
    return {
        "source_header": source_header,
        "normalized_header": source_header.strip(),
        "internal_column": internal,
        "source_position": position,
        "rows_seen": 0,
        "finite_count": 0,
        "minimum_finite": None,
        "maximum_finite": None,
        "negative_minimum": None,
        "negative_maximum": None,
        "numeric_representation": "not_assessed",
        "mathematical_negative_assessment": _negative_semantics(source_header),
        "counts": {name: 0 for name in metrics},
        "large_integer_precision_risk": 0,
        "by_file": defaultdict(lambda: defaultdict(int)),
        "by_label": defaultdict(lambda: defaultdict(int)),
        "invalid_tokens": Counter(),
        "infinity_with_zero_flow_duration": 0,
        "infinity_with_nonzero_or_missing_flow_duration": 0,
        "sample": {},
    }


def _negative_semantics(header: str) -> dict[str, str]:
    normalized = header.strip().casefold()
    if "init_win_bytes" in normalized:
        return {
            "mathematically_possible": "no_for_a_window_byte_count",
            "classification": "unresolved_potential_sentinel",
            "reason": "Negative byte counts are not physically meaningful; the frequent -1 may be an unavailable-value sentinel, but the source extract does not document that encoding.",
        }
    if any(term in normalized for term in ("duration", "iat", "packet", "bytes", "length", "count", "flag", "size", "mean", "std", "variance", "min", "max", "active", "idle", "header", "segment", "bulk", "ratio", "rate")):
        return {
            "mathematically_possible": "no_under_the_published_feature_definition",
            "classification": "potentially_invalid_preserved",
            "reason": "CICFlowMeter describes this field as a count, size, time interval, statistic, or ratio; negative values conflict with that definition, but row-level extraction causes are not established.",
        }
    return {
        "mathematically_possible": "unresolved",
        "classification": "unresolved",
        "reason": "No feature-specific negative-value interpretation is asserted.",
    }


def _update_feature(
    result: dict[str, Any],
    source_text: pd.Series,
    numeric: pd.Series,
    labels: pd.Series,
    source: str,
) -> None:
    stripped = source_text.astype(str).str.strip()
    folded = stripped.str.casefold()
    empty = folded.eq("")
    explicit_null = folded.isin(MISSING_NULL_TOKENS)
    nan_token = folded.isin(NAN_TOKENS)
    missing = empty | explicit_null | nan_token
    values = numeric.to_numpy(dtype=np.float64, na_value=np.nan)
    invalid = (~missing.to_numpy()) & np.isnan(values)
    pos_inf = np.isposinf(values)
    neg_inf = np.isneginf(values)
    finite = np.isfinite(values)
    negative = finite & (values < 0)
    zero = finite & (values == 0)

    updates = {
        "empty_string": empty.to_numpy(),
        "explicit_null": explicit_null.to_numpy(),
        "nan_token": nan_token.to_numpy(),
        "missing_total": missing.to_numpy(),
        "invalid_numeric": invalid,
        "positive_infinity": pos_inf,
        "negative_infinity": neg_inf,
        "negative": negative,
        "finite_zero": zero,
        "overflow_or_nonfinite_conversion": (
            np.isinf(values)
            & ~folded.isin(POSITIVE_INFINITY_TOKENS | NEGATIVE_INFINITY_TOKENS).to_numpy()
        ),
    }
    result["rows_seen"] += len(source_text)
    for metric, mask in updates.items():
        count = int(mask.sum())
        result["counts"][metric] += count
        if count:
            result["by_file"][source][metric] += count
            selected = labels.loc[mask]
            for label, value_count in selected.value_counts(dropna=False).items():
                result["by_label"][str(label)][metric] += int(value_count)
    if invalid.any():
        result["invalid_tokens"].update(
            {
                str(value): int(count)
                for value, count in stripped.loc[invalid].value_counts().head(20).items()
            }
        )
    long_integer_tokens = stripped[stripped.str.fullmatch(r"[+-]?\d{16,}", na=False)]
    if not long_integer_tokens.empty:
        result["large_integer_precision_risk"] += sum(
            abs(int(token)) > 2**53
            and int(float(token)) != int(token)
            for token in long_integer_tokens
        )
    finite_values = values[finite]
    if finite_values.size:
        result["finite_count"] += int(finite_values.size)
        current_min = float(finite_values.min())
        current_max = float(finite_values.max())
        result["minimum_finite"] = (
            current_min if result["minimum_finite"] is None
            else min(result["minimum_finite"], current_min)
        )
        result["maximum_finite"] = (
            current_max if result["maximum_finite"] is None
            else max(result["maximum_finite"], current_max)
        )
    negative_values = values[negative]
    if negative_values.size:
        current_min = float(negative_values.min())
        current_max = float(negative_values.max())
        result["negative_minimum"] = (
            current_min if result["negative_minimum"] is None
            else min(result["negative_minimum"], current_min)
        )
        result["negative_maximum"] = (
            current_max if result["negative_maximum"] is None
            else max(result["negative_maximum"], current_max)
        )


def _update_fingerprints(
    database: sqlite3.Connection,
    features: pd.DataFrame,
    labels: pd.Series,
    source: str,
) -> None:
    """Aggregate 128-bit content fingerprints to disk, never in a global map."""
    first = pd.util.hash_pandas_object(
        features, index=False, hash_key="0123456789abcdef"
    ).to_numpy(dtype=np.uint64)
    second = pd.util.hash_pandas_object(
        features, index=False, hash_key="fedcba9876543210"
    ).to_numpy(dtype=np.uint64)
    feature_digest = np.char.add(
        np.char.zfill(np.char.mod("%016x", first), 16),
        np.char.zfill(np.char.mod("%016x", second), 16),
    )
    all_values = features.copy()
    all_values["__quality_label"] = labels.to_numpy()
    exact_first = pd.util.hash_pandas_object(
        all_values, index=False, hash_key="abcdef0123456789"
    ).to_numpy(dtype=np.uint64)
    exact_second = pd.util.hash_pandas_object(
        all_values, index=False, hash_key="9876543210fedcba"
    ).to_numpy(dtype=np.uint64)
    exact_digest = np.char.add(
        np.char.zfill(np.char.mod("%016x", exact_first), 16),
        np.char.zfill(np.char.mod("%016x", exact_second), 16),
    )
    frame = pd.DataFrame(
        {"feature": feature_digest, "exact": exact_digest, "label": labels.to_numpy()}
    )
    feature_groups = frame.groupby(["feature", "label"], sort=False, dropna=False).size()
    exact_groups = frame.groupby("exact", sort=False, dropna=False).size()
    inserts = [
        ("feature", str(digest), source, str(label), int(count))
        for (digest, label), count in feature_groups.items()
    ]
    inserts.extend(
        ("exact", str(digest), source, "", int(count))
        for digest, count in exact_groups.items()
    )
    database.executemany(
        "INSERT INTO fingerprints(kind,digest,source,label,n) VALUES(?,?,?,?,?) "
        "ON CONFLICT(kind,digest,source,label) DO UPDATE SET n=n+excluded.n",
        inserts,
    )


def _summarize_fingerprints(database: sqlite3.Connection) -> dict[str, Any]:
    def scalar(query: str) -> int:
        value = database.execute(query).fetchone()[0]
        return int(value or 0)

    exact_extra = scalar(
        "SELECT COALESCE(SUM(n-1),0) FROM "
        "(SELECT digest,SUM(n) n FROM fingerprints WHERE kind='exact' "
        "GROUP BY digest HAVING SUM(n)>1)"
    )
    exact_groups = scalar(
        "SELECT COUNT(*) FROM (SELECT digest FROM fingerprints "
        "WHERE kind='exact' GROUP BY digest HAVING SUM(n)>1)"
    )
    exact_within = scalar(
        "SELECT COALESCE(SUM(n-1),0) FROM fingerprints WHERE kind='exact' AND n>1"
    )
    exact_cross = scalar(
        "SELECT COUNT(*) FROM (SELECT digest FROM fingerprints WHERE kind='exact' "
        "GROUP BY digest HAVING COUNT(DISTINCT source)>1)"
    )
    feature_extra = scalar(
        "SELECT COALESCE(SUM(total-1),0) FROM (SELECT digest,SUM(n) total "
        "FROM fingerprints WHERE kind='feature' GROUP BY digest HAVING SUM(n)>1)"
    )
    feature_groups = scalar(
        "SELECT COUNT(*) FROM (SELECT digest FROM fingerprints WHERE kind='feature' "
        "GROUP BY digest HAVING SUM(n)>1)"
    )
    feature_within = scalar(
        "SELECT COALESCE(SUM(n-1),0) FROM fingerprints WHERE kind='feature' AND n>1"
    )
    feature_cross = scalar(
        "SELECT COUNT(*) FROM (SELECT digest FROM fingerprints WHERE kind='feature' "
        "GROUP BY digest HAVING COUNT(DISTINCT source)>1)"
    )
    conflicts = scalar(
        "SELECT COUNT(*) FROM (SELECT digest FROM fingerprints WHERE kind='feature' "
        "GROUP BY digest HAVING COUNT(DISTINCT label)>1)"
    )
    source_names = [
        row[0]
        for row in database.execute(
            "SELECT DISTINCT source FROM fingerprints ORDER BY source"
        ).fetchall()
    ]
    duplicates_by_source: dict[str, Any] = {}
    for source in source_names:
        exact_source = database.execute(
            "SELECT COALESCE(SUM(n-1),0), SUM(CASE WHEN n>1 THEN 1 ELSE 0 END) "
            "FROM fingerprints WHERE kind='exact' AND source=?",
            (source,),
        ).fetchone()
        feature_source = database.execute(
            "SELECT COALESCE(SUM(n-1),0), "
            "SUM(CASE WHEN n>1 THEN 1 ELSE 0 END) FROM ("
            "SELECT digest,SUM(n) n FROM fingerprints "
            "WHERE kind='feature' AND source=? GROUP BY digest)",
            (source,),
        ).fetchone()
        duplicates_by_source[source] = {
            "exact_duplicate_excess_rows": int(exact_source[0] or 0),
            "exact_repeated_groups_within_file": int(exact_source[1] or 0),
            "feature_vector_duplicate_excess_rows": int(feature_source[0] or 0),
            "feature_vector_repeated_groups_within_file": int(feature_source[1] or 0),
        }
    conflicts_by_label = {
        str(label): int(count)
        for label, count in database.execute(
            "SELECT label, COUNT(DISTINCT digest) FROM fingerprints "
            "WHERE kind='feature' AND digest IN ("
            "SELECT digest FROM fingerprints WHERE kind='feature' "
            "GROUP BY digest HAVING COUNT(DISTINCT label)>1) GROUP BY label"
        ).fetchall()
    }
    return {
        "computed": True,
        "method": (
            "Two independently keyed 64-bit Pandas row fingerprints are combined "
            "to 128 bits and externally aggregated in SQLite; collision probability "
            "is negligible but not mathematically zero."
        ),
        "exact_complete_row_duplicates": {
            "duplicate_excess_rows": exact_extra,
            "repeated_fingerprint_groups": exact_groups,
            "within_source_duplicate_excess_rows": exact_within,
            "across_source_groups": exact_cross,
        },
        "feature_vector_duplicates": {
            "duplicate_excess_rows": feature_extra,
            "repeated_fingerprint_groups": feature_groups,
            "within_source_duplicate_excess_rows": feature_within,
            "across_source_groups": feature_cross,
            "groups_with_different_labels": conflicts,
            "conflicting_groups_by_label": conflicts_by_label,
        },
        "by_source_file": duplicates_by_source,
        "records_removed": 0,
    }


def _sample_diagnostics(
    sample: pd.DataFrame,
    feature_results: dict[str, dict[str, Any]],
    *,
    label_column: str,
    sample_size: int,
) -> dict[str, Any]:
    summary: dict[str, Any] = {
        "method": "Deterministic systematic sample; all reported estimates are sample-only.",
        "sample_rows": sample_size,
        "features": {},
    }
    if sample.empty:
        return summary
    for internal, result in feature_results.items():
        if internal not in sample:
            continue
        values = pd.to_numeric(sample[internal], errors="coerce").to_numpy(
            dtype=np.float64, na_value=np.nan
        )
        finite = values[np.isfinite(values)]
        if not finite.size:
            continue
        observed = _sample_numeric_summary(finite)
        observed.update({
            "sample_label_counts": {
                str(label): int(count)
                for label, count in sample[label_column].value_counts(dropna=False).items()
            },
            "outliers_removed": 0,
        })
        observed["low_cardinality_sample"] = observed["sample_unique_values"] <= 10
        observed["near_constant_sample"] = (
            observed["sample_dominant_value_percent"] >= 99.9
        )
        observed["by_source_file_sample"] = {
            str(source): _sample_numeric_summary(
                pd.to_numeric(subset[internal], errors="coerce").to_numpy(
                    dtype=np.float64, na_value=np.nan
                )
            )
            for source, subset in sample.groupby("__sample_source", sort=True, dropna=False)
        }
        observed["by_label_sample"] = {
            str(label): _sample_numeric_summary(
                pd.to_numeric(subset[internal], errors="coerce").to_numpy(
                    dtype=np.float64, na_value=np.nan
                )
            )
            for label, subset in sample.groupby(label_column, sort=True, dropna=False)
        }
        result["sample"] = observed
        result["sample_cardinality_classification"] = (
            "low_cardinality_and_near_constant_sample"
            if observed["low_cardinality_sample"] and observed["near_constant_sample"]
            else "low_cardinality_sample"
            if observed["low_cardinality_sample"]
            else "near_constant_sample"
            if observed["near_constant_sample"]
            else "variable_sample"
        )
        summary["features"][internal] = {
            "source_header": result["source_header"],
            **observed,
        }
    return summary


def _sample_numeric_summary(values: np.ndarray) -> dict[str, Any]:
    """Describe one bounded numeric sample without implying full coverage."""
    finite = values[np.isfinite(values)]
    if not finite.size:
        return {"n_finite_sample": 0}
    q1, median, q3 = np.quantile(finite, [0.25, 0.5, 0.75]).tolist()
    iqr = float(q3 - q1)
    mad = float(np.median(np.abs(finite - median)))
    low_fence = float(q1 - 1.5 * iqr)
    high_fence = float(q3 + 1.5 * iqr)
    iqr_mask = (finite < low_fence) | (finite > high_fence)
    modified_z = (
        np.abs(0.6745 * (finite - median) / mad)
        if mad > 0
        else np.zeros_like(finite)
    )
    frequencies = pd.Series(finite).value_counts(normalize=True)
    return {
        "n_finite_sample": int(finite.size),
        "minimum_sample": float(finite.min()),
        "maximum_sample": float(finite.max()),
        "q1_sample": float(q1),
        "median_sample": float(median),
        "q3_sample": float(q3),
        "iqr_sample": iqr,
        "mad_sample": mad,
        "iqr_fences_sample": [low_fence, high_fence],
        "iqr_outlier_count_sample": int(iqr_mask.sum()),
        "iqr_outlier_percent_sample": float(iqr_mask.mean() * 100.0),
        "mad_modified_z_gt_3_5_count_sample": int((modified_z > 3.5).sum()),
        "sample_unique_values": int(pd.Series(finite).nunique()),
        "sample_dominant_value_percent": float(frequencies.iloc[0] * 100.0),
    }


def _finish_feature_results(
    results: dict[str, dict[str, Any]],
    rows_total: int,
    outliers: dict[str, Any],
    *,
    file_rows: dict[str, int],
    label_counts: Counter[str],
) -> None:
    for result in results.values():
        result["missing_percent"] = (
            result["counts"]["missing_total"] * 100.0 / rows_total if rows_total else 0.0
        )
        result["negative_percent"] = (
            result["counts"]["negative"] * 100.0 / rows_total if rows_total else 0.0
        )
        result["numeric_representation"] = (
            "mixed_or_invalid"
            if result["counts"]["invalid_numeric"] or result["counts"]["overflow_or_nonfinite_conversion"]
            else "numeric_with_missing_or_nonfinite"
            if result["counts"]["missing_total"] or result["counts"]["positive_infinity"] or result["counts"]["negative_infinity"]
            else "numeric"
        )
        result["invalid_tokens"] = dict(result["invalid_tokens"].most_common(20))
        result["by_file"] = {
            source: dict(counts) for source, counts in result["by_file"].items()
        }
        result["by_label"] = {
            label: dict(counts) for label, counts in result["by_label"].items()
        }
        percentage_metrics = (
            "missing_total",
            "invalid_numeric",
            "positive_infinity",
            "negative_infinity",
            "negative",
            "overflow_or_nonfinite_conversion",
        )
        result["metric_percentages_by_file"] = {
            source: {
                metric: counts.get(metric, 0) * 100.0 / total if total else 0.0
                for metric in percentage_metrics
            }
            for source, total in file_rows.items()
            for counts in [result["by_file"].get(source, {})]
        }
        result["metric_percentages_by_label"] = {
            label: {
                metric: result["by_label"].get(label, {}).get(metric, 0)
                * 100.0
                / total
                if total
                else 0.0
                for metric in percentage_metrics
            }
            for label, total in label_counts.items()
        }
        result["finding_class"] = (
            "valid_or_no_anomaly_detected"
        )
        _classify_feature_findings(result)


def _classify_feature_findings(result: dict[str, Any]) -> None:
    """Classify observed anomalies without changing or discarding source values."""
    counts = result["counts"]
    findings: list[dict[str, Any]] = []
    if counts["missing_total"]:
        findings.append(
            {
                "classification": "unresolved_missingness",
                "count": counts["missing_total"],
                "reason": "The source cell is missing; the CSV does not provide a defensible replacement.",
            }
        )
    if counts["invalid_numeric"]:
        findings.append(
            {
                "classification": "confirmed_invalid_representation",
                "count": counts["invalid_numeric"],
                "reason": "A non-missing source token cannot be parsed numerically for a numeric flow feature.",
            }
        )
    infinity_count = counts["positive_infinity"] + counts["negative_infinity"]
    if infinity_count:
        header = result["source_header"].strip().casefold()
        findings.append(
            {
                "classification": (
                    "confirmed_invalid_nonfinite_measurement"
                    if header in {"flow bytes/s", "flow packets/s"}
                    else "unresolved_nonfinite_value"
                ),
                "count": infinity_count,
                "reason": (
                    "A flow-rate infinity paired with zero Flow Duration is an undefined rate; "
                    "the source does not supply a finite corrected value."
                    if header in {"flow bytes/s", "flow packets/s"}
                    else "The source contains a non-finite value and its cause is not established."
                ),
            }
        )
    if counts["negative"]:
        semantic = result["mathematical_negative_assessment"]
        findings.append(
            {
                "classification": (
                    "unresolved_potential_sentinel"
                    if semantic["classification"] == "unresolved_potential_sentinel"
                    else "potentially_invalid"
                ),
                "count": counts["negative"],
                "reason": semantic["reason"],
            }
        )
    if result["large_integer_precision_risk"]:
        findings.append(
            {
                "classification": "confirmed_precision_risk",
                "count": result["large_integer_precision_risk"],
                "reason": "The source integer cannot be represented exactly as float64.",
            }
        )
    result["finding_classifications"] = findings
    if any(item["classification"].startswith("confirmed_invalid") for item in findings):
        result["finding_class"] = "confirmed_invalid_preserved"
    elif any(item["classification"] == "potentially_invalid" for item in findings):
        result["finding_class"] = "potentially_invalid_preserved"
    elif findings:
        result["finding_class"] = "unresolved_preserved"
    else:
        result["finding_class"] = "valid_or_no_anomaly_detected"


def _quality_summary(report: dict[str, Any]) -> dict[str, Any]:
    features = report["features"]
    totals = {
        metric: sum(feature["counts"][metric] for feature in features.values())
        for metric in (
            "empty_string",
            "explicit_null",
            "nan_token",
            "missing_total",
            "invalid_numeric",
            "positive_infinity",
            "negative_infinity",
            "negative",
            "overflow_or_nonfinite_conversion",
        )
    }
    constants = [
        result["internal_column"]
        for result in features.values()
        if result["finite_count"] == report["dataset_overview"]["rows"]
        and result["minimum_finite"] == result["maximum_finite"]
    ]
    negative_features = [
        {
            "source_header": result["source_header"],
            "internal_column": result["internal_column"],
            "count": result["counts"]["negative"],
            "percentage": result["negative_percent"],
            "minimum": result["negative_minimum"],
            "maximum": result["negative_maximum"],
            "assessment": result["mathematical_negative_assessment"],
        }
        for result in features.values()
        if result["counts"]["negative"]
    ]
    numeric_representation_counts = Counter(
        result["numeric_representation"] for result in features.values()
    )
    findings_by_classification: Counter[str] = Counter()
    for result in features.values():
        for finding in result.get("finding_classifications", []):
            findings_by_classification[finding["classification"]] += finding["count"]
    return {
        "counts": totals,
        "findings_by_classification": dict(findings_by_classification),
        "constant_features": constants,
        "low_cardinality_features_sample": [
            result["internal_column"]
            for result in features.values()
            if result.get("sample", {}).get("low_cardinality_sample")
        ],
        "near_constant_features_sample": [
            result["internal_column"]
            for result in features.values()
            if result.get("sample", {}).get("near_constant_sample")
        ],
        "numeric_representation_counts": dict(numeric_representation_counts),
        "large_integer_precision_risk_features": [
            result["internal_column"]
            for result in features.values()
            if result["large_integer_precision_risk"]
        ],
        "negative_features": negative_features,
        "features_with_missing": [
            key for key, result in features.items() if result["counts"]["missing_total"]
        ],
        "features_with_infinities": [
            key
            for key, result in features.items()
            if result["counts"]["positive_infinity"] or result["counts"]["negative_infinity"]
        ],
        "features_with_invalid_numeric": [
            key for key, result in features.items() if result["counts"]["invalid_numeric"]
        ],
        "features_with_numeric_overflow": [
            key
            for key, result in features.items()
            if result["counts"]["overflow_or_nonfinite_conversion"]
        ],
    }
