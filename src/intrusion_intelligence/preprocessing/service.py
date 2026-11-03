"""Run leakage-aware, auditable cleaning without changing source files."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import shutil
import sqlite3
import tempfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq

from intrusion_intelligence.config import ProjectConfig
from intrusion_intelligence.errors import ProjectError
from intrusion_intelligence.ingestion.service import inspect_dataset
from intrusion_intelligence.preprocessing.assessment import (
    PROVENANCE_COLUMNS,
    assess_dataset,
)
from intrusion_intelligence.preprocessing.cleaning import (
    clean_source_chunk,
    normalize_missing_mask,
    standardize_source_headers,
)
from intrusion_intelligence.preprocessing.policy import (
    DEFAULT_POLICY_PATH,
    load_policy,
    validate_policy,
)
from intrusion_intelligence.preprocessing.reporting import (
    write_cleaning_report,
    write_quality_report,
)

TRANSFORMATION_VERSION = "2.0.0"
_SOURCE_LABEL_COLUMN = "__source_label"
_REJECTION_COLUMN = "__rejection_reason"


def clean_dataset(
    config: ProjectConfig,
    *,
    chunk_size: int | None = None,
    sample_stride: int = 100,
    output_directory: str | Path | None = None,
    policy_path: str | Path | None = None,
    dry_run: bool = False,
) -> dict[str, Any]:
    """Assess, standardize, clean, quarantine, and validate a dataset copy.

    Raw CSVs are read as strings and are never modified. Processed Parquet files
    contain normalized column names, numeric features, canonical nulls, and
    trimmed labels. Source labels and row provenance remain as metadata.
    """
    selected_chunk_size = chunk_size or config.ingestion.chunk_size
    if selected_chunk_size <= 0 or sample_stride <= 0:
        raise ValueError("chunk_size and sample_stride must be positive.")
    selected_policy_path = Path(policy_path or (config.project_root / DEFAULT_POLICY_PATH))
    policy = load_policy(selected_policy_path)
    validate_policy(policy)
    output_root = Path(
        output_directory
        or (config.paths.processed_data / f"{config.dataset.name}-phase04-v2")
    ).expanduser().resolve()
    final_cleaned = output_root / "cleaned"
    quarantine_final = (
        config.paths.interim_data
        / "quarantine"
        / output_root.name
        / "rejected.parquet"
    )
    metadata_final = output_root / "metadata"
    if final_cleaned.exists() or metadata_final.exists() or quarantine_final.exists():
        raise ProjectError(
            "Processed output already exists and will not be overwritten; choose a new --output-dir."
        )

    if dry_run:
        return {
            "status": "dry_run",
            "cleaning_completed": False,
            "source_files_modified": False,
            "processed_outputs_written": False,
            "output_directory": str(final_cleaned),
            "quarantine_file": str(quarantine_final),
            "policy_path": str(selected_policy_path),
            "policy": policy,
            "planned_transformations": [
                "Normalize headers to deterministic snake_case names and suffix collisions by source position.",
                "Parse numeric features; canonicalize missing tokens and replace positive/negative infinity with NaN.",
                "Trim labels, preserve their raw values in __source_label, and quarantine missing or unexpected labels.",
                "Preserve negative values, outliers, duplicate records, and all feature columns under the default policy.",
                "Write per-source Parquet outputs with source file, source row number, and deterministic record ID.",
            ],
        }

    before = assess_dataset(
        config,
        chunk_size=selected_chunk_size,
        sample_stride=sample_stride,
        compute_duplicates=True,
    )
    report_directory = config.paths.eda_reports.parent / "data_quality"
    before_json, before_md = write_quality_report(
        before, report_directory / f"{config.dataset.name}_quality_report_v2_before"
    )
    inventory = inspect_dataset(
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
    if not inventory.files or not inventory.schema_validation.is_compatible:
        raise ProjectError("Input schemas failed Phase 02 compatibility validation.")

    expected_labels = tuple(policy["labels"]["expected_values"])
    categorical = tuple(policy["column_roles"]["categorical"])
    datetimes = tuple(policy["column_roles"]["datetime"])
    identifiers = tuple(policy["column_roles"]["identifiers"])
    run_timestamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
    output_root.mkdir(parents=True, exist_ok=True)
    stage_parent = Path(tempfile.mkdtemp(prefix=".phase04-stage-", dir=output_root))
    stage_cleaned = stage_parent / "cleaned"
    stage_audit_csv = stage_parent / "audit_csv"
    stage_metadata = stage_parent / "metadata"
    stage_quarantine = stage_parent / "rejected.parquet"
    stage_cleaned.mkdir()
    stage_audit_csv.mkdir()
    stage_metadata.mkdir()

    outputs: list[dict[str, Any]] = []
    source_header_map: list[dict[str, Any]] | None = None
    source_header_maps_by_file: dict[str, list[dict[str, Any]]] = {}
    cleaned_headers: tuple[str, ...] | None = None
    label_position: int | None = None
    rows_input = 0
    rows_written = 0
    rows_quarantined = 0
    rows_deduplicated = 0
    rejection_counts: Counter[str] = Counter()
    label_mapping_counts: Counter[tuple[str, str]] = Counter()
    missing_counts: Counter[str] = Counter()
    positive_inf_counts: Counter[str] = Counter()
    negative_inf_counts: Counter[str] = Counter()
    conversion_failure_counts: Counter[str] = Counter()
    conversion_examples: dict[str, list[str]] = {}
    quarantine_writer: pq.ParquetWriter | None = None
    duplicate_database: sqlite3.Connection | None = None
    if policy["duplicates"]["action"] == "drop_exact_duplicates":
        duplicate_database = sqlite3.connect(stage_parent / "seen-exact-rows.sqlite")
        duplicate_database.execute("CREATE TABLE seen (digest TEXT PRIMARY KEY) WITHOUT ROWID")

    try:
        for inspected in inventory.files:
            source = inspected.relative_path
            if inspected.status != "valid" or not inspected.internal_label_column:
                raise ProjectError(f"Input became invalid during cleaning: {source}")
            current_headers, current_mapping = standardize_source_headers(
                inspected.original_columns
            )
            source_header_maps_by_file[source] = current_mapping
            alignment_positions: tuple[int, ...]
            if cleaned_headers is None:
                cleaned_headers = current_headers
                source_header_map = current_mapping
                alignment_positions = tuple(range(len(current_headers)))
                label_position = inspected.internal_columns.index(
                    inspected.internal_label_column
                )
                label_column = cleaned_headers[label_position]
                if label_column != "label":
                    raise ProjectError("The normalized target column must be named 'label'.")
            else:
                if len(current_headers) != len(cleaned_headers) or set(current_headers) != set(cleaned_headers):
                    raise ProjectError(
                        f"Normalized schema differs from the first source file: {source}"
                    )
                # Phase 02 accepts compatible order-only differences. Align by the
                # collision-safe normalized names before cleaning/fingerprinting.
                alignment_positions = tuple(
                    current_headers.index(name) for name in cleaned_headers
                )

            input_info = before["files"][source]
            target = stage_cleaned / Path(source).with_suffix(".parquet")
            audit_target = stage_audit_csv / Path(source).with_suffix(".csv")
            target.parent.mkdir(parents=True, exist_ok=True)
            audit_target.parent.mkdir(parents=True, exist_ok=True)
            output_writer: pq.ParquetWriter | None = None
            audit_first = True
            source_offset = 0
            file_written = 0
            file_quarantined = 0
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
                        row_count = len(frame)
                        start_row = source_offset + 1
                        frame.columns = list(inspected.original_columns)
                        if alignment_positions != tuple(range(len(alignment_positions))):
                            frame = frame.iloc[:, list(alignment_positions)].copy()
                        row_numbers = list(range(start_row, start_row + row_count))
                        record_ids = [
                            hashlib.blake2b(
                                f"{source}\0{input_info['sha256']}:{row_number}".encode("utf-8"),
                                digest_size=12,
                            ).hexdigest()
                            for row_number in row_numbers
                        ]
                        retained, quarantined, chunk_counts = clean_source_chunk(
                            frame,
                            cleaned_headers=cleaned_headers,
                            label_position=label_position,
                            expected_labels=expected_labels,
                            categorical_columns=categorical,
                            datetime_columns=datetimes,
                            identifier_columns=identifiers,
                            source_file=source,
                            source_row_numbers=row_numbers,
                            record_ids=record_ids,
                        )
                        _accumulate_counts(
                            chunk_counts,
                            label_mapping_counts,
                            missing_counts,
                            positive_inf_counts,
                            negative_inf_counts,
                            conversion_failure_counts,
                            conversion_examples,
                        )
                        rows_input += row_count
                        valid_indices = retained.index
                        if duplicate_database is not None and len(retained):
                            duplicate_mask = _exact_duplicate_mask(frame, duplicate_database)
                            duplicate_valid = duplicate_mask[valid_indices]
                            if duplicate_valid.any():
                                duplicate_positions = valid_indices[duplicate_valid].to_numpy()
                                duplicate_rows = frame.iloc[duplicate_positions].copy()
                                duplicate_rows.columns = list(cleaned_headers)
                                duplicate_rows["__source_label"] = duplicate_rows[label_column].astype("string")
                                duplicate_rows["__source_file"] = source
                                duplicate_rows["__source_row_number"] = [
                                    row_numbers[index] for index in duplicate_positions
                                ]
                                duplicate_rows["__record_id"] = [
                                    record_ids[index] for index in duplicate_positions
                                ]
                                duplicate_rows[_REJECTION_COLUMN] = "exact_duplicate"
                                retained = retained.loc[~duplicate_valid]
                                quarantined = pd.concat(
                                    [quarantined, duplicate_rows], ignore_index=True
                                )
                                removed = int(duplicate_valid.sum())
                                rows_deduplicated += removed
                        if len(quarantined):
                            quarantined = _canonicalize_quarantine(
                                quarantined,
                                cleaned_headers,
                            )
                            quarantine_writer = _append_parquet_table(
                                quarantine_writer,
                                quarantined,
                                stage_quarantine,
                            )
                            file_quarantined += len(quarantined)
                            rows_quarantined += len(quarantined)
                            reason_counts = quarantined[_REJECTION_COLUMN].value_counts()
                            for reason, count in reason_counts.items():
                                rejection_counts[str(reason)] += int(count)
                        if output_writer is None:
                            output_writer = _open_parquet_writer(target, retained)
                        if len(retained):
                            table = pa.Table.from_pandas(retained, preserve_index=False)
                            _write_table(output_writer, table, selected_chunk_size)
                            retained.to_csv(
                                audit_target,
                                mode="w" if audit_first else "a",
                                header=audit_first,
                                index=False,
                                encoding="utf-8",
                                lineterminator="\n",
                                na_rep="NaN",
                            )
                            audit_first = False
                            file_written += len(retained)
                            rows_written += len(retained)
                        source_offset += row_count
                finally:
                    reader.close()
            except (OSError, UnicodeError, ValueError, pa.ArrowException, pd.errors.ParserError) as exc:
                raise ProjectError(
                    f"Unable to transform source file {source}: {exc.__class__.__name__}"
                ) from exc
            finally:
                if output_writer is not None:
                    output_writer.close()
            if source_offset != input_info["rows"]:
                raise ProjectError(f"Source row count changed during cleaning: {source}")
            if file_written == 0:
                empty = _empty_clean_frame(
                    cleaned_headers,
                    label_position,
                    categorical,
                    datetimes,
                    identifiers,
                )
                writer = _open_parquet_writer(target, empty)
                writer.close()
                empty.to_csv(audit_target, index=False, encoding="utf-8", na_rep="NaN")
            outputs.append(
                {
                    "source_file": source,
                    "source_sha256": input_info["sha256"],
                    "path": f"cleaned/{Path(source).with_suffix('.parquet').as_posix()}",
                    "rows_input": source_offset,
                    "rows_retained": file_written,
                    "rows_quarantined": file_quarantined,
                    "sha256": _sha256_file(target),
                    "parquet_schema": str(pq.ParquetFile(target).schema_arrow),
                }
            )

        if cleaned_headers is None or label_position is None or source_header_map is None:
            raise ProjectError("No source schema was available to clean.")
        if quarantine_writer is None:
            empty_quarantine = _empty_quarantine_frame(cleaned_headers)
            quarantine_writer = _open_parquet_writer(stage_quarantine, empty_quarantine)
        quarantine_writer.close()
        quarantine_writer = None
        if duplicate_database is not None:
            duplicate_database.commit()
            duplicate_database.close()
            duplicate_database = None

        after = assess_dataset(
            config,
            dataset_directory=stage_audit_csv,
            chunk_size=selected_chunk_size,
            sample_stride=sample_stride,
            compute_duplicates=False,
        )
        parquet_validation = _validate_parquet_outputs(
            [stage_cleaned / Path(item["source_file"]).with_suffix(".parquet") for item in outputs],
            expected_columns=[
                *cleaned_headers,
                _SOURCE_LABEL_COLUMN,
                *PROVENANCE_COLUMNS,
            ],
            chunk_size=selected_chunk_size,
        )
        quarantine_validation = _validate_parquet_outputs(
            [stage_quarantine],
            expected_columns=[
                *cleaned_headers,
                _SOURCE_LABEL_COLUMN,
                *PROVENANCE_COLUMNS,
                _REJECTION_COLUMN,
            ],
            chunk_size=selected_chunk_size,
            label_column=None,
        )
        after_infinities = sum(
            feature["counts"]["positive_infinity"]
            + feature["counts"]["negative_infinity"]
            for feature in after["features"].values()
        )
        after_labels = after["dataset_overview"]["label_counts"]
        labels_valid = set(after_labels).issubset(set(expected_labels)) and "" not in after_labels
        feature_policy = _build_feature_policy(
            cleaned_headers,
            label_column=cleaned_headers[label_position],
            identifier_columns=identifiers,
            datetime_columns=datetimes,
            categorical_columns=categorical,
            source_header_map=source_header_map,
        )
        feature_policy_valid = (
            feature_policy["target_column"] not in feature_policy["candidate_predictive_features"]
            and not set(PROVENANCE_COLUMNS + (_SOURCE_LABEL_COLUMN,)).intersection(
                feature_policy["candidate_predictive_features"]
            )
            and not set(feature_policy["excluded_identifier_columns"]).intersection(
                feature_policy["candidate_predictive_features"]
            )
        )
        input_hashes_after = {
            item.relative_path: _sha256_file(item.path)
            for item in inventory.files
        }
        raw_files_unchanged = all(
            input_hashes_after[name] == before["files"][name]["sha256"]
            for name in before["files"]
        )
        row_accounting = rows_input == rows_written + rows_quarantined
        expected_output_rows = before["dataset_overview"]["rows"] - rows_quarantined
        validation = {
            "schema_compatible": after["schema"]["compatible"],
            "cleaned_headers_unique": len(cleaned_headers) == len(set(cleaned_headers)),
            "parquet_files_reopened": parquet_validation["files_reopened"],
            "parquet_row_count_matches": parquet_validation["rows"] == rows_written,
            "parquet_labels_match_quality_scan": parquet_validation["label_counts"] == after_labels,
            "quarantine_file_reopened": quarantine_validation["files_reopened"],
            "quarantine_row_count_matches": quarantine_validation["rows"] == rows_quarantined,
            "infinities_absent_from_cleaned_features": after_infinities == 0,
            "labels_valid_and_nonempty": labels_valid,
            "feature_policy_separates_target_and_metadata": feature_policy_valid,
            "excluded_rows_accounted_for": row_accounting,
            "expected_cleaned_row_count": rows_written == expected_output_rows,
            "raw_files_unchanged": raw_files_unchanged,
        }
        verified = all(validation.values())
        after["duplicate_analysis"] = {
            **before["duplicate_analysis"],
            "cleaning_action": policy["duplicates"]["action"],
            "duplicate_excess_rows_removed": rows_deduplicated,
            "feature_vector_conflicts_removed": 0,
            "feature_vector_conflicts_preserved": before["duplicate_analysis"]
            ["feature_vector_duplicates"]["groups_with_different_labels"],
            "computed_on_source_before_transformations": True,
        }
        after["processing"] = {
            "format": "Parquet",
            "transformation_version": TRANSFORMATION_VERSION,
            "policy_version": policy["version"],
            "input_rows": rows_input,
            "retained_rows": rows_written,
            "quarantined_rows": rows_quarantined,
            "rejection_counts": dict(rejection_counts),
            "infinities_replaced_with_nan": dict(
                positive_inf_counts + negative_inf_counts
            ),
            "numeric_conversion_failures": dict(conversion_failure_counts),
        }
        after_json, after_md = write_quality_report(
            after,
            report_directory / f"{config.dataset.name}_quality_report_v2_after",
        )
        processing_id = hashlib.sha256(
            f"{run_timestamp}|{config.dataset.name}|{TRANSFORMATION_VERSION}".encode()
        ).hexdigest()[:16]
        policy_copy = stage_metadata / "data_quality_policy.toml"
        shutil.copyfile(selected_policy_path, policy_copy)
        feature_policy_path = stage_metadata / "feature_policy.json"
        feature_policy["processing_id"] = processing_id
        feature_policy_path.write_text(
            json.dumps(feature_policy, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        run_label_mapping = [
            {"original": original, "normalized": normalized, "rows": count}
            for (original, normalized), count in sorted(label_mapping_counts.items())
        ]
        label_validation = {
            "target_column": cleaned_headers[label_position],
            "expected_values": list(expected_labels),
            "input_label_counts": before["dataset_overview"]["label_counts"],
            "original_to_normalized_mapping": run_label_mapping,
            "missing_label_rows_quarantined": rejection_counts.get("missing_label", 0),
            "unexpected_label_rows_quarantined": rejection_counts.get("invalid_label", 0),
            "output_label_counts": after_labels,
            "original_label_preserved_in": _SOURCE_LABEL_COLUMN,
            "valid_output": labels_valid,
        }
        label_validation_path = stage_metadata / "label_validation.json"
        label_validation_path.write_text(
            json.dumps(label_validation, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        run_report: dict[str, Any] = {
            "report_version": "2.0",
            "dataset_name": config.dataset.name,
            "generated_at_utc": run_timestamp,
            "processing_id": processing_id,
            "status": "completed" if verified else "failed_validation",
            "transformation_version": TRANSFORMATION_VERSION,
            "policy": policy,
            "configuration": {
                "chunk_size": selected_chunk_size,
                "sample_stride": sample_stride,
                "random_seed": config.experiment.random_seed,
                "output_format": "parquet",
                "python_version": platform.python_version(),
                "pandas_version": pd.__version__,
                "numpy_version": np.__version__,
                "pyarrow_version": pa.__version__,
            },
            "records": {
                "input": rows_input,
                "output": rows_written,
                "excluded": rows_quarantined,
                "excluded_by_reason": dict(rejection_counts),
                "label_counts_before": before["dataset_overview"]["label_counts"],
                "label_counts_after": after_labels,
                "label_mapping": run_label_mapping,
            },
            "transformations": {
                "header_mapping": source_header_map,
                "numeric_columns": feature_policy["numeric_columns"],
                "categorical_columns": feature_policy["categorical_columns"],
                "identifier_columns": feature_policy["excluded_identifier_columns"],
                "target_column": feature_policy["target_column"],
                "source_cells_changed": sum(missing_counts.values())
                + sum(positive_inf_counts.values())
                + sum(negative_inf_counts.values())
                + sum(conversion_failure_counts.values())
                + sum(
                    count
                    for (original, normalized), count in label_mapping_counts.items()
                    if original != normalized
                ),
                "missing_values_canonicalized_by_column": dict(missing_counts),
                "positive_infinities_replaced_by_column": dict(positive_inf_counts),
                "negative_infinities_replaced_by_column": dict(negative_inf_counts),
                "numeric_conversion_failures_by_column": dict(conversion_failure_counts),
                "numeric_conversion_examples": conversion_examples,
                "rows_removed_as_exact_duplicates": rows_deduplicated,
                "features_removed": 0,
                "missing_values_imputed": 0,
                "negative_values_changed": 0,
                "outliers_removed": 0,
                "provenance_columns": list(PROVENANCE_COLUMNS),
                "original_label_column": _SOURCE_LABEL_COLUMN,
                "feature_policy_path": "metadata/feature_policy.json",
                "format": "Parquet",
            },
            "duplicates": before["duplicate_analysis"],
            "validation": validation,
            "parquet_validation": parquet_validation,
            "quarantine_validation": quarantine_validation,
            "inputs": before["files"],
            "outputs": outputs,
            "quality_reports": {
                "before_json": _project_relative(before_json, config.project_root),
                "before_markdown": _project_relative(before_md, config.project_root),
                "after_json": _project_relative(after_json, config.project_root),
                "after_markdown": _project_relative(after_md, config.project_root),
            },
            "quarantine": {
                "path": _project_relative(quarantine_final, config.project_root),
                "sha256": _sha256_file(stage_quarantine),
                "rows": rows_quarantined,
                "rejection_counts": dict(rejection_counts),
            },
            "limitations": [
                "Parquet is the authoritative cleaned format; Phase 02 ingestion currently reads CSV, so downstream loading should use pandas.read_parquet or PyArrow.",
                "Negative measurements and extreme finite values are retained because the source alone does not establish a faithful correction.",
                "Exact duplicate records are preserved by default; repeated feature vectors and conflicting labels require later investigation.",
                "Destination port remains a candidate feature. Source file, row number, record ID, source label, timestamps, and direct endpoint identifiers are excluded from the candidate feature set.",
                "The CIC-IDS2017 extract lacks timestamps, source/destination IPs, protocol, a standalone source port, and Flow ID.",
                "No train/validation/test split or model evaluation was performed in this phase.",
            ],
        }
        if not verified:
            write_cleaning_report(
                run_report,
                report_directory / f"{config.dataset.name}_cleaning_report_v2",
            )
            raise ProjectError("Processed outputs failed validation; see the v2 cleaning report.")

        output_root.mkdir(parents=True, exist_ok=True)
        manifest = {
            "manifest_version": "2.0",
            "run_status": run_report["status"],
            "dataset_name": config.dataset.name,
            "processing_id": processing_id,
            "generated_at_utc": run_timestamp,
            "transformation_version": TRANSFORMATION_VERSION,
            "policy_version": policy.get("version"),
            "configuration": run_report["configuration"],
            "input_files": [
                {
                    "source_file": name,
                    "sha256": info["sha256"],
                    "size_bytes": info["size_bytes"],
                    "rows": info["rows"],
                }
                for name, info in before["files"].items()
            ],
            "output_files": outputs,
            "input_rows": rows_input,
            "output_rows": rows_written,
            "quarantined_rows": rows_quarantined,
            "raw_files_unchanged": raw_files_unchanged,
            "column_mapping": source_header_map,
            "column_mapping_by_source_file": source_header_maps_by_file,
            "feature_policy": "metadata/feature_policy.json",
            "label_validation": "metadata/label_validation.json",
            "cleaning_policy": "metadata/data_quality_policy.toml",
            "quarantine": run_report["quarantine"],
            "quality_reports": run_report["quality_reports"],
        }
        (stage_metadata / "manifest.json").write_text(
            json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
        (stage_metadata / "transformation_history.json").write_text(
            json.dumps(
                {
                    "processing_id": processing_id,
                    "generated_at_utc": run_timestamp,
                    "transformation_version": TRANSFORMATION_VERSION,
                    "policy": policy,
                    "transformations": run_report["transformations"],
                    "source_checksums": {
                        name: values["sha256"] for name, values in before["files"].items()
                    },
                    "source_column_mappings": source_header_maps_by_file,
                    "record_id": "blake2b-96(source_relative_path + NUL + input_sha256 + ':' + source_row_number)",
                    "label_used_for_record_id": False,
                },
                ensure_ascii=False,
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        final_cleaned.parent.mkdir(parents=True, exist_ok=True)
        quarantine_final.parent.mkdir(parents=True, exist_ok=True)
        os.replace(stage_cleaned, final_cleaned)
        os.replace(stage_metadata, metadata_final)
        os.replace(stage_quarantine, quarantine_final)
        run_report["artifacts"] = {
            "manifest": _project_relative(metadata_final / "manifest.json", config.project_root),
            "transformation_history": _project_relative(
                metadata_final / "transformation_history.json", config.project_root
            ),
            "feature_policy": _project_relative(metadata_final / "feature_policy.json", config.project_root),
            "label_validation": _project_relative(metadata_final / "label_validation.json", config.project_root),
            "cleaning_policy": _project_relative(metadata_final / "data_quality_policy.toml", config.project_root),
            "processed_directory": _project_relative(final_cleaned, config.project_root),
            "quarantine_file": _project_relative(quarantine_final, config.project_root),
        }
        report_json, report_md = write_cleaning_report(
            run_report,
            report_directory / f"{config.dataset.name}_cleaning_report_v2",
        )
        run_report["artifacts"]["cleaning_report_json"] = _project_relative(
            report_json, config.project_root
        )
        run_report["artifacts"]["cleaning_report_markdown"] = _project_relative(
            report_md, config.project_root
        )
        write_cleaning_report(
            run_report,
            report_directory / f"{config.dataset.name}_cleaning_report_v2",
        )
        return run_report
    finally:
        if quarantine_writer is not None:
            quarantine_writer.close()
        if duplicate_database is not None:
            duplicate_database.close()
        shutil.rmtree(stage_parent, ignore_errors=True)


def _accumulate_counts(
    chunk: dict[str, Any],
    label_mapping: Counter[tuple[str, str]],
    missing: Counter[str],
    positive_inf: Counter[str],
    negative_inf: Counter[str],
    conversion_failures: Counter[str],
    conversion_examples: dict[str, list[str]],
) -> None:
    for item in chunk["label_mapping"]:
        label_mapping[(item["original"], item["normalized"])] += item["rows"]
    for key, target in (
        ("missing_values_canonicalized", missing),
        ("positive_infinities_replaced", positive_inf),
        ("negative_infinities_replaced", negative_inf),
        ("invalid_numeric_conversions", conversion_failures),
    ):
        target.update(chunk[key])
    for name, examples in chunk["invalid_numeric_examples"].items():
        observed = conversion_examples.setdefault(name, [])
        for value in examples:
            if value not in observed and len(observed) < 5:
                observed.append(value)


def _exact_duplicate_mask(
    frame: pd.DataFrame,
    database: sqlite3.Connection,
) -> np.ndarray:
    """Return a cross-file exact-row duplicate mask using two 64-bit hashes."""
    first = pd.util.hash_pandas_object(
        frame, index=False, hash_key="0123456789abcdef"
    ).to_numpy(dtype=np.uint64)
    second = pd.util.hash_pandas_object(
        frame, index=False, hash_key="fedcba9876543210"
    ).to_numpy(dtype=np.uint64)
    digests = [f"{left:016x}{right:016x}" for left, right in zip(first, second)]
    within = pd.Series(digests).duplicated(keep="first").to_numpy()
    unique = list(dict.fromkeys(digests))
    existing: set[str] = set()
    for start in range(0, len(unique), 500):
        batch = unique[start : start + 500]
        placeholders = ",".join("?" for _ in batch)
        existing.update(
            row[0]
            for row in database.execute(
                f"SELECT digest FROM seen WHERE digest IN ({placeholders})", batch
            ).fetchall()
        )
    duplicate = within | np.fromiter((value in existing for value in digests), dtype=bool)
    new = [value for value in unique if value not in existing]
    database.executemany("INSERT OR IGNORE INTO seen(digest) VALUES (?)", ((value,) for value in new))
    return duplicate


def _append_parquet_table(
    writer: pq.ParquetWriter | None,
    frame: pd.DataFrame,
    destination: Path,
) -> pq.ParquetWriter:
    table = pa.Table.from_pandas(frame, preserve_index=False)
    if writer is None:
        writer = _open_parquet_writer(destination, frame)
    _write_table(writer, table, 100_000)
    return writer


def _open_parquet_writer(destination: Path, frame: pd.DataFrame) -> pq.ParquetWriter:
    schema = pa.Table.from_pandas(frame.iloc[:0], preserve_index=False).schema
    return pq.ParquetWriter(destination, schema, compression="zstd", use_dictionary=True)


def _write_table(
    writer: pq.ParquetWriter,
    table: pa.Table,
    row_group_size: int,
) -> None:
    if not table.schema.remove_metadata().equals(writer.schema.remove_metadata()):
        raise ProjectError("A processed chunk changed the established Parquet schema.")
    if table.num_rows:
        writer.write_table(table, row_group_size=row_group_size)


def _empty_clean_frame(
    headers: tuple[str, ...],
    label_position: int,
    categorical: tuple[str, ...],
    datetimes: tuple[str, ...],
    identifiers: tuple[str, ...],
) -> pd.DataFrame:
    source = pd.DataFrame(columns=headers)
    cleaned, _, _ = clean_source_chunk(
        source,
        cleaned_headers=headers,
        label_position=label_position,
        expected_labels=("__empty__",),
        categorical_columns=categorical,
        datetime_columns=datetimes,
        identifier_columns=identifiers,
        source_file="",
        source_row_numbers=[],
        record_ids=[],
    )
    return cleaned[[*headers, _SOURCE_LABEL_COLUMN, *PROVENANCE_COLUMNS]]


def _empty_quarantine_frame(headers: tuple[str, ...]) -> pd.DataFrame:
    frame = pd.DataFrame({name: pd.Series(dtype="string") for name in headers})
    frame[_SOURCE_LABEL_COLUMN] = pd.Series(dtype="string")
    frame["__source_file"] = pd.Series(dtype="string")
    frame["__source_row_number"] = pd.Series(dtype="int64")
    frame["__record_id"] = pd.Series(dtype="string")
    frame[_REJECTION_COLUMN] = pd.Series(dtype="string")
    return frame


def _canonicalize_quarantine(
    frame: pd.DataFrame,
    headers: tuple[str, ...],
) -> pd.DataFrame:
    """Keep quarantine rows raw while enforcing one stable Parquet schema."""
    result = frame[[*headers, _SOURCE_LABEL_COLUMN, *PROVENANCE_COLUMNS, _REJECTION_COLUMN]].copy()
    for name in [*headers, _SOURCE_LABEL_COLUMN, "__source_file", "__record_id", _REJECTION_COLUMN]:
        result[name] = result[name].astype("string")
    result["__source_row_number"] = pd.to_numeric(
        result["__source_row_number"], errors="raise"
    ).astype("int64")
    return result


def _validate_parquet_outputs(
    files: list[Path],
    *,
    expected_columns: list[str],
    chunk_size: int,
    label_column: str | None = "label",
) -> dict[str, Any]:
    rows = 0
    label_counts: Counter[str] = Counter()
    nonfinite: Counter[str] = Counter()
    reopenable = bool(files)
    for path in files:
        parquet_file = pq.ParquetFile(path)
        if parquet_file.schema_arrow.names != expected_columns:
            raise ProjectError(f"Parquet columns do not match the policy schema: {path}")
        if len(parquet_file.schema_arrow.names) != len(set(parquet_file.schema_arrow.names)):
            raise ProjectError(f"Duplicate processed column names: {path}")
        for batch in parquet_file.iter_batches(batch_size=chunk_size):
            frame = batch.to_pandas()
            rows += len(frame)
            if label_column and label_column in frame:
                label_counts.update(frame[label_column].dropna().astype(str).value_counts().to_dict())
            for name in frame.select_dtypes(include=[np.number]).columns:
                nonfinite[name] += int(np.isinf(frame[name].to_numpy(dtype=np.float64)).sum())
    return {
        "files_reopened": reopenable,
        "file_count": len(files),
        "rows": rows,
        "label_counts": dict(sorted(label_counts.items())),
        "nonfinite_counts": dict(nonfinite),
        "expected_columns": expected_columns,
        "all_columns_unique": len(expected_columns) == len(set(expected_columns)),
    }


def _build_feature_policy(
    headers: tuple[str, ...],
    *,
    label_column: str,
    identifier_columns: tuple[str, ...],
    datetime_columns: tuple[str, ...],
    categorical_columns: tuple[str, ...],
    source_header_map: list[dict[str, Any]],
) -> dict[str, Any]:
    identifiers_present = [name for name in identifier_columns if name in headers]
    timestamps_present = [name for name in datetime_columns if name in headers]
    excluded = list(dict.fromkeys([*identifiers_present, *timestamps_present]))
    candidate = [name for name in headers if name != label_column and name not in excluded]
    categorical_present = [name for name in categorical_columns if name in candidate]
    numeric = [name for name in candidate if name not in categorical_present]
    metadata = [
        *excluded,
        _SOURCE_LABEL_COLUMN,
        "__source_file",
        "__source_row_number",
        "__record_id",
    ]
    return {
        "policy_version": "1.0",
        "target_column": label_column,
        "candidate_predictive_features": candidate,
        "numeric_columns": numeric,
        "categorical_columns": categorical_present,
        "excluded_identifier_columns": excluded,
        "metadata_columns": metadata,
        "retained_candidate_network_fields": [
            name for name in ("source_port", "destination_port", "protocol")
            if name in candidate
        ],
        "source_column_mapping": source_header_map,
        "notes": [
            "The target, original source label, source file, source row, deterministic record ID, direct endpoints, and timestamp are not candidate predictive features.",
            "Ports and protocol remain candidate features when present; evaluate them with feature ablation and group-aware splits.",
            "The CIC-IDS2017 CSV export has no standalone source port, protocol, timestamp, Flow ID, source IP, or destination IP field.",
        ],
    }


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _project_relative(path: Path, project_root: Path) -> str:
    try:
        return path.resolve().relative_to(project_root.resolve()).as_posix()
    except ValueError:
        return str(path.resolve())
