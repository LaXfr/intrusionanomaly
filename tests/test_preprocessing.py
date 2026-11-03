"""Synthetic-only tests for auditable Phase 04 data cleaning."""

from __future__ import annotations

import csv
import hashlib
import json
from pathlib import Path

import pandas as pd
import pytest

from intrusion_intelligence.config import load_config
from intrusion_intelligence.errors import ProjectError
from intrusion_intelligence.ingestion import iter_dataset_chunks, load_dataset
from intrusion_intelligence.preprocessing.assessment import assess_dataset
from intrusion_intelligence.preprocessing.cleaning import standardize_source_headers
from intrusion_intelligence.preprocessing.policy import load_policy, validate_policy
from intrusion_intelligence.preprocessing.service import (
    _build_feature_policy,
    clean_dataset,
)
from intrusion_intelligence.preprocessing.cli import main

POLICY = Path(__file__).parents[1] / "configs" / "data_quality_policy.toml"


def _write_csv(path: Path, headers: list[str], rows: list[list[str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.writer(stream)
        writer.writerow(headers)
        writer.writerows(rows)


def _config(tmp_path: Path, dataset: Path):
    raw_root = tmp_path / "raw"
    raw_root.mkdir(exist_ok=True)
    dataset_directory = dataset.relative_to(raw_root).as_posix()
    return load_config(
        environ={
            "NII_RAW_DATA_DIR": str(raw_root),
            "NII_INTERIM_DATA_DIR": str(tmp_path / "interim"),
            "NII_DATASET_DIRECTORY": dataset_directory,
            "NII_DATASET_NAME": "SYNTHETIC-PHASE04",
            "NII_EDA_REPORT_DIR": str(tmp_path / "reports" / "eda"),
            "NII_REPORT_FIGURES_DIR": str(tmp_path / "reports" / "figures"),
            "NII_PROCESSED_DATA_DIR": str(tmp_path / "processed"),
            "NII_CHUNK_SIZE": "2",
        }
    )


def _fixture_dataset(tmp_path: Path) -> Path:
    root = tmp_path / "raw" / "CIC-IDS2017"
    headers = [
        "Flow Duration",
        "Flow Bytes/s",
        "Value",
        "Value",
        " Value",
        "Constant",
        " Label",
    ]
    rows = [
        ["0", "Infinity", "1", "1", "10", "7", "BENIGN"],
        ["0", "Infinity", "1", "1", "10", "7", "BENIGN"],
        ["0", "Infinity", "1", "1", "10", "7", "DoS Hulk"],
        ["-1", "NaN", "", "NULL", "5", "7", "BENIGN"],
        ["1", "not-numeric", "3", "4", "7", "7", " BENIGN "],
        ["2", "2", "8", "9", "9", "7", "UNKNOWN"],
        ["3", "3", "9", "9", "11", "7", "   "],
    ]
    _write_csv(root / "first.csv", headers, rows)
    _write_csv(
        root / "second.csv",
        headers,
        [rows[0], ["2", "2.0", "6", "7", "8", "7", "BENIGN"]],
    )
    return root


def test_assessment_covers_missing_infinite_negative_and_mixed_tokens(tmp_path: Path) -> None:
    root = _fixture_dataset(tmp_path)
    config = _config(tmp_path, root)

    report = assess_dataset(config, chunk_size=2, sample_stride=1)

    assert report["coverage"] == "complete"
    assert report["dataset_overview"]["rows"] == 9
    assert report["dataset_overview"]["label_counts"] == {
        " BENIGN ": 1,
        "   ": 1,
        "BENIGN": 5,
        "DoS Hulk": 1,
        "UNKNOWN": 1,
    }
    assert report["schema"]["files_have_identical_headers"] is True
    assert report["schema"]["duplicate_source_headers"][0]["positions"] == [3, 4]
    assert report["schema"]["whitespace_collisions"][0]["positions"] == [3, 4, 5]
    rate = next(value for value in report["features"].values() if value["source_header"] == "Flow Bytes/s")
    assert rate["counts"]["positive_infinity"] == 4
    assert any(
        item["classification"] == "confirmed_invalid_nonfinite_measurement"
        for item in rate["finding_classifications"]
    )
    assert rate["counts"]["nan_token"] == 1
    assert rate["counts"]["invalid_numeric"] == 1
    assert rate["infinity_with_zero_flow_duration"] == 4
    duration = next(value for value in report["features"].values() if value["source_header"] == "Flow Duration")
    assert duration["counts"]["negative"] == 1
    assert duration["negative_minimum"] == -1.0
    assert duration["finding_class"] == "potentially_invalid_preserved"
    first_value = next(
        value
        for value in report["features"].values()
        if value["source_position"] == 3
    )
    assert first_value["counts"]["empty_string"] == 1
    duplicate = report["duplicate_analysis"]
    assert duplicate["exact_complete_row_duplicates"]["duplicate_excess_rows"] >= 1
    assert duplicate["feature_vector_duplicates"]["groups_with_different_labels"] >= 1
    assert duplicate["records_removed"] == 0
    assert report["outlier_diagnostics"]["sample_rows"] == 9
    assert "Constant" in report["quality_summary"]["constant_features"]
    assert "Constant" in report["quality_summary"]["near_constant_features_sample"]
    assert report["features"]["Flow Bytes/s"]["counts"]["invalid_numeric"] == 1
    assert "by_source_file_sample" in rate["sample"]
    assert "by_label_sample" in rate["sample"]


def test_assessment_is_deterministic_for_same_source_and_settings(tmp_path: Path) -> None:
    root = _fixture_dataset(tmp_path)
    config = _config(tmp_path, root)

    first = assess_dataset(config, chunk_size=2, sample_stride=1)
    second = assess_dataset(config, chunk_size=3, sample_stride=1)

    assert first["dataset_overview"]["label_counts"] == second["dataset_overview"]["label_counts"]
    assert first["duplicate_analysis"] == second["duplicate_analysis"]
    assert {
        key: value["row_content_fingerprint_sha256"]
        for key, value in first["files"].items()
    } == {
        key: value["row_content_fingerprint_sha256"]
        for key, value in second["files"].items()
    }


def test_policy_rejects_unsupported_imputation_or_row_removal() -> None:
    policy = load_policy(POLICY)
    policy["missing"]["action"] = "replace_with_zero"
    with pytest.raises(ProjectError, match="Unsupported cleaning rule"):
        validate_policy(policy)


def test_schema_normalization_suffixes_every_collision_by_source_position() -> None:
    names, mapping = standardize_source_headers(
        [" Flow Duration", "Flow Duration", "Flow  Duration", "Label"]
    )

    assert names == (
        "flow_duration__source_col_1",
        "flow_duration__source_col_2",
        "flow_duration__source_col_3",
        "label",
    )
    assert len(names) == len(set(names))
    assert mapping[0]["source_header"] == " Flow Duration"


def test_clean_dry_run_writes_no_processed_files(tmp_path: Path) -> None:
    root = _fixture_dataset(tmp_path)
    config = _config(tmp_path, root)
    output = tmp_path / "processed" / "dry-run"
    raw_checksums = {
        path.name: hashlib.sha256(path.read_bytes()).hexdigest()
        for path in root.glob("*.csv")
    }

    result = clean_dataset(
        config,
        output_directory=output,
        policy_path=POLICY,
        dry_run=True,
    )

    assert result["status"] == "dry_run"
    assert result["cleaning_completed"] is False
    assert result["processed_outputs_written"] is False
    assert not output.exists()
    assert raw_checksums == {
        path.name: hashlib.sha256(path.read_bytes()).hexdigest()
        for path in root.glob("*.csv")
    }


def test_clean_outputs_normalize_values_and_quarantine_bad_labels(tmp_path: Path) -> None:
    root = _fixture_dataset(tmp_path)
    config = _config(tmp_path, root)
    output_root = tmp_path / "processed" / "actual"
    original_checksums = {
        path.name: hashlib.sha256(path.read_bytes()).hexdigest()
        for path in root.glob("*.csv")
    }

    report = clean_dataset(
        config,
        chunk_size=2,
        sample_stride=1,
        output_directory=output_root,
        policy_path=POLICY,
    )

    assert report["status"] == "completed"
    assert report["records"]["input"] == 9
    assert report["records"]["output"] == 7
    assert report["records"]["excluded"] == 2
    assert report["records"]["excluded_by_reason"] == {
        "invalid_label": 1,
        "missing_label": 1,
    }
    assert report["validation"]["raw_files_unchanged"] is True
    assert report["validation"]["infinities_absent_from_cleaned_features"] is True
    assert report["validation"]["labels_valid_and_nonempty"] is True
    assert report["transformations"]["positive_infinities_replaced_by_column"]["flow_bytes_s"] == 4
    assert report["transformations"]["numeric_conversion_failures_by_column"]["flow_bytes_s"] == 1
    assert original_checksums == {
        path.name: hashlib.sha256(path.read_bytes()).hexdigest()
        for path in root.glob("*.csv")
    }
    cleaned = output_root / "cleaned"
    loaded = pd.read_parquet(cleaned)
    assert len(loaded) == 7
    assert set(loaded["__source_file"]) == {"first.csv", "second.csv"}
    assert loaded["label"].tolist().count("DoS Hulk") == 1
    assert " BENIGN " in set(loaded["__source_label"])
    assert loaded["__record_id"].is_unique
    assert loaded["flow_bytes_s"].isna().sum() == 6
    assert not any(name in loaded.columns for name in ("value", " Value"))
    quarantine = pd.read_parquet(report["quarantine"]["path"])
    assert len(quarantine) == 2
    assert set(quarantine["__rejection_reason"]) == {"invalid_label", "missing_label"}
    manifest = json.loads((output_root / "metadata" / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["output_rows"] == 7
    assert manifest["quarantined_rows"] == 2
    assert len(manifest["output_files"]) == 2
    assert all(item["sha256"] for item in manifest["output_files"])
    after_report = json.loads(
        Path(report["quality_reports"]["after_json"]).read_text(encoding="utf-8")
    )
    assert after_report["dataset_overview"]["rows"] == 7
    assert after_report["features"]["flow_bytes_s"]["counts"]["positive_infinity"] == 0
    assert Path(report["quality_reports"]["after_markdown"]).is_file()
    assert Path(report["artifacts"]["cleaning_report_markdown"]).is_file()


def test_clean_aligns_files_with_same_columns_in_different_orders(tmp_path: Path) -> None:
    root = tmp_path / "raw" / "CIC-IDS2017"
    _write_csv(root / "first.csv", ["Flow Duration", "Destination Port", "Label"], [["1", "80", "BENIGN"]])
    _write_csv(root / "second.csv", ["Label", "Destination Port", "Flow Duration"], [["BENIGN", "443", "2"]])
    config = _config(tmp_path, root)
    output_root = tmp_path / "processed" / "ordered"

    report = clean_dataset(
        config,
        chunk_size=1,
        sample_stride=1,
        output_directory=output_root,
        policy_path=POLICY,
    )

    second_path = next((output_root / "cleaned").rglob("second.parquet"))
    second = pd.read_parquet(second_path)
    manifest = json.loads((output_root / "metadata" / "manifest.json").read_text(encoding="utf-8"))
    assert report["records"]["output"] == 2
    assert second.loc[0, "label"] == "BENIGN"
    assert second.loc[0, "flow_duration"] == 2.0
    assert second.loc[0, "destination_port"] == 443.0
    second_mapping = manifest["column_mapping_by_source_file"]["second.csv"]
    assert next(item for item in second_mapping if item["cleaned_header"] == "flow_duration")["source_position"] == 3


def test_clean_rejects_missing_columns_before_publishing_processed_data(tmp_path: Path) -> None:
    root = _fixture_dataset(tmp_path)
    _write_csv(
        root / "second.csv",
        ["Flow Duration", "Flow Bytes/s", "Value", "Value", " Value", " Label"],
        [["1", "2", "3", "4", "5", "BENIGN"]],
    )
    config = _config(tmp_path, root)
    output_root = tmp_path / "processed" / "incompatible"

    with pytest.raises(ProjectError, match="Missing columns.*Constant"):
        clean_dataset(
            config,
            chunk_size=2,
            sample_stride=1,
            output_directory=output_root,
            policy_path=POLICY,
        )

    assert not (output_root / "cleaned").exists()


def test_exact_duplicate_exclusion_is_configurable_and_traceable(tmp_path: Path) -> None:
    root = _fixture_dataset(tmp_path)
    config = _config(tmp_path, root)
    policy_path = tmp_path / "drop_duplicates.toml"
    policy_text = POLICY.read_text(encoding="utf-8").replace(
        "[duplicates]\naction = \"preserve\"",
        "[duplicates]\naction = \"drop_exact_duplicates\"",
    )
    policy_path.write_text(policy_text, encoding="utf-8")

    report = clean_dataset(
        config,
        chunk_size=2,
        sample_stride=1,
        output_directory=tmp_path / "processed" / "drop-duplicates",
        policy_path=policy_path,
    )

    assert report["records"]["input"] == 9
    assert report["records"]["output"] == 5
    assert report["records"]["excluded_by_reason"]["exact_duplicate"] == 2
    assert report["validation"]["excluded_rows_accounted_for"] is True
    quarantine = pd.read_parquet(report["quarantine"]["path"])
    assert int((quarantine["__rejection_reason"] == "exact_duplicate").sum()) == 2


def test_feature_policy_excludes_target_identifiers_and_provenance_but_keeps_ports() -> None:
    headers = (
        "flow_id",
        "source_ip",
        "destination_port",
        "protocol",
        "timestamp",
        "flow_duration",
        "label",
    )
    mapping = [{"source_position": index, "cleaned_header": name} for index, name in enumerate(headers, 1)]

    policy = _build_feature_policy(
        headers,
        label_column="label",
        identifier_columns=("flow_id", "source_ip", "destination_ip"),
        datetime_columns=("timestamp",),
        categorical_columns=("protocol",),
        source_header_map=mapping,
    )

    assert policy["target_column"] == "label"
    assert policy["candidate_predictive_features"] == [
        "destination_port",
        "protocol",
        "flow_duration",
    ]
    assert {"flow_id", "source_ip", "timestamp"}.issubset(
        policy["excluded_identifier_columns"]
    )
    assert "label" not in policy["candidate_predictive_features"]
    assert "__record_id" in policy["metadata_columns"]


def test_clean_empty_dataset_fails_without_creating_processed_outputs(tmp_path: Path) -> None:
    raw_root = tmp_path / "raw"
    dataset = raw_root / "CIC-IDS2017"
    dataset.mkdir(parents=True)
    config = _config(tmp_path, dataset)
    output = tmp_path / "processed" / "empty"

    with pytest.raises(ProjectError, match="No supported CSV files"):
        clean_dataset(config, output_directory=output, policy_path=POLICY)

    assert not output.exists()


def test_output_collision_is_not_overwritten(tmp_path: Path) -> None:
    root = _fixture_dataset(tmp_path)
    config = _config(tmp_path, root)
    output_root = tmp_path / "processed" / "existing"
    (output_root / "cleaned").mkdir(parents=True)

    with pytest.raises(ProjectError, match="will not be overwritten"):
        clean_dataset(
            config,
            output_directory=output_root,
            policy_path=POLICY,
        )


def test_policy_cli_reports_valid_policy(capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = main(["policy", "validate", "--path", str(POLICY)])

    assert exit_code == 0
    output = capsys.readouterr().out
    assert "Cleaning policy valid" in output
    assert "\\ufffd" in output
