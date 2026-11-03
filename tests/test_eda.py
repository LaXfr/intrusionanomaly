"""Synthetic-only tests for the reusable EDA utilities."""

from __future__ import annotations

import csv
import json
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from intrusion_intelligence.config import load_config
from intrusion_intelligence.eda import (
    analyze_dataset,
    correlation_summary,
    duplicate_summary,
    label_distribution,
    missing_value_summary,
    numeric_feature_summary,
    run_eda,
)
from intrusion_intelligence.errors import EDAAnalysisError


def test_label_distribution_preserves_original_categories() -> None:
    labels = pd.Series(["BENIGN", "BENIGN", "Attack A", "Attack B"])

    summary = label_distribution(labels)

    assert summary["counts"] == {"BENIGN": 2, "Attack A": 1, "Attack B": 1}
    assert summary["benign_malicious"]["BENIGN"] == 2
    assert summary["benign_malicious"]["MALICIOUS"] == 2
    assert summary["percentages"]["Attack A"] == 25.0
    assert label_distribution(pd.Series(dtype="object"))["total_rows"] == 0
    single_class = label_distribution(pd.Series(["BENIGN", "BENIGN"]))
    assert single_class["benign_malicious"]["malicious_percent"] == 0.0


def test_missing_summary_counts_empty_and_textual_na_without_mutating() -> None:
    frame = pd.DataFrame(
        {"number": ["1", "", "NaN"], "label": ["BENIGN", "Attack", "N/A"]}
    )
    original = frame.copy(deep=True)

    summary = missing_value_summary(frame)

    assert summary["rows_with_missing"] == 2
    assert summary["by_column"]["number"]["count"] == 2
    assert summary["by_column"]["label"]["count"] == 1
    pd.testing.assert_frame_equal(frame, original)
    empty_summary = missing_value_summary(pd.DataFrame({"feature": pd.Series(dtype=str)}))
    assert empty_summary["rows_with_missing"] == 0


def test_numeric_summary_excludes_nan_and_infinity_from_statistics() -> None:
    frame = pd.DataFrame({"flow": ["1", "3", "Infinity", "-Infinity", "NaN"]})

    summary = numeric_feature_summary(frame)["flow"]

    assert summary["count"] == 2
    assert summary["mean"] == 2.0
    assert summary["min"] == 1.0
    assert summary["max"] == 3.0
    assert numeric_feature_summary(pd.DataFrame({"text": ["a", "b"]})) == {}


def test_correlations_mask_infinity_and_find_strong_pairs() -> None:
    frame = pd.DataFrame(
        {"x": [1, 2, 3, 4, np.inf], "y": [2, 4, 6, 8, 10], "text": list("abcde")}
    )

    summary = correlation_summary(frame, columns=("x", "y", "text"))

    assert summary["pearson_pairs"][0]["feature_a"] == "x"
    assert summary["pearson_pairs"][0]["feature_b"] == "y"
    assert summary["pearson_pairs"][0]["correlation"] == pytest.approx(1.0)
    assert np.isfinite(summary["pearson_matrix"].loc["x", "y"])


def test_duplicate_summary_finds_exact_and_conflicting_label_groups() -> None:
    frame = pd.DataFrame(
        {
            "feature": [1, 1, 1],
            "Label": ["BENIGN", "BENIGN", "Attack"],
            "_eda_source_file": ["a.csv", "b.csv", "b.csv"],
        }
    )

    summary = duplicate_summary(frame, label_column="Label")

    assert summary["duplicate_rows"] == 1
    assert summary["duplicate_feature_rows"] == 3
    assert summary["conflicting_label_groups"] == 1
    assert summary["cross_file_duplicate_groups"] == 1
    with pytest.raises(ValueError, match="Label column"):
        duplicate_summary(frame, label_column="missing")


def test_chunked_analysis_and_report_generation_use_synthetic_csvs(
    tmp_path: Path,
) -> None:
    raw_root = tmp_path / "raw"
    dataset = raw_root / "CIC-IDS2017"
    dataset.mkdir(parents=True)
    headers = [
        "Destination Port",
        "Flow Duration",
        "Flow Bytes/s",
        "Constant Feature",
        "Near Constant",
        "Label",
    ]
    rows = []
    for index in range(100):
        label = "Attack" if index == 99 else "BENIGN"
        rate = "Infinity" if index == 0 else ("" if index == 1 else str(index * 2))
        rows.append(
            [
                str(80 if index % 2 else 443),
                str(index),
                rate,
                "7",
                "2" if index == 99 else "1",
                label,
            ]
        )
    rows[4] = ["80", "4", "8", "7", "1", "BENIGN"]
    rows[5] = ["80", "4", "8", "7", "1", "Attack"]

    for filename, selected in (("first.csv", rows[:60]), ("second.csv", rows[60:])):
        with (dataset / filename).open("w", encoding="utf-8", newline="") as stream:
            writer = csv.writer(stream)
            writer.writerow(headers)
            writer.writerows(selected)

    config = load_config(
        environ={
            "NII_RAW_DATA_DIR": str(raw_root),
            "NII_DATASET_DIRECTORY": "CIC-IDS2017",
            "NII_DATASET_NAME": "SYNTHETIC-EDA-TEST",
            "NII_EDA_REPORT_DIR": str(tmp_path / "reports" / "eda"),
            "NII_REPORT_FIGURES_DIR": str(tmp_path / "reports" / "figures"),
        }
    )
    result, outputs = run_eda(
        config,
        chunk_size=17,
        sample_size=100,
        max_per_label=100,
        seed=19,
    )
    summary = result.summary

    assert summary["dataset_overview"]["rows_full"] == 100
    assert summary["dataset_overview"]["files_count"] == 2
    assert summary["dataset_overview"]["numeric_columns_count"] == 5
    assert summary["label_distribution"]["counts"] == {"BENIGN": 98, "Attack": 2}
    assert summary["data_quality"]["missing_cells_full"] == 1
    assert summary["data_quality"]["infinite_value_count_full"] == 1
    assert summary["network_fields"]["destination_port"]["coverage"] == "complete"
    assert summary["feature_quality"]["constant_features_exact_full"] == [
        "Constant Feature"
    ]
    near_constant = next(
        item
        for item in summary["feature_quality"]["potentially_uninformative_or_high_cardinality_sample"]
        if item["column"] == "Near Constant"
    )
    assert near_constant["sample_dominant_value_percent"] == 99.0
    assert summary["duplicate_analysis"]["conflicting_label_groups"] == 1
    assert summary["label_distribution"]["class_imbalance"]["per_label_file_support"][
        "Attack"
    ]["files_present"] == 2
    assert summary["analysis_method"]["sample_seed"] == 19
    assert outputs.json_report.is_file()
    assert outputs.markdown_report.is_file()
    assert len(outputs.figures) >= 9
    saved = json.loads(outputs.json_report.read_text(encoding="utf-8"))
    assert saved["analysis_method"]["full_scan"] is True
    assert saved["dataset_name"] == "SYNTHETIC-EDA-TEST"
    assert (tmp_path / "reports" / "figures" / "eda" / "correlation_heatmap.png").is_file()


def test_analysis_rejects_non_positive_sample_size(tmp_path: Path) -> None:
    config = load_config(
        environ={
            "NII_RAW_DATA_DIR": str(tmp_path / "raw"),
            "NII_DATASET_DIRECTORY": "CIC-IDS2017",
        }
    )

    with pytest.raises(EDAAnalysisError, match="sample size"):
        analyze_dataset(config, sample_size=0)


def test_analysis_rejects_missing_dataset_directory(tmp_path: Path) -> None:
    config = load_config(
        environ={
            "NII_RAW_DATA_DIR": str(tmp_path / "raw"),
            "NII_DATASET_DIRECTORY": "missing-dataset",
        }
    )

    with pytest.raises(EDAAnalysisError, match="valid compatible dataset"):
        analyze_dataset(config, sample_size=1)
