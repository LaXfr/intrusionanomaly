"""Synthetic regression tests for the Phase 11 evaluation utilities."""

from __future__ import annotations

import numpy as np
import pandas as pd
import pytest
from types import SimpleNamespace
from sklearn.dummy import DummyClassifier

from intrusion_intelligence.evaluation.ablation import build_ablation_plan, run_ablation_experiment
from intrusion_intelligence.evaluation.audit import classify_evidence, duplicate_group_summary, partition_integrity, prediction_schema_audit
from intrusion_intelligence.evaluation.benchmark import artifact_size_bytes
from intrusion_intelligence.evaluation.metrics import anomaly_metrics, binary_calibration, binary_metrics, multiclass_metrics, threshold_metrics
from intrusion_intelligence.evaluation.robustness import run_input_stress
from intrusion_intelligence.evaluation.uncertainty import cluster_bootstrap_interval, wilson_interval
from intrusion_intelligence.feature_engineering import FeatureContract, FeatureSpec


def test_binary_metrics_and_threshold_sensitivity_cover_positive_attack_class() -> None:
    result = binary_metrics([0, 0, 1, 1], [0.1, 0.8, 0.7, 0.9], threshold=0.5)
    assert result["positive_label"] == "1"
    assert result["confusion_matrix"] == [[1, 1], [0, 2]]
    assert result["precision"] == pytest.approx(2 / 3)
    assert result["recall"] == 1.0
    assert result["specificity"] == 0.5
    assert result["false_positive_rate"] == 0.5
    assert result["roc_auc"] == pytest.approx(0.75)
    assert result["average_precision"] == pytest.approx(5 / 6)
    rows = threshold_metrics([0, 1], [0.4, 0.6], [0.3, 0.7])
    assert [row["recall"] for row in rows] == [1.0, 0.0]


def test_binary_metrics_reject_invalid_scores_and_calibration_reports_reliability() -> None:
    with pytest.raises(ValueError):
        binary_metrics([0, 1], [0.2, np.inf], threshold=0.5)
    result = binary_calibration([0, 0, 1, 1], [0.1, 0.4, 0.6, 0.9], bins=4)
    assert result["brier_score"] == pytest.approx(0.085)
    assert result["calibrator_fitted"] is False
    assert sum(row["observations"] for row in result["reliability_bins"]) == 4


def test_multiclass_metrics_respect_explicit_class_id_order_and_rare_support() -> None:
    result = multiclass_metrics([7, 3, 3], [7, 7, 3], class_ids=[3, 7], class_names=["rare", "common"])
    assert result["confusion_matrix"] == [[1, 1], [0, 1]]
    assert result["per_class"][0]["class_name"] == "rare"
    assert result["per_class"][0]["support"] == 2
    with pytest.raises(ValueError, match="outside"):
        multiclass_metrics([9], [9], class_ids=[3, 7], class_names=["rare", "common"])


def test_anomaly_metrics_higher_score_is_anomalous_and_boundary_is_explicit() -> None:
    result = anomaly_metrics([0, 0, 1, 1], [0.1, 0.5, 0.5, 0.8], threshold=0.5, comparison=">")
    assert result["anomaly_score_orientation"] == "higher_is_more_anomalous"
    assert result["threshold_comparison"] == ">"
    assert result["confusion_matrix"] == [[2, 0], [1, 1]]
    inclusive = anomaly_metrics([0, 1], [0.5, 0.5], threshold=0.5, comparison=">=")
    assert inclusive["confusion_matrix"] == [[0, 1], [0, 1]]
    with pytest.raises(ValueError, match="finite"):
        anomaly_metrics([0, 1], [0.1, np.nan], threshold=0.5)


def test_split_audit_and_evidence_governance_detect_overlap_and_reuse() -> None:
    report = partition_integrity({"train": [1, 2], "test": [2, 3]}, {"train": ["Monday"], "test": ["Monday"]})
    assert report["pairwise_row_overlap_counts"]["train:test"] == 1
    assert report["groups_disjoint"] is False
    assert classify_evidence(partition="test", used_for_selection=False, results_inspected=False) == "fresh_held_out_evaluation"
    assert classify_evidence(partition="test", used_for_selection=True, results_inspected=True) == "previously_inspected_test_evaluation"
    summary = duplicate_group_summary(100, 5, 2, 8, 1)
    assert summary["conflicting_label_groups"] == 1


def test_prediction_schema_audit_catches_target_and_metadata_leakage() -> None:
    frame = pd.DataFrame({"flow_duration": [1], "Label": ["ATTACK"], "source_filename": ["capture.parquet"]})
    result = prediction_schema_audit(frame, feature_names=["flow_duration"], target_name="Label", forbidden_names=["source_filename"])
    assert result["passed"] is False
    assert result["forbidden_columns_in_prediction_matrix"] == ["Label", "source_filename"]


def test_group_bootstrap_refuses_too_few_groups_and_wilson_is_bounded() -> None:
    result = cluster_bootstrap_interval([1, 0], ["a", "b"], lambda values: float(np.mean(values)), minimum_groups=8)
    assert result["status"] == "not_reliable_insufficient_groups"
    assert result["interval"] is None
    lower, upper = wilson_interval(5, 10)
    assert 0 <= lower < 0.5 < upper <= 1
    assert wilson_interval(0, 0) is None


def test_ablation_refits_temporary_estimator_on_consistent_training_columns() -> None:
    train = pd.DataFrame({"a": [0, 1, 0, 1], "b": [1, 1, 0, 0]})
    evaluation = pd.DataFrame({"a": [0, 1], "b": [1, 0]})
    output = run_ablation_experiment(train, [0, 1, 0, 1], evaluation, [0, 1],
        variants={"full": [], "drop_b": ["b"]},
        estimator_factory=lambda _name, _features: DummyClassifier(strategy="most_frequent"),
        metric_function=lambda truth, pred: {"accuracy": float(np.mean(np.asarray(truth) == pred))},
        target_name="Label")
    assert [row["feature_count"] for row in output] == [2, 1]
    assert all(row["production_artifact_written"] is False for row in output)
    assert build_ablation_plan(["a", "destination_port"], {"ports": ["destination_port"]})[1]["status"] == "planned"
    with pytest.raises(ValueError, match="target"):
        run_ablation_experiment(train.assign(Label=[0, 1, 0, 1]), [0, 1, 0, 1], evaluation.assign(Label=[0, 1]), [0, 1],
            variants={"full": []}, estimator_factory=lambda *_: DummyClassifier(), metric_function=lambda *_: {}, target_name="Label")


def test_robustness_contract_rejects_missing_required_and_infinite_values() -> None:
    contract = FeatureContract("1.0", "synthetic", "Label", (),
        (FeatureSpec("x", "numeric"), FeatureSpec("y", "numeric")), (), ())
    assert list(contract.predictive_features) == ["x", "y"]
    class FakeModel:
        model_id = "synthetic"
        family = "binary_logistic_regression"
        outputs = (SimpleNamespace(semantic="synthetic score"),)

        def transform(self, values):
            if list(values.columns) != ["x", "y"]:
                raise ValueError("missing required column")
            if np.isinf(values.to_numpy(dtype=float)).any():
                raise ValueError("infinite values rejected")
            return values.fillna(0.0)

        def output_values(self, values, _output):
            return values.sum(axis=1).to_numpy()

    frame = pd.DataFrame({"x": [1.0, 2.0], "y": [2.0, 3.0]})
    report = run_input_stress(FakeModel(), frame, contract)
    assert report["required_column"]["status"] == "rejected_as_expected"
    assert report["infinite_numeric"]["status"] == "rejected_as_expected"
    assert next(item for item in report["results"] if item["case"] == "numeric_missing_value")["status"] == "accepted"


def test_artifact_size_returns_file_size(tmp_path) -> None:
    artifact = tmp_path / "model.bin"
    artifact.write_bytes(b"abc")
    assert artifact_size_bytes(artifact) == 3
