from __future__ import annotations

import numpy as np
import pandas as pd
import pytest
from sklearn.linear_model import LogisticRegression
import sqlite3

from intrusion_intelligence.binary.logistic_artifacts import load_logistic_bundle, save_logistic_bundle
from intrusion_intelligence.binary.logistic_experiment import (
    LogisticExperimentError,
    _binary_metrics,
    _load_config,
    _validate_feature_boundary,
)
from intrusion_intelligence.binary.logistic_inference import LogisticPredictor
from intrusion_intelligence.binary.service import BinaryExperimentError, _binary_labels, _query_collisions, _signatures
from intrusion_intelligence.feature_engineering import FeatureContract, FeatureSchemaError
from intrusion_intelligence.preprocessing.pipeline import PreprocessingError, build_preprocessor


def contract_fixture() -> FeatureContract:
    return FeatureContract.from_dict({
        "schema_version": "1.0.0", "dataset_name": "fixture",
        "target": {"name": "label", "allowed_values": ["BENIGN", "ATTACK"]},
        "features": [{"name": "value", "type": "numeric", "role": "predictive", "included": True}],
        "metadata_fields": [], "excluded_fields": [],
    })


def test_binary_target_mapping_preserves_original_labels_and_rejects_missing():
    original = pd.Series(["BENIGN", "DDoS", "PortScan"])
    assert _binary_labels(original).tolist() == ["BENIGN", "ATTACK", "ATTACK"]
    assert original.tolist() == ["BENIGN", "DDoS", "PortScan"]
    with pytest.raises(BinaryExperimentError, match="missing or empty"):
        _binary_labels(pd.Series(["BENIGN", "  "]))


def test_feature_boundary_and_duplicate_vector_exclusion_are_explicit():
    contract = contract_fixture()
    _validate_feature_boundary(contract)
    with pytest.raises(FeatureSchemaError, match="target cannot be"):
        _validate_feature_boundary(FeatureContract.from_dict({
            "schema_version": "1", "dataset_name": "fixture",
            "target": {"name": "label"},
            "features": [{"name": "label", "type": "numeric", "role": "predictive", "included": True}],
        }))
    references = _signatures(pd.DataFrame({"value": [1.0, 2.0]}))
    candidates = _signatures(pd.DataFrame({"value": [2.0, 3.0]}))
    with sqlite3.connect(":memory:") as database:
        database.execute("CREATE TABLE signatures (signature TEXT PRIMARY KEY)")
        database.executemany("INSERT INTO signatures VALUES (?)", ((str(value),) for value in references))
        assert _query_collisions(database, candidates).tolist() == [True, False]


def test_linear_preprocessor_fits_training_only_and_rejects_target_as_feature():
    contract = contract_fixture()
    training_X = pd.DataFrame({"value": [-2.0, 2.0]})
    validation_X = pd.DataFrame({"value": [10000.0]})
    preprocessor = build_preprocessor("linear", contract=contract, feature_selection=False)
    preprocessor.fit(training_X)
    before = preprocessor.preprocessing_metadata()
    assert before["learned_scaling_statistics"]["value"]["mean"] == 0.0
    preprocessor.transform(validation_X, mode="inference")
    assert preprocessor.preprocessing_metadata() == before
    with pytest.raises(PreprocessingError, match="Target or metadata"):
        preprocessor.transform(pd.DataFrame({"value": [0.0], "label": ["ATTACK"]}), mode="inference")


def test_metric_calculations_threshold_edge_cases_and_invalid_inputs():
    y = np.asarray([0, 0, 1, 1])
    scores = np.asarray([0.1, 0.4, 0.6, 0.9])
    result = _binary_metrics(y, scores, 0.5)
    assert result["confusion_matrix"] == [[2, 0], [0, 2]]
    assert result["roc_auc"] == 1.0
    assert result["average_precision_pr_auc"] == 1.0
    assert result["attack_recall_true_positive_rate"] == 1.0
    assert _binary_metrics(y, scores, 0.7)["confusion_matrix"] == [[2, 0], [1, 1]]
    with pytest.raises(LogisticExperimentError, match="Threshold"):
        _binary_metrics(y, scores, 1.1)
    with pytest.raises(LogisticExperimentError, match="invalid labels"):
        _binary_metrics(np.asarray([0, 2, 0, 1]), scores, 0.5)
    with pytest.raises(LogisticExperimentError, match="invalid labels"):
        _binary_metrics(np.asarray([0, 256, 0, 1]), scores, 0.5)


def test_logistic_artifact_roundtrip_checksum_probability_and_reproducible_fit(tmp_path):
    contract = contract_fixture()
    X = pd.DataFrame({"value": [-2.0, -1.0, 1.0, 2.0]})
    y = np.asarray([0, 0, 1, 1])
    preprocessor = build_preprocessor("linear", contract=contract, feature_selection=False)
    preprocessor.fit(X)
    transformed = preprocessor.transform(X, mode="training")
    first = LogisticRegression(solver="lbfgs", penalty="l2", C=1.0, random_state=42).fit(transformed, y)
    second = LogisticRegression(solver="lbfgs", penalty="l2", C=1.0, random_state=42).fit(transformed, y)
    assert np.array_equal(first.coef_, second.coef_)
    bundle = save_logistic_bundle(first, preprocessor, tmp_path, version="1.0.0", metadata={})
    estimator, loaded_preprocessor, metadata = load_logistic_bundle(bundle)
    assert metadata["input_feature_names"] == ["value"]
    assert estimator.predict_proba(loaded_preprocessor.transform(X, mode="inference")).shape == (4, 2)
    predictor = LogisticPredictor(bundle)
    assert len(predictor.predict(X)) == 4
    assert all(not row["score_is_calibrated_probability"] for row in predictor.predict(X))
    with pytest.raises(FileExistsError):
        save_logistic_bundle(first, preprocessor, tmp_path, version="1.0.0", metadata={})
    classifier = bundle / "classifier.joblib"
    classifier.write_bytes(classifier.read_bytes() + b"tamper")
    with pytest.raises(ValueError, match="size mismatch|checksum mismatch"):
        load_logistic_bundle(bundle)


def test_logistic_configuration_keeps_established_protocol():
    config = _load_config(__import__("pathlib").Path("configs/binary_logistic.toml"))
    assert config["split"]["train"] == ["Monday", "Tuesday", "Wednesday"]
    assert config["split"]["validation"] == ["Thursday"]
    assert config["split"]["test"] == ["Friday"]
    assert config["training"]["decision_threshold"] == 0.5
    assert config["training"]["solver"] == "lbfgs"
