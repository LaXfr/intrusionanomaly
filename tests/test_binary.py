from __future__ import annotations

import json

import numpy as np
import pandas as pd
import pytest
from intrusion_intelligence.binary import artifacts, inference
from intrusion_intelligence.binary.artifacts import load_binary_bundle
from intrusion_intelligence.binary.inference import BinaryPredictor
from intrusion_intelligence.binary.service import BinaryExperimentError, _binary_labels, _signatures
from intrusion_intelligence.feature_engineering import FeatureContract
from intrusion_intelligence.preprocessing.pipeline import LeakageSafePreprocessor


class _TestPreprocessor(LeakageSafePreprocessor):
    def __init__(self, contract: FeatureContract) -> None:
        self.contract = contract
        self.is_fitted_ = True
        self.pipeline_ = object()
        self._feature_names_out = ("value",)
        self.profile = "tree"
        self.config = {"random_seed": 7}
        self.derived_features = ()

    def transform(self, X: pd.DataFrame, *, mode: str = "inference") -> np.ndarray:
        del mode
        return X.to_numpy(dtype=np.float64)

    def preprocessing_metadata(self) -> dict:
        return {"fixture": True}


def test_binary_target_mapping_preserves_attack_classes_and_rejects_missing() -> None:
    labels = pd.Series(["BENIGN", "DDoS", "PortScan", "Bot"])
    assert _binary_labels(labels).tolist() == ["BENIGN", "ATTACK", "ATTACK", "ATTACK"]
    with pytest.raises(BinaryExperimentError, match="missing or empty"):
        _binary_labels(pd.Series(["BENIGN", pd.NA], dtype="string"))


def test_feature_vector_signatures_are_stable_and_detect_identical_rows() -> None:
    frame = pd.DataFrame({"a": [1.0, 1.0, 2.0], "b": ["x", "x", "y"]})
    signatures = _signatures(frame)
    assert len(signatures[0]) == 32
    assert signatures[0] == signatures[1]
    assert signatures[0] != signatures[2]


def test_binary_artifact_metadata_checksum_and_predictor_interface(tmp_path, monkeypatch) -> None:
    contract = FeatureContract.from_dict({
        "schema_version": "9.8.7", "dataset_name": "fixture", "target": {"name": "label", "allowed_values": ["BENIGN", "ATTACK"]},
        "features": [{"name": "value", "type": "numeric", "role": "predictive", "included": True}],
        "metadata_fields": [], "excluded_fields": [],
    })
    preprocessor = _TestPreprocessor(contract)
    class Model:
        classes_ = np.asarray([0, 1])

        def predict_proba(self, X):
            return np.column_stack([np.full(len(X), 0.25), np.full(len(X), 0.75)])

    model = Model()
    artifact = tmp_path / "artifact"
    artifact.mkdir()
    classifier_bytes, preprocessor_bytes = b"classifier fixture", b"preprocessor fixture"
    (artifact / "classifier.joblib").write_bytes(classifier_bytes)
    (artifact / "preprocessor.joblib").write_bytes(preprocessor_bytes)
    import hashlib
    metadata_path = artifact / "metadata.json"
    metadata_path.write_text(json.dumps({
        "artifact_type": "supervised_binary_classifier",
        "target_mapping": {"BENIGN": 0, "ATTACK": 1},
        "artifact_version": "9.8.7",
        "model_id": "binary-random_forest-v9.8.7",
        "decision_threshold": 0.5,
        "score_semantics": "uncalibrated fixture score",
        "feature_schema_version": contract.schema_version,
        "input_feature_names": list(contract.predictive_features),
        "artifact_sha256": {
            "classifier.joblib": hashlib.sha256(classifier_bytes).hexdigest(),
            "preprocessor.joblib": hashlib.sha256(preprocessor_bytes).hexdigest(),
        },
    }), encoding="utf-8")
    monkeypatch.setattr(artifacts.joblib, "load", lambda path: model if str(path).endswith("classifier.joblib") else preprocessor)
    loaded_model, loaded_preprocessor, metadata = load_binary_bundle(artifact)
    assert metadata["target_mapping"] == {"BENIGN": 0, "ATTACK": 1}
    assert np.array_equal(loaded_model.classes_, [0, 1])
    monkeypatch.setattr(inference, "load_binary_bundle", lambda _: (model, preprocessor, metadata))
    features = pd.DataFrame({"value": [0.0, 1.0]})
    predictions = BinaryPredictor(artifact).predict(features)
    assert len(predictions) == 2
    assert all(item["score_is_calibrated_probability"] is False for item in predictions)
    assert all(item["model_version"] == "9.8.7" for item in predictions)

    classifier_path = artifact / "classifier.joblib"
    classifier_path.write_bytes(classifier_path.read_bytes() + b"tamper")
    with pytest.raises(ValueError, match="checksum mismatch"):
        load_binary_bundle(artifact)
