from __future__ import annotations

import json

import numpy as np
import pandas as pd
import pytest
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
import pyarrow as pa
import pyarrow.parquet as pq

from intrusion_intelligence.explainability.background_data import load_training_background
from intrusion_intelligence.explainability.alert_enrichment import enrich_phase09_records
from intrusion_intelligence.explainability.explainers import build_shap_session, normalize_shap_values
from intrusion_intelligence.explainability.feature_mapping import aggregate_contributions, aggregate_global_importance, map_transformed_features
from intrusion_intelligence.explainability.model_registry import ExplainableModel
from intrusion_intelligence.explainability.schemas import ExplainabilityError, ExplanationOutput, ExplanationRecord
from intrusion_intelligence.feature_engineering import FeatureContract


def _model(family, estimator, columns):
    names = tuple(columns)
    return ExplainableModel(
        key=family, family=family, explainer_type="tree" if family.endswith("random_forest") else "linear" if family.endswith("logistic_regression") else "permutation",
        output_space="test output", artifact_directory=__import__("pathlib").Path("."), estimator=estimator,
        preprocessor=None, metadata={"model_id": family, "artifact_version": "test", "output_feature_names": list(names)},
        outputs=(ExplanationOutput("positive", 1 if family.endswith("random_forest") else 0, "positive-class score"),),
    )


def test_normalize_legacy_and_modern_multiclass_shap_shapes():
    samples, features, outputs = 3, 4, 2
    source = np.arange(samples * features * outputs).reshape(samples, features, outputs)
    np.testing.assert_array_equal(normalize_shap_values(source, samples, features, 1, output_count=outputs), source[:, :, 1])
    np.testing.assert_array_equal(normalize_shap_values(source.transpose(2, 0, 1), samples, features, 1, output_count=outputs), source[:, :, 1])
    np.testing.assert_array_equal(normalize_shap_values([source[:, :, i] for i in range(outputs)], samples, features, 1, output_count=outputs), source[:, :, 1])
    with pytest.raises(ExplainabilityError):
        normalize_shap_values(np.zeros((2, 2)), samples, features, 0, output_count=outputs)


def test_feature_mapping_preserves_signed_local_values_and_groups_one_hot():
    names = ["numeric__Flow Bytes/s", "categorical__protocol_TCP", "derived_unknown"]
    mapping = map_transformed_features(names, ["Flow Bytes/s", "protocol"], explicit_sources={"derived_unknown": "protocol"})
    assert mapping == {names[0]: "Flow Bytes/s", names[1]: "protocol", names[2]: "protocol"}
    local = aggregate_contributions(np.array([0.3, -0.1, 0.4]), names, mapping)
    assert local[0] == {"feature": "protocol", "contribution": pytest.approx(0.3)}
    assert local[1] == {"feature": "Flow Bytes/s", "contribution": pytest.approx(0.3)}
    global_rows = aggregate_global_importance(np.array([[0.3, -0.1, 0.4], [0.3, 0.1, 0.4]]), names, mapping)
    assert global_rows[0]["feature"] == "protocol"
    assert global_rows[0]["mean_absolute_shap"] == pytest.approx(0.5)
    assert map_transformed_features(["mystery"], ["Flow Bytes/s"]) == {"mystery": None}


def test_shap_sessions_validate_fitted_synthetic_classifiers_and_anomaly_direction():
    import shap

    rng = np.random.default_rng(5)
    data = rng.normal(size=(80, 4))
    y = (data[:, 0] + data[:, 1] > 0).astype(int)
    frame = pd.DataFrame(data, columns=[f"f{i}" for i in range(4)])
    background = frame.iloc[:12]
    sample = frame.iloc[12:15]
    for family, estimator in (
        ("binary_random_forest", RandomForestClassifier(n_estimators=8, max_depth=3, random_state=2).fit(data, y)),
        ("binary_logistic_regression", LogisticRegression(random_state=2).fit(data, y)),
    ):
        model = _model(family, estimator, frame.columns)
        session = build_shap_session(model, background)
        output = ExplanationOutput("positive", 1 if family.endswith("random_forest") else 0, "positive-class score")
        values, bases, predictions, diagnostic = session.explain(sample, output)
        assert values.shape == (3, 4)
        assert np.isfinite(values).all() and diagnostic["passed"]
        np.testing.assert_allclose(bases + values.sum(axis=1), predictions, atol=2e-3)

    anomaly = IsolationForest(n_estimators=10, random_state=2).fit(data)
    anomaly_model = _model("anomaly", anomaly, frame.columns)
    session = build_shap_session(anomaly_model, background, random_seed=9)
    values, bases, scores, diagnostic = session.explain(sample, anomaly_model.outputs[0], max_evaluations=9)
    assert np.allclose(scores, -anomaly.score_samples(sample.to_numpy()))
    assert diagnostic["passed"]
    np.testing.assert_allclose(bases + values.sum(axis=1), scores, atol=1e-4)


def test_explanation_record_json_and_alert_sidecar_invariants():
    record = ExplanationRecord(
        explanation_id="x", model_id="m", model_version="1", model_family="anomaly", explainer_type="permutation",
        output_name="anomaly_score", output_semantics="higher-is-more-anomalous score", explanation_representation="SHAP",
        predicted_label="NORMAL", predicted_class_id=None, model_output_value=0.2, decision_threshold=0.5,
        decision_threshold_space="higher_is_more_anomalous_score", persisted_decision_threshold=None,
        reference_dataset_id="train-benign", feature_names=["f"], transformed_feature_contributions=[{"feature": "f", "contribution": 0.1}],
        original_feature_contributions=[{"feature": "f", "contribution": 0.1}], positive_contributions=[], negative_contributions=[],
        top_influential_features=[], expected_value=0.1, additivity_diagnostic={"passed": True}, explanation_summary="Observed feature value was computed.",
    )
    assert json.loads(json.dumps(record.to_dict()))["output_semantics"] == "higher-is-more-anomalous score"
    events = [{"event_id": "e1", "flow_record_reference": "r1", "threat_score": 91.0, "severity": "HIGH", "score_breakdown": {"threat_score": 91.0}, "correlation_rules": ["same_host"]}]
    alerts = [{"alert_id": "a1", "supporting_event_ids": ["e1"], "threat_score": 91.0, "severity": "HIGH", "correlation_rules": ["same_host"]}]
    enriched_events, enriched_alerts = enrich_phase09_records(events, alerts, {"r1": [{"explanation_id": "x"}]})
    assert enriched_events[0]["threat_score"] == events[0]["threat_score"]
    assert enriched_events[0]["severity"] == events[0]["severity"]
    assert enriched_events[0]["correlation_rules"] == events[0]["correlation_rules"]
    assert enriched_alerts[0]["threat_score"] == alerts[0]["threat_score"]
    assert enriched_alerts[0]["correlation_rules"] == alerts[0]["correlation_rules"]
    assert enriched_alerts[0]["explanation_references"] == [{"explanation_id": "x"}]


def test_training_background_is_deterministic_and_anomaly_is_benign_only(tmp_path):
    contract = FeatureContract.from_dict({
        "schema_version": "1.0.0", "dataset_name": "fixture",
        "target": {"name": "label", "allowed_values": ["BENIGN", "ATTACK"]},
        "features": [{"name": "feature", "type": "numeric", "role": "predictive", "included": True}],
        "metadata_fields": [], "excluded_fields": [],
    })
    for filename, labels, offset in (
        ("Monday.parquet", ["BENIGN", "ATTACK", "BENIGN", "ATTACK"], 0),
        ("Tuesday.parquet", ["ATTACK", "BENIGN", "ATTACK", "BENIGN"], 10),
        ("Wednesday.parquet", ["BENIGN", "ATTACK", "BENIGN", "ATTACK"], 20),
        ("Friday.parquet", ["BENIGN"] * 4, 100),
    ):
        frame = pd.DataFrame({"feature": np.arange(offset, offset + 4, dtype=float), "label": labels})
        pq.write_table(pa.Table.from_pandas(frame), tmp_path / filename)
    first = load_training_background(tmp_path, contract, model_family="anomaly", sample_size=5, random_seed=17)
    second = load_training_background(tmp_path, contract, model_family="anomaly", sample_size=5, random_seed=17)
    assert first.features.equals(second.features)
    assert len(first.features) == 5
    assert set(first.features["feature"]).issubset({0.0, 2.0, 11.0, 13.0, 20.0, 22.0})
    assert not any("Friday" in name for name in first.source_files)
    assert first.metadata()["target_values_in_features"] is False


def test_local_shap_plots_write_summary_and_waterfall(tmp_path):
    from intrusion_intelligence.explainability.pipeline import _write_plots

    rng = np.random.default_rng(12)
    data = rng.normal(size=(40, 3))
    labels = (data[:, 0] > 0).astype(int)
    frame = pd.DataFrame(data, columns=["a", "b", "c"])
    estimator = LogisticRegression(random_state=3).fit(data, labels)
    model = _model("binary_logistic_regression", estimator, frame.columns)
    session = build_shap_session(model, frame.iloc[:8])
    _write_plots(session, frame.iloc[8:12], model.outputs, tmp_path, model.key)
    assert {path.name for path in tmp_path.glob("*.png")} == {
        "positive_beeswarm.png", "positive_bar.png", "positive_waterfall.png"
    }
