from __future__ import annotations

import json
from datetime import datetime, timezone

import numpy as np
import pandas as pd
import pytest

from intrusion_intelligence.intelligence.alerts import deduplicate_alerts, generate_alerts
from intrusion_intelligence.intelligence.config import load_intelligence_config
from intrusion_intelligence.intelligence.correlation import CorrelationError, correlate_events
from intrusion_intelligence.intelligence.events import build_flow_event
from intrusion_intelligence.intelligence.normalization import (
    EmpiricalScoreReference,
    normalize_anomaly_output,
    normalize_binary_output,
    normalize_detector_outputs,
    normalize_multiclass_output,
)
from intrusion_intelligence.intelligence.pipeline import (
    IntelligencePipelineError,
    run_intelligence_pipeline,
)
from intrusion_intelligence.intelligence.reporting import write_intelligence_outputs
from intrusion_intelligence.intelligence.scoring import (
    DEFAULT_WEIGHTS,
    ThreatScoringError,
    score_evidence,
    validate_weights,
)
from intrusion_intelligence.intelligence.severity import (
    DEFAULT_BANDS,
    SeverityError,
    assign_severity,
    validate_severity_bands,
)
from intrusion_intelligence.intelligence.service import _input_columns
from intrusion_intelligence.feature_engineering import FeatureContract

LABELS = ("BENIGN", "DDoS", "PortScan")
NOW = datetime(2026, 11, 3, 12, 0, tzinfo=timezone.utc)


def _multi(label: str = "DDoS", benign: float = 0.1, model_id: str = "multiclass-random_forest-v1.0.0") -> dict:
    rest = (1.0 - benign) / 2
    scores = {"BENIGN": benign, "DDoS": rest, "PortScan": rest}
    class_id = LABELS.index(label)
    return {"predicted_class": class_id, "predicted_label": label, "class_scores": scores, "model_id": model_id}


def _anomaly(decision: str = "ANOMALOUS", score: float = 0.9, threshold: float = 0.5) -> dict:
    return {
        "raw_model_score": -score,
        "anomaly_score": score,
        "threshold": threshold,
        "decision": decision,
        "operating_point": "target-fpr-1pct",
        "model_id": "isolation-forest-v1.0.0",
        "preprocessing_version": "1.0.0",
        "feature_schema_version": "1.0.0",
    }


def _record(index: int = 1, *, timestamp: str | None = "2026-11-03T12:00:00Z", source_ip: str | None = "192.0.2.10", destination_ip: str | None = "198.51.100.5", source_port: int | None = None, destination_port: int | None = 443, protocol: str | None = "TCP") -> dict:
    return {
        "flow_record_reference": f"flow-{index}",
        "source_filename": "synthetic.csv",
        "source_row_number": index,
        "timestamp": timestamp,
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "source_port": 51000 + index if source_port is None else source_port,
        "destination_port": destination_port,
        "protocol": protocol,
    }


def _pipeline_event(index: int = 1, *, multi: dict | None = None, anomaly: dict | None = None, binary: dict | None = None, **record_kwargs) -> dict:
    result = run_intelligence_pipeline(
        [_record(index, **record_kwargs)],
        binary_predictions=[binary] if binary is not None else None,
        multiclass_predictions=[multi] if multi is not None else None,
        anomaly_predictions=[anomaly] if anomaly is not None else None,
        class_labels=LABELS,
        benign_reference_scores=[0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8],
        processed_at=NOW,
    )
    return result["events"][0]


def test_multiclass_probability_distribution_normalizes_attack_evidence_and_preserves_model() -> None:
    signal = normalize_multiclass_output(_multi(benign=0.2), class_labels=LABELS)
    assert signal.availability_status == "available"
    assert signal.normalized_value == pytest.approx(0.8)
    assert signal.model_id == "multiclass-random_forest-v1.0.0"
    assert signal.model_version == "1.0.0"
    assert signal.calibration_status == "valid_probability_distribution_uncalibrated"
    assert signal.details["score_is_calibrated_probability"] is False


def test_multiclass_hard_prediction_is_categorical_not_a_probability() -> None:
    signal = normalize_multiclass_output({"predicted_class": 0, "predicted_label": "BENIGN", "model_id": "rf-v1.0.0"}, class_labels=LABELS)
    assert signal.normalized_value == 0
    assert signal.calibration_status == "hard_prediction_only"
    assert "no probability" in signal.interpretation


@pytest.mark.parametrize("scores", [
    {"BENIGN": 0.1, "DDoS": 0.1, "PortScan": 0.1},
    {"BENIGN": 1.1, "DDoS": -0.1, "PortScan": 0.0},
    {"BENIGN": 0.1, "DDoS": 0.9},
])
def test_multiclass_invalid_score_mapping_is_not_scored(scores: dict) -> None:
    signal = normalize_multiclass_output({"predicted_label": "DDoS", "predicted_class": 1, "class_scores": scores}, class_labels=LABELS)
    assert signal.availability_status == "invalid"
    assert signal.normalized_value is None
    assert signal.original_value["class_scores"] == scores


def test_multiclass_rejects_inconsistent_class_mapping() -> None:
    signal = normalize_multiclass_output({**_multi(), "predicted_class": 2}, class_labels=LABELS)
    assert signal.availability_status == "invalid"
    assert "disagree" in signal.details["reason"]


def test_anomaly_normalization_uses_benign_reference_percentile_and_preserves_threshold() -> None:
    reference = EmpiricalScoreReference([0.1, 0.2, 0.3, 0.4])
    signal = normalize_anomaly_output(_anomaly(decision="NORMAL", score=0.35), benign_reference_scores=reference)
    assert signal.normalized_value == pytest.approx(0.75)
    assert signal.details["standardized_anomaly_score"] == pytest.approx(0.35)
    assert signal.details["threshold"] == pytest.approx(0.5)
    assert signal.details["raw_model_score"] == pytest.approx(-0.35)
    assert signal.details["reference_observations"] == 4
    assert "not malicious probability" in signal.interpretation


def test_anomaly_without_reference_uses_existing_decision_indicator() -> None:
    signal = normalize_anomaly_output(_anomaly(score=0.9), benign_reference_scores=None)
    assert signal.normalized_value == 1.0
    assert signal.details["normalization_method"] == "calibrated_threshold_decision_indicator"


def test_anomaly_rejects_decision_that_conflicts_with_strict_threshold() -> None:
    signal = normalize_anomaly_output(_anomaly(decision="NORMAL", score=0.9))
    assert signal.availability_status == "invalid"
    assert signal.normalized_value is None


def test_binary_score_and_hard_prediction_are_supported() -> None:
    score = normalize_binary_output({"malicious_score": 0.8, "predicted_label": "MALICIOUS", "threshold": 0.5, "model_id": "binary-v2.0.0"})
    hard = normalize_binary_output({"predicted_label": "BENIGN", "model_id": "binary-v2.0.0"})
    assert score.normalized_value == 0.8
    assert score.details["malicious_prediction"] is True
    assert score.model_version == "2.0.0"
    assert hard.normalized_value == 0
    assert hard.calibration_status == "hard_prediction_only"


def test_binary_conflicting_threshold_decision_is_invalid() -> None:
    signal = normalize_binary_output({"malicious_score": 0.8, "predicted_label": "BENIGN", "threshold": 0.5})
    assert signal.availability_status == "invalid"


def test_missing_binary_signal_is_explicitly_unavailable() -> None:
    signal = normalize_binary_output(None)
    assert signal.availability_status == "unavailable"
    assert signal.normalized_value is None


def test_default_weighted_score_preserves_all_contributions() -> None:
    evidence = normalize_detector_outputs(binary={"malicious_score": 0.8}, multiclass=_multi(benign=0.2, model_id="rf-v1.0.0"), anomaly=_anomaly(score=0.9), class_labels=LABELS, benign_reference_scores=[0, 1])
    breakdown = score_evidence(evidence)
    expected = 100 * (0.30 * 0.8 + 0.25 * 0.8 + 0.45 * 0.5)
    assert breakdown["threat_score"] == pytest.approx(expected)
    assert breakdown["available_signals"] == ["binary", "multiclass", "anomaly"]
    assert breakdown["signal_breakdown"]["multiclass"]["contribution"] == pytest.approx(0.2)
    assert breakdown["correlated_signal_groups"]["supervised"] == ["binary", "multiclass"]


def test_missing_signals_are_excluded_and_available_weights_renormalized() -> None:
    evidence = normalize_detector_outputs(multiclass=_multi(benign=0.2, model_id="rf-v1.0.0"), anomaly=_anomaly(decision="NORMAL", score=0.4), class_labels=LABELS, benign_reference_scores=[0.1, 0.2, 0.3, 0.4])
    result = score_evidence(evidence)
    expected = 100 * (0.25 * 0.8 + 0.45 * 1.0) / 0.70
    assert result["threat_score"] == pytest.approx(expected)
    assert result["available_signals"] == ["multiclass", "anomaly"]
    assert result["unavailable_signals"][0]["signal"] == "binary"
    assert result["signal_breakdown"]["multiclass"]["effective_weight"] == pytest.approx(0.25 / 0.70)


def test_invalid_evidence_is_excluded_from_score_not_converted_to_zero() -> None:
    evidence = normalize_detector_outputs(multiclass={"predicted_label": "UNKNOWN"}, class_labels=LABELS)
    result = score_evidence(evidence)
    assert result["threat_score"] is None
    assert result["calculation_status"] == "insufficient_evidence"
    assert any(item["signal"] == "multiclass" and item["status"] == "invalid" for item in result["unavailable_signals"])


def test_weight_validation_rejects_negative_nan_and_empty_weights() -> None:
    for weights in (
        {"binary": -1, "multiclass": 0.5, "anomaly": 0.5},
        {"binary": float("nan"), "multiclass": 0.5, "anomaly": 0.5},
        {"binary": 0, "multiclass": 0, "anomaly": 0},
    ):
        with pytest.raises(ThreatScoringError):
            validate_weights(weights)


@pytest.mark.parametrize("value,expected", [(0, "LOW"), (24.999, "LOW"), (25, "MEDIUM"), (49.999, "MEDIUM"), (50, "HIGH"), (74.999, "HIGH"), (75, "CRITICAL"), (100, "CRITICAL")])
def test_severity_boundaries_map_exactly_once(value: float, expected: str) -> None:
    assert assign_severity(value) == expected


def test_severity_supports_generator_policy_and_unscored_state() -> None:
    bands = ({"name": item["name"], "minimum": item["minimum"], "maximum": item["maximum"]} for item in DEFAULT_BANDS)
    assert assign_severity(None) == "UNSCORED"
    assert assign_severity(50, bands) == "HIGH"


def test_severity_policy_rejects_gaps_and_out_of_range_scores() -> None:
    with pytest.raises(SeverityError):
        validate_severity_bands([{"name": "LOW", "minimum": 0, "maximum": 20}, {"name": "HIGH", "minimum": 25, "maximum": 101}])
    with pytest.raises(SeverityError):
        assign_severity(101)


def test_flow_event_preserves_provenance_predictions_and_stable_id() -> None:
    first = _pipeline_event(5)
    second = _pipeline_event(5)
    assert first["event_id"] == second["event_id"]
    assert first["flow_record_reference"] == "flow-5"
    assert first["source_row_number"] == 5
    assert first["timestamp_utc"].endswith("+00:00")
    assert first["severity_policy_version"] == "1.0.0"


def test_flow_event_marks_unassociated_and_missing_metadata() -> None:
    event = _pipeline_event(1, timestamp=None, source_ip=None)
    assert event["timestamp_utc"] is None
    assert any("Unavailable correlation metadata" in warning for warning in event["validation_warnings"])
    assert event["metadata_provenance"]["timestamp"]["status"] == "unavailable"


def test_event_statuses_preserve_anomaly_only_and_detector_disagreement() -> None:
    anomaly_only = _pipeline_event(1, anomaly=_anomaly())
    disagreement = _pipeline_event(2, multi=_multi("BENIGN", benign=0.9), anomaly=_anomaly())
    all_positive = _pipeline_event(3, binary={"predicted_label": "MALICIOUS"}, multi=_multi(), anomaly=_anomaly())
    unavailable = _pipeline_event(4)
    assert anomaly_only["event_status"] == "ANOMALOUS"
    assert "supervised_engines_unavailable" in anomaly_only["detector_disagreements"]
    assert "anomaly_flags_flow_supervised_engine_predicts_benign" in disagreement["detector_disagreements"]
    assert all_positive["event_status"] == "SUSPICIOUS"
    assert unavailable["event_status"] == "INSUFFICIENT_EVIDENCE"


def test_correlation_source_rule_sorts_out_of_order_and_aggregates_counts() -> None:
    events = [
        _pipeline_event(3, multi=_multi(), timestamp="2026-11-03T12:04:00Z"),
        _pipeline_event(1, multi=_multi(), timestamp="2026-11-03T12:00:00Z"),
        _pipeline_event(2, multi=_multi(), timestamp="2026-11-03T12:02:00Z"),
    ]
    groups, audit = correlate_events(events, enabled_rules=["source_ip"], window_minutes=5)
    assert len(groups) == 1
    group = groups[0]
    assert group["unique_event_count"] == 3
    assert group["unique_flow_count"] == 3
    assert group["first_observed_utc"] < group["last_observed_utc"]
    assert group["highest_severity"] in {"HIGH", "CRITICAL"}
    assert audit["groups_by_rule"]["source_ip"] == 1


def test_correlation_destination_service_and_category_rules_are_supported() -> None:
    events = [_pipeline_event(1, multi=_multi(), source_port=50000), _pipeline_event(2, multi=_multi(), source_port=50000)]
    groups, _ = correlate_events(events, enabled_rules=["destination_ip", "destination_service", "attack_category", "repeated_flow_tuple", "temporal_activity"], window_minutes=5)
    assert {group["correlation_rule"] for group in groups} == {"destination_ip", "destination_service", "attack_category", "repeated_flow_tuple", "temporal_activity"}


def test_correlation_skips_missing_times_and_keys_without_null_grouping() -> None:
    events = [_pipeline_event(1, multi=_multi(), timestamp=None, source_ip=None), _pipeline_event(2, multi=_multi(), timestamp=None, source_ip=None)]
    groups, audit = correlate_events(events, enabled_rules=["source_ip", "destination_ip"], window_minutes=5)
    assert groups == []
    assert audit["events_skipped_by_rule"]["source_ip"]["missing_timestamp"] == 2
    assert audit["temporal_correlation_supported"] == 0


def test_correlation_skips_missing_fields_and_separates_unrelated_keys() -> None:
    events = [_pipeline_event(1, multi=_multi()), _pipeline_event(2, multi=_multi(), source_ip="192.0.2.11")]
    groups, _ = correlate_events(events, enabled_rules=["source_ip"], window_minutes=5)
    assert groups == []
    missing = [_pipeline_event(3, multi=_multi(), source_ip=None), _pipeline_event(4, multi=_multi(), source_ip=None)]
    groups, audit = correlate_events(missing, enabled_rules=["source_ip"], window_minutes=5)
    assert groups == []
    assert audit["events_skipped_by_rule"]["source_ip"]["missing_key_fields"] == 2


def test_correlation_enforces_time_windows_and_allowed_configuration() -> None:
    events = [_pipeline_event(1, multi=_multi(), timestamp="2026-11-03T12:00:00Z"), _pipeline_event(2, multi=_multi(), timestamp="2026-11-03T12:06:00Z")]
    groups, _ = correlate_events(events, enabled_rules=["source_ip"], window_minutes=5)
    assert groups == []
    with pytest.raises(CorrelationError):
        correlate_events(events, window_minutes=2)


def test_correlation_rejects_naive_timestamps_and_suppresses_duplicate_event_inputs() -> None:
    naive = _pipeline_event(1, multi=_multi(), timestamp="2026-11-03T12:00:00")
    duplicate = _pipeline_event(2, multi=_multi(), timestamp="2026-11-03T12:01:00Z")
    groups, audit = correlate_events([naive, duplicate, duplicate], enabled_rules=["temporal_activity"], window_minutes=5)
    assert groups == []
    assert audit["duplicate_suspicious_event_inputs_suppressed"] == 1
    assert audit["events_skipped_by_rule"]["temporal_activity"]["invalid_or_naive_timestamp"] == 1


def test_alert_includes_detector_versions_missing_evidence_severity_rationale_and_eval_status() -> None:
    event = _pipeline_event(1, multi=_multi(), anomaly=_anomaly())
    alerts, _ = generate_alerts([event], [], config={"single_event_minimum_score": 50, "single_event_requires_positive_signal": True})
    alert = alerts[0]
    assert set(alert["model_versions"]) == {"binary", "multiclass", "anomaly"}
    assert "binary" in alert["missing_detector_evidence"]
    assert "band" in alert["severity_rationale"]
    assert alert["ground_truth_evaluation_status"] == "not_evaluated"


def test_alert_generation_includes_evidence_explanation_and_no_normal_alerts() -> None:
    suspicious = _pipeline_event(1, multi=_multi(), anomaly=_anomaly())
    normal = _pipeline_event(2, multi=_multi("BENIGN", benign=1.0), anomaly=_anomaly("NORMAL", score=0.1))
    alerts, duplicates = generate_alerts([suspicious, normal], [], config={"single_event_minimum_score": 50, "single_event_requires_positive_signal": True})
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert["status"] == "NEW"
    assert alert["severity"] in {"HIGH", "CRITICAL"}
    assert alert["supporting_event_ids"] == [suspicious["event_id"]]
    assert "predicted" in alert["explanation"] and "threat score" in alert["explanation"]
    assert duplicates == []


def test_group_alert_aggregates_event_references_and_time_bounds() -> None:
    events = [_pipeline_event(i, multi=_multi()) for i in range(1, 4)]
    groups, _ = correlate_events(events, enabled_rules=["source_ip"], window_minutes=5)
    alerts, _ = generate_alerts(events, groups, config={"minimum_correlated_events": 2, "correlated_minimum_score": 20})
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert["alert_type"] == "CORRELATED_ACTIVITY"
    assert alert["related_event_count"] == 3
    assert alert["first_observed_utc"] is not None
    assert alert["last_observed_utc"] is not None
    assert alert["correlation_rules"] == ["source_ip"]
    assert "source_ip" in alert["explanation"]


def test_alert_deduplication_merges_same_event_set_but_keeps_category_differences() -> None:
    event = _pipeline_event(1, multi=_multi())
    groups, _ = correlate_events([event, _pipeline_event(2, multi=_multi())], enabled_rules=["source_ip", "destination_ip"])
    alerts, suppressed = generate_alerts([event, _pipeline_event(2, multi=_multi())], groups, config={"correlated_minimum_score": 10})
    assert len(alerts) == 1
    assert set(alerts[0]["correlation_rules"]) == {"destination_ip", "source_ip"}
    assert len(suppressed) == 1
    distinct = dict(alerts[0])
    distinct["alert_fingerprint"] = ""
    distinct["attack_categories"] = ["PortScan"]
    deduped, records = deduplicate_alerts([alerts[0], distinct])
    assert len(deduped) == 2
    assert records == []


def test_pipeline_supports_each_single_engine_and_missing_evidence() -> None:
    configurations = [
        {"binary_predictions": [{"predicted_label": "MALICIOUS"}]},
        {"multiclass_predictions": [_multi()]},
        {"anomaly_predictions": [_anomaly()]},
        {},
    ]
    results = [run_intelligence_pipeline([_record(i)], class_labels=LABELS, processed_at=NOW, **config) for i, config in enumerate(configurations)]
    assert results[0]["events"][0]["score_breakdown"]["available_signals"] == ["binary"]
    assert results[1]["events"][0]["score_breakdown"]["available_signals"] == ["multiclass"]
    assert results[2]["events"][0]["score_breakdown"]["available_signals"] == ["anomaly"]
    assert results[3]["events"][0]["event_status"] == "INSUFFICIENT_EVIDENCE"
    assert results[3]["events"][0]["threat_score"] is None


def test_pipeline_keeps_prediction_alignment_and_fails_on_length_mismatch() -> None:
    result = run_intelligence_pipeline(
        [_record(1), _record(2)],
        multiclass_predictions=[_multi("DDoS"), _multi("PortScan")],
        class_labels=LABELS,
        processed_at=NOW,
    )
    assert [event["flow_record_reference"] for event in result["events"]] == ["flow-1", "flow-2"]
    assert [event["normalized_evidence"]["multiclass"]["details"]["predicted_label"] for event in result["events"]] == ["DDoS", "PortScan"]
    with pytest.raises(IntelligencePipelineError):
        run_intelligence_pipeline([_record(1), _record(2)], multiclass_predictions=[_multi()], class_labels=LABELS)


def test_reprocessing_same_records_produces_deterministic_event_and_alert_ids() -> None:
    first_multi = _multi()
    first_multi["prediction_timestamp_utc"] = "2026-11-03T12:00:00Z"
    second_multi = _multi()
    second_multi["prediction_timestamp_utc"] = "2026-11-03T12:15:00Z"
    first = run_intelligence_pipeline(records=[_record(1)], multiclass_predictions=[first_multi], class_labels=LABELS, processed_at=NOW)
    second = run_intelligence_pipeline(records=[_record(1)], multiclass_predictions=[second_multi], class_labels=LABELS, processed_at=NOW)
    assert first["events"][0]["event_id"] == second["events"][0]["event_id"]
    assert first["events"][0]["event_fingerprint"] == second["events"][0]["event_fingerprint"]
    assert first["events"][0]["detector_results"]["multiclass"]["prediction_timestamp_utc"] != second["events"][0]["detector_results"]["multiclass"]["prediction_timestamp_utc"]
    assert [alert["alert_id"] for alert in first["alerts"]] == [alert["alert_id"] for alert in second["alerts"]]


def test_configuration_loads_and_records_actual_model_availability() -> None:
    config = load_intelligence_config("configs/intelligence.toml")
    assert config["detectors"]["binary"]["enabled"] is True
    assert config["detectors"]["multiclass"]["enabled"] is True
    assert config["detectors"]["anomaly"]["enabled"] is True
    assert config["correlation"]["window_minutes"] == 5
    assert set(config["correlation"]["enabled_rules"]) == {"source_ip", "destination_ip", "destination_service", "attack_category", "repeated_flow_tuple", "temporal_activity"}


def test_actual_detection_input_columns_exclude_ground_truth_labels(tmp_path) -> None:
    import pyarrow as pa
    import pyarrow.parquet as pq

    contract = FeatureContract.from_file("configs/feature_schema.json")
    path = tmp_path / "with_labels.parquet"
    pq.write_table(pa.table({
        "label": ["DDoS"],
        "__source_label": ["DDoS"],
        "__source_file": ["Friday-test.csv"],
        "__source_row_number": [1],
        "__record_id": ["record-1"],
    }), path)
    columns = _input_columns(path, contract, include_target=False)
    assert "label" not in columns
    assert "__source_label" not in columns
    assert "__source_file" in columns
    assert "__record_id" in columns


def test_held_out_label_stratified_selector_is_deterministic_and_records_class_counts(tmp_path) -> None:
    import pyarrow as pa
    import pyarrow.parquet as pq

    from intrusion_intelligence.intelligence.service import _select_label_stratified_rows

    path = tmp_path / "Friday-sample.parquet"
    pq.write_table(pa.table({"label": ["BENIGN"] * 7 + ["DDoS"] * 5}), path)
    selected, counts = _select_label_stratified_rows(path, "label", cap_per_label=3, batch_size=2)
    selected_again, counts_again = _select_label_stratified_rows(path, "label", cap_per_label=3, batch_size=4)
    assert counts == {"BENIGN": 7, "DDoS": 5}
    assert selected == selected_again
    assert counts_again == counts
    assert len(selected) == 6
    assert len(set(selected)) == 6


def test_reporting_writes_nested_events_alerts_summary_and_figures(tmp_path) -> None:
    result = run_intelligence_pipeline(
        [_record(1), _record(2)],
        multiclass_predictions=[_multi(), _multi()],
        anomaly_predictions=[_anomaly(), _anomaly()],
        class_labels=LABELS,
        processed_at=NOW,
    )
    paths = write_intelligence_outputs(result, intelligence_directory=tmp_path / "intelligence", figure_directory=tmp_path / "figures", run_id="test-run")
    assert json.loads((tmp_path / "intelligence" / "test-run" / "security_alerts.json").read_text())
    events = [json.loads(line) for line in (tmp_path / "intelligence" / "test-run" / "flow_detection_events.jsonl").read_text().splitlines()]
    assert len(events) == 2
    assert "raw_model_score" in events[0]["detector_results"]["anomaly"]
    assert pd.read_csv(tmp_path / "intelligence" / "test-run" / "security_alerts_summary.csv").shape[0] >= 1
    assert "score_distribution_figure" in paths


def test_flow_record_target_values_are_not_copied_into_detection_event() -> None:
    record = _record(1)
    record["label"] = "DDoS"
    event = run_intelligence_pipeline([record], multiclass_predictions=[_multi()], class_labels=LABELS, processed_at=NOW)["events"][0]
    assert "label" not in event
    assert "ground_truth" not in event
