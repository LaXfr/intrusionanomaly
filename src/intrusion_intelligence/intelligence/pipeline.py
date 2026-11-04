"""Reusable evidence-to-alert pipeline for real or precomputed predictions."""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping

from intrusion_intelligence.intelligence.alerts import generate_alerts
from intrusion_intelligence.intelligence.correlation import RULE_FIELDS, correlate_events
from intrusion_intelligence.intelligence.events import build_flow_event, predicted_attack_category
from intrusion_intelligence.intelligence.normalization import (
    EmpiricalScoreReference,
    normalize_detector_outputs,
)
from intrusion_intelligence.intelligence.schemas import json_safe
from intrusion_intelligence.intelligence.scoring import DEFAULT_WEIGHTS, score_evidence
from intrusion_intelligence.intelligence.severity import DEFAULT_BANDS


class IntelligencePipelineError(ValueError):
    """Raised when source flows and detector output cannot be aligned safely."""


def run_intelligence_pipeline(
    records: Iterable[Mapping[str, Any]],
    *,
    binary_predictions: Iterable[Mapping[str, Any] | None] | None = None,
    multiclass_predictions: Iterable[Mapping[str, Any] | None] | None = None,
    anomaly_predictions: Iterable[Mapping[str, Any] | None] | None = None,
    class_labels: Iterable[str] | None = None,
    benign_reference_scores: Iterable[float] | EmpiricalScoreReference | None = None,
    weights: Mapping[str, Any] = DEFAULT_WEIGHTS,
    severity_bands: Iterable[Mapping[str, Any]] = DEFAULT_BANDS,
    correlation_config: Mapping[str, Any] | None = None,
    alert_config: Mapping[str, Any] | None = None,
    scoring_version: str = "1.0.0",
    severity_policy_version: str = "1.0.0",
    pipeline_version: str = "1.0.0",
    feature_schema_version: str | None = None,
    model_artifact_references: Mapping[str, str] | None = None,
    processed_at: datetime | None = None,
) -> dict[str, Any]:
    """Analyze aligned flow records and return events, groups, alerts, and audit.

    Prediction sequences must have the same length and order as `records`.
    This interface accepts precomputed outputs and never loads or trains a model.
    """
    flow_rows = [dict(record) for record in records]
    if not flow_rows:
        raise IntelligencePipelineError("At least one source flow record is required.")
    binary_rows = _aligned(binary_predictions, len(flow_rows), "binary")
    multiclass_rows = _aligned(multiclass_predictions, len(flow_rows), "multiclass")
    anomaly_rows = _aligned(anomaly_predictions, len(flow_rows), "anomaly")
    if isinstance(benign_reference_scores, EmpiricalScoreReference):
        reference = benign_reference_scores
    elif benign_reference_scores is not None:
        try:
            reference = EmpiricalScoreReference(benign_reference_scores)
        except (TypeError, ValueError) as exc:
            raise IntelligencePipelineError(f"Invalid benign anomaly-score reference: {exc}") from exc
    else:
        reference = None
    bands = tuple(dict(item) for item in severity_bands)
    correlation = dict(correlation_config or {})
    alert = dict(alert_config or {})
    current = processed_at or datetime.now(timezone.utc)
    if current.tzinfo is None:
        current = current.replace(tzinfo=timezone.utc)

    events: list[dict[str, Any]] = []
    for index, record in enumerate(flow_rows):
        evidence = normalize_detector_outputs(
            binary=binary_rows[index],
            multiclass=multiclass_rows[index],
            anomaly=anomaly_rows[index],
            class_labels=class_labels,
            benign_reference_scores=reference,
        )
        score = score_evidence(
            evidence,
            weights=weights,
            scoring_version=scoring_version,
        )
        event = build_flow_event(
            record,
            evidence,
            score,
            pipeline_version=pipeline_version,
            feature_schema_version=feature_schema_version,
            severity_bands=bands,
            now=current,
            row_position=index,
        ).to_dict()
        event["severity_policy_version"] = severity_policy_version
        event["model_artifact_references"] = dict(model_artifact_references or {})
        events.append(event)

    groups, correlation_audit = correlate_events(
        events,
        enabled_rules=correlation.get("enabled_rules", tuple(RULE_FIELDS)),
        window_minutes=int(correlation.get("window_minutes", 5)),
        allowed_windows_minutes=correlation.get("allowed_windows_minutes", (1, 5, 15)),
        minimum_events=int(correlation.get("minimum_events", 2)),
    )
    alerts, deduplicated_alerts = generate_alerts(
        events,
        groups,
        config=alert,
        severity_bands=bands,
        now=current,
    )
    summary = _summarize(
        events,
        groups,
        alerts,
        deduplicated_alerts,
        correlation_audit,
        weights=weights,
        scoring_version=scoring_version,
        severity_policy_version=severity_policy_version,
        pipeline_version=pipeline_version,
        feature_schema_version=feature_schema_version,
        model_artifact_references=model_artifact_references or {},
        processed_at=current,
    )
    return {
        "events": events,
        "correlated_event_groups": groups,
        "alerts": alerts,
        "deduplicated_alerts": deduplicated_alerts,
        "correlation_audit": correlation_audit,
        "summary": summary,
    }


def _aligned(values: Iterable[Mapping[str, Any] | None] | None, length: int, name: str) -> list[dict[str, Any] | None]:
    if values is None:
        return [None] * length
    if hasattr(values, "to_dict") and getattr(values, "ndim", None) == 2:
        rows = values.to_dict(orient="records")
    else:
        rows = list(values)
    if len(rows) != length:
        raise IntelligencePipelineError(
            f"{name} prediction count {len(rows)} does not match source flow count {length}; rows will not be reordered or truncated."
        )
    result: list[dict[str, Any] | None] = []
    for position, row in enumerate(rows):
        if row is None:
            result.append(None)
        elif isinstance(row, Mapping):
            result.append(dict(row))
        else:
            raise IntelligencePipelineError(f"{name} prediction at position {position} must be a mapping or None.")
    return result


def _summarize(
    events: list[dict[str, Any]],
    groups: list[dict[str, Any]],
    alerts: list[dict[str, Any]],
    deduplicated: list[dict[str, Any]],
    correlation_audit: dict[str, Any],
    *,
    weights: Mapping[str, Any],
    scoring_version: str,
    severity_policy_version: str,
    pipeline_version: str,
    feature_schema_version: str | None,
    model_artifact_references: Mapping[str, str],
    processed_at: datetime,
) -> dict[str, Any]:
    detector_status: dict[str, dict[str, int]] = {}
    for name in ("binary", "multiclass", "anomaly"):
        detector_status[name] = dict(Counter(event["normalized_evidence"][name]["availability_status"] for event in events))
    predicted_categories = Counter(category for event in events if (category := predicted_attack_category(event)))
    disagreement_counts = Counter(flag for event in events for flag in event["detector_disagreements"])
    event_status_counts = Counter(event["event_status"] for event in events)
    event_severity_counts = Counter(event["severity"] for event in events)
    alert_severity_counts = Counter(alert["severity"] for alert in alerts)
    alert_category_counts = Counter(category for alert in alerts for category in alert["attack_categories"])
    alert_rule_counts = Counter(rule for alert in alerts for rule in alert["correlation_rules"])
    available_flow_count = sum(bool(event["score_breakdown"].get("available_signals")) for event in events)
    source_values = {event["source_filename"] for event in events if event.get("source_filename")}
    destination_values = {event["network_context"].get("destination_ip") for event in events if event["network_context"].get("destination_ip")}
    metadata_counts = {
        field: sum(event["network_context"].get(field) is not None for event in events)
        for field in ("source_ip", "destination_ip", "source_port", "destination_port", "protocol")
    }
    return json_safe({
        "processed_at_utc": processed_at.astimezone(timezone.utc).isoformat(timespec="seconds"),
        "pipeline_version": pipeline_version,
        "scoring_config_version": scoring_version,
        "severity_policy_version": severity_policy_version,
        "feature_schema_version": feature_schema_version,
        "model_artifact_references": dict(model_artifact_references),
        "heuristic_score_is_probability": False,
        "total_analyzed_flows": len(events),
        "flows_with_usable_detection_evidence": available_flow_count,
        "flow_events_by_status": dict(event_status_counts),
        "flow_events_by_severity": dict(event_severity_counts),
        "generated_alert_count": len(alerts),
        "alerts_by_severity": dict(alert_severity_counts),
        "alerts_by_predicted_attack_category": dict(alert_category_counts),
        "alerts_by_correlation_rule": dict(alert_rule_counts),
        "detector_availability": detector_status,
        "detector_disagreement_counts": dict(disagreement_counts),
        "distinct_source_files": len(source_values),
        "unique_source_ip_count": len({value for value in (event["network_context"].get("source_ip") for event in events) if value}),
        "unique_destination_ip_count": len(destination_values),
        "network_metadata_rows_present": metadata_counts,
        "correlated_group_count": len(groups),
        "duplicate_alerts_suppressed": len(deduplicated),
        "deduplication_records": deduplicated,
        "correlation_audit": correlation_audit,
        "weights": dict(weights),
        "available_signals_are_renormalized_when_others_are_missing": True,
        "note": "Threat scores are deterministic heuristic prioritization values, not probabilities of compromise or ground-truth labels.",
    })
