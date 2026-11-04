"""Evidence-based alert criteria, aggregation, explanations, and idempotency."""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping

from intrusion_intelligence.intelligence.events import predicted_attack_category
from intrusion_intelligence.intelligence.schemas import SecurityAlert, json_safe
from intrusion_intelligence.intelligence.severity import DEFAULT_BANDS, assign_severity


def generate_alerts(
    events: Iterable[Any],
    correlated_groups: Iterable[Mapping[str, Any]],
    *,
    config: Mapping[str, Any],
    severity_bands: tuple[dict[str, Any], ...] = DEFAULT_BANDS,
    now: datetime | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Generate group alerts and qualifying single-flow alerts; omit normal flows."""
    event_rows = [_mapping(event) for event in events]
    event_by_id = {str(event["event_id"]): event for event in event_rows}
    group_rows = [dict(group) for group in correlated_groups]
    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None:
        current = current.replace(tzinfo=timezone.utc)
    group_minimum = float(config.get("correlated_minimum_score", 25.0))
    group_count = int(config.get("minimum_correlated_events", 2))
    single_minimum = float(config.get("single_event_minimum_score", 50.0))
    minimum_evidence = int(config.get("minimum_available_signals", 1))
    require_positive = bool(config.get("single_event_requires_positive_signal", True))
    status = str(config.get("initial_status", "NEW")).upper()
    if status != "NEW":
        raise ValueError("New offline alerts must start with status NEW.")
    raw_alerts: list[dict[str, Any]] = []
    covered: set[str] = set()

    for group in group_rows:
        ids = [str(item) for item in group.get("event_ids", [])]
        members = [event_by_id[event_id] for event_id in ids if event_id in event_by_id]
        if len({event["event_id"] for event in members}) < group_count:
            continue
        scores = [float(event["threat_score"]) for event in members if event.get("threat_score") is not None]
        if not scores or max(scores) < group_minimum:
            continue
        raw_alerts.append(_build_alert(
            members,
            alert_type="CORRELATED_ACTIVITY",
            config=config,
            severity_bands=severity_bands,
            now=current,
            correlation_groups=[group],
        ))
        covered.update(str(event["event_id"]) for event in members)

    for event in event_rows:
        if str(event["event_id"]) in covered or event.get("event_status") in {"NORMAL", "INSUFFICIENT_EVIDENCE"}:
            continue
        score = event.get("threat_score")
        if score is None or float(score) < single_minimum:
            continue
        signals = event.get("score_breakdown", {}).get("available_signals", [])
        if len(signals) < minimum_evidence:
            continue
        if require_positive and not _has_positive_detection(event):
            continue
        raw_alerts.append(_build_alert(
            [event],
            alert_type="SINGLE_FLOW_SUSPICION",
            config=config,
            severity_bands=severity_bands,
            now=current,
            correlation_groups=[],
        ))
    return deduplicate_alerts(raw_alerts)


def deduplicate_alerts(alerts: Iterable[Mapping[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Merge exact repeated alert fingerprints while retaining source events."""
    by_fingerprint: dict[str, dict[str, Any]] = {}
    suppressed: list[dict[str, Any]] = []
    for source in alerts:
        alert = json_safe(dict(source))
        fingerprint = str(alert.get("alert_fingerprint") or alert_fingerprint(alert))
        alert["alert_fingerprint"] = fingerprint
        alert["alert_id"] = "alt_" + fingerprint[:24]
        existing = by_fingerprint.get(fingerprint)
        if existing is None:
            by_fingerprint[fingerprint] = alert
            continue
        prior_severity = existing["severity"]
        if float(alert["threat_score"]) > float(existing["threat_score"]):
            existing["threat_score"] = alert["threat_score"]
            existing["scoring_breakdown"] = alert["scoring_breakdown"]
            existing["severity"] = alert["severity"]
        existing["mean_threat_score"] = max(float(existing["mean_threat_score"]), float(alert["mean_threat_score"]))
        existing["severity_history"] = sorted(set(existing.get("severity_history", [])) | set(alert.get("severity_history", [])), key=_severity_rank)
        existing["correlation_rules"] = sorted(set(existing.get("correlation_rules", [])) | set(alert.get("correlation_rules", [])))
        existing["correlation_keys"] = _unique_dicts(existing.get("correlation_keys", []) + alert.get("correlation_keys", []))
        existing["supporting_event_ids"] = sorted(set(existing.get("supporting_event_ids", [])) | set(alert.get("supporting_event_ids", [])))
        existing["related_event_count"] = max(existing["related_event_count"], alert["related_event_count"])
        existing["related_flow_count"] = max(existing["related_flow_count"], alert["related_flow_count"])
        if prior_severity != existing["severity"]:
            existing.setdefault("duplicate_updates", []).append({"reason": "duplicate fingerprint carried higher severity", "from": prior_severity, "to": existing["severity"]})
        suppressed.append({"duplicate_alert_id": alert["alert_id"], "retained_alert_id": existing["alert_id"], "fingerprint": fingerprint, "reason": "identical event-fingerprint and attack-category set"})
    return [by_fingerprint[key] for key in sorted(by_fingerprint)], suppressed


def alert_fingerprint(alert: Mapping[str, Any]) -> str:
    events = sorted(set(map(str, alert.get("event_fingerprints", []))))
    categories = sorted(set(map(str, alert.get("attack_categories", []))))
    payload = {"alert_type": alert.get("alert_type"), "event_fingerprints": events, "attack_categories": categories}
    return hashlib.sha256(json.dumps(json_safe(payload), sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _build_alert(
    events: list[dict[str, Any]],
    *,
    alert_type: str,
    config: Mapping[str, Any],
    severity_bands: tuple[dict[str, Any], ...],
    now: datetime,
    correlation_groups: list[dict[str, Any]],
) -> dict[str, Any]:
    scores = [float(event["threat_score"]) for event in events if event.get("threat_score") is not None]
    maximum = max(scores) if scores else 0.0
    mean_score = sum(scores) / len(scores) if scores else 0.0
    severity = assign_severity(maximum, severity_bands)
    categories = sorted({category for event in events if (category := predicted_attack_category(event))})
    disagreement_flags = sorted({flag for event in events for flag in event.get("detector_disagreements", [])})
    latest_context: dict[str, Any] = {}
    if correlation_groups:
        latest_context.update(correlation_groups[0].get("network_context", {}))
    else:
        for event in events:
            latest_context.update({key: value for key, value in event.get("network_context", {}).items() if value is not None})
    timed = sorted(event["timestamp_utc"] for event in events if event.get("timestamp_utc"))
    first = timed[0] if timed else None
    last = timed[-1] if timed else None
    event_ids = sorted({str(event["event_id"]) for event in events})
    event_fingerprints = sorted({str(event["event_fingerprint"]) for event in events})
    groups = correlation_groups
    rules = sorted({str(group["correlation_rule"]) for group in groups})
    keys = [
        {"group_id": group["group_id"], "rule": group["correlation_rule"], "key": group["correlation_key"], "window_minutes": group["correlation_window_minutes"]}
        for group in groups
    ]
    per_detector = _evidence_summary(events)
    breakdown_event = max(events, key=lambda item: float(item.get("threat_score") or 0.0))
    explanation = _explanation(events, alert_type, rules, keys, maximum, breakdown_event, config)
    title_category = categories[0] if len(categories) == 1 else "multiple attack-category predictions" if categories else "anomaly or detector disagreement"
    title = (
        f"Repeated {title_category} activity ({len(event_ids)} flow events)"
        if alert_type == "CORRELATED_ACTIVITY"
        else f"{title_category} signal on flow {events[0]['flow_record_reference']}"
    )
    warnings = sorted({warning for event in events for warning in event.get("validation_warnings", [])})
    limitations = list(config.get("known_limitations", [])) + warnings
    if any(item.get("availability_status") != "available" for event in events for item in event.get("normalized_evidence", {}).values()):
        limitations.append("One or more detector outputs were unavailable or invalid; the score uses valid available evidence only.")
    investigation_steps = list(config.get("investigation_steps", [
        "Review the supporting source flow records and verify their provenance.",
        "Compare the model predictions and anomaly evidence with the original network context.",
        "Review additional events sharing the available correlation key and time window.",
    ]))
    raw = {
        "alert_type": alert_type,
        "event_fingerprints": event_fingerprints,
        "attack_categories": categories,
    }
    fingerprint = alert_fingerprint(raw)
    alert = SecurityAlert(
        alert_id="alt_" + fingerprint[:24],
        alert_fingerprint=fingerprint,
        alert_type=alert_type,
        created_at_utc=now.astimezone(timezone.utc).isoformat(timespec="seconds"),
        status="NEW",
        severity=severity,
        threat_score=maximum,
        mean_threat_score=mean_score,
        attack_categories=categories,
        detection_status="SUSPICIOUS" if alert_type == "CORRELATED_ACTIVITY" or len(event_ids) > 1 else events[0].get("event_status", "SUSPICIOUS"),
        correlation_rules=rules,
        correlation_keys=keys,
        first_observed_utc=first,
        last_observed_utc=last,
        related_event_count=len(event_ids),
        related_flow_count=len({str(event["flow_record_reference"]) for event in events}),
        supporting_event_ids=event_ids,
        network_context=json_safe(latest_context),
        detector_evidence_summary=per_detector,
        detector_disagreements=disagreement_flags,
        scoring_breakdown=breakdown_event.get("score_breakdown", {}),
        title=title,
        explanation=explanation,
        investigation_steps=investigation_steps,
        known_limitations=sorted(set(map(str, limitations))),
        severity_history=sorted({str(event.get("severity", "UNSCORED")) for event in events}, key=_severity_rank),
        duplicate_updates=[],
        model_versions={
            detector: next((event.get("model_versions", {}).get(detector) for event in events if event.get("model_versions", {}).get(detector)), None)
            for detector in ("binary", "multiclass", "anomaly")
        },
        missing_detector_evidence=sorted({
            detector for event in events for detector, item in event.get("normalized_evidence", {}).items()
            if item.get("availability_status") != "available"
        }),
        severity_rationale=f"Maximum supporting heuristic threat score {maximum:.2f}/100 falls in the configured {severity} band; band cutoffs are policy thresholds, not empirically calibrated incident severity.",
        confidence_limitations=sorted(set(map(str, limitations))),
        ground_truth_evaluation_status="not_evaluated",
    ).to_dict()
    alert["event_fingerprints"] = event_fingerprints
    return alert


def _explanation(
    events: list[dict[str, Any]],
    alert_type: str,
    rules: list[str],
    keys: list[dict[str, Any]],
    maximum: float,
    highest_event: dict[str, Any],
    config: Mapping[str, Any],
) -> str:
    pieces: list[str] = []
    if alert_type == "CORRELATED_ACTIVITY":
        details = keys[0] if keys else {}
        pieces.append(
            f"{len({event['event_id'] for event in events})} suspicious flow events shared the {details.get('rule', 'configured')} correlation key within {details.get('window_minutes')} minutes."
        )
    else:
        pieces.append("One flow-level event met the configured alert score and positive-detection criteria.")
    evidence = highest_event.get("normalized_evidence", {})
    binary = evidence.get("binary", {})
    if binary.get("availability_status") == "available":
        details = binary.get("details", {})
        pieces.append(f"Binary detector prediction was {'malicious' if details.get('malicious_prediction') else 'benign'}; supplied score {details.get('malicious_score')}.")
    else:
        pieces.append("Binary detector evidence was unavailable.")
    multiclass = evidence.get("multiclass", {})
    if multiclass.get("availability_status") == "available":
        details = multiclass.get("details", {})
        label = details.get("predicted_label")
        if label:
            pieces.append(f"The multi-class model predicted {label!r}; its scores are uncalibrated class evidence.")
    else:
        pieces.append("Multi-class detector evidence was unavailable.")
    anomaly = evidence.get("anomaly", {})
    if anomaly.get("availability_status") == "available":
        details = anomaly.get("details", {})
        if details.get("decision") == "ANOMALOUS":
            percentile = highest_event.get("normalized_evidence", {}).get("anomaly", {}).get("normalized_value")
            pieces.append(
                f"The anomaly detector marked the flow ANOMALOUS at score {details.get('standardized_anomaly_score'):.6g} above calibrated threshold {details.get('threshold'):.6g}; its benign-reference percentile was {percentile:.1%}. This percentile describes unusualness, not malicious probability."
            )
        else:
            pieces.append(f"The anomaly detector marked the flow NORMAL at score {details.get('standardized_anomaly_score'):.6g} against threshold {details.get('threshold'):.6g}.")
    else:
        pieces.append("Anomaly detector evidence was unavailable.")
    if highest_event.get("detector_disagreements"):
        pieces.append("Detector disagreement: " + ", ".join(highest_event["detector_disagreements"]) + ".")
    score_parts = []
    for name in highest_event.get("score_breakdown", {}).get("available_signals", []):
        detail = highest_event["score_breakdown"]["signal_breakdown"][name]
        score_parts.append(f"{name} {detail['normalized_value']:.3f} (weight {detail['configured_weight']:.2f})")
    if score_parts:
        pieces.append(f"Heuristic threat score {maximum:.2f}/100 used " + ", ".join(score_parts) + "; it is a prioritization score, not probability of compromise.")
    missing = [name for name, value in evidence.items() if value.get("availability_status") != "available"]
    if missing:
        pieces.append("Unavailable evidence: " + ", ".join(missing) + ".")
    if alert_type == "SINGLE_FLOW_SUSPICION" and not highest_event.get("timestamp_utc"):
        pieces.append("No usable event timestamp was present, so temporal correlation was skipped.")
    return " ".join(pieces)


def _evidence_summary(events: list[dict[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for detector in ("binary", "multiclass", "anomaly"):
        statuses = Counter(event.get("normalized_evidence", {}).get(detector, {}).get("availability_status", "unavailable") for event in events)
        labels = Counter()
        for event in events:
            item = event.get("normalized_evidence", {}).get(detector, {})
            details = item.get("details", {})
            label = details.get("predicted_label") or details.get("decision")
            if label is not None:
                labels[str(label)] += 1
        result[detector] = {"availability_statuses": dict(statuses), "decision_counts": dict(labels)}
    return result


def _has_positive_detection(event: Mapping[str, Any]) -> bool:
    for name in ("binary", "multiclass", "anomaly"):
        item = event.get("normalized_evidence", {}).get(name, {})
        if item.get("availability_status") != "available":
            continue
        details = item.get("details", {})
        if details.get("malicious_prediction") is True or details.get("predicted_attack") is True or details.get("decision") == "ANOMALOUS":
            return True
    return False


def _mapping(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    if hasattr(value, "to_dict"):
        return value.to_dict()
    raise TypeError("Alerts must be generated from dictionaries or typed event records.")


def _unique_dicts(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    keyed = {json.dumps(row, sort_keys=True, separators=(",", ":")): row for row in rows}
    return [keyed[key] for key in sorted(keyed)]


def _severity_rank(value: str) -> int:
    return {"UNSCORED": -1, "LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}.get(value.upper(), -1)
