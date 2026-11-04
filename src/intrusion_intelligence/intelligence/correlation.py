"""Rule-based temporal correlation that skips unavailable or invalid keys."""

from __future__ import annotations

import hashlib
import json
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable, Mapping

import pandas as pd

from intrusion_intelligence.intelligence.events import predicted_attack_category
from intrusion_intelligence.intelligence.schemas import CorrelatedEventGroup, json_safe

RULE_FIELDS: dict[str, tuple[str, ...]] = {
    "source_ip": ("source_ip",),
    "destination_ip": ("destination_ip",),
    "destination_service": ("destination_ip", "destination_port", "protocol"),
    "attack_category": ("source_ip", "destination_ip", "predicted_attack_category"),
    "repeated_flow_tuple": ("source_ip", "destination_ip", "source_port", "destination_port", "protocol"),
    "temporal_activity": ("source_ip", "destination_ip"),
    # Backward-compatible alias for configurations created before rule naming was clarified.
    "repeated_activity": ("source_ip", "destination_ip", "source_port", "destination_port", "protocol"),
}


class CorrelationError(ValueError):
    """Raised when correlation configuration is invalid."""


def correlate_events(
    events: Iterable[Any],
    *,
    enabled_rules: Iterable[str] = tuple(RULE_FIELDS),
    window_minutes: int = 5,
    allowed_windows_minutes: Iterable[int] = (1, 5, 15),
    minimum_events: int = 2,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Group suspicious events sharing explicit network keys in a time window.

    Missing timestamps or key fields disable a rule for that event. Events are
    sorted by parsed UTC time; input order is never used as a time proxy.
    """
    allowed = tuple(int(value) for value in allowed_windows_minutes)
    if window_minutes not in allowed or window_minutes <= 0:
        raise CorrelationError(f"window_minutes must be one of the configured values {allowed}.")
    if minimum_events < 2:
        raise CorrelationError("minimum_events must be at least 2 for correlation.")
    rules = tuple(enabled_rules)
    unknown = sorted(set(rules) - set(RULE_FIELDS))
    if unknown:
        raise CorrelationError(f"Unknown correlation rules: {unknown}.")
    event_rows = [_to_mapping(event) for event in events]
    suspicious_all = [event for event in event_rows if event.get("event_status") not in {"NORMAL", "INSUFFICIENT_EVIDENCE"}]
    unique_suspicious: dict[str, dict[str, Any]] = {}
    for event in suspicious_all:
        identity = str(event.get("event_fingerprint") or event.get("event_id"))
        unique_suspicious.setdefault(identity, event)
    suspicious = list(unique_suspicious.values())
    groups: list[dict[str, Any]] = []
    audit: dict[str, Any] = {
        "enabled_rules": list(rules),
        "window_minutes": int(window_minutes),
        "minimum_events": int(minimum_events),
        "suspicious_events_considered": len(suspicious),
        "duplicate_suspicious_event_inputs_suppressed": len(suspicious_all) - len(suspicious),
        "rule_definitions": {
            rule: {
                "required_fields": list(RULE_FIELDS[rule]),
                "eligibility": "suspicious event with all required non-empty values and timezone-aware timestamp",
                "key_definition": "exact string values of required fields; attack_category also requires both endpoint identities",
                "window_minutes": int(window_minutes),
                "minimum_group_size": int(minimum_events),
                "missing_field_behavior": "skip event for this rule and count reason",
            }
            for rule in rules
        },
        "groups_by_rule": {rule: 0 for rule in rules},
        "eligible_events_by_rule": {rule: 0 for rule in rules},
        "events_in_groups_by_rule": {rule: 0 for rule in rules},
        "eligible_events_without_group_by_rule": {rule: 0 for rule in rules},
        "events_skipped_by_rule": {rule: {"missing_timestamp": 0, "invalid_or_naive_timestamp": 0, "missing_key_fields": 0} for rule in rules},
        "temporal_correlation_supported": 0,
        "temporal_correlation_skipped": 0,
    }
    for rule in rules:
        required_fields = RULE_FIELDS[rule]
        buckets: dict[tuple[Any, ...], list[tuple[pd.Timestamp, dict[str, Any], dict[str, Any]]]] = defaultdict(list)
        eligible_ids: set[str] = set()
        for event in suspicious:
            raw_timestamp = event.get("timestamp_utc")
            timestamp = _parse_timestamp(raw_timestamp)
            if timestamp is None:
                warnings = " ".join(map(str, event.get("validation_warnings", []))).lower()
                invalid_marked = "timezone-naive" in warnings or "invalid event timestamp" in warnings
                reason = "invalid_or_naive_timestamp" if invalid_marked or (raw_timestamp is not None and str(raw_timestamp).strip()) else "missing_timestamp"
                audit["events_skipped_by_rule"][rule][reason] += 1
                continue
            key_map: dict[str, Any] = {}
            missing = False
            for field in required_fields:
                if field == "predicted_attack_category":
                    value = predicted_attack_category(event)
                else:
                    value = event.get("network_context", {}).get(field)
                if value is None or str(value).strip() in {"", "<NA>", "nan", "None"}:
                    missing = True
                    break
                key_map[field] = value
            if missing:
                audit["events_skipped_by_rule"][rule]["missing_key_fields"] += 1
                continue
            key = tuple(str(key_map[field]) for field in required_fields)
            buckets[key].append((timestamp, event, key_map))
            eligible_ids.add(str(event.get("event_id", event.get("event_fingerprint"))))
        audit["eligible_events_by_rule"][rule] = len(eligible_ids)
        rule_group_count = 0
        grouped_ids: set[str] = set()
        for key in sorted(buckets, key=lambda item: tuple(map(str, item))):
            rows = sorted(buckets[key], key=lambda item: (item[0], item[1].get("event_id", "")))
            start = 0
            while start < len(rows):
                first_timestamp = rows[start][0]
                end = start + 1
                latest = first_timestamp + timedelta(minutes=window_minutes)
                while end < len(rows) and rows[end][0] <= latest:
                    end += 1
                window_rows = rows[start:end]
                if len(window_rows) >= minimum_events:
                    group = _make_group(rule, key, required_fields, window_minutes, minimum_events, window_rows)
                    groups.append(group)
                    rule_group_count += 1
                    grouped_ids.update(group["event_ids"])
                start = end
        audit["groups_by_rule"][rule] = rule_group_count
        audit["events_in_groups_by_rule"][rule] = len(grouped_ids)
        audit["eligible_events_without_group_by_rule"][rule] = len(eligible_ids - grouped_ids)
    audit["temporal_correlation_supported"] = sum(audit["groups_by_rule"].values())
    audit["temporal_correlation_skipped"] = sum(
        count
        for rule_counts in audit["events_skipped_by_rule"].values()
        for count in rule_counts.values()
    )
    audit["correlated_event_references"] = sum(group["unique_event_count"] for group in groups)
    audit["unmatched_suspicious_events"] = len(suspicious) - len({event_id for group in groups for event_id in group["event_ids"]})
    return groups, audit


def _make_group(
    rule: str,
    key: tuple[Any, ...],
    required_fields: tuple[str, ...],
    window_minutes: int,
    minimum_events: int,
    rows: list[tuple[pd.Timestamp, dict[str, Any], dict[str, Any]]],
) -> dict[str, Any]:
    events = [item[1] for item in rows]
    timestamps = [item[0] for item in rows]
    event_ids = sorted({str(event["event_id"]) for event in events})
    fingerprints = sorted({str(event["event_fingerprint"]) for event in events})
    flow_refs = {str(event["flow_record_reference"]) for event in events}
    scores = [float(event["threat_score"]) for event in events if event.get("threat_score") is not None]
    category_counts = Counter(category for event in events if (category := predicted_attack_category(event)))
    detector_counts = _decision_counts(events)
    common_context = dict(zip(required_fields, key))
    services = {
        (
            str(event.get("network_context", {}).get("destination_ip")),
            str(event.get("network_context", {}).get("destination_port")),
            str(event.get("network_context", {}).get("protocol")),
        )
        for event in events
        if event.get("network_context", {}).get("destination_ip") is not None
        and event.get("network_context", {}).get("destination_port") is not None
    }
    highest = max((str(event.get("severity", "UNSCORED")) for event in events), key=_severity_rank)
    payload = {"rule": rule, "key": common_context, "window": window_minutes, "event_fingerprints": fingerprints}
    group_id = "grp_" + hashlib.sha256(json.dumps(json_safe(payload), sort_keys=True, separators=(",", ":")).encode()).hexdigest()[:24]
    most_frequent = sorted(category_counts.items(), key=lambda pair: (-pair[1], pair[0]))
    result = CorrelatedEventGroup(
        group_id=group_id,
        correlation_rule=rule,
        correlation_key=json_safe(common_context),
        correlation_window_minutes=int(window_minutes),
        event_ids=event_ids,
        event_fingerprints=fingerprints,
        unique_event_count=len(event_ids),
        unique_flow_count=len(flow_refs),
        first_observed_utc=timestamps[0].isoformat(),
        last_observed_utc=timestamps[-1].isoformat(),
        network_context=common_context,
        predicted_attack_category=most_frequent[0][0] if most_frequent else None,
        attack_category_counts=dict(category_counts),
        detector_decision_counts=detector_counts,
        maximum_threat_score=max(scores) if scores else 0.0,
        mean_threat_score=sum(scores) / len(scores) if scores else 0.0,
        highest_severity=highest,
        distinct_destination_services=len(services),
        validation_warnings=[],
    ).to_dict()
    result["explanation_metadata"] = {
        "rule": rule,
        "required_fields": list(required_fields),
        "key_values": json_safe(common_context),
        "window_minutes": int(window_minutes),
        "minimum_group_size": int(minimum_events),
        "grouping_basis": "explicit shared key plus timezone-aware observed timestamps; source row order is not used",
    }
    return result


def _decision_counts(events: list[dict[str, Any]]) -> dict[str, dict[str, int]]:
    counts = {name: Counter() for name in ("binary", "multiclass", "anomaly")}
    for event in events:
        evidence = event.get("normalized_evidence", {})
        for name in counts:
            item = evidence.get(name, {})
            status = item.get("availability_status", "unavailable")
            if status != "available":
                counts[name][status] += 1
                continue
            details = item.get("details", {})
            if name == "binary":
                decision = details.get("malicious_prediction")
            elif name == "multiclass":
                decision = details.get("predicted_attack")
            else:
                decision = details.get("decision") == "ANOMALOUS" if details.get("decision") in {"NORMAL", "ANOMALOUS"} else None
            counts[name]["positive" if decision is True else "negative" if decision is False else "available_no_decision"] += 1
    return {name: dict(counter) for name, counter in counts.items()}


def _parse_timestamp(value: Any) -> pd.Timestamp | None:
    if value is None:
        return None
    try:
        timestamp = pd.Timestamp(value)
    except (TypeError, ValueError, OverflowError):
        return None
    if pd.isna(timestamp) or timestamp.tzinfo is None:
        return None
    return timestamp.tz_convert("UTC")


def _to_mapping(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    if hasattr(value, "to_dict"):
        return value.to_dict()
    raise TypeError("Correlation events must be dictionaries or typed event records.")


def _severity_rank(value: str) -> int:
    return {"UNSCORED": -1, "LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}.get(value.upper(), -1)
