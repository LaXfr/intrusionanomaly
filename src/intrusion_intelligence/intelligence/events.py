"""Generate traceable flow-level events without changing model predictions."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Mapping

import pandas as pd

from intrusion_intelligence.intelligence.schemas import FlowDetectionEvent, SignalEvidence, json_safe
from intrusion_intelligence.intelligence.severity import DEFAULT_BANDS, assign_severity

NETWORK_FIELDS = ("source_ip", "destination_ip", "source_port", "destination_port", "protocol", "capture_group")


def build_flow_event(
    record: Mapping[str, Any],
    evidence: Mapping[str, SignalEvidence],
    score_breakdown: Mapping[str, Any],
    *,
    pipeline_version: str = "1.0.0",
    feature_schema_version: str | None = None,
    severity_bands: tuple[dict[str, Any], ...] = DEFAULT_BANDS,
    now: datetime | None = None,
    row_position: int = 0,
) -> FlowDetectionEvent:
    """Build one stable event ID and retain all available detector values."""
    source_file = _first(record, "source_filename", "source_file", "__source_file")
    row_number = _int_or_none(_first(record, "source_row_number", "__source_row_number"))
    record_ref = _first(record, "flow_record_reference", "source_record_reference", "__record_id", "record_id")
    if record_ref is None and source_file is not None and row_number is not None:
        record_ref = f"{source_file}#row={row_number}"
    unassociated = record_ref is None
    if unassociated:
        record_ref = f"unassociated-row:{row_position}"

    timestamp_value = _first(record, "timestamp", "event_timestamp", "timestamp_utc", "__timestamp")
    timestamp_utc, timestamp_error = _timestamp_utc(timestamp_value)
    warnings: list[str] = []
    if unassociated:
        warnings.append("No stable source record reference was supplied; row-position reference is run-local.")
    if timestamp_error:
        warnings.append(timestamp_error)
    network_context = {
        name: json_safe(_first(record, name, f"{name}_value"))
        for name in NETWORK_FIELDS
        if _first(record, name, f"{name}_value") is not None
    }
    missing_fields = [name for name in ("source_ip", "destination_ip", "timestamp") if name not in network_context and name != "timestamp"]
    if timestamp_utc is None:
        missing_fields.append("timestamp")
    if missing_fields:
        warnings.append("Unavailable correlation metadata: " + ", ".join(sorted(set(missing_fields))) + ".")

    signal_docs = {name: evidence[name].to_dict() for name in ("binary", "multiclass", "anomaly")}
    raw_results = {
        name: None if evidence[name].availability_status == "unavailable" else json_safe(evidence[name].original_value)
        for name in ("binary", "multiclass", "anomaly")
    }
    disagreements = detector_disagreements(evidence)
    score = score_breakdown.get("threat_score")
    score_value = None if score is None else float(score)
    positive = _positive_signals(evidence)
    if score_value is None:
        status = "INSUFFICIENT_EVIDENCE"
    elif not positive:
        status = "NORMAL"
    elif len(positive) >= 2:
        status = "SUSPICIOUS"
    elif "anomaly" in positive:
        status = "ANOMALOUS"
    else:
        status = "MALICIOUS_PREDICTION"
    model_versions = {name: evidence[name].model_version for name in ("binary", "multiclass", "anomaly")}
    flow_id = _text_or_none(_first(record, "flow_id", "Flow ID", "flowId"))
    event_payload = {
        "pipeline_version": pipeline_version,
        "flow_record_reference": str(record_ref),
        "source_filename": source_file,
        "source_row_number": row_number,
        "network_context": network_context,
        "timestamp_utc": timestamp_utc,
        # Keep the complete raw outputs on the event, but do not let volatile
        # inference timestamps defeat repeat-run idempotency.
        "detectors": _fingerprint_value(raw_results),
        "scoring_config_version": score_breakdown.get("scoring_config_version"),
    }
    fingerprint = _digest(event_payload)
    event_id = "evt_" + _digest({"pipeline_version": pipeline_version, "flow_record_reference": str(record_ref)})[:24]
    generated = now or datetime.now(timezone.utc)
    if generated.tzinfo is None:
        generated = generated.replace(tzinfo=timezone.utc)
    return FlowDetectionEvent(
        event_id=event_id,
        event_fingerprint=fingerprint,
        flow_record_reference=str(record_ref),
        source_filename=_text_or_none(source_file),
        source_row_number=row_number,
        timestamp_utc=timestamp_utc,
        flow_id=flow_id,
        network_context=network_context,
        metadata_provenance=json_safe(record.get("metadata_provenance", {
            name: {"status": "observed" if _first(record, name) is not None else "unavailable", "origin": "caller_supplied" if _first(record, name) is not None else None}
            for name in (*NETWORK_FIELDS, "timestamp", "flow_id")
        })),
        detector_results=raw_results,
        normalized_evidence=signal_docs,
        threat_score=score_value,
        severity=assign_severity(score_value, severity_bands),
        score_breakdown=dict(score_breakdown),
        event_status=status,
        detector_disagreements=disagreements,
        model_versions=model_versions,
        feature_schema_version=feature_schema_version,
        pipeline_version=pipeline_version,
        generated_at_utc=generated.astimezone(timezone.utc).isoformat(timespec="seconds"),
        validation_warnings=warnings,
    )


def detector_disagreements(evidence: Mapping[str, SignalEvidence]) -> list[str]:
    """Return explicit disagreements among valid detector decisions."""
    binary = evidence.get("binary")
    multi = evidence.get("multiclass")
    anomaly = evidence.get("anomaly")
    binary_positive = _binary_attack(binary)
    multi_positive = _multiclass_attack(multi)
    anomaly_positive = _anomaly_positive(anomaly)
    flags: list[str] = []
    supervised_present = binary_positive is not None or multi_positive is not None
    supervised_benign = (binary_positive is False) or (multi_positive is False)
    supervised_attack = (binary_positive is True) or (multi_positive is True)
    if binary_positive is False and multi_positive is True:
        flags.append("binary_predicts_benign_multiclass_predicts_attack")
    if binary_positive is True and multi_positive is False:
        flags.append("binary_predicts_malicious_multiclass_predicts_benign")
    if anomaly_positive is True and supervised_benign:
        flags.append("anomaly_flags_flow_supervised_engine_predicts_benign")
    if anomaly_positive is False and supervised_attack:
        flags.append("supervised_engine_predicts_attack_anomaly_is_normal")
    if binary_positive is True and multi_positive is True and anomaly_positive is True:
        flags.append("all_available_detection_families_indicate_suspicious_activity")
    if not supervised_present and anomaly_positive is not None:
        flags.append("supervised_engines_unavailable")
    return flags


def predicted_attack_category(event: Mapping[str, Any]) -> str | None:
    multi = event.get("normalized_evidence", {}).get("multiclass", {})
    if multi.get("availability_status") != "available":
        return None
    label = multi.get("details", {}).get("predicted_label")
    return str(label) if label and str(label) != "BENIGN" else None


def _positive_signals(evidence: Mapping[str, SignalEvidence]) -> list[str]:
    values = {
        "binary": _binary_attack(evidence.get("binary")),
        "multiclass": _multiclass_attack(evidence.get("multiclass")),
        "anomaly": _anomaly_positive(evidence.get("anomaly")),
    }
    return [name for name, value in values.items() if value is True]


def _binary_attack(signal: SignalEvidence | None) -> bool | None:
    if signal is None or signal.availability_status != "available":
        return None
    value = signal.details.get("malicious_prediction")
    return value if isinstance(value, bool) else None


def _multiclass_attack(signal: SignalEvidence | None) -> bool | None:
    if signal is None or signal.availability_status != "available":
        return None
    value = signal.details.get("predicted_attack")
    return value if isinstance(value, bool) else None


def _anomaly_positive(signal: SignalEvidence | None) -> bool | None:
    if signal is None or signal.availability_status != "available":
        return None
    decision = signal.details.get("decision")
    return True if decision == "ANOMALOUS" else False if decision == "NORMAL" else None


def _timestamp_utc(value: Any) -> tuple[str | None, str | None]:
    if value is None or str(value).strip() == "":
        return None, None
    try:
        timestamp = pd.Timestamp(value)
    except (TypeError, ValueError, OverflowError):
        return None, f"Invalid event timestamp {value!r}; temporal correlation disabled for this flow."
    if pd.isna(timestamp) or timestamp.tzinfo is None:
        return None, f"Event timestamp {value!r} is invalid or timezone-naive; temporal correlation disabled for this flow."
    return timestamp.tz_convert("UTC").isoformat(), None


def _first(record: Mapping[str, Any], *keys: str) -> Any:
    for key in keys:
        value = record.get(key)
        if value is not None and str(value).strip() not in {"", "<NA>", "nan"}:
            return value
    return None


def _int_or_none(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError, OverflowError):
        return None


def _text_or_none(value: Any) -> str | None:
    return None if value is None else str(value)


def _digest(value: Any) -> str:
    serialized = json.dumps(json_safe(value), sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


_VOLATILE_FINGERPRINT_KEYS = {
    "prediction_timestamp_utc",
    "predicted_at_utc",
    "inference_timestamp_utc",
    "processing_timestamp_utc",
    "generated_at_utc",
}


def _fingerprint_value(value: Any) -> Any:
    """Remove processing-time fields from the stable detector fingerprint only."""
    if isinstance(value, Mapping):
        return {
            str(key): _fingerprint_value(item)
            for key, item in value.items()
            if str(key).lower() not in _VOLATILE_FINGERPRINT_KEYS
        }
    if isinstance(value, list):
        return [_fingerprint_value(item) for item in value]
    if isinstance(value, tuple):
        return [_fingerprint_value(item) for item in value]
    return value
