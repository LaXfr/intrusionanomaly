"""Typed, serializable records for normalized detection evidence and alerts."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import date, datetime
from pathlib import Path
from typing import Any

import numpy as np


def json_safe(value: Any) -> Any:
    """Convert common NumPy/Pandas/path/datetime values into JSON-safe values."""
    if value is None or isinstance(value, (str, bool, int, float)):
        if isinstance(value, float) and not np.isfinite(value):
            return None
        return value
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, np.generic):
        return json_safe(value.item())
    if isinstance(value, np.ndarray):
        return [json_safe(item) for item in value.tolist()]
    if isinstance(value, dict):
        return {str(key): json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [json_safe(item) for item in value]
    if hasattr(value, "isoformat"):
        try:
            return value.isoformat()
        except (TypeError, ValueError):
            pass
    if hasattr(value, "item"):
        try:
            return json_safe(value.item())
        except (TypeError, ValueError):
            pass
    return str(value)


@dataclass(frozen=True, slots=True)
class SignalEvidence:
    """One detector result, retaining original and normalized evidence."""

    source_detector: str
    original_value: Any = None
    normalized_value: float | None = None
    interpretation: str = ""
    availability_status: str = "unavailable"
    model_id: str | None = None
    model_version: str | None = None
    calibration_status: str | None = None
    validation_status: str = "not_run"
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return json_safe(asdict(self))


@dataclass(frozen=True, slots=True)
class FlowDetectionEvent:
    """Traceable analysis for one source flow record."""

    event_id: str
    event_fingerprint: str
    flow_record_reference: str
    source_filename: str | None
    source_row_number: int | None
    timestamp_utc: str | None
    flow_id: str | None
    network_context: dict[str, Any]
    metadata_provenance: dict[str, Any]
    detector_results: dict[str, Any]
    normalized_evidence: dict[str, Any]
    threat_score: float | None
    severity: str
    score_breakdown: dict[str, Any]
    event_status: str
    detector_disagreements: list[str]
    model_versions: dict[str, str | None]
    feature_schema_version: str | None
    pipeline_version: str
    generated_at_utc: str
    validation_warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return json_safe(asdict(self))


@dataclass(frozen=True, slots=True)
class CorrelatedEventGroup:
    """A set of suspicious events linked by one explicit rule and time window."""

    group_id: str
    correlation_rule: str
    correlation_key: dict[str, Any]
    correlation_window_minutes: int
    event_ids: list[str]
    event_fingerprints: list[str]
    unique_event_count: int
    unique_flow_count: int
    first_observed_utc: str
    last_observed_utc: str
    network_context: dict[str, Any]
    predicted_attack_category: str | None
    attack_category_counts: dict[str, int]
    detector_decision_counts: dict[str, dict[str, int]]
    maximum_threat_score: float
    mean_threat_score: float
    highest_severity: str
    distinct_destination_services: int
    validation_warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return json_safe(asdict(self))


@dataclass(frozen=True, slots=True)
class SecurityAlert:
    """Exportable alert record; lifecycle starts at NEW and is not persisted."""

    alert_id: str
    alert_fingerprint: str
    alert_type: str
    created_at_utc: str
    status: str
    severity: str
    threat_score: float
    mean_threat_score: float
    attack_categories: list[str]
    detection_status: str
    correlation_rules: list[str]
    correlation_keys: list[dict[str, Any]]
    first_observed_utc: str | None
    last_observed_utc: str | None
    related_event_count: int
    related_flow_count: int
    supporting_event_ids: list[str]
    network_context: dict[str, Any]
    detector_evidence_summary: dict[str, Any]
    detector_disagreements: list[str]
    scoring_breakdown: dict[str, Any]
    title: str
    explanation: str
    investigation_steps: list[str]
    known_limitations: list[str]
    severity_history: list[str]
    duplicate_updates: list[dict[str, Any]] = field(default_factory=list)
    model_versions: dict[str, str | None] = field(default_factory=dict)
    missing_detector_evidence: list[str] = field(default_factory=list)
    severity_rationale: str = ""
    confidence_limitations: list[str] = field(default_factory=list)
    ground_truth_evaluation_status: str = "not_evaluated"

    def to_dict(self) -> dict[str, Any]:
        return json_safe(asdict(self))
