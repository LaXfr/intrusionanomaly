"""Validated model and explanation records used by Phase 10."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

import numpy as np


class ExplainabilityError(ValueError):
    """Raised when an explanation request violates an artifact or data contract."""


@dataclass(frozen=True, slots=True)
class ExplanationOutput:
    name: str
    index: int
    semantic: str
    class_label: str | None = None
    class_id: int | None = None


@dataclass(slots=True)
class ExplanationRecord:
    explanation_id: str
    model_id: str
    model_version: str
    model_family: str
    explainer_type: str
    output_name: str
    output_semantics: str
    explanation_representation: str
    predicted_label: str | None
    predicted_class_id: int | None
    model_output_value: float
    decision_threshold: float | None
    decision_threshold_space: str | None
    persisted_decision_threshold: float | None
    reference_dataset_id: str
    feature_names: list[str]
    transformed_feature_contributions: list[dict[str, Any]]
    original_feature_contributions: list[dict[str, Any]]
    positive_contributions: list[dict[str, Any]]
    negative_contributions: list[dict[str, Any]]
    top_influential_features: list[dict[str, Any]]
    expected_value: float
    additivity_diagnostic: dict[str, Any]
    explanation_summary: str
    flow_record_reference: str | None = None
    source_filename: str | None = None
    source_row_number: int | None = None
    configuration: dict[str, Any] = field(default_factory=dict)
    explanation_status: str = "available"
    explanation_timestamp_utc: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds")
    )

    def to_dict(self) -> dict[str, Any]:
        return _json_safe(asdict(self))


def _json_safe(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(item) for item in value]
    if isinstance(value, np.ndarray):
        return _json_safe(value.tolist())
    if isinstance(value, np.generic):
        return value.item()
    if isinstance(value, float) and not np.isfinite(value):
        return None
    return value
