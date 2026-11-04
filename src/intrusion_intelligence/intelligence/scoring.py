"""Transparent deterministic weighted evidence scoring."""

from __future__ import annotations

import math
from typing import Any, Mapping

from intrusion_intelligence.intelligence.schemas import SignalEvidence

DEFAULT_WEIGHTS = {"binary": 0.30, "multiclass": 0.25, "anomaly": 0.45}


class ThreatScoringError(ValueError):
    """Raised when scoring weights or evidence fall outside the schema."""


def validate_weights(weights: Mapping[str, Any]) -> dict[str, float]:
    if set(weights) != set(DEFAULT_WEIGHTS):
        raise ThreatScoringError(f"Weights must define exactly {sorted(DEFAULT_WEIGHTS)}.")
    parsed: dict[str, float] = {}
    for name, value in weights.items():
        if isinstance(value, bool):
            raise ThreatScoringError(f"Weight {name!r} must be numeric.")
        try:
            number = float(value)
        except (TypeError, ValueError, OverflowError) as exc:
            raise ThreatScoringError(f"Weight {name!r} must be numeric.") from exc
        if not math.isfinite(number) or number < 0:
            raise ThreatScoringError(f"Weight {name!r} must be finite and non-negative.")
        parsed[name] = number
    if sum(parsed.values()) <= 0:
        raise ThreatScoringError("At least one evidence weight must be positive.")
    return parsed


def score_evidence(
    evidence: Mapping[str, SignalEvidence | Mapping[str, Any] | None],
    *,
    weights: Mapping[str, Any] = DEFAULT_WEIGHTS,
    scoring_version: str = "1.0.0",
    score_min: float = 0.0,
    score_max: float = 100.0,
) -> dict[str, Any]:
    """Score only available normalized evidence; unavailable signals are omitted."""
    weight_map = validate_weights(weights)
    if not math.isfinite(score_min) or not math.isfinite(score_max) or score_min >= score_max:
        raise ThreatScoringError("Score bounds must be finite and score_min < score_max.")
    breakdown: dict[str, Any] = {}
    available: list[str] = []
    unavailable: list[dict[str, str]] = []
    for name in DEFAULT_WEIGHTS:
        item = evidence.get(name)
        if item is None:
            status, value, reason, raw = "unavailable", None, "no result supplied", None
        elif isinstance(item, SignalEvidence):
            status, value, reason, raw = item.availability_status, item.normalized_value, item.interpretation, item.original_value
        else:
            status = str(item.get("availability_status", "unavailable"))
            value = item.get("normalized_value")
            reason = str(item.get("interpretation", item.get("validation_status", status)))
            raw = item.get("original_value")
        valid_value = _unit_value(value)
        weight = weight_map[name]
        if status != "available" or valid_value is None or weight <= 0:
            unavailable.append({"signal": name, "status": status if status != "available" else "invalid", "reason": reason})
            breakdown[name] = {
                "available": False,
                "availability_status": status,
                "original_value": raw,
                "normalized_value": valid_value,
                "configured_weight": weight,
                "contribution": 0.0,
                "reason": reason,
            }
            continue
        available.append(name)
        breakdown[name] = {
            "available": True,
            "availability_status": status,
            "original_value": raw,
            "normalized_value": valid_value,
            "configured_weight": weight,
            "contribution": weight * valid_value,
            "effective_weight": None,
            "interpretation": reason,
        }
    denominator = sum(weight_map[name] for name in available)
    if denominator <= 0:
        return {
            "threat_score": None,
            "score_min": score_min,
            "score_max": score_max,
            "available_signals": [],
            "unavailable_signals": unavailable,
            "signal_breakdown": breakdown,
            "scoring_config_version": scoring_version,
            "calculation_status": "insufficient_evidence",
            "formula": "100 * sum(configured_weight * normalized_evidence) / sum(available configured weights)",
            "correlated_signal_groups": {"supervised": ["binary", "multiclass"]},
        }
    for name in available:
        breakdown[name]["effective_weight"] = weight_map[name] / denominator
    numerator = sum(float(breakdown[name]["contribution"]) for name in available)
    score = score_min + (score_max - score_min) * (numerator / denominator)
    score = min(score_max, max(score_min, score))
    return {
        "threat_score": float(score),
        "score_min": score_min,
        "score_max": score_max,
        "available_signals": available,
        "unavailable_signals": unavailable,
        "signal_breakdown": breakdown,
        "scoring_config_version": scoring_version,
        "calculation_status": "calculated",
        "formula": "100 * sum(configured_weight * normalized_evidence) / sum(available configured weights)",
        "correlated_signal_groups": {"supervised": ["binary", "multiclass"]},
        "note": "Heuristic prioritization score; not a probability of compromise.",
    }


def _unit_value(value: Any) -> float | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        number = float(value)
    except (TypeError, ValueError, OverflowError):
        return None
    if not math.isfinite(number) or number < 0 or number > 1:
        return None
    return number
