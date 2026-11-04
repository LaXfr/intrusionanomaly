"""Normalize existing detector outputs without discarding their raw values."""

from __future__ import annotations

import math
import re
from typing import Any, Iterable

import numpy as np

from intrusion_intelligence.intelligence.schemas import SignalEvidence, json_safe

BENIGN_LABEL = "BENIGN"


class EmpiricalScoreReference:
    """Sorted benign reference scores with efficient repeated percentile queries."""

    def __init__(self, scores: Iterable[float]) -> None:
        values = np.asarray(list(scores), dtype=np.float64)
        if values.ndim != 1 or not len(values) or not np.isfinite(values).all():
            raise ValueError("Anomaly percentile reference must be a non-empty finite score vector.")
        self.scores = np.sort(values)

    def percentile(self, score: float) -> float:
        return float(np.searchsorted(self.scores, score, side="right") / len(self.scores))


def unavailable_signal(name: str, reason: str = "detector output was not supplied") -> SignalEvidence:
    return SignalEvidence(
        source_detector=name,
        interpretation=reason,
        availability_status="unavailable",
        validation_status="not_run",
        details={"reason": reason},
    )


def normalize_binary_output(output: dict[str, Any] | None) -> SignalEvidence:
    """Use a binary model's malicious-class score or an explicit hard decision."""
    if output is None:
        return unavailable_signal("binary")
    raw = dict(output)
    model_id = _optional_text(raw.get("model_id"))
    model_version = _optional_text(raw.get("model_version")) or _version_from_id(model_id)
    score = raw.get("malicious_score", raw.get("malicious_probability", raw.get("positive_class_score")))
    scores = raw.get("class_scores", raw.get("probabilities"))
    if score is None and isinstance(scores, dict):
        score = scores.get("MALICIOUS", scores.get("ATTACK"))
    decision = _binary_decision(raw.get("predicted_label", raw.get("prediction", raw.get("predicted_class"))))
    threshold = raw.get("threshold", raw.get("decision_threshold"))
    if score is not None:
        value = _probability(score)
        if value is None:
            return _invalid("binary", raw, "malicious-class score must be a finite number in [0, 1]", model_id, model_version)
        if threshold is not None:
            threshold_value = _finite_float(threshold)
            if threshold_value is None or not 0 <= threshold_value <= 1:
                return _invalid("binary", raw, "binary threshold must be in [0, 1]", model_id, model_version)
            if decision is None:
                decision = value >= threshold_value
            elif decision != (value >= threshold_value):
                return _invalid("binary", raw, "binary decision conflicts with the supplied score and threshold", model_id, model_version)
        details = {
            "predicted_label": json_safe(raw.get("predicted_label", raw.get("prediction"))),
            "malicious_score": value,
            "decision_threshold": None if threshold is None else float(threshold),
            "malicious_prediction": decision,
            "score_semantics": "uncalibrated model score unless explicitly calibrated by its source",
            "score_is_calibrated_probability": bool(raw.get("score_is_calibrated_probability", False)),
        }
        return SignalEvidence(
            source_detector="binary",
            original_value=json_safe(raw),
            normalized_value=value,
            interpretation="malicious-class model score; not a compromise probability",
            availability_status="available",
            model_id=model_id,
            model_version=model_version,
            calibration_status="calibrated_probability" if details["score_is_calibrated_probability"] else "uncalibrated_score",
            validation_status="valid",
            details=details,
        )
    if decision is None:
        return _invalid("binary", raw, "binary output needs a malicious score or a recognized hard prediction", model_id, model_version)
    return SignalEvidence(
        source_detector="binary",
        original_value=json_safe(raw),
        normalized_value=1.0 if decision else 0.0,
        interpretation="categorical malicious prediction indicator; not a probability",
        availability_status="available",
        model_id=model_id,
        model_version=model_version,
        calibration_status="hard_prediction_only",
        validation_status="valid",
        details={
            "predicted_label": json_safe(raw.get("predicted_label", raw.get("prediction", raw.get("predicted_class")))),
            "malicious_prediction": bool(decision),
            "decision_threshold": None if threshold is None else json_safe(threshold),
            "score_semantics": "hard prediction indicator; no probability was supplied",
        },
    )


def normalize_multiclass_output(
    output: dict[str, Any] | None,
    *,
    class_labels: Iterable[str] | None = None,
) -> SignalEvidence:
    """Derive attack evidence only from a valid documented class mapping."""
    if output is None:
        return unavailable_signal("multiclass")
    raw = dict(output)
    model_id = _optional_text(raw.get("model_id"))
    model_version = _optional_text(raw.get("model_version")) or _version_from_id(model_id)
    scores = raw.get("class_scores", raw.get("probabilities"))
    labels = tuple(map(str, class_labels or raw.get("class_labels", ())))
    predicted_label = raw.get("predicted_label", raw.get("prediction"))
    predicted_class = raw.get("predicted_class", raw.get("class_id"))
    if isinstance(scores, dict):
        if not labels:
            labels = tuple(map(str, scores.keys()))
        if set(scores) != set(labels) or BENIGN_LABEL not in labels:
            return _invalid("multiclass", raw, "class scores do not match a documented taxonomy containing BENIGN", model_id, model_version)
        values = [_probability(scores[label]) for label in labels]
        if any(value is None for value in values) or not math.isclose(sum(values), 1.0, abs_tol=1e-3, rel_tol=1e-3):
            return _invalid("multiclass", raw, "class scores must be a finite normalized distribution", model_id, model_version)
        score_map = {label: float(scores[label]) for label in labels}
        if predicted_label is None and predicted_class is not None and labels:
            class_id = _nonnegative_int(predicted_class)
            if class_id is None or class_id >= len(labels):
                return _invalid("multiclass", raw, "predicted class identifier is outside the documented taxonomy", model_id, model_version)
            predicted_label = labels[class_id]
        if predicted_label is not None and str(predicted_label) not in labels:
            return _invalid("multiclass", raw, "predicted label is outside the documented taxonomy", model_id, model_version)
        if predicted_class is not None and predicted_label is not None and labels:
            class_id = _nonnegative_int(predicted_class)
            if class_id is None or class_id >= len(labels) or labels[class_id] != str(predicted_label):
                return _invalid("multiclass", raw, "predicted class identifier and label disagree", model_id, model_version)
        benign_score = score_map[BENIGN_LABEL]
        return SignalEvidence(
            source_detector="multiclass",
            original_value=json_safe(raw),
            normalized_value=1.0 - benign_score,
            interpretation="one minus BENIGN predict_proba score; uncalibrated supervised evidence, not compromise probability",
            availability_status="available",
            model_id=model_id,
            model_version=model_version,
            calibration_status="valid_probability_distribution_uncalibrated",
            validation_status="valid",
            details={
                "predicted_label": None if predicted_label is None else str(predicted_label),
                "predicted_class": None if predicted_class is None else int(predicted_class),
                "class_scores": score_map,
                "benign_class_score": benign_score,
                "attack_evidence_method": "1 - benign_class_score",
                "score_is_calibrated_probability": False,
                "predicted_attack": None if predicted_label is None else str(predicted_label) != BENIGN_LABEL,
                "class_labels": list(labels),
            },
        )
    if predicted_label is None and predicted_class is not None:
        class_id = _nonnegative_int(predicted_class)
        if class_id is None or not labels or class_id >= len(labels):
            return _invalid("multiclass", raw, "hard class identifier requires a valid documented taxonomy", model_id, model_version)
        predicted_label = labels[class_id]
    if predicted_label is None or not labels or str(predicted_label) not in labels or BENIGN_LABEL not in labels:
        return _invalid("multiclass", raw, "hard prediction is missing or outside the documented taxonomy", model_id, model_version)
    class_id = _nonnegative_int(predicted_class) if predicted_class is not None else None
    if class_id is not None and labels[class_id] != str(predicted_label):
        return _invalid("multiclass", raw, "predicted class identifier and label disagree", model_id, model_version)
    is_attack = str(predicted_label) != BENIGN_LABEL
    return SignalEvidence(
        source_detector="multiclass",
        original_value=json_safe(raw),
        normalized_value=1.0 if is_attack else 0.0,
        interpretation="categorical attack prediction indicator; no probability was supplied",
        availability_status="available",
        model_id=model_id,
        model_version=model_version,
        calibration_status="hard_prediction_only",
        validation_status="valid",
        details={
            "predicted_label": str(predicted_label),
            "predicted_class": class_id,
            "predicted_attack": is_attack,
            "class_scores": None,
            "benign_class_score": None,
            "attack_evidence_method": "hard_prediction_indicator",
            "score_is_calibrated_probability": False,
            "class_labels": list(labels),
        },
    )


def normalize_anomaly_output(
    output: dict[str, Any] | None,
    *,
    benign_reference_scores: Iterable[float] | EmpiricalScoreReference | None = None,
) -> SignalEvidence:
    """Convert higher-is-more-anomalous scores to a benign-reference percentile."""
    if output is None:
        return unavailable_signal("anomaly")
    raw = dict(output)
    model_id = _optional_text(raw.get("model_id"))
    model_version = _optional_text(raw.get("model_version")) or _version_from_id(model_id)
    score = _finite_float(raw.get("anomaly_score", raw.get("standardized_anomaly_score")))
    threshold = _finite_float(raw.get("threshold", raw.get("calibrated_threshold")))
    decision = _anomaly_decision(raw.get("decision", raw.get("anomaly_decision")))
    if score is None or threshold is None or decision is None:
        return _invalid("anomaly", raw, "anomaly output needs finite score, threshold, and NORMAL/ANOMALOUS decision", model_id, model_version)
    expected = score > threshold
    if expected != decision:
        return _invalid("anomaly", raw, "anomaly decision conflicts with the score and strict threshold rule", model_id, model_version)
    reference: EmpiricalScoreReference | None = None
    if benign_reference_scores is not None:
        try:
            reference = benign_reference_scores if isinstance(benign_reference_scores, EmpiricalScoreReference) else EmpiricalScoreReference(benign_reference_scores)
        except (TypeError, ValueError):
            reference = None
    if reference is not None:
        percentile = reference.percentile(score)
        normalized = min(1.0, max(0.0, percentile))
        method = "empirical_benign_validation_percentile_right_ecdf"
        calibration_status = "empirical_validation_reference"
        interpretation = "percentile relative to benign validation scores; unusualness, not malicious probability"
    else:
        normalized = 1.0 if decision else 0.0
        method = "calibrated_threshold_decision_indicator"
        calibration_status = "threshold_only_reference_unavailable"
        interpretation = "threshold-based anomaly indicator; no percentile reference was available"
    return SignalEvidence(
        source_detector="anomaly",
        original_value=json_safe(raw),
        normalized_value=normalized,
        interpretation=interpretation,
        availability_status="available",
        model_id=model_id,
        model_version=model_version,
        calibration_status=calibration_status,
        validation_status="valid",
        details={
            "raw_model_score": json_safe(raw.get("raw_model_score")),
            "standardized_anomaly_score": score,
            "threshold": threshold,
            "decision": "ANOMALOUS" if decision else "NORMAL",
            "operating_point": json_safe(raw.get("operating_point")),
            "normalization_method": method,
            "normalization_reference": "benign validation scores" if reference is not None else None,
            "reference_observations": None if reference is None else int(len(reference.scores)),
            "preprocessing_version": json_safe(raw.get("preprocessing_version")),
            "feature_schema_version": json_safe(raw.get("feature_schema_version")),
        },
    )


def normalize_detector_outputs(
    *,
    binary: dict[str, Any] | None = None,
    multiclass: dict[str, Any] | None = None,
    anomaly: dict[str, Any] | None = None,
    class_labels: Iterable[str] | None = None,
    benign_reference_scores: Iterable[float] | None = None,
) -> dict[str, SignalEvidence]:
    return {
        "binary": normalize_binary_output(binary),
        "multiclass": normalize_multiclass_output(multiclass, class_labels=class_labels),
        "anomaly": normalize_anomaly_output(anomaly, benign_reference_scores=benign_reference_scores),
    }


def _invalid(name: str, raw: dict[str, Any], reason: str, model_id: str | None, model_version: str | None) -> SignalEvidence:
    return SignalEvidence(
        source_detector=name,
        original_value=json_safe(raw),
        interpretation=reason,
        availability_status="invalid",
        model_id=model_id,
        model_version=model_version,
        validation_status="invalid",
        details={"reason": reason},
    )


def _finite_float(value: Any) -> float | None:
    if isinstance(value, (bool, np.bool_)):
        return None
    try:
        result = float(value)
    except (TypeError, ValueError, OverflowError):
        return None
    return result if math.isfinite(result) else None


def _probability(value: Any) -> float | None:
    result = _finite_float(value)
    return result if result is not None and 0.0 <= result <= 1.0 else None


def _optional_text(value: Any) -> str | None:
    return None if value is None or str(value).strip() == "" else str(value)


def _version_from_id(model_id: str | None) -> str | None:
    match = re.search(r"(?:^|[-_])v?(\d+\.\d+\.\d+)$", model_id or "")
    return match.group(1) if match else None


def _binary_decision(value: Any) -> bool | None:
    if isinstance(value, (bool, np.bool_)):
        return bool(value)
    text = str(value).strip().upper() if value is not None else ""
    if text in {"MALICIOUS", "ATTACK", "INTRUSION", "1", "TRUE", "ANOMALOUS"}:
        return True
    if text in {"BENIGN", "NORMAL", "0", "FALSE", "NON-MALICIOUS"}:
        return False
    return None


def _anomaly_decision(value: Any) -> bool | None:
    if isinstance(value, (bool, np.bool_)):
        return bool(value)
    text = str(value).strip().upper() if value is not None else ""
    if text in {"ANOMALOUS", "ANOMALY", "1", "TRUE"}:
        return True
    if text in {"NORMAL", "0", "FALSE"}:
        return False
    return None


def _nonnegative_int(value: Any) -> int | None:
    try:
        parsed = int(value)
    except (TypeError, ValueError, OverflowError):
        return None
    return parsed if parsed >= 0 and parsed == value else None
