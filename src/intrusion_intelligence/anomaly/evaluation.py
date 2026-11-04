"""Thresholded and score-based evaluation for benign-baseline anomaly models."""

from __future__ import annotations

from typing import Any, Iterable

import numpy as np
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    balanced_accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)

from intrusion_intelligence.anomaly.data import BENIGN_LABEL, validate_original_labels


class AnomalyEvaluationError(ValueError):
    """Raised when original labels and anomaly scores cannot be evaluated."""


def evaluate_operating_point(
    original_labels: Iterable[str],
    anomaly_scores: Iterable[float],
    threshold: float,
    *,
    allowed_labels: Iterable[str],
    benign_label: str = BENIGN_LABEL,
) -> dict[str, Any]:
    """Evaluate one frozen threshold; attack labels are used only here."""
    labels = validate_original_labels(original_labels, allowed_labels, benign_label=benign_label)
    scores = np.asarray(list(anomaly_scores), dtype=np.float64)
    if scores.ndim != 1 or len(scores) != len(labels):
        raise AnomalyEvaluationError("Original labels and anomaly scores must have equal one-dimensional lengths.")
    if not len(scores) or not np.isfinite(scores).all() or not np.isfinite(float(threshold)):
        raise AnomalyEvaluationError("Evaluation needs non-empty finite scores and a finite threshold.")
    truth = (labels != benign_label).astype(np.uint8)
    predicted = (scores > float(threshold)).astype(np.uint8)
    matrix = confusion_matrix(truth, predicted, labels=[0, 1])
    tn, fp, fn, tp = (int(value) for value in matrix.ravel())
    negatives, positives = tn + fp, tp + fn
    has_both_classes = negatives > 0 and positives > 0
    return {
        "threshold": float(threshold),
        "comparison": "anomalous if anomaly_score > threshold; equality is NORMAL",
        "observations": int(len(scores)),
        "benign_support": int(negatives),
        "attack_support": int(positives),
        "true_negative": tn,
        "false_positive": fp,
        "false_negative": fn,
        "true_positive": tp,
        "confusion_matrix_labels": ["BENIGN", "ATTACK"],
        "confusion_matrix": matrix.tolist(),
        "attack_precision": _ratio(tp, tp + fp),
        "attack_recall": _ratio(tp, positives),
        "attack_f1": _ratio(2 * tp, 2 * tp + fp + fn),
        "false_positive_rate": _ratio(fp, negatives),
        "false_negative_rate": _ratio(fn, positives),
        "specificity": _ratio(tn, negatives),
        "balanced_accuracy": float(balanced_accuracy_score(truth, predicted)) if has_both_classes else None,
        "accuracy": float(accuracy_score(truth, predicted)),
        "roc_auc": float(roc_auc_score(truth, scores)) if has_both_classes else None,
        "average_precision": float(average_precision_score(truth, scores)) if positives else None,
        "score_summary": {
            "benign_mean": float(np.mean(scores[truth == 0])) if negatives else None,
            "benign_median": float(np.median(scores[truth == 0])) if negatives else None,
            "attack_mean": float(np.mean(scores[truth == 1])) if positives else None,
            "attack_median": float(np.median(scores[truth == 1])) if positives else None,
        },
        "undefined_metric_status": {
            "roc_auc": None if has_both_classes else "undefined: evaluation contains only one binary class",
            "average_precision": None if positives else "undefined: no attack observations are present",
            "attack_recall": None if positives else "undefined: no attack observations are present",
            "false_positive_rate": None if negatives else "undefined: no benign observations are present",
        },
    }


def per_attack_category_summary(
    original_labels: Iterable[str],
    anomaly_scores: Iterable[float],
    threshold: float,
    *,
    allowed_labels: Iterable[str],
    benign_label: str = BENIGN_LABEL,
) -> list[dict[str, Any]]:
    """Report threshold detection and score distribution for every known attack."""
    labels = validate_original_labels(original_labels, allowed_labels, benign_label=benign_label)
    scores = np.asarray(list(anomaly_scores), dtype=np.float64)
    if len(labels) != len(scores) or not np.isfinite(scores).all():
        raise AnomalyEvaluationError("Per-category labels and finite scores must be row-aligned.")
    records: list[dict[str, Any]] = []
    for label in allowed_labels:
        if label == benign_label:
            continue
        selected = scores[labels == label]
        detected = int(np.count_nonzero(selected > threshold))
        support = int(len(selected))
        records.append(
            {
                "original_label": str(label),
                "test_support": support,
                "detected_as_anomalous": detected,
                "classified_as_normal": support - detected,
                "detection_recall": detected / support if support else None,
                "mean_anomaly_score": float(np.mean(selected)) if support else None,
                "median_anomaly_score": float(np.median(selected)) if support else None,
                "score_std": float(np.std(selected)) if support else None,
                "score_min": float(np.min(selected)) if support else None,
                "score_max": float(np.max(selected)) if support else None,
                "status": "evaluated" if support else "not represented in held-out capture-day test",
            }
        )
    return records


def _ratio(numerator: int, denominator: int) -> float | None:
    return float(numerator / denominator) if denominator else None

