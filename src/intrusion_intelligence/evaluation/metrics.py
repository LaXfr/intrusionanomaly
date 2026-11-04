"""Consistent classification and probability-quality metrics."""

from __future__ import annotations

from typing import Any, Sequence

import numpy as np
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    balanced_accuracy_score,
    brier_score_loss,
    confusion_matrix,
    f1_score,
    log_loss,
    matthews_corrcoef,
    precision_recall_fscore_support,
    precision_score,
    recall_score,
    roc_auc_score,
)


def binary_metrics(y_true: Sequence[Any], scores: Sequence[float], *, threshold: float, positive_label: Any = 1) -> dict[str, Any]:
    """Return positive-class metrics; ``scores`` must increase toward positive."""
    truth_raw = np.asarray(y_true)
    score = np.asarray(scores, dtype=np.float64)
    if truth_raw.ndim != 1 or score.ndim != 1 or len(truth_raw) != len(score) or not len(score):
        raise ValueError("Binary labels and scores must be non-empty, aligned one-dimensional vectors.")
    if not np.isfinite(score).all() or not np.isfinite(float(threshold)):
        raise ValueError("Binary scores and threshold must be finite.")
    truth = truth_raw == positive_label
    predicted = score >= float(threshold)
    tn, fp, fn, tp = confusion_matrix(truth, predicted, labels=[False, True]).ravel()
    precision = float(precision_score(truth, predicted, zero_division=0))
    recall = float(recall_score(truth, predicted, zero_division=0))
    f1 = float(f1_score(truth, predicted, zero_division=0))
    return {
        "observations": int(len(score)),
        "positive_label": str(positive_label),
        "positive_support": int(truth.sum()),
        "negative_support": int((~truth).sum()),
        "threshold": float(threshold),
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "balanced_accuracy": float(balanced_accuracy_score(truth, predicted)),
        "average_precision": float(average_precision_score(truth, score)) if truth.any() else None,
        "false_positive_rate": float(fp / (fp + tn)) if tn + fp else None,
        "false_negative_rate": float(fn / (fn + tp)) if fn + tp else None,
        "accuracy": float(accuracy_score(truth, predicted)),
        "specificity": float(tn / (tn + fp)) if tn + fp else None,
        "roc_auc": float(roc_auc_score(truth, score)) if truth.any() and (~truth).any() else None,
        "matthews_correlation_coefficient": float(matthews_corrcoef(truth, predicted)),
        "confusion_matrix_labels": ["BENIGN", str(positive_label)],
        "confusion_matrix": [[int(tn), int(fp)], [int(fn), int(tp)]],
        "score_is_calibrated_probability": False,
    }


def threshold_metrics(y_true: Sequence[Any], scores: Sequence[float], thresholds: Sequence[float], *, positive_label: Any = 1) -> list[dict[str, Any]]:
    """Evaluate a fixed threshold grid without selecting an operating point."""
    return [binary_metrics(y_true, scores, threshold=float(threshold), positive_label=positive_label) for threshold in thresholds]


def anomaly_metrics(y_true: Sequence[Any], anomaly_scores: Sequence[float], *, threshold: float, positive_label: Any = 1, comparison: str = ">") -> dict[str, Any]:
    """Evaluate anomaly scores with explicit orientation and threshold boundary semantics."""
    truth_raw = np.asarray(y_true)
    scores = np.asarray(anomaly_scores, dtype=np.float64)
    if comparison not in {">", ">="}:
        raise ValueError("Anomaly threshold comparison must be '>' or '>='.")
    if truth_raw.ndim != 1 or scores.ndim != 1 or len(truth_raw) != len(scores) or not len(scores):
        raise ValueError("Anomaly labels and scores must be non-empty aligned vectors.")
    if not np.isfinite(scores).all() or not np.isfinite(float(threshold)):
        raise ValueError("Anomaly scores and threshold must be finite.")
    predicted = scores > float(threshold) if comparison == ">" else scores >= float(threshold)
    base = binary_metrics(truth_raw, scores, threshold=float(threshold), positive_label=positive_label)
    base["confusion_matrix"] = confusion_matrix(truth_raw == positive_label, predicted, labels=[False, True]).astype(int).tolist()
    tn, fp, fn, tp = np.asarray(base["confusion_matrix"]).ravel()
    base.update({"threshold_comparison": comparison, "anomaly_score_orientation": "higher_is_more_anomalous",
        "precision": float(precision_score(truth_raw == positive_label, predicted, zero_division=0)),
        "recall": float(recall_score(truth_raw == positive_label, predicted, zero_division=0)),
        "f1": float(f1_score(truth_raw == positive_label, predicted, zero_division=0)),
        "accuracy": float(accuracy_score(truth_raw == positive_label, predicted)),
        "balanced_accuracy": float(balanced_accuracy_score(truth_raw == positive_label, predicted)),
        "matthews_correlation_coefficient": float(matthews_corrcoef(truth_raw == positive_label, predicted)),
        "false_positive_rate": float(fp / (fp + tn)) if tn + fp else None,
        "false_negative_rate": float(fn / (fn + tp)) if fn + tp else None,
        "specificity": float(tn / (tn + fp)) if tn + fp else None,
        "score_is_calibrated_probability": False})
    return base


def multiclass_metrics(y_true: Sequence[int], y_pred: Sequence[int], *, class_ids: Sequence[int], class_names: Sequence[str]) -> dict[str, Any]:
    """Return labelled multi-class metrics using an explicit saved class order."""
    truth = np.asarray(y_true)
    predicted = np.asarray(y_pred)
    ids = np.asarray(class_ids, dtype=int)
    names = list(map(str, class_names))
    if truth.ndim != 1 or predicted.ndim != 1 or len(truth) != len(predicted) or not len(truth):
        raise ValueError("Multi-class true and predicted labels must be non-empty and aligned.")
    if len(ids) != len(names) or len(set(ids.tolist())) != len(ids) or len(set(names)) != len(names):
        raise ValueError("Class IDs and names must form a unique aligned mapping.")
    unsupported = sorted(set(np.unique(truth).tolist()) - set(ids.tolist()))
    if unsupported:
        raise ValueError(f"True labels include IDs outside the persisted taxonomy: {unsupported}.")
    precision, recall, f1, support = precision_recall_fscore_support(
        truth, predicted, labels=ids, zero_division=0
    )
    matrix = confusion_matrix(truth, predicted, labels=ids)
    per_class = []
    for index, class_id in enumerate(ids):
        per_class.append({
            "class_id": int(class_id), "class_name": names[index],
            "precision": float(precision[index]), "recall": float(recall[index]), "f1": float(f1[index]),
            "support": int(support[index]), "correct": int(matrix[index, index]),
            "misclassified": int(support[index] - matrix[index, index]),
            "false_negatives": int(support[index] - matrix[index, index]),
            "present_in_evaluation": bool(support[index] > 0),
        })
    macro_present = [i for i, value in enumerate(support) if value > 0]
    return {
        "observations": int(len(truth)),
        "class_ids": ids.tolist(), "class_names": names,
        "accuracy": float(accuracy_score(truth, predicted)),
        "balanced_accuracy": float(balanced_accuracy_score(truth, predicted)),
        "macro_precision": float(np.mean(precision[macro_present])) if macro_present else None,
        "macro_recall": float(np.mean(recall[macro_present])) if macro_present else None,
        "macro_f1": float(np.mean(f1[macro_present])) if macro_present else None,
        "weighted_precision": float(precision_score(truth, predicted, labels=ids, average="weighted", zero_division=0)),
        "weighted_recall": float(recall_score(truth, predicted, labels=ids, average="weighted", zero_division=0)),
        "weighted_f1": float(f1_score(truth, predicted, labels=ids, average="weighted", zero_division=0)),
        "matthews_correlation_coefficient": float(matthews_corrcoef(truth, predicted)),
        "confusion_matrix": matrix.astype(int).tolist(),
        "per_class": per_class,
        "unseen_true_class_ids": [],
    }


def binary_calibration(y_true: Sequence[Any], probability: Sequence[float], *, positive_label: Any = 1, bins: int = 10) -> dict[str, Any]:
    """Assess binary probability reliability; do not fit a calibrator."""
    truth = np.asarray(y_true) == positive_label
    scores = np.asarray(probability, dtype=float)
    if bins < 1 or truth.ndim != 1 or scores.ndim != 1 or len(truth) != len(scores) or not len(scores):
        raise ValueError("Calibration labels, scores, and bin count are invalid.")
    if not np.isfinite(scores).all() or np.any((scores < 0) | (scores > 1)):
        raise ValueError("Probability assessment requires finite scores in [0, 1].")
    edges = np.linspace(0.0, 1.0, bins + 1)
    indices = np.minimum(np.digitize(scores, edges[1:-1], right=False), bins - 1)
    records = []
    ece = 0.0
    for index in range(bins):
        mask = indices == index
        if not mask.any():
            continue
        mean_score = float(scores[mask].mean())
        observed = float(truth[mask].mean())
        weight = float(mask.mean())
        ece += weight * abs(mean_score - observed)
        records.append({"bin": index, "lower": float(edges[index]), "upper": float(edges[index + 1]), "observations": int(mask.sum()), "mean_score": mean_score, "observed_positive_rate": observed})
    return {
        "observations": int(len(scores)),
        "positive_support": int(truth.sum()),
        "brier_score": float(brier_score_loss(truth, scores)),
        "log_loss": float(log_loss(truth, np.column_stack([1 - scores, scores]), labels=[False, True])),
        "expected_calibration_error": float(ece),
        "reliability_bins": records,
        "calibrator_fitted": False,
        "interpretation": "Observed frequency on this evaluation population; not calibrated compromise probability.",
    }


def multiclass_calibration(y_true: Sequence[int], probabilities: np.ndarray, *, class_ids: Sequence[int], bins: int = 10) -> dict[str, Any]:
    """Assess multi-class log loss, Brier score, and top-label reliability."""
    truth = np.asarray(y_true, dtype=int)
    scores = np.asarray(probabilities, dtype=float)
    ids = np.asarray(class_ids, dtype=int)
    if scores.ndim != 2 or scores.shape != (len(truth), len(ids)) or len(truth) == 0:
        raise ValueError("Multi-class probabilities must align with observations and saved class IDs.")
    if not np.isfinite(scores).all() or np.any(scores < 0) or np.any(scores > 1):
        raise ValueError("Class probability scores must be finite and in [0, 1].")
    if not np.allclose(scores.sum(axis=1), 1.0, atol=1e-5):
        raise ValueError("Multi-class probability rows must sum to one.")
    lookup = {int(value): index for index, value in enumerate(ids)}
    if any(int(value) not in lookup for value in np.unique(truth)):
        raise ValueError("True class IDs are outside the saved class mapping.")
    columns = np.asarray([lookup[int(value)] for value in truth])
    one_hot = np.zeros_like(scores)
    one_hot[np.arange(len(truth)), columns] = 1.0
    top = scores.argmax(axis=1)
    top_confidence = scores[np.arange(len(truth)), top]
    correct = top == columns
    edges = np.linspace(0.0, 1.0, bins + 1)
    bin_id = np.minimum(np.digitize(top_confidence, edges[1:-1]), bins - 1)
    ece = 0.0
    reliability = []
    for index in range(bins):
        mask = bin_id == index
        if not mask.any():
            continue
        confidence, accuracy = float(top_confidence[mask].mean()), float(correct[mask].mean())
        ece += float(mask.mean()) * abs(confidence - accuracy)
        reliability.append({"bin": index, "observations": int(mask.sum()), "mean_top_probability": confidence, "top_label_accuracy": accuracy})
    return {
        "observations": int(len(truth)), "class_count": int(len(ids)),
        "multiclass_log_loss": float(log_loss(truth, scores, labels=ids)),
        "multiclass_brier_score": float(np.mean(np.sum((scores - one_hot) ** 2, axis=1))),
        "top_label_expected_calibration_error": float(ece), "reliability_bins": reliability,
        "calibrator_fitted": False,
    }
