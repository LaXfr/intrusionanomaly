"""Multi-class metrics, confusion diagnostics, and score alignment."""

from __future__ import annotations

from collections import Counter
from typing import Any

import numpy as np
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    balanced_accuracy_score,
    confusion_matrix,
    f1_score,
    precision_recall_fscore_support,
    precision_score,
    recall_score,
    roc_auc_score,
)

from intrusion_intelligence.multiclass.taxonomy import ClassTaxonomy


def align_class_scores(
    scores: np.ndarray,
    estimator_class_ids: np.ndarray,
    taxonomy: ClassTaxonomy,
) -> np.ndarray:
    """Align estimator score columns to the persisted taxonomy order."""
    values = np.asarray(scores)
    class_ids = np.asarray(estimator_class_ids, dtype=np.int64)
    if values.ndim != 2 or values.shape[1] != len(class_ids):
        raise ValueError("Score columns do not match the estimator's class identifiers.")
    if np.any(class_ids < 0) or np.any(class_ids >= len(taxonomy.labels)):
        raise ValueError("Estimator contains a class identifier outside the taxonomy.")
    aligned = np.zeros((values.shape[0], len(taxonomy.labels)), dtype=np.float32)
    aligned[:, class_ids] = values.astype(np.float32, copy=False)
    return aligned


def evaluate_multiclass(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    taxonomy: ClassTaxonomy,
    *,
    scores: np.ndarray | None = None,
    learned_class_ids: np.ndarray | None = None,
    partition: str,
) -> dict[str, Any]:
    """Calculate overall, per-class, and confusion metrics with explicit undefined values."""
    truth = np.asarray(y_true, dtype=np.int64)
    predicted = np.asarray(y_pred, dtype=np.int64)
    if truth.ndim != 1 or predicted.ndim != 1 or truth.shape != predicted.shape or not len(truth):
        raise ValueError("y_true and y_pred must be non-empty one-dimensional arrays of equal length.")
    class_ids = np.arange(len(taxonomy.labels), dtype=np.int64)
    learned = set(
        class_ids.tolist()
        if learned_class_ids is None
        else np.asarray(learned_class_ids, dtype=np.int64).tolist()
    )
    unknown_ids = sorted(set(truth.tolist()) - learned)
    known_mask = np.isin(truth, list(learned))
    known_truth = truth[known_mask]
    known_predicted = predicted[known_mask]
    if not len(known_truth):
        raise ValueError("No evaluation observations belong to a class learned during training.")
    labels_present = np.unique(known_truth)
    metrics: dict[str, Any] = {
        "partition": partition,
        "observations_total": int(len(truth)),
        "observations_scored": int(len(known_truth)),
        "observations_in_unseen_training_classes": int(len(truth) - len(known_truth)),
        "unseen_training_classes": [taxonomy.labels[index] for index in unknown_ids],
        "metric_scope": "Only observations whose true class was present in training are included.",
        "accuracy": float(accuracy_score(known_truth, known_predicted)),
        "balanced_accuracy": float(balanced_accuracy_score(known_truth, known_predicted)),
        "macro_precision": float(precision_score(known_truth, known_predicted, labels=labels_present, average="macro", zero_division=0)),
        "macro_recall": float(recall_score(known_truth, known_predicted, labels=labels_present, average="macro", zero_division=0)),
        "macro_f1": float(f1_score(known_truth, known_predicted, labels=labels_present, average="macro", zero_division=0)),
        "weighted_precision": float(precision_score(known_truth, known_predicted, labels=labels_present, average="weighted", zero_division=0)),
        "weighted_recall": float(recall_score(known_truth, known_predicted, labels=labels_present, average="weighted", zero_division=0)),
        "weighted_f1": float(f1_score(known_truth, known_predicted, labels=labels_present, average="weighted", zero_division=0)),
    }
    matrix = confusion_matrix(truth, predicted, labels=class_ids)
    precision, recall, f1, support = precision_recall_fscore_support(
        truth,
        predicted,
        labels=class_ids,
        average=None,
        zero_division=0,
    )
    predicted_counts = matrix.sum(axis=0)
    per_class: list[dict[str, Any]] = []
    for index, label in enumerate(taxonomy.labels):
        true_count = int(support[index])
        predicted_count = int(predicted_counts[index])
        status = "ok"
        if index not in learned:
            status = "unseen_in_training"
        elif true_count == 0:
            status = "not_present_in_partition"
        per_class.append(
            {
                "class_id": index,
                "label": label,
                "status": status,
                "precision": None if predicted_count == 0 else float(precision[index]),
                "recall": None if true_count == 0 else float(recall[index]),
                "f1": None if true_count == 0 else float(f1[index]),
                "support": true_count,
                "predicted_count": predicted_count,
                "false_negative_count": int(true_count - matrix[index, index]),
                "correctly_classified_count": int(matrix[index, index]),
                "misclassified_count": int(true_count - matrix[index, index]),
            }
        )
    if scores is not None:
        score_values = np.asarray(scores)
        if score_values.shape != (len(truth), len(taxonomy.labels)):
            raise ValueError("Aligned score matrix must have one column per taxonomy label.")
        if len(labels_present) >= 2 and np.isin(class_ids, labels_present).all():
            metrics["multiclass_roc_auc_ovr_macro"] = float(
                roc_auc_score(
                    known_truth,
                    score_values[known_mask],
                    labels=class_ids,
                    multi_class="ovr",
                    average="macro",
                )
            )
            binary_truth = np.column_stack([known_truth == index for index in class_ids]).astype(np.uint8)
            metrics["multiclass_average_precision_macro"] = float(
                average_precision_score(binary_truth, score_values[known_mask], average="macro")
            )
            for index, label in enumerate(taxonomy.labels):
                per_class[index]["average_precision_ovr"] = float(
                    average_precision_score(binary_truth[:, index], score_values[known_mask, index])
                )
        else:
            metrics["multiclass_roc_auc_ovr_macro"] = None
            metrics["multiclass_average_precision_macro"] = None
            for row in per_class:
                row["average_precision_ovr"] = None
    else:
        metrics["multiclass_roc_auc_ovr_macro"] = None
        metrics["multiclass_average_precision_macro"] = None
        for row in per_class:
            row["average_precision_ovr"] = None
    pairs = _confusion_pairs(matrix, taxonomy)
    return {
        "metrics": metrics,
        "per_class": per_class,
        "confusion_matrix": matrix.astype(int).tolist(),
        "confusion_class_order": list(taxonomy.labels),
        "normalized_confusion_matrix": _normalize_rows(matrix).tolist(),
        "frequent_confusion_pairs": pairs,
    }


def _confusion_pairs(matrix: np.ndarray, taxonomy: ClassTaxonomy) -> list[dict[str, Any]]:
    pairs: list[dict[str, Any]] = []
    for true_id in range(len(taxonomy.labels)):
        support = int(matrix[true_id].sum())
        for predicted_id in range(len(taxonomy.labels)):
            count = int(matrix[true_id, predicted_id])
            if true_id != predicted_id and count:
                pairs.append(
                    {
                        "true_label": taxonomy.labels[true_id],
                        "predicted_label": taxonomy.labels[predicted_id],
                        "count": count,
                        "percent_of_true_class": count / support if support else None,
                    }
                )
    return sorted(pairs, key=lambda item: (-item["count"], item["true_label"], item["predicted_label"]))


def _normalize_rows(matrix: np.ndarray) -> np.ndarray:
    totals = matrix.sum(axis=1, keepdims=True)
    return np.divide(matrix, totals, out=np.zeros_like(matrix, dtype=float), where=totals != 0)
