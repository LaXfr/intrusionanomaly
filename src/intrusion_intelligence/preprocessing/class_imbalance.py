"""Training-label-only class distribution and weighting helpers."""

from __future__ import annotations

from typing import Any

import numpy as np
import pandas as pd
from sklearn.utils.class_weight import compute_class_weight


def training_class_distribution(
    y_train: pd.Series | np.ndarray,
    *,
    class_weight: str | None = None,
) -> dict[str, Any]:
    """Summarize labels and optionally compute balanced weights from y_train.

    The API accepts only the training target by design; it never inspects a
    full dataset or validation/test labels.
    """
    labels = np.asarray(y_train)
    if labels.ndim != 1 or labels.size == 0:
        raise ValueError("y_train must be a non-empty one-dimensional label vector.")
    if pd.isna(labels).any():
        raise ValueError("y_train contains missing labels.")
    classes, counts = np.unique(labels, return_counts=True)
    proportions = counts / counts.sum()
    weights: dict[str, float] | None = None
    if class_weight is not None:
        if class_weight != "balanced":
            raise ValueError("Only class_weight=None or 'balanced' is supported.")
        calculated = compute_class_weight(class_weight="balanced", classes=classes, y=labels)
        weights = {str(category): float(weight) for category, weight in zip(classes, calculated)}
    return {
        "source": "training_labels_only",
        "row_count": int(labels.size),
        "class_counts": {str(category): int(count) for category, count in zip(classes, counts)},
        "class_proportions": {
            str(category): float(proportion)
            for category, proportion in zip(classes, proportions)
        },
        "class_weight_strategy": class_weight,
        "class_weights": weights,
    }
