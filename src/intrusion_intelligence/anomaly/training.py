"""Benign-only Isolation Forest fitting utilities."""

from __future__ import annotations

import time
from typing import Any

import numpy as np
from scipy import sparse
from sklearn.ensemble import IsolationForest


class AnomalyTrainingError(ValueError):
    """Raised when Isolation Forest cannot be fit on the permitted population."""


def fit_isolation_forest(
    benign_training_features: np.ndarray | sparse.spmatrix,
    model_config: dict[str, Any],
) -> tuple[IsolationForest, dict[str, Any], float]:
    """Fit Isolation Forest on a feature matrix only; labels are not accepted."""
    X = benign_training_features
    row_count = int(X.shape[0]) if hasattr(X, "shape") else 0
    feature_count = int(X.shape[1]) if hasattr(X, "shape") and len(X.shape) == 2 else 0
    if row_count < 2 or feature_count < 1:
        raise AnomalyTrainingError("Isolation Forest needs at least two benign rows and one feature.")
    values = X.data if sparse.issparse(X) else np.asarray(X)
    if not np.isfinite(values).all():
        raise AnomalyTrainingError("Benign training features must be finite after preprocessing.")
    requested_samples = model_config.get("max_samples", "auto")
    config = dict(model_config)
    if isinstance(requested_samples, int):
        config["max_samples"] = min(requested_samples, row_count)
    estimator = IsolationForest(**config)
    started = time.perf_counter()
    estimator.fit(X)
    duration = time.perf_counter() - started
    effective = dict(config)
    effective["max_samples_requested"] = requested_samples
    effective["max_samples_effective"] = int(estimator.max_samples_)
    effective["training_rows"] = row_count
    effective["feature_count"] = feature_count
    return estimator, effective, float(duration)

