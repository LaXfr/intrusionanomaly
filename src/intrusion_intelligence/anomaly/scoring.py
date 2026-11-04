"""Common higher-is-more-anomalous score convention for Isolation Forest."""

from __future__ import annotations

from typing import Any

import numpy as np
from scipy import sparse


class AnomalyScoringError(ValueError):
    """Raised when an estimator or transformed input cannot be scored safely."""


def higher_is_more_anomalous(
    estimator: Any,
    transformed_features: np.ndarray | sparse.spmatrix,
) -> tuple[np.ndarray, np.ndarray]:
    """Return ``(raw score_samples, -raw)`` with larger common scores anomalous."""
    if not hasattr(estimator, "score_samples"):
        raise AnomalyScoringError("The anomaly estimator must implement score_samples().")
    matrix = transformed_features
    if sparse.issparse(matrix):
        values = matrix.data
        row_count = matrix.shape[0]
    else:
        values = np.asarray(matrix)
        row_count = values.shape[0] if values.ndim == 2 else 0
    if row_count < 1:
        raise AnomalyScoringError("Scoring input must be a non-empty two-dimensional matrix.")
    if not np.isfinite(values).all():
        raise AnomalyScoringError("Scoring input contains NaN or infinity.")
    try:
        raw = np.asarray(estimator.score_samples(matrix), dtype=np.float64)
    except (TypeError, ValueError, AttributeError) as exc:
        raise AnomalyScoringError(f"Estimator could not score the transformed feature matrix: {exc}") from exc
    if raw.ndim != 1 or len(raw) != row_count or not np.isfinite(raw).all():
        raise AnomalyScoringError("Estimator returned missing, non-finite, or misaligned raw scores.")
    anomaly = -raw
    return raw, anomaly

