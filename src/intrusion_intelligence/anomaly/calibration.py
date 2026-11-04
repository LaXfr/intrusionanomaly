"""Benign-validation-only empirical anomaly threshold calibration."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

import numpy as np


class CalibrationError(ValueError):
    """Raised when benign calibration scores or target operating points are invalid."""


def calibrate_operating_points(
    benign_validation_scores: Iterable[float],
    operating_points: Iterable[Mapping[str, Any]],
    *,
    quantile_method: str = "higher",
    minimum_observations: int = 2,
) -> dict[str, Any]:
    """Calibrate upper-tail thresholds using only benign validation scores.

    A prediction is anomalous only when ``score > threshold``. The upper
    quantile uses NumPy's ``higher`` order statistic by default; ties therefore
    make the achieved empirical validation FPR no greater than the target.
    """
    scores = np.asarray(list(benign_validation_scores), dtype=np.float64)
    if scores.ndim != 1 or len(scores) < minimum_observations:
        raise CalibrationError(
            f"At least {minimum_observations} benign validation scores are required; received {len(scores)}."
        )
    if not np.isfinite(scores).all():
        raise CalibrationError("Benign validation scores must be finite; NaN or infinity is not accepted.")
    if quantile_method not in {"inverted_cdf", "averaged_inverted_cdf", "closest_observation", "interpolated_inverted_cdf", "hazen", "weibull", "linear", "median_unbiased", "normal_unbiased", "lower", "higher", "midpoint", "nearest"}:
        raise CalibrationError(f"Unsupported empirical quantile method: {quantile_method!r}.")
    points = list(operating_points)
    if not points:
        raise CalibrationError("At least one operating point must be configured.")
    results: dict[str, Any] = {}
    seen_rates: set[float] = set()
    for point in points:
        point_id = str(point.get("id", ""))
        try:
            target_fpr = float(point["target_fpr"])
        except (KeyError, TypeError, ValueError) as exc:
            raise CalibrationError(f"Operating point {point_id!r} has no valid target_fpr.") from exc
        if not point_id or not 0 < target_fpr < 1 or target_fpr in seen_rates or point_id in results:
            raise CalibrationError("Operating-point identifiers and FPR targets must be unique and valid.")
        seen_rates.add(target_fpr)
        threshold = float(np.quantile(scores, 1.0 - target_fpr, method=quantile_method))
        achieved = float(np.mean(scores > threshold))
        tie_count = int(np.count_nonzero(scores == threshold))
        expected_tail_rows = target_fpr * len(scores)
        results[point_id] = {
            "operating_point": point_id,
            "target_fpr": target_fpr,
            "threshold": threshold,
            "comparison": "anomalous if anomaly_score > threshold; equality is NORMAL",
            "quantile": 1.0 - target_fpr,
            "quantile_method": quantile_method,
            "benign_validation_observations": int(len(scores)),
            "achieved_validation_fpr": achieved,
            "threshold_tie_observations": tie_count,
            "empirical_fpr_resolution": 1.0 / len(scores),
            "expected_tail_observations_at_target": expected_tail_rows,
            "resolution_status": "below_empirical_resolution" if expected_tail_rows < 1 else "empirically_resolvable",
            "score_summary": {
                "minimum": float(np.min(scores)),
                "median": float(np.median(scores)),
                "mean": float(np.mean(scores)),
                "maximum": float(np.max(scores)),
            },
        }
    return {
        "score_orientation": "higher_is_more_anomalous",
        "calibration_population": "BENIGN validation observations only",
        "labels_used_for_threshold_selection": False,
        "quantile_method": quantile_method,
        "operating_points": results,
    }

