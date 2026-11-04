"""Uncertainty summaries that refuse misleading low-cluster intervals."""

from __future__ import annotations

from typing import Any, Callable, Sequence

import numpy as np


def wilson_interval(successes: int, trials: int, *, confidence: float = 0.95) -> tuple[float, float] | None:
    """Wilson score interval for a binomial rate; row-independence is assumed."""
    if trials <= 0 or successes < 0 or successes > trials or not 0.0 < confidence < 1.0:
        return None
    from scipy.stats import norm

    z = float(norm.ppf(0.5 + confidence / 2.0))
    p = successes / trials
    denominator = 1 + z * z / trials
    center = (p + z * z / (2 * trials)) / denominator
    radius = z * np.sqrt(p * (1 - p) / trials + z * z / (4 * trials * trials)) / denominator
    return float(max(0.0, center - radius)), float(min(1.0, center + radius))


def cluster_bootstrap_interval(
    values: Sequence[Any], groups: Sequence[Any], metric: Callable[[np.ndarray], float], *,
    iterations: int = 1000, random_seed: int = 42, confidence: float = 0.95, minimum_groups: int = 8,
) -> dict[str, Any]:
    """Bootstrap whole groups, returning unavailable when there are too few clusters."""
    observations = np.asarray(values)
    group_ids = np.asarray(groups, dtype=object)
    unique = np.unique(group_ids)
    if observations.ndim == 0 or len(observations) != len(group_ids):
        raise ValueError("Bootstrap values and groups must be aligned.")
    if iterations < 1 or not 0.0 < confidence < 1.0:
        raise ValueError("Bootstrap iteration count and confidence must be valid.")
    if len(unique) < minimum_groups:
        return {"status": "not_reliable_insufficient_groups", "group_count": int(len(unique)), "minimum_groups": int(minimum_groups), "interval": None}
    rng = np.random.default_rng(random_seed)
    rows = {group: np.flatnonzero(group_ids == group) for group in unique}
    estimates = []
    for _ in range(iterations):
        sampled_groups = rng.choice(unique, size=len(unique), replace=True)
        indices = np.concatenate([rows[group] for group in sampled_groups])
        result = float(metric(observations[indices]))
        if np.isfinite(result):
            estimates.append(result)
    if len(estimates) < iterations * 0.8:
        return {"status": "not_reliable_metric_undefined_in_resamples", "group_count": int(len(unique)), "valid_iterations": len(estimates), "interval": None}
    alpha = 1.0 - confidence
    return {"status": "estimated_group_bootstrap", "group_count": int(len(unique)), "iterations": int(iterations), "random_seed": int(random_seed), "confidence": float(confidence), "interval": [float(np.quantile(estimates, alpha / 2)), float(np.quantile(estimates, 1 - alpha / 2))]}
