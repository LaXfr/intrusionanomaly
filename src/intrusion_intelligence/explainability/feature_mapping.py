"""Map fitted transformed columns back to declared input features."""

from __future__ import annotations

from typing import Any, Iterable

import numpy as np

from intrusion_intelligence.explainability.schemas import ExplainabilityError


def map_transformed_features(
    transformed_names: Iterable[str],
    original_names: Iterable[str],
    *,
    explicit_sources: dict[str, str] | None = None,
) -> dict[str, str | None]:
    """Resolve transformer output names without guessing unknown columns."""
    originals = tuple(map(str, original_names))
    explicit = explicit_sources or {}
    result: dict[str, str | None] = {}
    for transformed in map(str, transformed_names):
        if transformed in explicit:
            source = explicit[transformed]
            if source not in originals:
                raise ExplainabilityError(f"Explicit source {source!r} is not a declared input feature.")
            result[transformed] = source
            continue
        leaf_name = transformed.rsplit("__", 1)[-1]
        candidates = [name for name in originals if leaf_name == name or leaf_name.startswith(name + "_") or transformed.endswith("__" + name)]
        candidates.sort(key=len, reverse=True)
        result[transformed] = candidates[0] if candidates and (len(candidates) == 1 or len(candidates[0]) > len(candidates[1])) else None
    return result


def aggregate_contributions(values: np.ndarray, transformed_names: Iterable[str], mapping: dict[str, str | None]) -> list[dict[str, Any]]:
    """Sum signed local SHAP values by declared source feature."""
    rows = np.asarray(values, dtype=float).reshape(-1)
    names = tuple(map(str, transformed_names))
    if len(rows) != len(names):
        raise ExplainabilityError("Contribution vector and transformed feature names differ in length.")
    grouped: dict[str, float] = {}
    unmapped: list[dict[str, Any]] = []
    for name, value in zip(names, rows):
        source = mapping.get(name)
        if source is None:
            unmapped.append({"transformed_feature": name, "contribution": float(value)})
        else:
            grouped[source] = grouped.get(source, 0.0) + float(value)
    return sorted(({"feature": name, "contribution": value} for name, value in grouped.items()), key=lambda row: (-abs(row["contribution"]), row["feature"])) + unmapped


def aggregate_global_importance(values: np.ndarray, transformed_names: Iterable[str], mapping: dict[str, str | None]) -> list[dict[str, Any]]:
    """Aggregate mean absolute transformed SHAP values by original feature."""
    matrix = np.asarray(values, dtype=float)
    names = tuple(map(str, transformed_names))
    if matrix.ndim != 2 or matrix.shape[1] != len(names):
        raise ExplainabilityError("Global contribution matrix does not match transformed feature names.")
    raw = np.mean(np.abs(matrix), axis=0)
    totals: dict[str, float] = {}
    unmapped = []
    for name, importance in zip(names, raw):
        source = mapping.get(name)
        if source is None:
            unmapped.append({"transformed_feature": name, "mean_absolute_shap": float(importance), "source_feature": None})
        else:
            totals[source] = totals.get(source, 0.0) + float(importance)
    rows = [{"feature": name, "mean_absolute_shap": value} for name, value in totals.items()]
    rows.sort(key=lambda row: (-row["mean_absolute_shap"], row["feature"]))
    return rows + unmapped
