"""Controlled feature-group ablation helpers; never writes production artifacts."""

from __future__ import annotations

from typing import Any, Callable, Mapping, Sequence

import numpy as np
import pandas as pd


def build_ablation_plan(feature_names: Sequence[str], groups: Mapping[str, Sequence[str]]) -> list[dict[str, Any]]:
    """Build supported feature-set variants and explicit not-applicable entries."""
    base = list(map(str, feature_names))
    plan = [{"variant": "full_approved_features", "status": "planned", "removed_features": [], "feature_count": len(base)}]
    names = (
        ("ports_removed", "ports"), ("protocol_removed", "protocol"),
        ("ports_and_protocol_removed", "ports_protocol"), ("high_correlation_features_removed", "high_correlation"),
    )
    group_values = {name: [feature for feature in groups.get(name, ()) if feature in base] for name in ("ports", "protocol", "ports_protocol", "high_correlation")}
    for variant, group in names:
        removed = sorted(set(group_values[group]))
        plan.append({"variant": variant, "status": "planned" if removed else "not_applicable_no_features_present", "removed_features": removed, "feature_count": len(base) - len(removed)})
    plan.append({"variant": "identifiers_and_metadata_negative_control", "status": "schema_boundary_audit_only", "removed_features": [], "feature_count": len(base), "prohibited_fields": sorted(set(groups.get("prohibited", ())))})
    return plan


def run_ablation_experiment(
    train_X: pd.DataFrame, train_y: Sequence[Any], eval_X: pd.DataFrame, eval_y: Sequence[Any], *,
    variants: Mapping[str, Sequence[str]], estimator_factory: Callable[[str, Sequence[str]], Any],
    metric_function: Callable[[Sequence[Any], Sequence[Any]], Mapping[str, Any]], target_name: str,
) -> list[dict[str, Any]]:
    """Fit temporary estimators on train-only feature subsets and evaluate a fixed holdout."""
    if train_X.empty or eval_X.empty or list(train_X.columns) != list(eval_X.columns):
        raise ValueError("Ablation train/evaluation features must be non-empty and have identical ordered schemas.")
    if target_name in train_X.columns or target_name in eval_X.columns:
        raise ValueError("The target column cannot enter an ablation feature matrix.")
    if len(train_X) != len(train_y) or len(eval_X) != len(eval_y):
        raise ValueError("Ablation labels must align to their feature matrices.")
    outputs = []
    for name, removed in variants.items():
        removed_set = set(map(str, removed))
        unknown = removed_set - set(map(str, train_X.columns))
        if unknown:
            raise ValueError(f"Ablation {name!r} contains unknown features: {sorted(unknown)}.")
        kept = [column for column in train_X.columns if column not in removed_set]
        if not kept:
            raise ValueError(f"Ablation {name!r} removes every feature.")
        estimator = estimator_factory(name, kept)
        estimator.fit(train_X.loc[:, kept], train_y)
        prediction = estimator.predict(eval_X.loc[:, kept])
        outputs.append({"variant": name, "removed_features": sorted(removed_set), "feature_count": len(kept), "training_rows": len(train_X), "evaluation_rows": len(eval_X), "metrics": dict(metric_function(eval_y, prediction)), "production_artifact_written": False})
    return outputs
