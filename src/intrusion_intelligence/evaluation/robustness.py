"""Deterministic input stress checks for persisted detector contracts."""

from __future__ import annotations

from typing import Any

import numpy as np
import pandas as pd

from intrusion_intelligence.explainability.model_registry import ExplainableModel
from intrusion_intelligence.feature_engineering import FeatureContract


def run_input_stress(model: ExplainableModel, X: pd.DataFrame, contract: FeatureContract) -> dict[str, Any]:
    """Compare valid baseline inputs with controlled synthetic perturbations."""
    if X.empty or len(X.columns) != len(contract.predictive_features):
        raise ValueError("Robustness input must be non-empty and match the original feature count.")
    reference = X.iloc[:min(16, len(X))].copy()
    output = model.outputs[0]
    baseline_features = model.transform(reference)
    baseline = model.output_values(baseline_features, output)
    cases: list[tuple[str, pd.DataFrame, str]] = []
    if contract.optional_features:
        cases.append(("optional_feature_missing", reference.drop(columns=[contract.optional_features[0]]), "contract optional-field insertion"))
    else:
        cases.append(("optional_feature_missing", reference.copy(), "not_applicable_no_optional_features"))
    with_missing = reference.copy()
    numeric = [name for name in contract.numeric_features if name in with_missing]
    if numeric:
        with_missing[numeric[0]] = np.nan
        cases.append(("numeric_missing_value", with_missing, f"set {numeric[0]} to NaN"))
        extreme = reference.copy()
        extreme[numeric[0]] = 1e12
        cases.append(("large_finite_value", extreme, f"set {numeric[0]} to 1e12"))
        zero = reference.copy()
        zero_features = [name for name in ("flow_bytes_s", "flow_packets_s", "fwd_packets_s", "bwd_packets_s") if name in zero]
        if zero_features:
            zero.loc[:, zero_features] = 0.0
            cases.append(("zero_rate_values", zero, f"set rates to zero: {zero_features}"))
    results = []
    for name, frame, method in cases:
        if method == "not_applicable_no_optional_features":
            results.append({"case": name, "status": method, "synthetic": True})
            continue
        try:
            transformed = model.transform(frame)
            predicted = model.output_values(transformed, output)
            results.append({"case": name, "status": "accepted", "method": method, "synthetic": True, "finite_outputs": bool(np.isfinite(predicted).all()), "mean_absolute_output_change": float(np.mean(np.abs(predicted - baseline))), "output_semantics": output.semantic})
        except Exception as exc:
            results.append({"case": name, "status": "rejected", "method": method, "synthetic": True, "error_type": type(exc).__name__, "error": str(exc)})
    missing_required = reference.drop(columns=[contract.predictive_features[0]])
    try:
        model.transform(missing_required)
        required_status = "unexpectedly_accepted"
    except Exception as exc:
        required_status = {"status": "rejected_as_expected", "error_type": type(exc).__name__}
    invalid = reference.copy()
    invalid[numeric[0] if numeric else contract.predictive_features[0]] = np.inf
    try:
        model.transform(invalid)
        infinity_status = "unexpectedly_accepted"
    except Exception as exc:
        infinity_status = {"status": "rejected_as_expected", "error_type": type(exc).__name__}
    return {"model_id": model.model_id, "model_family": model.family, "sample_rows": len(reference), "results": results, "required_column": required_status, "infinite_numeric": infinity_status, "unknown_categorical_values": "not_applicable_numeric_only_feature_contract", "interpretation": "Synthetic input stress only; not an adversarial robustness guarantee."}
