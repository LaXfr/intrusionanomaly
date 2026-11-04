"""SHAP construction, shape normalization, and additivity checks."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import numpy as np
import pandas as pd

from intrusion_intelligence.explainability.model_registry import ExplainableModel
from intrusion_intelligence.explainability.schemas import ExplainabilityError, ExplanationOutput


@dataclass(slots=True)
class ShapSession:
    explainer: Any
    model: ExplainableModel
    background: pd.DataFrame
    seed: int
    _cached_input: bytes | None = None
    _cached_raw_values: Any = None
    _cached_expected_value: Any = None

    def explain(self, values: pd.DataFrame, output: ExplanationOutput, *, max_evaluations: int = 157) -> tuple[np.ndarray, np.ndarray, np.ndarray, dict[str, Any]]:
        if self.model.family == "anomaly":
            raw = self.explainer(values.to_numpy(dtype=float), max_evals=max_evaluations, silent=True)
            shap_values = normalize_shap_values(raw.values, len(values), len(self.model.feature_names), output.index, output_count=1)
            base_values = np.asarray(raw.base_values, dtype=float).reshape(-1)
        else:
            input_matrix = values.to_numpy(dtype=float)
            input_key = input_matrix.tobytes()
            if input_key != self._cached_input:
                self._cached_raw_values = self.explainer.shap_values(input_matrix)
                self._cached_expected_value = np.asarray(self.explainer.expected_value, dtype=float)
                self._cached_input = input_key
            raw = self._cached_raw_values
            output_count = len(self.model.estimator.classes_) if self.model.family.endswith("random_forest") else len(self.model.outputs)
            shap_values = normalize_shap_values(raw, len(values), len(self.model.feature_names), output.index, output_count=output_count)
            expected = self._cached_expected_value
            base_values = np.full(len(values), float(expected.reshape(-1)[0])) if expected.ndim == 0 else np.full(len(values), float(expected.reshape(-1)[output.index]))
        actual = self.model.output_values(values, output)
        residuals = base_values + shap_values.sum(axis=1) - actual
        diagnostics = {
            "checked": True,
            "output_semantics": output.semantic,
            "max_absolute_residual": float(np.max(np.abs(residuals))),
            "mean_absolute_residual": float(np.mean(np.abs(residuals))),
            "additive_method": "permutation_telescoping" if self.model.family == "anomaly" else "interventional_tree_or_linear",
            "tolerance": 2e-3 if self.model.family.endswith("random_forest") else 1e-4,
            "passed": bool(np.max(np.abs(residuals)) <= (2e-3 if self.model.family.endswith("random_forest") else 1e-4)),
        }
        if not diagnostics["passed"]:
            raise ExplainabilityError(f"SHAP output failed additivity check for {self.model.model_id}/{output.name}: {diagnostics}")
        return shap_values, base_values, actual, diagnostics


def build_shap_session(model: ExplainableModel, background: pd.DataFrame, *, random_seed: int = 42) -> ShapSession:
    """Select SHAP explainer against transformed rows from training only."""
    try:
        import shap
    except ImportError as exc:
        raise ExplainabilityError("SHAP is unavailable; install the explainability optional dependency.") from exc
    if background.empty or list(background.columns) != list(model.feature_names):
        raise ExplainabilityError("Transformed SHAP background has an empty or incompatible feature schema.")
    matrix = background.to_numpy(dtype=np.float64)
    if model.family.endswith("random_forest"):
        explainer = shap.TreeExplainer(model.estimator, data=matrix, model_output="probability", feature_perturbation="interventional")
    elif model.family.endswith("logistic_regression"):
        masker = shap.maskers.Independent(matrix, max_samples=len(matrix))
        explainer = shap.LinearExplainer(model.estimator, masker)
    elif model.family == "anomaly":
        rng = np.random.default_rng(random_seed)
        masker = shap.maskers.Independent(matrix, max_samples=len(matrix))
        callable_model = lambda data: model.output_values(pd.DataFrame(data, columns=model.feature_names), model.outputs[0])
        explainer = shap.PermutationExplainer(callable_model, masker, seed=int(rng.integers(0, 2**31 - 1)))
    else:
        raise ExplainabilityError(f"No validated SHAP strategy is configured for {model.family!r}.")
    return ShapSession(explainer, model, background, random_seed)


def normalize_shap_values(values: Any, sample_count: int, feature_count: int, output_index: int, *, output_count: int) -> np.ndarray:
    """Normalize SHAP 0.4x list and modern multi-output array conventions."""
    if isinstance(values, (list, tuple)):
        if output_index >= len(values):
            raise ExplainabilityError("SHAP list output omitted the requested model class.")
        array = np.asarray(values[output_index], dtype=float)
        if array.shape != (sample_count, feature_count):
            raise ExplainabilityError(f"Unexpected class SHAP shape: {array.shape}.")
        return array
    array = np.asarray(values, dtype=float)
    if array.shape == (sample_count, feature_count) and output_count == 1:
        return array
    if array.shape == (sample_count, feature_count, output_count):
        return array[:, :, output_index]
    if array.shape == (output_count, sample_count, feature_count):
        return array[output_index]
    if array.shape == (sample_count, output_count, feature_count):
        return array[:, output_index, :]
    raise ExplainabilityError(f"Unsupported SHAP value shape {array.shape} for n={sample_count}, p={feature_count}, outputs={output_count}.")
