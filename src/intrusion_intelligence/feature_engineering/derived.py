"""Optional deterministic network-flow derived features."""

from __future__ import annotations

from typing import Any

import numpy as np
import pandas as pd
from sklearn.base import BaseEstimator, TransformerMixin
from sklearn.utils.validation import check_is_fitted

DERIVED_FEATURES: dict[str, dict[str, Any]] = {
    "total_packets": {
        "sources": ("total_fwd_packets", "total_backward_packets"),
        "formula": "total_fwd_packets + total_backward_packets",
        "purpose": "Aggregate directional packet counts into one flow count.",
        "missing_behavior": "Return NaN if either source value is missing.",
        "zero_behavior": "Addition has no denominator; preserve the sum.",
        "redundancy": "Related to the two directional packet-count inputs.",
    },
    "total_bytes": {
        "sources": ("total_length_of_fwd_packets", "total_length_of_bwd_packets"),
        "formula": "total_length_of_fwd_packets + total_length_of_bwd_packets",
        "purpose": "Aggregate forward and backward flow byte counts.",
        "missing_behavior": "Return NaN if either source value is missing.",
        "zero_behavior": "Addition has no denominator; preserve the sum.",
        "redundancy": "Related to the two directional byte-count inputs.",
    },
    "forward_packet_proportion": {
        "sources": ("total_fwd_packets", "total_backward_packets"),
        "formula": "total_fwd_packets / (total_fwd_packets + total_backward_packets)",
        "purpose": "Represent the forward share of directional packets.",
        "missing_behavior": "Return NaN if either source value is missing.",
        "zero_behavior": "Return NaN when total packet count is zero; never invent a ratio.",
        "redundancy": "Algebraically related to total packet count and forward packet count.",
    },
    "forward_byte_proportion": {
        "sources": ("total_length_of_fwd_packets", "total_length_of_bwd_packets"),
        "formula": "total_length_of_fwd_packets / (total_length_of_fwd_packets + total_length_of_bwd_packets)",
        "purpose": "Represent the forward share of directional bytes.",
        "missing_behavior": "Return NaN if either source value is missing.",
        "zero_behavior": "Return NaN when total byte count is zero; never invent a ratio.",
        "redundancy": "Algebraically related to total byte count and forward byte count.",
    },
}


class FlowFeatureEngineer(TransformerMixin, BaseEstimator):
    """Add explicitly enabled flow features without fitting data statistics."""

    def __init__(self, derived_features: tuple[str, ...] = ()) -> None:
        self.derived_features = derived_features

    def fit(self, X: pd.DataFrame, y: Any = None) -> "FlowFeatureEngineer":
        if not isinstance(X, pd.DataFrame):
            raise TypeError("FlowFeatureEngineer requires a pandas DataFrame.")
        if X.columns.has_duplicates:
            raise ValueError("FlowFeatureEngineer input columns must be unique.")
        unknown = [name for name in self.derived_features if name not in DERIVED_FEATURES]
        if unknown:
            raise ValueError(f"Unknown derived features requested: {unknown}.")
        required = list(dict.fromkeys(
            source
            for name in self.derived_features
            for source in DERIVED_FEATURES[name]["sources"]
        ))
        missing = [name for name in required if name not in X.columns]
        if missing:
            raise ValueError(f"Cannot derive configured flow features; missing sources: {missing}.")
        collisions = [name for name in self.derived_features if name in X.columns]
        if collisions:
            raise ValueError(f"Derived feature names collide with source columns: {collisions}.")
        self.feature_names_in_ = np.asarray(X.columns, dtype=object)
        self.n_features_in_ = len(self.feature_names_in_)
        self._is_fitted = True
        return self

    def transform(self, X: pd.DataFrame) -> pd.DataFrame:
        check_is_fitted(self, "_is_fitted")
        if not isinstance(X, pd.DataFrame):
            raise TypeError("FlowFeatureEngineer requires a pandas DataFrame.")
        if list(X.columns) != list(self.feature_names_in_):
            raise ValueError("FlowFeatureEngineer input schema or feature order changed.")
        result = X.copy()
        for name in self.derived_features:
            left_name, right_name = DERIVED_FEATURES[name]["sources"]
            left = pd.to_numeric(result[left_name], errors="raise").to_numpy(dtype=float, na_value=np.nan)
            right = pd.to_numeric(result[right_name], errors="raise").to_numpy(dtype=float, na_value=np.nan)
            valid = np.isfinite(left) & np.isfinite(right)
            with np.errstate(over="ignore", invalid="ignore"):
                total = left + right
            valid &= np.isfinite(total)
            if name == "total_packets" or name == "total_bytes":
                values = np.where(valid, total, np.nan)
            elif name == "forward_packet_proportion" or name == "forward_byte_proportion":
                valid &= (total > 0) & (left >= 0) & (right >= 0)
                values = np.divide(left, total, out=np.full_like(total, np.nan), where=valid)
            else:
                raise ValueError(f"No implementation is registered for derived feature {name!r}.")
            result[name] = values
        return result

    def get_feature_names_out(self, input_features: Any = None) -> np.ndarray:
        check_is_fitted(self, "_is_fitted")
        source = list(self.feature_names_in_) if input_features is None else list(input_features)
        if source != list(self.feature_names_in_):
            raise ValueError("input_features do not match the fitted source schema.")
        return np.asarray([*source, *self.derived_features], dtype=object)
