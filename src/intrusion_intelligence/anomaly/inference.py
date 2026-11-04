"""Reusable batch inference without fitting or threshold recalibration."""

from __future__ import annotations

from pathlib import Path

import numpy as np
import pandas as pd

from intrusion_intelligence.anomaly.artifacts import load_anomaly_bundle
from intrusion_intelligence.anomaly.scoring import higher_is_more_anomalous


class AnomalyInferenceError(ValueError):
    """Raised when anomaly inference input or selected operating point is invalid."""


class AnomalyPredictor:
    """Load a frozen anomaly artifact and score feature-only DataFrames."""

    def __init__(self, artifact_directory: str | Path) -> None:
        self.artifact_directory = Path(artifact_directory).expanduser().resolve()
        try:
            self.estimator, self.preprocessor, self.metadata, self.calibration = load_anomaly_bundle(
                self.artifact_directory
            )
        except (ValueError, OSError) as exc:
            raise AnomalyInferenceError(str(exc)) from exc

    def predict(
        self,
        X: pd.DataFrame,
        *,
        operating_point: str | None = None,
    ) -> pd.DataFrame:
        """Score rows, apply a frozen calibrated threshold, and return decisions."""
        if not isinstance(X, pd.DataFrame) or X.empty:
            raise AnomalyInferenceError("Inference requires a non-empty feature-only DataFrame.")
        point_id = operating_point or self.metadata["default_operating_point"]
        point = self.calibration["operating_points"].get(point_id)
        if point is None:
            raise AnomalyInferenceError(f"Unknown calibrated operating point {point_id!r}.")
        before = self.preprocessor.preprocessing_metadata()
        try:
            transformed = self.preprocessor.transform(X, mode="inference")
            raw, anomaly = higher_is_more_anomalous(self.estimator, transformed)
        except (ValueError, TypeError) as exc:
            raise AnomalyInferenceError(f"Unable to score input with the saved anomaly artifacts: {exc}") from exc
        threshold = float(point["threshold"])
        after = self.preprocessor.preprocessing_metadata()
        if before != after:
            raise AnomalyInferenceError("Inference modified the fitted preprocessing state.")
        return pd.DataFrame(
            {
                "model_id": self.metadata["model_id"],
                "raw_model_score": raw,
                "anomaly_score": anomaly,
                "threshold": threshold,
                "decision": np.where(anomaly > threshold, "ANOMALOUS", "NORMAL"),
                "operating_point": point_id,
                "preprocessing_version": self.metadata["preprocessor_version"],
                "feature_schema_version": self.metadata["feature_schema_version"],
            },
            index=X.index,
        )

