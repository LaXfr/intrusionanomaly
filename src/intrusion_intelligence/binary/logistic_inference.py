"""Inference for a separately persisted binary Logistic Regression bundle."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

from intrusion_intelligence.binary.logistic_artifacts import load_logistic_bundle


class LogisticInferenceError(ValueError):
    """Raised when a logistic artifact or feature-only input is invalid."""


class LogisticPredictor:
    def __init__(self, artifact_directory: str | Path) -> None:
        try:
            self.estimator, self.preprocessor, self.metadata = load_logistic_bundle(artifact_directory)
        except (ValueError, OSError) as exc:
            raise LogisticInferenceError(str(exc)) from exc

    def predict(self, X: pd.DataFrame) -> list[dict[str, Any]]:
        if not isinstance(X, pd.DataFrame) or X.empty:
            raise LogisticInferenceError("Logistic inference requires a non-empty feature-only DataFrame.")
        prior = self.preprocessor.preprocessing_metadata()
        try:
            transformed = self.preprocessor.transform(X, mode="inference")
            matrix = np.asarray(self.estimator.predict_proba(transformed), dtype=np.float64)
        except (ValueError, TypeError) as exc:
            raise LogisticInferenceError(f"Unable to score logistic input: {exc}") from exc
        classes = list(np.asarray(self.estimator.classes_, dtype=int))
        if matrix.shape != (len(X), len(classes)) or 1 not in classes:
            raise LogisticInferenceError("Logistic estimator returned an incompatible class-score matrix.")
        if not np.isfinite(matrix).all() or np.any(matrix < 0) or np.any(matrix > 1):
            raise LogisticInferenceError("Logistic estimator returned invalid class scores.")
        if prior != self.preprocessor.preprocessing_metadata():
            raise LogisticInferenceError("Logistic inference modified fitted preprocessing state.")
        attack_scores = matrix[:, classes.index(1)]
        threshold = float(self.metadata["decision_threshold"])
        return [
            {
                "predicted_label": "ATTACK" if score >= threshold else "BENIGN",
                "malicious_score": float(score),
                "threshold": threshold,
                "score_is_calibrated_probability": False,
                "model_id": self.metadata["model_id"],
                "model_version": self.metadata["artifact_version"],
                "score_semantics": self.metadata["score_semantics"],
            }
            for score in attack_scores
        ]
