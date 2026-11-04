"""Reusable inference for a persisted BENIGN-versus-ATTACK model."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

from intrusion_intelligence.binary.artifacts import load_binary_bundle


class BinaryInferenceError(ValueError):
    """Raised for invalid binary prediction input or artifact state."""


class BinaryPredictor:
    def __init__(self, artifact_directory: str | Path) -> None:
        try:
            self.estimator, self.preprocessor, self.metadata = load_binary_bundle(artifact_directory)
        except (ValueError, OSError) as exc:
            raise BinaryInferenceError(str(exc)) from exc

    @property
    def model_id(self) -> str:
        return str(self.metadata["model_id"])

    def predict(self, X: pd.DataFrame) -> list[dict[str, Any]]:
        if not isinstance(X, pd.DataFrame) or X.empty:
            raise BinaryInferenceError("Binary inference requires a non-empty feature-only DataFrame.")
        before = self.preprocessor.preprocessing_metadata()
        try:
            transformed = self.preprocessor.transform(X, mode="inference")
            probabilities = np.asarray(self.estimator.predict_proba(transformed), dtype=np.float64)
            classes = list(np.asarray(self.estimator.classes_, dtype=int))
        except (ValueError, TypeError) as exc:
            raise BinaryInferenceError(f"Unable to score binary input: {exc}") from exc
        if probabilities.shape != (len(X), len(classes)) or 1 not in classes:
            raise BinaryInferenceError("Binary estimator returned an incompatible class-score matrix.")
        if before != self.preprocessor.preprocessing_metadata():
            raise BinaryInferenceError("Binary inference modified fitted preprocessing state.")
        attack_index = classes.index(1)
        threshold = float(self.metadata["decision_threshold"])
        scores = probabilities[:, attack_index]
        return [
            {
                "predicted_label": "ATTACK" if score >= threshold else "BENIGN",
                "malicious_score": float(score),
                "threshold": threshold,
                "score_is_calibrated_probability": False,
                "model_id": self.model_id,
                "model_version": str(self.metadata["artifact_version"]),
                "score_semantics": self.metadata["score_semantics"],
            }
            for score in scores
        ]
