"""Batch inference for persisted known-traffic multi-class classifiers."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

from intrusion_intelligence.multiclass.artifacts import load_model_bundle
from intrusion_intelligence.multiclass.evaluation import align_class_scores


class MultiClassPredictor:
    """Apply a saved matching preprocessor and return original attack labels."""

    def __init__(self, artifact_directory: str | Path) -> None:
        self.artifact_directory = Path(artifact_directory)
        self.estimator, self.preprocessor, self.taxonomy, self.metadata = load_model_bundle(
            self.artifact_directory
        )

    @property
    def model_id(self) -> str:
        """Return the immutable model identifier from bundle metadata."""
        return str(self.metadata["model_id"])

    def predict(self, X: pd.DataFrame) -> list[dict[str, Any]]:
        """Predict a batch without refitting, retaining taxonomy score ordering."""
        transformed = self.preprocessor.transform(X, mode="inference")
        predicted_ids = np.asarray(self.estimator.predict(transformed), dtype=np.int64)
        labels = self.taxonomy.decode(predicted_ids)
        score_matrix: np.ndarray | None = None
        if hasattr(self.estimator, "predict_proba"):
            raw_scores = self.estimator.predict_proba(transformed)
            score_matrix = align_class_scores(raw_scores, self.estimator.classes_, self.taxonomy)
        timestamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
        predictions: list[dict[str, Any]] = []
        for row_number, (class_id, label) in enumerate(zip(predicted_ids, labels)):
            score_map = None
            if score_matrix is not None:
                score_map = {
                    name: float(score_matrix[row_number, index])
                    for index, name in enumerate(self.taxonomy.labels)
                }
            predictions.append(
                {
                    "predicted_class": int(class_id),
                    "predicted_label": label,
                    "class_scores": score_map,
                    "model_id": self.model_id,
                    "prediction_timestamp_utc": timestamp,
                }
            )
        return predictions
