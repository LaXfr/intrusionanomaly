"""Validated, cached access to real local model artifacts and predictors."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

import pandas as pd
from sqlalchemy import select
from sqlalchemy.orm import Session

from intrusion_intelligence.anomaly.inference import AnomalyPredictor
from intrusion_intelligence.binary.inference import BinaryPredictor
from intrusion_intelligence.binary.logistic_inference import LogisticPredictor
from intrusion_intelligence.explainability.model_registry import load_explainable_models
from intrusion_intelligence.feature_engineering import FeatureContract
from intrusion_intelligence.multiclass.inference import MultiClassPredictor

from api.core.config import Settings
from api.core.errors import ApiError
from api.database.models import ModelRegistry

logger = logging.getLogger(__name__)


class ModelService:
    """Load and cache trusted model artifacts only after registry validation."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.contract = FeatureContract.from_file(settings.feature_schema_path)
        self._validated: dict[str, Any] | None = None
        self._predictors: dict[str, Any] = {}
        self._unavailable: dict[str, str] = {}
        self._descriptors: list[dict[str, Any]] = []

    def _load_registry(self) -> None:
        if self._validated is not None:
            return
        try:
            models, _ = load_explainable_models(self.settings.explainability_config_path, contract=self.contract)
        except Exception as exc:
            logger.exception("Configured model registry could not be validated")
            self._validated = {}
            self._unavailable["configured_registry"] = type(exc).__name__
            return
        self._validated = models
        for key, model in models.items():
            self._descriptors.append(self._describe(key, model))
        self._unavailable["xgboost"] = "No trained XGBoost artifact is registered."

    def _describe(self, key: str, model: Any) -> dict[str, Any]:
        metadata = model.metadata
        model_type = {"binary_random_forest": "binary", "binary_logistic_regression": "binary",
                      "multiclass_random_forest": "multiclass", "multiclass_logistic_regression": "multiclass", "anomaly": "anomaly"}[model.family]
        if model_type == "binary":
            class_mapping: Any = {"BENIGN": 0, "ATTACK": 1}
            threshold = {"decision_threshold": model.threshold, "semantics": "uncalibrated score threshold"}
        elif model_type == "multiclass":
            class_mapping = list(model.taxonomy.labels)
            threshold = None
        else:
            class_mapping = None
            threshold = {"operating_point": model.operating_point, "threshold": model.threshold, "higher_is_more_anomalous": True}
        return {"model_id": model.model_id, "model_name": key, "model_version": model.model_version,
                "model_type": model_type, "feature_schema_version": self.contract.schema_version,
                "input_feature_count": len(model.metadata["input_feature_names"]), "class_mapping": class_mapping,
                "threshold_configuration": threshold, "status": "READY", "supported_prediction_types": [model_type],
                "artifact_uri": str(model.artifact_directory.relative_to(self.settings.model_dir)),
                "preprocessor_uri": str(model.artifact_directory.relative_to(self.settings.model_dir)),
                "metrics": self._historical_metrics(model_type)}

    def _historical_metrics(self, model_type: str) -> dict[str, Any] | None:
        candidates = {
            "binary": self.settings.report_dir / "evaluation/binary/20261103T160232Z/binary_experiment.json",
            "multiclass": self.settings.report_dir / "evaluation/multiclass/20261103T134128Z/random_forest_held_out_test_metrics.json",
            "anomaly": self.settings.report_dir / "evaluation/anomaly_detection/20261103T141439Z/anomaly_evaluation_summary.json",
        }
        path = candidates[model_type]
        if not path.is_file():
            return None
        try:
            report = json.loads(path.read_text(encoding="utf-8"))
            if model_type == "binary":
                return {"evidence_status": "previously_inspected_test", "metrics": report.get("held_out_test_metrics")}
            if model_type == "multiclass":
                return {"evidence_status": "previously_inspected_row_split_test", "metrics": report}
            return {"evidence_status": "previously_inspected_capture_day_test", "default_operating_point": report.get("default_operating_point"),
                    "metrics": report.get("test_metrics", {}).get(report.get("default_operating_point"))}
        except (OSError, json.JSONDecodeError):
            logger.exception("Could not read historical evaluation metadata")
            return None

    def list_models(self) -> tuple[list[dict[str, Any]], dict[str, str]]:
        self._load_registry()
        return list(self._descriptors), dict(self._unavailable)

    def sync_database_registry(self, session: Session) -> list[dict[str, Any]]:
        descriptors, _ = self.list_models()
        for item in descriptors:
            row = session.scalar(select(ModelRegistry).where(ModelRegistry.model_id == item["model_id"]))
            values = {key: item[key] for key in ("model_name", "model_version", "model_type", "artifact_uri", "preprocessor_uri", "feature_schema_version", "class_mapping", "threshold_configuration", "metrics", "status")}
            if row is None:
                session.add(ModelRegistry(model_id=item["model_id"], **values))
            else:
                for key, value in values.items():
                    setattr(row, key, value)
        session.commit()
        return descriptors

    def resolve_model(self, engine: str, requested_id: str | None = None) -> tuple[str, Any]:
        descriptors, unavailable = self.list_models()
        candidates = [item for item in descriptors if item["model_type"] == engine]
        chosen = requested_id or self._default_model_id(engine, candidates)
        descriptor = next((item for item in candidates if item["model_id"] == chosen), None)
        if descriptor is None:
            if requested_id:
                raise ApiError(404, "MODEL_NOT_FOUND", f"Requested {engine} model is not registered.")
            raise ApiError(503, "MODEL_UNAVAILABLE", unavailable.get(engine, f"No validated {engine} model is available."))
        try:
            predictor = self._predictors.get(chosen)
            if predictor is None:
                artifact = self.settings.model_dir / descriptor["artifact_uri"]
                if engine == "binary":
                    if descriptor["model_name"] == "binary_logistic_regression":
                        predictor = LogisticPredictor(artifact)
                    else:
                        predictor = BinaryPredictor(artifact)
                elif engine == "multiclass":
                    predictor = MultiClassPredictor(artifact)
                elif engine == "anomaly":
                    predictor = AnomalyPredictor(artifact)
                else:
                    raise ApiError(400, "INVALID_ENGINE", "Unsupported detection engine.")
                self._predictors[chosen] = predictor
            return chosen, predictor
        except ApiError:
            raise
        except Exception as exc:
            self._unavailable[engine] = type(exc).__name__
            logger.exception("A validated model could not be loaded for inference")
            raise ApiError(503, "MODEL_UNAVAILABLE", f"Requested {engine} model is not ready for inference.") from exc

    def infer(self, engine: str, X: pd.DataFrame, *, requested_id: str | None = None, operating_point: str | None = None) -> tuple[str, list[dict[str, Any]]]:
        model_id, predictor = self.resolve_model(engine, requested_id)
        if engine == "binary":
            return model_id, predictor.predict(X)
        if engine == "multiclass":
            return model_id, predictor.predict(X)
        result = predictor.predict(X, operating_point=operating_point)
        return model_id, result.to_dict(orient="records")

    def _default_model_id(self, engine: str, candidates: list[dict[str, Any]]) -> str | None:
        preference = {"binary": "binary-random_forest-v1.0.1", "multiclass": "multiclass-random_forest-v1.0.0", "anomaly": "isolation-forest-v1.0.0"}
        desired = preference.get(engine)
        return desired if any(item["model_id"] == desired for item in candidates) else (candidates[0]["model_id"] if candidates else None)

    @property
    def class_labels(self) -> list[str]:
        self._load_registry()
        if not self._validated:
            return []
        model = next((item for item in self._validated.values() if item.family == "multiclass_random_forest"), None)
        return list(model.taxonomy.labels) if model else []
