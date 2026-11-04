"""On-demand SHAP explanations linked to a persisted event and source row."""

from __future__ import annotations

import tomllib
from functools import lru_cache
from pathlib import Path
from typing import Any
from uuid import UUID

import pandas as pd
from sqlalchemy.orm import Session

from api.core.config import Settings
from api.core.errors import ApiError
from api.database.models import DetectionEvent
from api.services.dataset_service import DatasetService
from intrusion_intelligence.explainability.background_data import load_training_background
from intrusion_intelligence.explainability.explainers import build_shap_session
from intrusion_intelligence.explainability.feature_mapping import aggregate_contributions, map_transformed_features
from intrusion_intelligence.explainability.model_registry import load_explainable_models
from intrusion_intelligence.feature_engineering import FeatureContract


@lru_cache(maxsize=5)
def _models(config_path: str):
    contract = FeatureContract.from_file(Path(config_path).parents[1] / "configs" / "feature_schema.json")
    return load_explainable_models(config_path, contract=contract)[0]


@lru_cache(maxsize=5)
def _session(model_key: str, config_path: str):
    config = tomllib.loads(Path(config_path).read_text(encoding="utf-8"))
    root = Path(config_path).parents[1]
    contract = FeatureContract.from_file(root / config["dataset"]["feature_schema"])
    model = _models(config_path)[model_key]
    background = load_training_background(root / config["dataset"]["parquet_directory"], contract,
        model_family=model.family, sample_size=int(config["background"]["sample_size"]),
        random_seed=int(config["random_seed"]))
    return model, build_shap_session(model, model.transform(background.features),
        random_seed=int(config["explanations"]["permutation_seed"])), contract, config


class EventExplanationService:
    def __init__(self, settings: Settings, datasets: DatasetService) -> None:
        self.settings, self.datasets = settings, datasets
        self.config_path = settings.explainability_config_path

    def explain(self, session: Session, event_id: UUID, engine: str) -> dict[str, Any]:
        event = session.get(DetectionEvent, event_id)
        if event is None:
            raise ApiError(404, "EVENT_NOT_FOUND", "Detection event was not found.")
        cached = (event.explanation_data or {}).get(engine)
        if cached:
            return cached
        if engine not in {"binary", "multiclass", "anomaly"}:
            raise ApiError(422, "INVALID_ENGINE", "engine must be binary, multiclass, or anomaly.")
        evidence = {"binary": event.binary_evidence, "multiclass": event.multiclass_evidence,
            "anomaly": event.anomaly_evidence}.get(engine)
        if not event.dataset_id or not evidence:
            return self._unavailable(engine, "The event has no persisted dataset row and detector evidence to explain.")
        model_id = evidence.get("model_id")
        if not model_id:
            return self._unsupported(engine, "The persisted event contains no model identifier for this detector.")
        try:
            models = _models(str(self.config_path))
            pair = next(((key, model) for key, model in models.items() if model.model_id == model_id), None)
            if pair is None:
                return self._unsupported(engine, "No validated SHAP strategy is configured for the model attached to this event.")
            key, model = pair
            row_number = (event.flow_metadata or {}).get("source_row_number")
            if not isinstance(row_number, int) or row_number < 1:
                return self._unavailable(engine, "The event does not carry a stable source row number.")
            dataset = self.datasets.get(session, event.dataset_id)
            path = self.datasets.resolve_path(dataset)
            # Read only the requested logical data row; no full dataset is materialized.
            raw = pd.read_csv(path, skiprows=range(1, row_number), nrows=1)
            contract = FeatureContract.from_file(self.settings.feature_schema_path)
            X = raw.loc[:, list(contract.predictive_features)]
            transformed = model.transform(X)
            model, shap_session, _contract, config = _session(key, str(self.config_path))
            output = self._output_for(model.outputs, engine, evidence)
            if output is None:
                return self._unsupported(engine, "The detector output recorded for this event has no compatible explanation target.")
            values, bases, outputs, diagnostics = shap_session.explain(transformed, output,
                max_evaluations=int(config["explanations"]["permutation_max_evaluations"]))
            mapping = map_transformed_features(model.feature_names, contract.predictive_features)
            contributions = aggregate_contributions(values[0], model.feature_names, mapping)
            result = {"availability_status": "available", "event_id": str(event.id), "dataset_id": str(event.dataset_id),
                "analysis_job_id": str(event.analysis_job_id) if event.analysis_job_id else None,
                "source_record_reference": event.source_record_reference, "source_row_number": row_number,
                "engine": engine, "model_id": model.model_id, "model_version": model.model_version,
                "output_name": output.name, "output_semantics": output.semantic,
                "model_output_value": float(outputs[0]), "expected_value": float(bases[0]),
                "raw_feature_values": {name: self._json_value(value) for name, value in X.iloc[0].items()},
                "transformed_feature_names": list(model.feature_names),
                "transformed_feature_values": [float(value) for value in transformed.iloc[0]],
                "transformed_shap_values": [float(value) for value in values[0]],
                "original_feature_contributions": contributions, "additivity_diagnostic": diagnostics,
                "reference_dataset_id": f"Phase04 training partition ({model.family}); labels excluded from feature values"}
            event.explanation_data = {**(event.explanation_data or {}), engine: result}
            refs = list(event.explanation_references or [])
            refs.append({"engine": engine, "model_id": model.model_id, "output_name": output.name, "storage": "detection_events.explanation_data"})
            event.explanation_references = refs
            session.commit()
            return result
        except ApiError as exc:
            session.rollback()
            if exc.code == "DATASET_FILE_MISSING":
                return self._unavailable(engine, "The uploaded dataset source row is no longer present in configured storage.")
            raise
        except ImportError:
            return self._unavailable(engine, "SHAP or an explainability dependency is not installed in the API environment.")
        except Exception as exc:
            # Report unavailable without disclosing paths, data, or internals; never return substitute values.
            session.rollback()
            return self._unavailable(engine, f"Explanation could not be computed ({type(exc).__name__}); no values were persisted.")

    @staticmethod
    def _output_for(outputs, engine: str, evidence: dict[str, Any]):
        if engine != "multiclass":
            return outputs[0] if len(outputs) == 1 else None
        details = evidence.get("details") or {}
        original = evidence.get("original_value") or {}
        label = details.get("predicted_label") or original.get("predicted_label")
        class_id = details.get("predicted_class") or original.get("predicted_class")
        return next((item for item in outputs if item.name == label or item.class_id == class_id), None)

    @staticmethod
    def _json_value(value: Any):
        if pd.isna(value):
            return None
        if hasattr(value, "item"):
            return value.item()
        return value

    @staticmethod
    def _unavailable(engine: str, reason: str) -> dict[str, Any]:
        return {"availability_status": "unavailable", "engine": engine, "reason": reason}

    @staticmethod
    def _unsupported(engine: str, reason: str) -> dict[str, Any]:
        return {"availability_status": "unsupported", "engine": engine, "reason": reason}
