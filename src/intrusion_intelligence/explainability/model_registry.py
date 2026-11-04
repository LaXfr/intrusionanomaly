"""Load and validate the existing versioned detector bundles for explanation."""

from __future__ import annotations

import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

from intrusion_intelligence.anomaly.artifacts import load_anomaly_bundle
from intrusion_intelligence.binary.artifacts import load_binary_bundle
from intrusion_intelligence.binary.logistic_artifacts import load_logistic_bundle
from intrusion_intelligence.explainability.schemas import ExplainabilityError, ExplanationOutput
from intrusion_intelligence.feature_engineering import FeatureContract
from intrusion_intelligence.multiclass.artifacts import load_model_bundle


@dataclass(slots=True)
class ExplainableModel:
    key: str
    family: str
    explainer_type: str
    output_space: str
    artifact_directory: Path
    estimator: Any
    preprocessor: Any
    metadata: dict[str, Any]
    outputs: tuple[ExplanationOutput, ...]
    threshold: float | None = None
    taxonomy: Any | None = None
    operating_point: str | None = None

    @property
    def model_id(self) -> str:
        return str(self.metadata["model_id"])

    @property
    def model_version(self) -> str:
        return str(self.metadata["artifact_version"])

    @property
    def feature_names(self) -> tuple[str, ...]:
        return tuple(self.metadata["output_feature_names"])

    def transform(self, X: pd.DataFrame) -> pd.DataFrame:
        if not isinstance(X, pd.DataFrame) or X.empty:
            raise ExplainabilityError("Explanation inputs must be a non-empty feature-only DataFrame.")
        expected = list(self.metadata["input_feature_names"])
        if list(X.columns) != expected:
            raise ExplainabilityError("Explanation input schema or order differs from the persisted model contract.")
        before = self.preprocessor.preprocessing_metadata()
        matrix = self.preprocessor.transform(X, mode="inference")
        if hasattr(matrix, "toarray"):
            matrix = matrix.toarray()
        transformed = np.asarray(matrix, dtype=np.float64)
        after = self.preprocessor.preprocessing_metadata()
        if before != after:
            raise ExplainabilityError("Explanation transformation modified the fitted preprocessor state.")
        if transformed.shape != (len(X), len(self.feature_names)) or not np.isfinite(transformed).all():
            raise ExplainabilityError("Transformed explanation data does not match the persisted feature contract.")
        return pd.DataFrame(transformed, index=X.index, columns=self.feature_names)

    def output_values(self, transformed: pd.DataFrame, output: ExplanationOutput) -> np.ndarray:
        matrix = transformed.to_numpy(dtype=np.float64)
        if self.family in {"binary_random_forest", "multiclass_random_forest"}:
            probabilities = np.asarray(self.estimator.predict_proba(matrix), dtype=np.float64)
            if probabilities.ndim != 2 or probabilities.shape[1] <= output.index:
                raise ExplainabilityError("Classifier probability output has an incompatible shape.")
            return probabilities[:, output.index]
        if self.family in {"binary_logistic_regression", "multiclass_logistic_regression"}:
            margins = np.asarray(self.estimator.decision_function(matrix), dtype=np.float64)
            if self.family == "binary_logistic_regression":
                if margins.ndim != 1:
                    raise ExplainabilityError("Binary Logistic Regression did not return a one-dimensional margin.")
                return margins
            if margins.ndim != 2 or margins.shape[1] <= output.index:
                raise ExplainabilityError("Multi-class Logistic Regression margin output has an incompatible shape.")
            return margins[:, output.index]
        if self.family == "anomaly":
            # Phase 08 defines higher_is_more_anomalous = -score_samples.
            scores = -np.asarray(self.estimator.score_samples(matrix), dtype=np.float64)
            if scores.ndim != 1:
                raise ExplainabilityError("Isolation Forest returned an incompatible score_samples output.")
            return scores
        raise ExplainabilityError(f"Unsupported explanation model family {self.family!r}.")

    def predict_metadata(self, transformed_row: pd.DataFrame, output: ExplanationOutput) -> dict[str, Any]:
        values = self.output_values(transformed_row, output)
        value = float(values[0])
        if self.family == "anomaly":
            decision = "ANOMALOUS" if self.threshold is not None and value > self.threshold else "NORMAL"
            return {"model_output_value": value, "predicted_label": decision, "predicted_class_id": None}
        if self.family.startswith("binary_"):
            probability = np.asarray(self.estimator.predict_proba(transformed_row.to_numpy()), dtype=np.float64)[0]
            classes = [int(item) for item in self.estimator.classes_]
            attack_probability = float(probability[classes.index(1)])
            label = "ATTACK" if self.threshold is not None and attack_probability >= self.threshold else "BENIGN"
            return {
                "model_output_value": value,
                "attack_probability_score": attack_probability,
                "predicted_label": label,
                "predicted_class_id": classes.index(1),
            }
        predicted_id = int(np.asarray(self.estimator.predict(transformed_row.to_numpy()))[0])
        label = str(self.taxonomy.decode([predicted_id])[0])
        return {"model_output_value": value, "predicted_label": label, "predicted_class_id": predicted_id}


def load_explainable_models(
    config_path: str | Path,
    *,
    contract: FeatureContract,
) -> tuple[dict[str, ExplainableModel], dict[str, Any]]:
    path = Path(config_path).expanduser().resolve()
    with path.open("rb") as handle:
        config = tomllib.load(handle)
    root = _project_root(path)
    models: dict[str, ExplainableModel] = {}
    for key, specification in config.get("models", {}).items():
        artifact = (root / specification["artifact_directory"]).resolve()
        family = str(specification["model_family"])
        explainer_type = str(specification["explainer"])
        output_space = str(specification["output_space"])
        if family == "binary_random_forest":
            estimator, preprocessor, metadata = load_binary_bundle(artifact)
            classes = [int(item) for item in estimator.classes_]
            if 1 not in classes:
                raise ExplainabilityError("Binary Random Forest artifact does not expose the ATTACK class.")
            outputs = (ExplanationOutput("ATTACK", classes.index(1), "attack probability", "ATTACK", 1),)
            model = ExplainableModel(key, family, explainer_type, output_space, artifact, estimator, preprocessor, metadata, outputs, float(metadata["decision_threshold"]))
        elif family == "binary_logistic_regression":
            estimator, preprocessor, metadata = load_logistic_bundle(artifact)
            classes = [int(item) for item in estimator.classes_]
            if classes != [0, 1]:
                raise ExplainabilityError(f"Binary Logistic Regression class order is unsupported: {classes}.")
            outputs = (ExplanationOutput("ATTACK_LOG_ODDS", 0, "ATTACK log-odds margin", "ATTACK", 1),)
            model = ExplainableModel(key, family, explainer_type, output_space, artifact, estimator, preprocessor, metadata, outputs, float(metadata["decision_threshold"]))
        elif family in {"multiclass_random_forest", "multiclass_logistic_regression"}:
            estimator, preprocessor, taxonomy, metadata = load_model_bundle(artifact)
            model_classes = [int(item) for item in estimator.classes_]
            labels_by_class_id = {index: str(label) for index, label in enumerate(taxonomy.labels)}
            outputs = tuple(
                ExplanationOutput(
                    name=labels_by_class_id[class_id],
                    index=position,
                    semantic="class probability" if family.endswith("random_forest") else "class logit",
                    class_label=labels_by_class_id[class_id],
                    class_id=class_id,
                )
                for position, class_id in enumerate(model_classes)
                if class_id in labels_by_class_id
            )
            if len(outputs) != len(model_classes):
                raise ExplainabilityError(f"Model {metadata.get('model_id')} has classes outside its persisted taxonomy.")
            model = ExplainableModel(key, family, explainer_type, output_space, artifact, estimator, preprocessor, metadata, outputs, taxonomy=taxonomy)
        elif family == "anomaly":
            estimator, preprocessor, metadata, calibration = load_anomaly_bundle(artifact)
            point = str(specification["operating_point"])
            point_doc = calibration.get("operating_points", {}).get(point)
            if point_doc is None:
                raise ExplainabilityError(f"Anomaly artifact does not contain operating point {point!r}.")
            outputs = (ExplanationOutput("anomaly_score", 0, "higher-is-more-anomalous score"),)
            model = ExplainableModel(key, family, explainer_type, output_space, artifact, estimator, preprocessor, metadata, outputs, float(point_doc["threshold"]), operating_point=point)
        else:
            raise ExplainabilityError(f"Model registry does not support family {family!r}.")
        _validate_model(model, contract)
        models[key] = model
    if not models:
        raise ExplainabilityError("No model specifications were configured for explainability.")
    return models, config


def _validate_model(model: ExplainableModel, contract: FeatureContract) -> None:
    metadata = model.metadata
    if metadata.get("feature_schema_version") != contract.schema_version:
        raise ExplainabilityError(f"Model {model.model_id} has an incompatible feature schema version.")
    if metadata.get("input_feature_names") != list(contract.predictive_features):
        raise ExplainabilityError(f"Model {model.model_id} has a different original feature order.")
    recorded_output = metadata.get("output_feature_names")
    fitted_output = list(model.preprocessor.get_feature_names_out())
    if recorded_output != fitted_output:
        raise ExplainabilityError(f"Model {model.model_id} transformed feature names/order do not match its metadata.")
    if not getattr(model.preprocessor, "is_fitted_", False):
        raise ExplainabilityError(f"Model {model.model_id} does not have a fitted preprocessor.")


def _project_root(config_path: Path) -> Path:
    # Configs are expected under project-root/configs; resolve paths without machine-specific constants.
    return config_path.parent.parent
