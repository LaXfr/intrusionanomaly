"""Leakage-safe, train-fitted preprocessing profiles for flow data."""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from typing import Any, Literal

from sklearn.base import BaseEstimator, TransformerMixin
from sklearn.compose import ColumnTransformer
from sklearn.feature_selection import VarianceThreshold
from sklearn.impute import SimpleImputer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, RobustScaler, StandardScaler

import numpy as np
import pandas as pd
import scipy.sparse as sp
import sklearn

from intrusion_intelligence.feature_engineering import (
    DEFAULT_SCHEMA_PATH,
    FeatureContract,
    FeatureSchemaError,
    FlowFeatureEngineer,
    validate_feature_matrix,
)
from intrusion_intelligence.preprocessing.config import (
    DEFAULT_PREPROCESSING_CONFIG,
    load_preprocessing_config,
)


class PreprocessingError(ValueError):
    """Raised when a configured train/inference transformation is invalid."""


class LeakageSafePreprocessor(TransformerMixin, BaseEstimator):
    """Fit preprocessing on training features and reuse it unchanged later."""

    def __init__(
        self,
        contract: FeatureContract,
        profile: Literal["linear", "tree", "anomaly"],
        config: dict[str, Any],
        *,
        derived_features: tuple[str, ...] = (),
        feature_selection: bool | None = None,
    ) -> None:
        if profile not in config["profiles"]:
            raise PreprocessingError(f"Unknown preprocessing profile {profile!r}.")
        self.contract = contract
        self.profile = profile
        self.config = config
        self.derived_features = tuple(derived_features)
        selection_config = config["feature_selection"]
        self.feature_selection = (
            bool(selection_config["enabled"])
            if feature_selection is None
            else bool(feature_selection)
        )
        self.pipeline_: Pipeline | None = None
        self.training_schema_fingerprint_: str | None = None
        self.training_dtypes_: dict[str, str] | None = None
        self.is_fitted_ = False

    def fit(
        self,
        X_train: pd.DataFrame,
        y: Any = None,
    ) -> "LeakageSafePreprocessor":
        """Fit imputers, encoder, scaler, and optional selector on training X only."""
        if y is not None:
            raise PreprocessingError("Fit accepts X_train only; keep target labels separate as y.")
        try:
            validated = validate_feature_matrix(X_train, self.contract, mode="training")
        except FeatureSchemaError as exc:
            raise PreprocessingError(str(exc)) from exc
        if validated.empty:
            raise PreprocessingError("Cannot fit preprocessing on zero training rows.")
        self.training_dtypes_ = {name: str(dtype) for name, dtype in validated.dtypes.items()}
        self.training_schema_fingerprint_ = self.contract.fingerprint(self.training_dtypes_)
        feature_engineer = FlowFeatureEngineer(self.derived_features)
        engineered = feature_engineer.fit_transform(validated)
        _validate_training_missingness(
            engineered,
            self.contract,
            self.derived_features,
            self.config,
        )
        pipeline = _build_pipeline(
            self.contract,
            self.profile,
            self.config,
            derived_features=self.derived_features,
            feature_selection=self.feature_selection,
        )
        try:
            pipeline.fit(validated)
        except (ValueError, TypeError) as exc:
            raise PreprocessingError(f"Unable to fit {self.profile!r} preprocessing: {exc}") from exc
        self.pipeline_ = pipeline
        self.is_fitted_ = True
        try:
            self._feature_names_out = tuple(pipeline.get_feature_names_out().tolist())
        except (AttributeError, ValueError) as exc:
            self.pipeline_ = None
            self.is_fitted_ = False
            raise PreprocessingError(f"Fitted pipeline could not produce stable feature names: {exc}") from exc
        return self

    def transform(
        self,
        X: pd.DataFrame,
        *,
        mode: Literal["inference", "training"] = "inference",
    ) -> np.ndarray | sp.spmatrix:
        """Transform rows with the fitted training parameters; never refit."""
        self._ensure_fitted()
        try:
            validated = validate_feature_matrix(X, self.contract, mode=mode)
        except FeatureSchemaError as exc:
            raise PreprocessingError(str(exc)) from exc
        transformed = self.pipeline_.transform(validated)
        values = transformed.data if sp.issparse(transformed) else np.asarray(transformed)
        if not np.isfinite(values).all():
            raise PreprocessingError("Transformed data contains NaN or infinity after preprocessing.")
        return transformed

    def fit_transform(
        self,
        X_train: pd.DataFrame,
        y: Any = None,
    ) -> np.ndarray | sp.spmatrix:
        """Fit on training features and return their transformed representation."""
        return self.fit(X_train, y=y).transform(X_train, mode="training")

    def transform_batches(
        self,
        batches: Iterable[pd.DataFrame],
    ) -> Iterator[np.ndarray | sp.spmatrix]:
        """Transform inference batches with the same fitted parameters."""
        for batch in batches:
            yield self.transform(batch, mode="inference")

    def get_feature_names_out(self) -> np.ndarray:
        """Return stable transformed feature names after fitting."""
        self._ensure_fitted()
        return np.asarray(self._feature_names_out, dtype=object)

    @property
    def numeric_imputation_statistics(self) -> dict[str, float]:
        """Return learned medians keyed by the numeric transformer input name."""
        self._ensure_fitted()
        if self.pipeline_ is None:
            raise PreprocessingError("Preprocessor has not been fitted.")
        transformer: ColumnTransformer = self.pipeline_.named_steps["transform"]
        if "numeric" not in transformer.named_transformers_:
            return {}
        numeric_pipeline: Pipeline = transformer.named_transformers_["numeric"]
        imputer: SimpleImputer = numeric_pipeline.named_steps["imputer"]
        return {
            name: float(value)
            for name, value in zip(self._numeric_input_names(), imputer.statistics_)
        }

    def scaling_statistics(self) -> dict[str, dict[str, float]]:
        """Return fitted scaler parameters without exposing training records."""
        self._ensure_fitted()
        if self.pipeline_ is None:
            raise PreprocessingError("Preprocessor has not been fitted.")
        transformer: ColumnTransformer = self.pipeline_.named_steps["transform"]
        if "numeric" not in transformer.named_transformers_:
            return {}
        numeric_pipeline: Pipeline = transformer.named_transformers_["numeric"]
        scaler = numeric_pipeline.named_steps.get("scaler")
        if scaler is None:
            return {}
        if hasattr(scaler, "mean_"):
            values = scaler.mean_
            key = "mean"
        else:
            values = scaler.center_
            key = "center"
        return {
            name: {key: float(value), "scale": float(scale)}
            for name, value, scale in zip(self._numeric_input_names(), values, scaler.scale_)
        }

    def selection_metadata(self) -> dict[str, Any]:
        """Return selected and filtered transformed fields."""
        self._ensure_fitted()
        if self.pipeline_ is None:
            raise PreprocessingError("Preprocessor has not been fitted.")
        raw_names = list(self.pipeline_.named_steps["transform"].get_feature_names_out())
        selector = self.pipeline_.named_steps.get("select")
        if selector is None:
            return {"enabled": False, "selected": raw_names, "excluded": []}
        mask = selector.get_support()
        return {
            "enabled": True,
            "selected": [name for name, keep in zip(raw_names, mask) if keep],
            "excluded": [name for name, keep in zip(raw_names, mask) if not keep],
            "threshold": float(selector.threshold),
        }

    def preprocessing_metadata(self) -> dict[str, Any]:
        """Describe fitted choices and learned parameters for artifact metadata."""
        self._ensure_fitted()
        profile = self.config["profiles"][self.profile]
        return {
            "profile": self.profile,
            "numeric_features": list(self.contract.numeric_features),
            "categorical_features": list(self.contract.categorical_features),
            "imputation": self.config["imputation"],
            "encoding": self.config["encoding"],
            "scaling_strategy": profile["scaler"],
            "feature_engineering": {
                "enabled": bool(self.derived_features),
                "derived_features": list(self.derived_features),
            },
            "feature_selection": self.selection_metadata(),
            "output_feature_names": list(self.get_feature_names_out()),
            "training_schema_fingerprint": self.training_schema_fingerprint_,
            "training_dtypes": self.training_dtypes_,
            "learned_numeric_imputation_statistics": self.numeric_imputation_statistics,
            "learned_scaling_statistics": self.scaling_statistics(),
            "scikit_learn_version": sklearn.__version__,
            "random_seed": self.config.get("random_seed", 42),
        }

    def _numeric_input_names(self) -> tuple[str, ...]:
        return (*self.contract.numeric_features, *self.derived_features)

    def _ensure_fitted(self) -> None:
        if not self.is_fitted_ or self.pipeline_ is None:
            raise PreprocessingError("Preprocessor has not been fitted.")


def build_preprocessor(
    profile: Literal["linear", "tree", "anomaly"],
    *,
    contract: FeatureContract | None = None,
    config: dict[str, Any] | None = None,
    schema_path: str | None = None,
    config_path: str | None = None,
    derived_features: tuple[str, ...] | None = None,
    feature_selection: bool | None = None,
) -> LeakageSafePreprocessor:
    """Build an independent supervised or anomaly preprocessing instance."""
    selected_contract = contract or FeatureContract.from_file(schema_path or DEFAULT_SCHEMA_PATH)
    selected_config = config or load_preprocessing_config(config_path or DEFAULT_PREPROCESSING_CONFIG)
    if profile not in selected_config["profiles"]:
        raise PreprocessingError(f"Unknown preprocessing profile {profile!r}.")
    engineering = selected_config["engineering"]
    if derived_features is None:
        derived_features = tuple(engineering.get("features", ())) if engineering.get("enabled", False) else ()
    return LeakageSafePreprocessor(
        selected_contract,
        profile,
        selected_config,
        derived_features=tuple(derived_features),
        feature_selection=feature_selection,
    )


def _build_pipeline(
    contract: FeatureContract,
    profile: str,
    config: dict[str, Any],
    *,
    derived_features: tuple[str, ...],
    feature_selection: bool,
) -> Pipeline:
    engineered_names = [*contract.predictive_features, *derived_features]
    if len(engineered_names) != len(set(engineered_names)):
        raise PreprocessingError("Feature engineering produced duplicate input names.")
    numeric_columns = [*contract.numeric_features, *derived_features]
    categorical_columns = list(contract.categorical_features)
    numeric_imputer = SimpleImputer(
        strategy=config["imputation"]["numeric_strategy"],
        add_indicator=bool(config["imputation"].get("add_numeric_indicators", False)),
        keep_empty_features=True,
    )
    numeric_steps: list[tuple[str, Any]] = [("imputer", numeric_imputer)]
    scaler_name = config["profiles"][profile]["scaler"]
    scaler = {
        "standard": StandardScaler(),
        "robust": RobustScaler(),
        "none": None,
    }[scaler_name]
    if scaler is not None:
        numeric_steps.append(("scaler", scaler))
    categorical_steps: list[tuple[str, Any]] = [
        (
            "imputer",
            SimpleImputer(
                strategy=config["imputation"]["categorical_strategy"],
                fill_value=config["imputation"]["categorical_missing_value"],
                keep_empty_features=True,
            ),
        ),
        (
            "encoder",
            OneHotEncoder(
                handle_unknown=config["encoding"]["handle_unknown"],
                sparse_output=bool(config["encoding"]["sparse_output"]),
                dtype=np.float64,
            ),
        ),
    ]
    transformers: list[tuple[str, Any, list[str]]] = []
    if numeric_columns:
        transformers.append(("numeric", Pipeline(numeric_steps), numeric_columns))
    if categorical_columns:
        transformers.append(("categorical", Pipeline(categorical_steps), categorical_columns))
    column_transformer = ColumnTransformer(
        transformers,
        remainder="drop",
        sparse_threshold=float(config["encoding"].get("sparse_threshold", 1.0)),
        verbose_feature_names_out=True,
    )
    steps: list[tuple[str, Any]] = [
        ("engineer", FlowFeatureEngineer(derived_features)),
        ("transform", column_transformer),
    ]
    if feature_selection and config["feature_selection"]["strategy"] == "variance_threshold":
        selection = config["feature_selection"]
        steps.append(("select", VarianceThreshold(threshold=float(selection["threshold"]))))
    return Pipeline(steps)


def _validate_training_missingness(
    engineered: pd.DataFrame,
    contract: FeatureContract,
    derived_features: tuple[str, ...],
    config: dict[str, Any],
) -> None:
    all_numeric = [*contract.numeric_features, *derived_features]
    entirely_missing = [name for name in all_numeric if engineered[name].isna().all()]
    if entirely_missing:
        raise PreprocessingError(
            "Training numeric features are entirely missing and have no safe median: "
            f"{entirely_missing}. Update the training schema or remove them through an explicit selection policy."
        )
    if config["imputation"]["categorical_strategy"] == "most_frequent":
        missing_categoricals = [
            name for name in contract.categorical_features
            if engineered[name].isna().all()
        ]
        if missing_categoricals:
            raise PreprocessingError(
                "Categorical training features are entirely missing and have no mode: "
                f"{missing_categoricals}. Use the configured missing-category strategy or update training data."
            )
