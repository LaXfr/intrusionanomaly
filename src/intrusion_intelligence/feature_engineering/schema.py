"""Versioned predictive-feature contracts and dataset separation helpers."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

import numpy as np
import pandas as pd
from pandas.api.types import is_bool_dtype, is_numeric_dtype

DEFAULT_SCHEMA_PATH = Path(__file__).resolve().parents[3] / "configs" / "feature_schema.json"


class FeatureSchemaError(ValueError):
    """Raised when feature data does not match the declared feature contract."""


@dataclass(frozen=True, slots=True)
class FeatureSpec:
    """Definition of one input feature permitted by a feature contract."""

    name: str
    feature_type: Literal["numeric", "categorical"]
    role: str = "predictive"
    included: bool = True
    source_column: str | None = None
    transformation_requirements: tuple[str, ...] = ()
    optional: bool = False
    exclusion_reason: str | None = None


@dataclass(frozen=True, slots=True)
class FeatureContract:
    """Immutable view of a machine-readable feature schema."""

    schema_version: str
    dataset_name: str
    target_name: str
    target_values: tuple[str, ...]
    features: tuple[FeatureSpec, ...]
    metadata_fields: tuple[str, ...]
    excluded_fields: tuple[str, ...]
    source_column_mapping: tuple[dict[str, Any], ...] = ()

    @property
    def predictive_features(self) -> tuple[str, ...]:
        """Return included predictive input columns in contract order."""
        return tuple(
            feature.name
            for feature in self.features
            if feature.included and feature.role == "predictive"
        )

    @property
    def numeric_features(self) -> tuple[str, ...]:
        return tuple(
            feature.name
            for feature in self.features
            if feature.included and feature.role == "predictive" and feature.feature_type == "numeric"
        )

    @property
    def categorical_features(self) -> tuple[str, ...]:
        return tuple(
            feature.name
            for feature in self.features
            if feature.included and feature.role == "predictive" and feature.feature_type == "categorical"
        )

    @property
    def optional_features(self) -> tuple[str, ...]:
        return tuple(
            feature.name
            for feature in self.features
            if feature.included and feature.role == "predictive" and feature.optional
        )

    @classmethod
    def from_file(cls, path: str | Path = DEFAULT_SCHEMA_PATH) -> "FeatureContract":
        """Load and validate a JSON feature contract."""
        schema_path = Path(path)
        try:
            document = json.loads(schema_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise FeatureSchemaError(f"Unable to load feature schema: {schema_path}") from exc
        return cls.from_dict(document)

    @classmethod
    def from_dict(cls, document: dict[str, Any]) -> "FeatureContract":
        """Create a contract from a parsed schema document."""
        target = document.get("target")
        if not isinstance(target, dict) or not target.get("name"):
            raise FeatureSchemaError("Feature schema must define a target name.")
        raw_features = document.get("features")
        if not isinstance(raw_features, list) or not raw_features:
            raise FeatureSchemaError("Feature schema must define at least one feature.")
        features: list[FeatureSpec] = []
        for item in raw_features:
            if not isinstance(item, dict) or not item.get("name"):
                raise FeatureSchemaError("Each feature definition must have a name.")
            feature_type = item.get("type")
            if feature_type not in {"numeric", "categorical"}:
                if item.get("included", True):
                    raise FeatureSchemaError(
                        f"Unsupported feature type for {item['name']!r}: {feature_type!r}."
                    )
                continue
            features.append(
                FeatureSpec(
                    name=str(item["name"]),
                    feature_type=feature_type,
                    role=str(item.get("role", "predictive")),
                    included=bool(item.get("included", True)),
                    source_column=item.get("source_column"),
                    transformation_requirements=tuple(item.get("transformation_requirements", ())),
                    optional=bool(item.get("optional", False)),
                    exclusion_reason=item.get("exclusion_reason"),
                )
            )
        names = [feature.name for feature in features if feature.included and feature.role == "predictive"]
        if len(names) != len(set(names)):
            raise FeatureSchemaError("Predictive feature names must be unique.")
        if target["name"] in names:
            raise FeatureSchemaError("The target cannot be an included predictive feature.")
        if not names:
            raise FeatureSchemaError("Feature schema contains no included predictive features.")
        leakage = document.get("leakage_policy", {})
        metadata_fields = tuple(dict.fromkeys(leakage.get("metadata_fields", ())))
        excluded_fields = tuple(dict.fromkeys(leakage.get("excluded_fields", ())))
        if target["name"] in metadata_fields or target["name"] in excluded_fields:
            raise FeatureSchemaError("Target must be represented separately from metadata fields.")
        return cls(
            schema_version=str(document.get("schema_version", "1.0")),
            dataset_name=str(document.get("dataset_name", "unspecified")),
            target_name=str(target["name"]),
            target_values=tuple(target.get("allowed_values", ())),
            features=tuple(features),
            metadata_fields=metadata_fields,
            excluded_fields=excluded_fields,
            source_column_mapping=tuple(document.get("source_column_mapping", ())),
        )

    def fingerprint(self, dtypes: dict[str, str] | None = None) -> str:
        """Hash ordered contract names, types, roles, and optional dtypes."""
        payload = {
            "schema_version": self.schema_version,
            "features": [
                {"name": feature.name, "type": feature.feature_type, "optional": feature.optional}
                for feature in self.features
                if feature.included and feature.role == "predictive"
            ],
            "dtypes": dtypes or {},
        }
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def validate_feature_matrix(
    frame: pd.DataFrame,
    contract: FeatureContract,
    *,
    mode: Literal["training", "inference"] = "training",
) -> pd.DataFrame:
    """Validate feature-only input and return it in contract order.

    Inference may omit only contract-declared optional columns. Such columns
    are inserted as missing values so the fitted imputer keeps output width.
    ``training`` always requires every declared feature.
    """
    if mode not in {"training", "inference"}:
        raise FeatureSchemaError(f"Unsupported feature-validation mode {mode!r}.")
    if not isinstance(frame, pd.DataFrame):
        raise FeatureSchemaError("Feature input must be a pandas DataFrame.")
    if frame.columns.has_duplicates:
        duplicates = frame.columns[frame.columns.duplicated()].unique().tolist()
        raise FeatureSchemaError(f"Duplicate feature names are not allowed: {duplicates}.")
    expected = list(contract.predictive_features)
    actual = list(frame.columns)
    contaminated = [
        name
        for name in actual
        if name == contract.target_name or name in contract.metadata_fields or name in contract.excluded_fields
    ]
    if contaminated:
        raise FeatureSchemaError(
            f"Target or metadata columns cannot enter X: {contaminated}."
        )
    unknown = [name for name in actual if name not in expected]
    if unknown:
        raise FeatureSchemaError(f"Unexpected feature columns are not permitted: {unknown}.")
    missing = [name for name in expected if name not in actual]
    if mode == "training" and missing:
        raise FeatureSchemaError(f"Training input is missing required features: {missing}.")
    if mode == "inference":
        required_missing = [name for name in missing if name not in contract.optional_features]
        if required_missing:
            raise FeatureSchemaError(
                f"Inference input is missing required features: {required_missing}."
            )
    expected_present = [name for name in expected if name in actual]
    if actual != expected_present:
        raise FeatureSchemaError(
            "Feature columns are out of contract order. "
            f"Expected {expected_present}; received {actual}."
        )
    validated = frame.copy()
    specs = {feature.name: feature for feature in contract.features if feature.included}
    for name in missing:
        dtype = "float64" if specs[name].feature_type == "numeric" else object
        validated[name] = pd.Series(np.nan, index=validated.index, dtype=dtype)
    validated = validated.loc[:, expected]
    _validate_feature_values(validated, contract)
    # Categorical numerics such as protocol codes remain categories; stringify
    # them before imputation so the configured missing token never mixes types.
    for name in contract.categorical_features:
        text_values = validated[name].astype("string")
        validated[name] = pd.Series(
            text_values.to_numpy(dtype=object, na_value=np.nan),
            index=validated.index,
            dtype=object,
        )
    return validated


def separate_features_target_metadata(
    frame: pd.DataFrame,
    contract: FeatureContract,
    *,
    require_target: bool = True,
) -> tuple[pd.DataFrame, pd.Series | None, pd.DataFrame]:
    """Select contract features, target, and known metadata without leakage.

    Unknown columns fail instead of being silently accepted or included.
    ``X``, ``y``, and metadata retain the same row index and order.
    """
    if not isinstance(frame, pd.DataFrame):
        raise FeatureSchemaError("Dataset input must be a pandas DataFrame.")
    if frame.columns.has_duplicates:
        duplicates = frame.columns[frame.columns.duplicated()].unique().tolist()
        raise FeatureSchemaError(f"Duplicate dataset columns are not allowed: {duplicates}.")
    known = set(contract.predictive_features) | set(contract.metadata_fields) | set(contract.excluded_fields) | {contract.target_name}
    unknown = [name for name in frame.columns if name not in known]
    if unknown:
        raise FeatureSchemaError(f"Dataset contains columns outside the feature contract: {unknown}.")
    missing = [name for name in contract.predictive_features if name not in frame.columns]
    if missing:
        raise FeatureSchemaError(f"Dataset is missing required predictive features: {missing}.")
    if require_target and contract.target_name not in frame.columns:
        raise FeatureSchemaError(f"Dataset is missing target column {contract.target_name!r}.")
    X = validate_feature_matrix(frame.loc[:, list(contract.predictive_features)], contract)
    y: pd.Series | None = None
    if contract.target_name in frame.columns:
        y = frame[contract.target_name].copy()
        if y.isna().any() or y.astype("string").str.strip().eq("").any():
            raise FeatureSchemaError("Target contains missing or blank labels.")
        if contract.target_values:
            invalid = sorted(set(y.astype("string")) - set(contract.target_values))
            if invalid:
                raise FeatureSchemaError(f"Target contains labels outside the contract: {invalid}.")
    metadata_names = [
        name for name in (*contract.metadata_fields, *contract.excluded_fields)
        if name in frame.columns
    ]
    metadata = frame.loc[:, metadata_names].copy()
    return X, y, metadata


def _validate_feature_values(frame: pd.DataFrame, contract: FeatureContract) -> None:
    specs = {feature.name: feature for feature in contract.features if feature.included}
    for name in frame.columns:
        spec = specs[name]
        series = frame[name]
        if spec.feature_type == "numeric":
            if not is_numeric_dtype(series.dtype) or is_bool_dtype(series.dtype):
                raise FeatureSchemaError(
                    f"Numeric feature {name!r} must have a numeric dtype; received {series.dtype}."
                )
            values = series.to_numpy(dtype="float64", na_value=np.nan)
            if np.isinf(values).any():
                raise FeatureSchemaError(f"Numeric feature {name!r} contains infinity.")
        else:
            _validate_categorical_dtype(name, series)


def _validate_categorical_dtype(name: str, series: pd.Series) -> None:
    if is_numeric_dtype(series.dtype) or isinstance(series.dtype, pd.CategoricalDtype):
        return
    if not (pd.api.types.is_string_dtype(series.dtype) or series.dtype == object):
        raise FeatureSchemaError(
            f"Categorical feature {name!r} has unsupported dtype {series.dtype}."
        )
    values = series.dropna().tolist()
    families = {"numeric" if isinstance(value, (int, float, np.number)) else type(value).__name__ for value in values}
    if len(families) > 1:
        raise FeatureSchemaError(
            f"Categorical feature {name!r} contains mixed value types: {sorted(families)}."
        )
