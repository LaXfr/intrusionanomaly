"""Load and validate train-fitted preprocessing configuration."""

from __future__ import annotations

import tomllib
from pathlib import Path
from typing import Any

from intrusion_intelligence.errors import ConfigurationError

DEFAULT_PREPROCESSING_CONFIG = Path(__file__).resolve().parents[3] / "configs" / "preprocessing.toml"
SUPPORTED_PROFILES = {"linear", "tree", "anomaly"}
SUPPORTED_SCALERS = {"standard", "robust", "none"}


def load_preprocessing_config(
    path: str | Path = DEFAULT_PREPROCESSING_CONFIG,
) -> dict[str, Any]:
    """Read preprocessing profiles and reject unsupported choices early."""
    config_path = Path(path)
    try:
        with config_path.open("rb") as stream:
            config = tomllib.load(stream)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ConfigurationError(f"Unable to load preprocessing config: {config_path}") from exc
    required = {"imputation", "encoding", "profiles", "feature_selection", "engineering"}
    missing = required - set(config)
    if missing:
        raise ConfigurationError(f"Preprocessing config is missing sections: {sorted(missing)}.")
    profiles = config["profiles"]
    if not SUPPORTED_PROFILES.issubset(profiles):
        raise ConfigurationError("Preprocessing config must define linear, tree, and anomaly profiles.")
    for name in SUPPORTED_PROFILES:
        scaler = profiles[name].get("scaler")
        if scaler not in SUPPORTED_SCALERS:
            raise ConfigurationError(f"Unsupported scaler for {name!r}: {scaler!r}.")
    if config["imputation"]["numeric_strategy"] != "median":
        raise ConfigurationError("Only training-fitted median numeric imputation is currently supported.")
    if config["imputation"]["categorical_strategy"] not in {"constant", "most_frequent"}:
        raise ConfigurationError("Categorical imputation must be 'constant' or 'most_frequent'.")
    if config["imputation"].get("all_missing_numeric") != "error":
        raise ConfigurationError("Entirely missing numeric training columns must use the 'error' policy.")
    if config["encoding"]["handle_unknown"] != "ignore":
        raise ConfigurationError("Categorical encoding must ignore unknown inference categories.")
    if config["feature_selection"]["strategy"] not in {"variance_threshold", "none"}:
        raise ConfigurationError("Unsupported feature selection strategy.")
    if float(config["feature_selection"].get("threshold", 0.0)) < 0:
        raise ConfigurationError("Variance threshold cannot be negative.")
    return config
