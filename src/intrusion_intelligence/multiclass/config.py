"""Validated configuration for the reusable multi-class experiment."""

from __future__ import annotations

import tomllib
from pathlib import Path
from typing import Any

from intrusion_intelligence.errors import ConfigurationError

DEFAULT_MULTICLASS_CONFIG = Path(__file__).resolve().parents[3] / "configs" / "multiclass.toml"


def load_multiclass_config(path: str | Path = DEFAULT_MULTICLASS_CONFIG) -> dict[str, Any]:
    """Read settings and resolve project paths relative to the TOML file."""
    config_path = Path(path).expanduser().resolve()
    try:
        with config_path.open("rb") as stream:
            config = tomllib.load(stream)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ConfigurationError(f"Unable to load multi-class configuration: {config_path}") from exc
    for section in ("dataset", "split", "training", "models", "artifacts", "reports"):
        if section not in config or not isinstance(config[section], dict):
            raise ConfigurationError(f"Multi-class configuration is missing [{section}].")
    root = config_path.parent.parent
    for section, key in (
        ("dataset", "parquet_directory"),
        ("dataset", "feature_schema"),
        ("artifacts", "directory"),
        ("reports", "evaluation_directory"),
        ("reports", "figure_directory"),
        ("reports", "experiment_directory"),
    ):
        value = config[section].get(key)
        if not isinstance(value, str) or not value.strip():
            raise ConfigurationError(f"[{section}].{key} must be a non-empty path.")
        candidate = Path(value).expanduser()
        config[section][key] = (root / candidate).resolve() if not candidate.is_absolute() else candidate.resolve()
    split = config["split"]
    fractions = [float(split.get(name, 0.0)) for name in ("train_fraction", "validation_fraction", "test_fraction")]
    if any(value <= 0 for value in fractions) or abs(sum(fractions) - 1.0) > 1e-9:
        raise ConfigurationError("Multi-class split fractions must be positive and sum to one.")
    if split.get("strategy") not in {"group_aware", "stratified_row"}:
        raise ConfigurationError("Unsupported multi-class split strategy.")
    training = config["training"]
    for name in ("max_training_rows", "batch_size", "random_seed"):
        if int(training.get(name, 0)) <= 0:
            raise ConfigurationError(f"[training].{name} must be a positive integer.")
    if not config["models"].get("logistic_regression", {}).get("enabled", False):
        raise ConfigurationError("The Logistic Regression baseline must be enabled.")
    if not config["models"].get("random_forest", {}).get("enabled", False):
        raise ConfigurationError("The Random Forest baseline must be enabled.")
    if int(training.get("retain_all_class_rows_below", 50)) < 1:
        raise ConfigurationError("[training].retain_all_class_rows_below must be a positive integer.")
    return config
