"""Validated anomaly-detection experiment configuration."""

from __future__ import annotations

import re
import tomllib
from pathlib import Path
from typing import Any

from intrusion_intelligence.errors import ConfigurationError

DEFAULT_ANOMALY_CONFIG = Path(__file__).resolve().parents[3] / "configs" / "anomaly_detection.toml"
VALID_DAYS = {"Monday", "Tuesday", "Wednesday", "Thursday", "Friday"}


def load_anomaly_config(path: str | Path = DEFAULT_ANOMALY_CONFIG) -> dict[str, Any]:
    """Load the TOML config and resolve project-relative paths."""
    config_path = Path(path).expanduser().resolve()
    try:
        with config_path.open("rb") as stream:
            config = tomllib.load(stream)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ConfigurationError(f"Unable to load anomaly configuration: {config_path}") from exc
    for section in ("dataset", "split", "training", "model", "calibration", "artifacts", "reports"):
        if section not in config or not isinstance(config[section], dict):
            raise ConfigurationError(f"Anomaly configuration is missing [{section}].")
    for section, key in (
        ("dataset", "parquet_directory"),
        ("dataset", "feature_schema"),
        ("dataset", "preprocessing_config"),
        ("artifacts", "model_directory"),
        ("artifacts", "preprocessor_directory"),
        ("reports", "evaluation_directory"),
        ("reports", "figure_directory"),
        ("reports", "experiment_directory"),
    ):
        value = config[section].get(key)
        if not isinstance(value, str) or not value.strip():
            raise ConfigurationError(f"[{section}].{key} must be a non-empty path.")
        candidate = Path(value).expanduser()
        config[section][key] = (config_path.parent.parent / candidate).resolve() if not candidate.is_absolute() else candidate.resolve()

    dataset = config["dataset"]
    if dataset.get("benign_label") != "BENIGN":
        raise ConfigurationError("The validated CIC-IDS2017 benign label must be exactly 'BENIGN'.")
    split = config["split"]
    if split.get("strategy") != "capture_day_holdout":
        raise ConfigurationError("Only explicit capture-day group holdouts are supported; row fallback is prohibited.")
    partitions = [split.get("train_days"), split.get("validation_days"), split.get("test_days")]
    if any(not isinstance(part, list) or not part for part in partitions):
        raise ConfigurationError("Train, validation, and test capture-day lists must be non-empty.")
    flattened = [str(day) for part in partitions for day in part]
    if len(flattened) != len(set(flattened)) or set(flattened) != VALID_DAYS:
        raise ConfigurationError("Capture-day partitions must assign each CIC-IDS2017 day exactly once.")
    for day in flattened:
        if day not in VALID_DAYS:
            raise ConfigurationError(f"Unsupported capture day: {day!r}.")
    training = config["training"]
    for key in ("max_benign_training_rows", "batch_size", "minimum_benign_training_rows", "minimum_benign_validation_rows"):
        if int(training.get(key, 0)) <= 0:
            raise ConfigurationError(f"[training].{key} must be a positive integer.")
    model = config.get("model", {}).get("isolation_forest")
    if not isinstance(model, dict):
        raise ConfigurationError("[model.isolation_forest] is required.")
    if int(model.get("n_estimators", 0)) < 1 or int(model.get("n_jobs", 0)) == 0:
        raise ConfigurationError("Isolation Forest requires positive n_estimators and non-zero n_jobs.")
    if isinstance(model.get("max_samples"), int) and model["max_samples"] < 2:
        raise ConfigurationError("Isolation Forest max_samples must be at least 2 or 'auto'.")
    if not isinstance(model.get("max_samples"), (int, str)) or model["max_samples"] not in ("auto",) and not isinstance(model["max_samples"], int):
        raise ConfigurationError("Isolation Forest max_samples must be an integer or 'auto'.")
    if model.get("contamination") != "auto":
        try:
            contamination = float(model["contamination"])
        except (TypeError, ValueError) as exc:
            raise ConfigurationError("contamination must be 'auto' or a value in (0, 0.5].") from exc
        if not 0 < contamination <= 0.5:
            raise ConfigurationError("contamination must be 'auto' or a value in (0, 0.5].")
    operating_points = config["calibration"].get("operating_points")
    if not isinstance(operating_points, list) or not operating_points:
        raise ConfigurationError("At least one calibrated operating point is required.")
    ids: set[str] = set()
    rates: set[float] = set()
    for point in operating_points:
        point_id = str(point.get("id", ""))
        if not re.fullmatch(r"[a-z0-9][a-z0-9_-]*", point_id) or point_id in ids:
            raise ConfigurationError(f"Invalid or duplicate operating-point id: {point_id!r}.")
        rate = float(point.get("target_fpr", 0))
        if not 0 < rate < 1 or rate in rates:
            raise ConfigurationError("Operating-point FPR targets must be unique values between 0 and 1.")
        ids.add(point_id)
        rates.add(rate)
    if config["calibration"].get("default_operating_point") not in ids:
        raise ConfigurationError("Default operating point must name a configured operating point.")
    for section, key in (("artifacts", "model_version"), ("artifacts", "preprocessor_version")):
        if not re.fullmatch(r"\d+\.\d+\.\d+", str(config[section].get(key, ""))):
            raise ConfigurationError(f"[{section}].{key} must use numeric major.minor.patch form.")
    return config
