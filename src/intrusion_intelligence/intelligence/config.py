"""TOML configuration for offline threat scoring and correlation."""

from __future__ import annotations

import tomllib
from pathlib import Path
from typing import Any

from intrusion_intelligence.errors import ConfigurationError
from intrusion_intelligence.intelligence.correlation import RULE_FIELDS
from intrusion_intelligence.intelligence.scoring import validate_weights
from intrusion_intelligence.intelligence.severity import validate_severity_bands

DEFAULT_INTELLIGENCE_CONFIG = Path(__file__).resolve().parents[3] / "configs" / "intelligence.toml"


def load_intelligence_config(path: str | Path = DEFAULT_INTELLIGENCE_CONFIG) -> dict[str, Any]:
    config_path = Path(path).expanduser().resolve()
    try:
        with config_path.open("rb") as stream:
            config = tomllib.load(stream)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ConfigurationError(f"Unable to load intelligence configuration: {config_path}") from exc
    required = ("dataset", "detectors", "scoring", "severity", "correlation", "alerts", "sampling", "reports")
    missing = [name for name in required if not isinstance(config.get(name), dict)]
    if missing:
        raise ConfigurationError(f"Intelligence configuration is missing sections: {missing}.")
    root = config_path.parent.parent
    for section, key in (
        ("dataset", "parquet_directory"),
        ("dataset", "feature_schema"),
        ("detectors.binary", "artifact_directory"),
        ("detectors.multiclass", "artifact_directory"),
        ("detectors.anomaly", "artifact_directory"),
        ("reports", "intelligence_directory"),
        ("reports", "figure_directory"),
    ):
        node: dict[str, Any] = config
        for part in section.split("."):
            node = node.setdefault(part, {})
        value = node.get(key)
        if not isinstance(value, str) or not value.strip():
            if section.startswith("detectors.") and not node.get("enabled", False):
                continue
            raise ConfigurationError(f"[{section}].{key} must be a non-empty path.")
        candidate = Path(value).expanduser()
        node[key] = (root / candidate).resolve() if not candidate.is_absolute() else candidate.resolve()
    for name in ("binary", "multiclass", "anomaly"):
        section = config["detectors"].setdefault(name, {"enabled": False})
        if not isinstance(section.get("enabled"), bool):
            raise ConfigurationError(f"[detectors.{name}].enabled must be boolean.")
    if not any(config["detectors"][name]["enabled"] for name in ("binary", "multiclass", "anomaly")):
        raise ConfigurationError("At least one detection engine must be enabled.")
    config["scoring"]["weights"] = validate_weights(config["scoring"].get("weights", {}))
    config["severity"]["bands"] = validate_severity_bands(config["severity"].get("bands", []))
    correlation = config["correlation"]
    allowed = correlation.get("allowed_windows_minutes", [1, 5, 15])
    if not isinstance(allowed, list) or not allowed or any(int(value) <= 0 for value in allowed):
        raise ConfigurationError("Correlation windows must be a non-empty list of positive integers.")
    if int(correlation.get("window_minutes", 0)) not in set(map(int, allowed)):
        raise ConfigurationError("The selected correlation window must be present in allowed_windows_minutes.")
    unknown_rules = set(correlation.get("enabled_rules", [])) - set(RULE_FIELDS)
    if unknown_rules:
        raise ConfigurationError(f"Unknown correlation rules: {sorted(unknown_rules)}.")
    if int(correlation.get("minimum_events", 0)) < 2:
        raise ConfigurationError("Correlation minimum_events must be at least 2.")
    alerts = config["alerts"]
    for key in ("single_event_minimum_score", "correlated_minimum_score"):
        value = float(alerts.get(key, -1))
        if not 0 <= value <= 100:
            raise ConfigurationError(f"[alerts].{key} must be in 0–100.")
    if int(alerts.get("minimum_available_signals", 0)) < 1:
        raise ConfigurationError("At least one available signal is required to create alerts.")
    sampling = config["sampling"]
    for key in ("rows_per_label_per_source_file", "batch_size"):
        if int(sampling.get(key, 0)) < 1:
            raise ConfigurationError(f"[sampling].{key} must be positive.")
    return config
