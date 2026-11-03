"""Load typed project settings from TOML and environment variables."""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Mapping, cast

from intrusion_intelligence.errors import ConfigurationError


@dataclass(frozen=True, slots=True)
class PathSettings:
    """Resolved paths used for local data and generated project artifacts."""

    raw_data: Path
    interim_data: Path
    processed_data: Path
    model_artifacts: Path
    report_figures: Path
    report_evaluation: Path
    dataset_metadata: Path
    ingestion_reports: Path
    eda_reports: Path


@dataclass(frozen=True, slots=True)
class DatasetSettings:
    """Dataset identity and source discovery rules."""

    name: str
    directory: Path
    source_url: str
    supported_extensions: tuple[str, ...]
    label_candidates: tuple[str, ...]
    recursive_discovery: bool


@dataclass(frozen=True, slots=True)
class IngestionSettings:
    """CSV interpretation and bounded loading defaults."""

    csv_encoding: str
    chunk_size: int
    loading_strategy: Literal["standard", "chunked"]


@dataclass(frozen=True, slots=True)
class ExperimentSettings:
    """Reproducibility settings shared by future experiments."""

    random_seed: int


@dataclass(frozen=True, slots=True)
class LoggingSettings:
    """Application logging configuration."""

    level: str


@dataclass(frozen=True, slots=True)
class DatabaseSettings:
    """Connection settings reserved for future database integration."""

    url: str | None


@dataclass(frozen=True, slots=True)
class ApplicationSettings:
    """General settings that describe the running application."""

    environment: str
    debug: bool


@dataclass(frozen=True, slots=True)
class ProjectConfig:
    """Complete immutable configuration for one project checkout."""

    project_root: Path
    paths: PathSettings
    dataset: DatasetSettings
    ingestion: IngestionSettings
    experiment: ExperimentSettings
    logging: LoggingSettings
    database: DatabaseSettings
    application: ApplicationSettings


def load_config(
    config_path: str | Path = Path("configs/project.toml"),
    *,
    environ: Mapping[str, str] | None = None,
) -> ProjectConfig:
    """Load project settings, applying supported environment overrides.

    Relative artifact and data paths are resolved from the repository root,
    defined as the parent directory of the ``configs`` directory containing
    the TOML file. The database URL is read from ``NII_DATABASE_URL`` and is
    never logged or used to establish a connection by this module.

    Args:
        config_path: Path to the project TOML configuration file.
        environ: Optional environment mapping, primarily useful for tests.

    Raises:
        ConfigurationError: If the file cannot be read or contains invalid
            values.
    """
    path = Path(config_path).expanduser().resolve()
    environment = os.environ if environ is None else environ

    try:
        with path.open("rb") as config_file:
            document = tomllib.load(config_file)
    except OSError as exc:
        raise ConfigurationError(f"Unable to read configuration file: {path}") from exc
    except tomllib.TOMLDecodeError as exc:
        raise ConfigurationError(f"Invalid TOML in configuration file: {path}") from exc

    if not isinstance(document, dict):
        raise ConfigurationError("The configuration document must contain TOML tables.")

    root = path.parent.parent
    paths = _section(document, "paths")
    dataset = _section(document, "dataset")
    ingestion = _section(document, "ingestion")
    experiment = _section(document, "experiment")
    logging_config = _section(document, "logging")
    database = _section(document, "database")
    application = _section(document, "application")
    raw_data_directory = _resolve_path(
        _setting(paths, "raw_data", "data/raw"),
        "NII_RAW_DATA_DIR",
        environment,
        root,
    )

    return ProjectConfig(
        project_root=root,
        paths=PathSettings(
            raw_data=raw_data_directory,
            interim_data=_resolve_path(
                _setting(paths, "interim_data", "data/interim"),
                "NII_INTERIM_DATA_DIR",
                environment,
                root,
            ),
            processed_data=_resolve_path(
                _setting(paths, "processed_data", "data/processed"),
                "NII_PROCESSED_DATA_DIR",
                environment,
                root,
            ),
            model_artifacts=_resolve_path(
                _setting(paths, "model_artifacts", "models"),
                "NII_MODEL_ARTIFACT_DIR",
                environment,
                root,
            ),
            report_figures=_resolve_path(
                _setting(paths, "report_figures", "reports/figures"),
                "NII_REPORT_FIGURES_DIR",
                environment,
                root,
            ),
            report_evaluation=_resolve_path(
                _setting(paths, "report_evaluation", "reports/evaluation"),
                "NII_REPORT_EVALUATION_DIR",
                environment,
                root,
            ),
            dataset_metadata=_resolve_path(
                _setting(paths, "dataset_metadata", "data/interim/metadata"),
                "NII_DATASET_METADATA_DIR",
                environment,
                root,
            ),
            ingestion_reports=_resolve_path(
                _setting(paths, "ingestion_reports", "reports/ingestion"),
                "NII_INGESTION_REPORT_DIR",
                environment,
                root,
            ),
            eda_reports=_resolve_path(
                _setting(paths, "eda_reports", "reports/eda"),
                "NII_EDA_REPORT_DIR",
                environment,
                root,
            ),
        ),
        dataset=DatasetSettings(
            name=_string_setting(
                dataset.get("name", "CIC-IDS2017"),
                "dataset.name",
                environment.get("NII_DATASET_NAME"),
            ),
            directory=_resolve_path(
                _setting(dataset, "directory", "CIC-IDS2017"),
                "NII_DATASET_DIRECTORY",
                environment,
                raw_data_directory,
            ),
            source_url=_string_setting(
                dataset.get(
                    "source_url", "https://www.unb.ca/cic/datasets/ids-2017.html"
                ),
                "dataset.source_url",
                environment.get("NII_DATASET_SOURCE_URL"),
            ),
            supported_extensions=_list_setting(
                dataset.get("supported_extensions", [".csv"]),
                "dataset.supported_extensions",
                environment.get("NII_SUPPORTED_FILE_EXTENSIONS"),
                lowercase=True,
                require_dot_prefix=True,
            ),
            label_candidates=_list_setting(
                dataset.get("label_candidates", ["Label"]),
                "dataset.label_candidates",
                environment.get("NII_LABEL_CANDIDATES"),
            ),
            recursive_discovery=_boolean_setting(
                dataset.get("recursive_discovery", True),
                "dataset.recursive_discovery",
                environment.get("NII_RECURSIVE_DISCOVERY"),
            ),
        ),
        ingestion=IngestionSettings(
            csv_encoding=_string_setting(
                ingestion.get("csv_encoding", "auto"),
                "ingestion.csv_encoding",
                environment.get("NII_CSV_ENCODING"),
            ),
            chunk_size=_positive_integer_setting(
                ingestion.get("chunk_size", 100000),
                "ingestion.chunk_size",
                environment.get("NII_CHUNK_SIZE"),
            ),
            loading_strategy=_choice_setting(
                ingestion.get("loading_strategy", "standard"),
                "ingestion.loading_strategy",
                environment.get("NII_LOADING_STRATEGY"),
                choices=("standard", "chunked"),
            ),
        ),
        experiment=ExperimentSettings(
            random_seed=_integer_setting(
                experiment.get("random_seed", 42),
                "random_seed",
                environment.get("NII_RANDOM_SEED"),
            )
        ),
        logging=LoggingSettings(
            level=_string_setting(
                logging_config.get("level", "INFO"),
                "logging.level",
                environment.get("NII_LOG_LEVEL"),
            ).upper()
        ),
        database=DatabaseSettings(
            url=_optional_string(
                environment.get("NII_DATABASE_URL", database.get("url", "")),
                "database.url",
            )
        ),
        application=ApplicationSettings(
            environment=_string_setting(
                application.get("environment", "development"),
                "application.environment",
                environment.get("NII_ENVIRONMENT"),
            ),
            debug=_boolean_setting(
                application.get("debug", False),
                "application.debug",
                environment.get("NII_APP_DEBUG"),
            ),
        ),
    )


def _section(document: dict[str, object], name: str) -> dict[str, object]:
    """Return a named TOML table or an empty table when it is absent."""
    value = document.get(name, {})
    if not isinstance(value, dict):
        raise ConfigurationError(f"Configuration section '{name}' must be a table.")
    return value


def _setting(section: dict[str, object], key: str, default: str) -> str:
    """Return a non-empty string setting from a TOML table."""
    value = section.get(key, default)
    if not isinstance(value, str) or not value.strip():
        raise ConfigurationError(
            f"Configuration value '{key}' must be a non-empty string."
        )
    return value


def _resolve_path(
    configured: str,
    environment_key: str,
    environ: Mapping[str, str],
    project_root: Path,
) -> Path:
    """Resolve a TOML or environment path relative to the project root."""
    selected = environ.get(environment_key, configured)
    if not selected.strip():
        raise ConfigurationError(
            f"Environment variable {environment_key} cannot be empty."
        )
    result = Path(selected).expanduser()
    return result if result.is_absolute() else (project_root / result).resolve()


def _string_setting(default: object, name: str, override: str | None) -> str:
    """Validate a string setting with an optional environment override."""
    value = override if override is not None else default
    if not isinstance(value, str) or not value.strip():
        raise ConfigurationError(
            f"Configuration value '{name}' must be a non-empty string."
        )
    return value.strip()


def _optional_string(value: object, name: str) -> str | None:
    """Normalize an optional string value without exposing it in errors."""
    if not isinstance(value, str):
        raise ConfigurationError(f"Configuration value '{name}' must be a string.")
    cleaned = value.strip()
    return cleaned or None


def _list_setting(
    default: object,
    name: str,
    override: str | None,
    *,
    lowercase: bool = False,
    require_dot_prefix: bool = False,
) -> tuple[str, ...]:
    """Validate a comma-separated environment override or TOML string list."""
    if override is not None:
        values = [value.strip() for value in override.split(",")]
    elif isinstance(default, list):
        values = default
    else:
        values = []

    if not values or any(
        not isinstance(value, str) or not value.strip() for value in values
    ):
        raise ConfigurationError(
            f"Configuration value '{name}' must be a non-empty string list."
        )

    normalized = tuple(
        value.strip().lower() if lowercase else value.strip()
        for value in values
    )
    if require_dot_prefix and any(not value.startswith(".") for value in normalized):
        raise ConfigurationError(
            f"Each extension in '{name}' must start with a dot."
        )
    return normalized


def _integer_setting(default: object, name: str, override: str | None) -> int:
    """Validate an integer setting and an optional string override."""
    try:
        value = int(override) if override is not None else default
    except ValueError as exc:
        raise ConfigurationError(
            f"Environment override for '{name}' must be an integer."
        ) from exc
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ConfigurationError(
            f"Configuration value '{name}' must be a non-negative integer."
        )
    return value


def _positive_integer_setting(default: object, name: str, override: str | None) -> int:
    """Validate an integer setting that must be greater than zero."""
    value = _integer_setting(default, name, override)
    if value == 0:
        raise ConfigurationError(
            f"Configuration value '{name}' must be greater than zero."
        )
    return value


def _choice_setting(
    default: object,
    name: str,
    override: str | None,
    *,
    choices: tuple[str, ...],
) -> Literal["standard", "chunked"]:
    """Validate a string setting against a small supported choice set."""
    value = _string_setting(default, name, override).lower()
    if value not in choices:
        allowed = ", ".join(choices)
        raise ConfigurationError(
            f"Configuration value '{name}' must be one of: {allowed}."
        )
    return cast(Literal["standard", "chunked"], value)


def _boolean_setting(default: object, name: str, override: str | None) -> bool:
    """Validate a boolean setting and common environment representations."""
    if override is not None:
        normalized = override.strip().lower()
        if normalized in {"1", "true", "yes", "on"}:
            return True
        if normalized in {"0", "false", "no", "off"}:
            return False
        raise ConfigurationError(
            f"Environment override for '{name}' must be a boolean."
        )
    if not isinstance(default, bool):
        raise ConfigurationError(f"Configuration value '{name}' must be a boolean.")
    return default
