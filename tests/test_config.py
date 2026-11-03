"""Tests for centralized configuration behavior."""

from pathlib import Path

import pytest

from intrusion_intelligence.config import load_config
from intrusion_intelligence.errors import ConfigurationError


def test_environment_overrides_are_applied_and_paths_are_project_relative() -> None:
    """Environment settings override defaults without machine-specific paths."""
    database_url = "postgresql+psycopg://example:example@localhost/example"
    config = load_config(
        environ={
            "NII_RANDOM_SEED": "17",
            "NII_RAW_DATA_DIR": "custom/raw",
            "NII_DATASET_DIRECTORY": "flows",
            "NII_EDA_REPORT_DIR": "custom/eda-reports",
            "NII_SUPPORTED_FILE_EXTENSIONS": ".csv,.CSV.GZ",
            "NII_LABEL_CANDIDATES": "Label, Class",
            "NII_CHUNK_SIZE": "256",
            "NII_LOADING_STRATEGY": "CHUNKED",
            "NII_LOG_LEVEL": "DEBUG",
            "NII_DATABASE_URL": database_url,
        }
    )

    assert config.experiment.random_seed == 17
    assert config.paths.raw_data == (config.project_root / "custom/raw").resolve()
    assert config.dataset.directory == (config.paths.raw_data / "flows").resolve()
    assert config.paths.eda_reports == (config.project_root / "custom/eda-reports").resolve()
    assert config.dataset.supported_extensions == (".csv", ".csv.gz")
    assert config.dataset.label_candidates == ("Label", "Class")
    assert config.ingestion.chunk_size == 256
    assert config.ingestion.loading_strategy == "chunked"
    assert config.logging.level == "DEBUG"
    assert config.database.url == database_url


def test_absolute_path_override_is_preserved(tmp_path: Path) -> None:
    """Absolute data path overrides remain absolute after loading."""
    target = tmp_path / "external-data"
    config = load_config(environ={"NII_PROCESSED_DATA_DIR": str(target)})

    assert config.paths.processed_data == target


def test_chunk_size_must_be_positive() -> None:
    """Reject a chunk configuration that would make no progress."""
    with pytest.raises(ConfigurationError, match="greater than zero"):
        load_config(environ={"NII_CHUNK_SIZE": "0"})


def test_loading_strategy_must_be_supported() -> None:
    """Reject an unrecognized CSV loading mode."""
    with pytest.raises(ConfigurationError, match="standard, chunked"):
        load_config(environ={"NII_LOADING_STRATEGY": "adaptive"})
