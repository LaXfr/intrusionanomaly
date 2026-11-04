"""Basic import smoke test for the project package."""

import intrusion_intelligence
from intrusion_intelligence.config import load_config


def test_project_package_imports_and_loads_default_config(monkeypatch) -> None:
    """Verify the package and its foundation configuration are importable."""
    monkeypatch.delenv("NII_DATABASE_URL", raising=False)
    config = load_config()

    assert intrusion_intelligence.__version__ == "0.1.0"
    assert config.experiment.random_seed == 42
    assert config.paths.raw_data.name == "raw"
    assert config.database.url is None
