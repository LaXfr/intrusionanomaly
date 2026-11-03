"""Small reusable setup for consistent application logging."""

from __future__ import annotations

import logging

from intrusion_intelligence.config import LoggingSettings
from intrusion_intelligence.errors import ConfigurationError


def configure_logging(settings: LoggingSettings | None = None) -> None:
    """Configure a standard console handler without duplicating handlers.

    Existing root handlers are retained so callers can integrate this setup
    with test runners or applications that configure logging themselves.

    Args:
        settings: Logging settings. Defaults to the project's ``INFO`` level.

    Raises:
        ConfigurationError: If the requested level is not supported by
            Python's standard logging module.
    """
    selected = settings or LoggingSettings(level="INFO")
    level_name = selected.level.upper()
    level = getattr(logging, level_name, None)
    if not isinstance(level, int):
        raise ConfigurationError(f"Unsupported logging level: {selected.level}")

    root_logger = logging.getLogger()
    root_logger.setLevel(level)
    if root_logger.handlers:
        return

    handler = logging.StreamHandler()
    handler.setFormatter(
        logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
    )
    root_logger.addHandler(handler)
