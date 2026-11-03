"""Discover supported dataset files below the configured raw data folder."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Sequence

from intrusion_intelligence.errors import DatasetDirectoryError, DatasetDiscoveryError

logger = logging.getLogger(__name__)


def validate_dataset_directory(dataset_directory: str | Path) -> Path:
    """Resolve and validate a dataset directory without scanning its contents."""
    directory = Path(dataset_directory).expanduser()
    if not directory.exists():
        raise DatasetDirectoryError(f"Dataset directory does not exist: {directory}")
    if not directory.is_dir():
        raise DatasetDirectoryError(f"Dataset path is not a directory: {directory}")
    return directory.resolve()


def discover_dataset_files(
    dataset_directory: str | Path,
    *,
    supported_extensions: Sequence[str] = (".csv",),
    recursive: bool = True,
) -> tuple[Path, ...]:
    """Return supported files in deterministic relative-path order.

    Directories and unrelated files are ignored. Recursive discovery supports
    archives extracted into nested folders without relying on vendor filenames.

    Raises:
        DatasetDirectoryError: If the directory is missing or is not a folder.
        DatasetDiscoveryError: If no files with the configured extensions exist.
    """
    directory = validate_dataset_directory(dataset_directory)
    extensions = _normalize_extensions(supported_extensions)
    candidates = directory.rglob("*") if recursive else directory.iterdir()
    try:
        files = tuple(
            sorted(
                (
                    path.resolve()
                    for path in candidates
                    if path.is_file()
                    and any(
                        path.name.casefold().endswith(extension)
                        for extension in extensions
                    )
                ),
                key=lambda path: path.relative_to(directory).as_posix().casefold(),
            )
        )
    except OSError as exc:
        raise DatasetDiscoveryError(
            f"Unable to list dataset directory: {directory}"
        ) from exc
    if not files:
        raise DatasetDiscoveryError(
            f"No supported dataset files ({', '.join(extensions)}) found in: "
            f"{directory}"
        )

    logger.info(
        "Discovered %d supported dataset file(s) under %s",
        len(files),
        directory,
    )
    return files


def _normalize_extensions(extensions: Sequence[str]) -> tuple[str, ...]:
    """Normalize extension values and reject unsafe or empty configuration."""
    normalized = tuple(extension.strip().lower() for extension in extensions)
    if not normalized or any(
        not extension.startswith(".") or "/" in extension or "\\" in extension
        for extension in normalized
    ):
        raise DatasetDiscoveryError(
            "Supported extensions must be a non-empty sequence such as ('.csv',)."
        )
    return tuple(dict.fromkeys(normalized))
