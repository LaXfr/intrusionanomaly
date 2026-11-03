"""Versioned persistence for fitted preprocessing pipelines."""

from __future__ import annotations

import json
import os
import re
import shutil
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
import sklearn

from intrusion_intelligence.preprocessing.pipeline import LeakageSafePreprocessor

ARTIFACT_FILENAME = "preprocessor.joblib"
METADATA_FILENAME = "metadata.json"


def save_preprocessor(
    preprocessor: LeakageSafePreprocessor,
    artifact_root: str | Path,
    *,
    version: str = "1.0.0",
) -> Path:
    """Persist an independent profile/version without overwriting artifacts."""
    if not preprocessor.is_fitted_:
        raise ValueError("Only a fitted preprocessing pipeline can be saved.")
    if not re.fullmatch(r"\d+\.\d+\.\d+", version):
        raise ValueError("Artifact version must use numeric major.minor.patch form.")
    root = Path(artifact_root).expanduser()
    destination = root / preprocessor.profile / version
    if destination.exists():
        raise FileExistsError(f"Preprocessing artifact already exists: {destination}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=f".{version}.stage-", dir=destination.parent))
    try:
        joblib.dump(preprocessor, staging / ARTIFACT_FILENAME, compress=3)
        metadata = _artifact_metadata(preprocessor, version)
        (staging / METADATA_FILENAME).write_text(
            json.dumps(metadata, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        if destination.exists():
            raise FileExistsError(f"Preprocessing artifact already exists: {destination}")
        staging.rename(destination)
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    return destination


def load_preprocessor(artifact_directory: str | Path) -> LeakageSafePreprocessor:
    """Load a fitted transformer and verify its feature metadata."""
    directory = Path(artifact_directory)
    try:
        metadata = json.loads((directory / METADATA_FILENAME).read_text(encoding="utf-8"))
        preprocessor = joblib.load(directory / ARTIFACT_FILENAME)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        raise ValueError(f"Unable to load preprocessing artifact from {directory}.") from exc
    if not isinstance(preprocessor, LeakageSafePreprocessor) or not preprocessor.is_fitted_:
        raise ValueError("Artifact does not contain a fitted LeakageSafePreprocessor.")
    if metadata.get("profile") != preprocessor.profile:
        raise ValueError("Artifact profile does not match its metadata.")
    if metadata.get("output_feature_names") != preprocessor.get_feature_names_out().tolist():
        raise ValueError("Artifact feature names do not match its metadata.")
    return preprocessor


def _artifact_metadata(
    preprocessor: LeakageSafePreprocessor,
    version: str,
) -> dict[str, Any]:
    return {
        "artifact_name": f"{preprocessor.profile}-preprocessor",
        "artifact_version": version,
        "created_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "profile": preprocessor.profile,
        "dataset_name": preprocessor.contract.dataset_name,
        "feature_schema_version": preprocessor.contract.schema_version,
        "target_name": preprocessor.contract.target_name,
        "input_feature_schema": [
            {
                "name": feature.name,
                "type": feature.feature_type,
                "role": feature.role,
                "optional": feature.optional,
                "source_column": feature.source_column,
            }
            for feature in preprocessor.contract.features
            if feature.included and feature.role == "predictive"
        ],
        **preprocessor.preprocessing_metadata(),
        "library_versions": {
            "scikit_learn": sklearn.__version__,
            "joblib": joblib.__version__,
            "numpy": np.__version__,
            "pandas": pd.__version__,
        },
    }
