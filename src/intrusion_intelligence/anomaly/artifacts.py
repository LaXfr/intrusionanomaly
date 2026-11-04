"""Versioned Isolation Forest artifacts compatible with Phase 05 preprocessors."""

from __future__ import annotations

import json
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
from sklearn.ensemble import IsolationForest

from intrusion_intelligence.preprocessing.artifacts import load_preprocessor, save_preprocessor
from intrusion_intelligence.preprocessing.pipeline import LeakageSafePreprocessor

MODEL_FILENAME = "model.joblib"
METADATA_FILENAME = "metadata.json"
CALIBRATION_FILENAME = "calibration.json"
PROJECT_ROOT = Path(__file__).resolve().parents[3]


class AnomalyArtifactError(ValueError):
    """Raised when a model, preprocessor, and calibration set are incompatible."""


def save_anomaly_bundle(
    estimator: IsolationForest,
    preprocessor: LeakageSafePreprocessor,
    *,
    model_root: str | Path,
    preprocessor_root: str | Path,
    model_version: str,
    preprocessor_version: str,
    metadata: dict[str, Any],
    calibration: dict[str, Any],
) -> tuple[Path, Path]:
    """Persist a model bundle and its separately versioned fitted preprocessor."""
    if not isinstance(estimator, IsolationForest) or not hasattr(estimator, "estimators_"):
        raise AnomalyArtifactError("A fitted Scikit-learn IsolationForest is required.")
    if not preprocessor.is_fitted_ or preprocessor.profile != "anomaly":
        raise AnomalyArtifactError("A fitted Phase 05 anomaly-profile preprocessor is required.")
    for version in (model_version, preprocessor_version):
        if not re.fullmatch(r"\d+\.\d+\.\d+", version):
            raise AnomalyArtifactError("Artifact versions must use numeric major.minor.patch form.")
    if not calibration.get("operating_points"):
        raise AnomalyArtifactError("Calibrated operating points are required before model persistence.")
    destination = Path(model_root).expanduser() / model_version
    if destination.exists():
        raise FileExistsError(f"Anomaly model artifact already exists: {destination}")
    preprocessor_path = save_preprocessor(
        preprocessor,
        preprocessor_root,
        version=preprocessor_version,
    )
    try:
        preprocessor_relative = preprocessor_path.resolve().relative_to(PROJECT_ROOT).as_posix()
    except ValueError:
        # Temporary locations are useful for isolated artifact round-trip tests.
        # Production configuration stores a project-relative path.
        preprocessor_relative = str(preprocessor_path.resolve())
    destination.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=f".{model_version}.stage-", dir=destination.parent))
    model_id = f"isolation-forest-v{model_version}"
    model_metadata = {
        "artifact_type": "benign_baseline_anomaly_detector",
        "model_id": model_id,
        "algorithm": "IsolationForest",
        "artifact_version": model_version,
        "created_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "preprocessor_artifact_path": preprocessor_relative,
        "preprocessor_version": preprocessor_version,
        "preprocessing_profile": preprocessor.profile,
        "feature_schema_version": preprocessor.contract.schema_version,
        "input_feature_names": list(preprocessor.contract.predictive_features),
        "output_feature_names": preprocessor.get_feature_names_out().tolist(),
        "feature_count": len(preprocessor.get_feature_names_out()),
        "score_orientation": "higher_is_more_anomalous",
        "raw_score_method": "IsolationForest.score_samples; raw score is inlier-oriented",
        "raw_to_anomaly_score_transformation": "anomaly_score = -raw_model_score",
        "scikit_learn_version": sklearn.__version__,
        "numpy_version": np.__version__,
        "pandas_version": pd.__version__,
        "joblib_version": joblib.__version__,
        **metadata,
    }
    try:
        joblib.dump(estimator, staging / MODEL_FILENAME, compress=3)
        (staging / METADATA_FILENAME).write_text(
            json.dumps(model_metadata, ensure_ascii=False, indent=2, default=_json_default) + "\n",
            encoding="utf-8",
        )
        (staging / CALIBRATION_FILENAME).write_text(
            json.dumps(calibration, ensure_ascii=False, indent=2, default=_json_default) + "\n",
            encoding="utf-8",
        )
        if destination.exists():
            raise FileExistsError(f"Anomaly model artifact already exists: {destination}")
        staging.rename(destination)
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    return destination, preprocessor_path


def load_anomaly_bundle(
    artifact_directory: str | Path,
) -> tuple[IsolationForest, LeakageSafePreprocessor, dict[str, Any], dict[str, Any]]:
    """Load and verify compatible model, preprocessor, and calibrated thresholds."""
    directory = Path(artifact_directory).expanduser().resolve()
    try:
        metadata = json.loads((directory / METADATA_FILENAME).read_text(encoding="utf-8"))
        calibration = json.loads((directory / CALIBRATION_FILENAME).read_text(encoding="utf-8"))
        estimator = joblib.load(directory / MODEL_FILENAME)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        raise AnomalyArtifactError(f"Unable to load anomaly model artifact at {directory}.") from exc
    if not isinstance(estimator, IsolationForest) or not hasattr(estimator, "estimators_"):
        raise AnomalyArtifactError("Artifact does not contain a fitted IsolationForest.")
    stored_path = Path(metadata.get("preprocessor_artifact_path", ""))
    preprocessor_directory = _resolve_preprocessor_directory(stored_path, directory)
    try:
        preprocessor = load_preprocessor(preprocessor_directory)
    except (ValueError, OSError) as exc:
        raise AnomalyArtifactError("The matching preprocessing artifact could not be loaded.") from exc
    if preprocessor.profile != "anomaly":
        raise AnomalyArtifactError("Persisted preprocessor does not use the anomaly profile.")
    if metadata.get("feature_schema_version") != preprocessor.contract.schema_version:
        raise AnomalyArtifactError("Model and preprocessor feature schema versions differ.")
    if metadata.get("input_feature_names") != list(preprocessor.contract.predictive_features):
        raise AnomalyArtifactError("Model input feature names do not match the preprocessor contract.")
    if metadata.get("output_feature_names") != preprocessor.get_feature_names_out().tolist():
        raise AnomalyArtifactError("Model transformed feature names do not match the preprocessor.")
    if int(getattr(estimator, "n_features_in_", -1)) != int(metadata.get("feature_count", -2)):
        raise AnomalyArtifactError("Estimator feature count does not match artifact metadata.")
    points = calibration.get("operating_points", {})
    if not points or metadata.get("default_operating_point") not in points:
        raise AnomalyArtifactError("Artifact does not contain its configured default operating point.")
    for point_id, point in points.items():
        if not np.isfinite(float(point.get("threshold", np.nan))):
            raise AnomalyArtifactError(f"Operating point {point_id!r} has an invalid threshold.")
    return estimator, preprocessor, metadata, calibration


def _resolve_preprocessor_directory(stored_path: Path, artifact_directory: Path) -> Path:
    """Resolve project-relative preprocessing paths after a model is relocated."""
    if stored_path.is_absolute():
        return stored_path
    candidates = [ancestor / stored_path for ancestor in artifact_directory.parents]
    candidates.append(PROJECT_ROOT / stored_path)
    return next((candidate for candidate in candidates if candidate.is_dir()), candidates[-1])


def _json_default(value: Any) -> Any:
    if isinstance(value, np.generic):
        return value.item()
    if isinstance(value, np.ndarray):
        return value.tolist()
    if isinstance(value, Path):
        return str(value)
    raise TypeError(f"Cannot serialize {type(value).__name__} in anomaly artifact metadata.")

