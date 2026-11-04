"""Checksummed, versioned Logistic Regression binary-classifier bundles."""

from __future__ import annotations

import hashlib
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
from sklearn.linear_model import LogisticRegression

from intrusion_intelligence.preprocessing.pipeline import LeakageSafePreprocessor


def save_logistic_bundle(
    estimator: LogisticRegression,
    preprocessor: LeakageSafePreprocessor,
    root: str | Path,
    *,
    version: str,
    metadata: dict[str, Any],
) -> Path:
    """Persist a logistic model without touching another model-family bundle."""
    if not isinstance(estimator, LogisticRegression):
        raise ValueError("A fitted LogisticRegression estimator is required.")
    if not preprocessor.is_fitted_:
        raise ValueError("A fitted training-only preprocessor is required.")
    if not re.fullmatch(r"\d+\.\d+\.\d+", version):
        raise ValueError("Logistic artifact version must use numeric major.minor.patch form.")
    destination = Path(root).expanduser() / "logistic_regression" / version
    if destination.exists():
        raise FileExistsError(f"Logistic artifact version already exists: {destination}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix=f".{version}.logistic-stage-", dir=destination.parent))
    try:
        joblib.dump(estimator, stage / "classifier.joblib", compress=3)
        joblib.dump(preprocessor, stage / "preprocessor.joblib", compress=3)
        files = {
            name: {
                "sha256": hashlib.sha256((stage / name).read_bytes()).hexdigest(),
                "size_bytes": (stage / name).stat().st_size,
            }
            for name in ("classifier.joblib", "preprocessor.joblib")
        }
        document = {
            "artifact_type": "supervised_binary_logistic_classifier",
            "model_id": f"binary-logistic_regression-v{version}",
            "model_name": "logistic_regression",
            "artifact_version": version,
            "created_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "target_mapping": {"BENIGN": 0, "ATTACK": 1},
            "positive_class": "ATTACK",
            "decision_threshold": 0.5,
            "score_semantics": "uncalibrated LogisticRegression predict_proba score; not a probability of compromise",
            "feature_schema_version": preprocessor.contract.schema_version,
            "input_feature_names": list(preprocessor.contract.predictive_features),
            "output_feature_names": preprocessor.get_feature_names_out().tolist(),
            "preprocessing": preprocessor.preprocessing_metadata(),
            "versions": {
                "scikit_learn": sklearn.__version__,
                "numpy": np.__version__,
                "pandas": pd.__version__,
                "joblib": joblib.__version__,
            },
            "artifact_files": files,
            "artifact_joblib_size_bytes": sum(item["size_bytes"] for item in files.values()),
            **metadata,
        }
        (stage / "metadata.json").write_text(
            json.dumps(document, ensure_ascii=False, indent=2, default=_json_default) + "\n",
            encoding="utf-8",
        )
        stage.rename(destination)
    except Exception:
        shutil.rmtree(stage, ignore_errors=True)
        raise
    return destination


def load_logistic_bundle(
    path: str | Path,
) -> tuple[LogisticRegression, LeakageSafePreprocessor, dict[str, Any]]:
    """Load and validate the model type, target map, schema, classes, and checksums."""
    directory = Path(path).expanduser()
    try:
        metadata = json.loads((directory / "metadata.json").read_text(encoding="utf-8"))
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        raise ValueError(f"Unable to load Logistic Regression bundle from {directory}.") from exc
    if metadata.get("artifact_type") != "supervised_binary_logistic_classifier":
        raise ValueError("Artifact is not a binary Logistic Regression bundle.")
    if metadata.get("target_mapping") != {"BENIGN": 0, "ATTACK": 1}:
        raise ValueError("Logistic artifact target mapping is incompatible.")
    records = metadata.get("artifact_files")
    if not isinstance(records, dict) or set(records) != {"classifier.joblib", "preprocessor.joblib"}:
        raise ValueError("Logistic artifact manifest is missing required model files.")
    for name, record in records.items():
        target = directory / name
        if not target.is_file():
            raise ValueError(f"Logistic artifact file is missing: {name}.")
        if target.stat().st_size != record.get("size_bytes"):
            raise ValueError(f"Logistic artifact size mismatch: {name}.")
        if hashlib.sha256(target.read_bytes()).hexdigest() != record.get("sha256"):
            raise ValueError(f"Logistic artifact checksum mismatch: {name}.")
    try:
        estimator = joblib.load(directory / "classifier.joblib")
        preprocessor = joblib.load(directory / "preprocessor.joblib")
    except (OSError, ValueError, EOFError) as exc:
        raise ValueError(f"Unable to deserialize verified Logistic Regression bundle from {directory}.") from exc
    if not isinstance(estimator, LogisticRegression):
        raise ValueError("Logistic artifact does not contain a LogisticRegression estimator.")
    if not isinstance(preprocessor, LeakageSafePreprocessor) or not preprocessor.is_fitted_:
        raise ValueError("Logistic artifact does not contain a fitted Phase 05 preprocessor.")
    if metadata.get("feature_schema_version") != preprocessor.contract.schema_version:
        raise ValueError("Logistic artifact feature schema version is incompatible.")
    if metadata.get("input_feature_names") != list(preprocessor.contract.predictive_features):
        raise ValueError("Logistic artifact feature ordering is incompatible.")
    if not np.array_equal(np.asarray(estimator.classes_), np.array([0, 1])):
        raise ValueError("Logistic estimator classes do not match BENIGN=0, ATTACK=1.")
    return estimator, preprocessor, metadata


def _json_default(value: Any) -> Any:
    if isinstance(value, np.generic):
        return value.item()
    if isinstance(value, np.ndarray):
        return value.tolist()
    if isinstance(value, Path):
        return str(value)
    raise TypeError(f"Cannot encode {type(value).__name__} in Logistic artifact metadata.")
