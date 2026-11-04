"""Versioned binary model artifact persistence."""

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

from intrusion_intelligence.preprocessing.pipeline import LeakageSafePreprocessor


def save_binary_bundle(estimator: Any, preprocessor: LeakageSafePreprocessor, root: str | Path, *, version: str, metadata: dict[str, Any]) -> Path:
    if not preprocessor.is_fitted_:
        raise ValueError("A fitted training-only preprocessor is required.")
    if not re.fullmatch(r"\d+\.\d+\.\d+", version):
        raise ValueError("Binary artifact version must use numeric major.minor.patch form.")
    destination = Path(root).expanduser() / "random_forest" / version
    if destination.exists():
        raise FileExistsError(f"Binary artifact version already exists: {destination}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix=f".{version}.stage-", dir=destination.parent))
    try:
        joblib.dump(estimator, stage / "classifier.joblib", compress=3)
        joblib.dump(preprocessor, stage / "preprocessor.joblib", compress=3)
        files = {}
        for name in ("classifier.joblib", "preprocessor.joblib"):
            files[name] = hashlib.sha256((stage / name).read_bytes()).hexdigest()
        doc = {
            "artifact_type": "supervised_binary_classifier",
            "model_id": f"binary-random_forest-v{version}",
            "model_name": "random_forest",
            "artifact_version": version,
            "created_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "target_mapping": {"BENIGN": 0, "ATTACK": 1},
            "positive_class": "ATTACK",
            "decision_threshold": 0.5,
            "score_semantics": "uncalibrated Random Forest predict_proba score, not a probability of compromise",
            "feature_schema_version": preprocessor.contract.schema_version,
            "input_feature_names": list(preprocessor.contract.predictive_features),
            "output_feature_names": preprocessor.get_feature_names_out().tolist(),
            "preprocessing": preprocessor.preprocessing_metadata(),
            "versions": {"scikit_learn": sklearn.__version__, "numpy": np.__version__, "pandas": pd.__version__, "joblib": joblib.__version__},
            "artifact_sha256": files,
            **metadata,
        }
        (stage / "metadata.json").write_text(json.dumps(doc, ensure_ascii=False, indent=2, default=_json_default) + "\n", encoding="utf-8")
        stage.rename(destination)
    except Exception:
        shutil.rmtree(stage, ignore_errors=True)
        raise
    return destination


def load_binary_bundle(path: str | Path) -> tuple[Any, LeakageSafePreprocessor, dict[str, Any]]:
    directory = Path(path).expanduser()
    try:
        metadata = json.loads((directory / "metadata.json").read_text(encoding="utf-8"))
        estimator = joblib.load(directory / "classifier.joblib")
        preprocessor = joblib.load(directory / "preprocessor.joblib")
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        raise ValueError(f"Unable to load binary artifact bundle from {directory}.") from exc
    if metadata.get("artifact_type") != "supervised_binary_classifier":
        raise ValueError("Artifact is not a binary classifier bundle.")
    if metadata.get("target_mapping") != {"BENIGN": 0, "ATTACK": 1}:
        raise ValueError("Binary artifact target mapping is incompatible.")
    if not isinstance(preprocessor, LeakageSafePreprocessor) or not preprocessor.is_fitted_:
        raise ValueError("Binary artifact does not contain a fitted Phase 05 preprocessor.")
    if metadata.get("feature_schema_version") != preprocessor.contract.schema_version or metadata.get("input_feature_names") != list(preprocessor.contract.predictive_features):
        raise ValueError("Binary classifier and preprocessor feature schema are incompatible.")
    if not np.array_equal(np.asarray(estimator.classes_), np.array([0, 1])):
        raise ValueError("Binary estimator classes do not match BENIGN=0, ATTACK=1.")
    for name, expected in metadata.get("artifact_sha256", {}).items():
        actual = hashlib.sha256((directory / name).read_bytes()).hexdigest()
        if actual != expected:
            raise ValueError(f"Artifact checksum mismatch: {name}.")
    return estimator, preprocessor, metadata


def _json_default(value: Any) -> Any:
    if isinstance(value, np.generic):
        return value.item()
    if isinstance(value, np.ndarray):
        return value.tolist()
    if isinstance(value, Path):
        return str(value)
    raise TypeError(f"Cannot encode {type(value).__name__} in binary metadata.")
