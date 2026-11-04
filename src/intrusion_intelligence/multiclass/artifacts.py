"""Versioned persistence for compatible multi-class model bundles."""

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

from intrusion_intelligence.multiclass.taxonomy import ClassTaxonomy
from intrusion_intelligence.preprocessing.pipeline import LeakageSafePreprocessor


CLASSIFIER_FILENAME = "classifier.joblib"
PREPROCESSOR_FILENAME = "preprocessor.joblib"
METADATA_FILENAME = "metadata.json"
TAXONOMY_FILENAME = "taxonomy.json"


def save_model_bundle(
    estimator: Any,
    preprocessor: LeakageSafePreprocessor,
    taxonomy: ClassTaxonomy,
    artifact_root: str | Path,
    *,
    model_name: str,
    version: str,
    metadata: dict[str, Any],
) -> Path:
    """Atomically save one estimator with its exact fitted preprocessor and mapping."""
    if not preprocessor.is_fitted_:
        raise ValueError("A fitted preprocessor is required to save a multi-class bundle.")
    if not re.fullmatch(r"[a-z0-9][a-z0-9_-]*", model_name):
        raise ValueError("model_name must be a lowercase filesystem-safe identifier.")
    if not re.fullmatch(r"\d+\.\d+\.\d+", version):
        raise ValueError("Artifact version must use numeric major.minor.patch form.")
    destination = Path(artifact_root).expanduser() / model_name / version
    if destination.exists():
        raise FileExistsError(f"Multi-class artifact already exists: {destination}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=f".{version}.stage-", dir=destination.parent))
    try:
        joblib.dump(estimator, staging / CLASSIFIER_FILENAME, compress=3)
        joblib.dump(preprocessor, staging / PREPROCESSOR_FILENAME, compress=3)
        (staging / TAXONOMY_FILENAME).write_text(
            json.dumps(taxonomy.to_dict(), ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        bundle_metadata = {
            "artifact_type": "supervised_multiclass_classifier",
            "model_id": f"multiclass-{model_name}-v{version}",
            "model_name": model_name,
            "artifact_version": version,
            "created_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "taxonomy_version": taxonomy.version,
            "class_labels": list(taxonomy.labels),
            "class_to_id": taxonomy.class_to_id,
            "feature_schema_version": preprocessor.contract.schema_version,
            "input_feature_names": list(preprocessor.contract.predictive_features),
            "output_feature_names": preprocessor.get_feature_names_out().tolist(),
            "preprocessing_profile": preprocessor.profile,
            "scikit_learn_version": sklearn.__version__,
            "numpy_version": np.__version__,
            "pandas_version": pd.__version__,
            "joblib_version": joblib.__version__,
            **metadata,
        }
        (staging / METADATA_FILENAME).write_text(
            json.dumps(bundle_metadata, ensure_ascii=False, indent=2, default=_json_default) + "\n",
            encoding="utf-8",
        )
        if destination.exists():
            raise FileExistsError(f"Multi-class artifact already exists: {destination}")
        staging.rename(destination)
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    return destination


def load_model_bundle(artifact_directory: str | Path) -> tuple[Any, LeakageSafePreprocessor, ClassTaxonomy, dict[str, Any]]:
    """Load a trusted bundle and verify classifier/preprocessor/taxonomy compatibility."""
    directory = Path(artifact_directory).expanduser()
    try:
        metadata = json.loads((directory / METADATA_FILENAME).read_text(encoding="utf-8"))
        taxonomy_doc = json.loads((directory / TAXONOMY_FILENAME).read_text(encoding="utf-8"))
        estimator = joblib.load(directory / CLASSIFIER_FILENAME)
        preprocessor = joblib.load(directory / PREPROCESSOR_FILENAME)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        raise ValueError(f"Unable to load multi-class artifact bundle from {directory}.") from exc
    if not isinstance(preprocessor, LeakageSafePreprocessor) or not preprocessor.is_fitted_:
        raise ValueError("Artifact bundle does not contain a fitted Phase 05 preprocessor.")
    taxonomy = ClassTaxonomy.from_dict(taxonomy_doc)
    if metadata.get("class_labels") != list(taxonomy.labels):
        raise ValueError("Artifact taxonomy does not match the metadata class order.")
    if metadata.get("class_to_id") != taxonomy.class_to_id:
        raise ValueError("Artifact class mapping does not match the persisted taxonomy.")
    if metadata.get("feature_schema_version") != preprocessor.contract.schema_version:
        raise ValueError("Model and preprocessing feature-schema versions do not match.")
    if metadata.get("input_feature_names") != list(preprocessor.contract.predictive_features):
        raise ValueError("Model input features do not match the fitted preprocessor contract.")
    if metadata.get("output_feature_names") != preprocessor.get_feature_names_out().tolist():
        raise ValueError("Model output feature names do not match the fitted preprocessor.")
    estimator_classes = np.asarray(getattr(estimator, "classes_", []), dtype=np.int64)
    if not len(estimator_classes) or np.any(estimator_classes < 0) or np.any(estimator_classes >= len(taxonomy.labels)):
        raise ValueError("Classifier classes do not match the persisted taxonomy identifiers.")
    return estimator, preprocessor, taxonomy, metadata


def _json_default(value: Any) -> Any:
    if isinstance(value, np.generic):
        return value.item()
    if isinstance(value, np.ndarray):
        return value.tolist()
    if isinstance(value, Path):
        return str(value)
    raise TypeError(f"Cannot encode {type(value).__name__} in artifact metadata.")
