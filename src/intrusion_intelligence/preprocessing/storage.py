"""Aligned persistence for already transformed feature matrices."""

from __future__ import annotations

import hashlib
import json
import shutil
import tempfile
from pathlib import Path

import numpy as np
import pandas as pd
import scipy.sparse as sp
from scipy.sparse import save_npz


def save_transformed_matrix(
    matrix: np.ndarray | sp.spmatrix,
    y: pd.Series,
    metadata: pd.DataFrame,
    feature_names: list[str] | tuple[str, ...],
    output_directory: str | Path,
    *,
    target_name: str = "label",
) -> Path:
    """Save dense/sparse features plus aligned labels and row metadata.

    Sparse feature matrices use SciPy NPZ; dense matrices use NPY. Target and
    metadata rows are stored separately in Parquet in the same row order.
    Existing output directories are never overwritten.
    """
    destination = Path(output_directory).expanduser()
    if destination.exists():
        raise FileExistsError(f"Transformed dataset already exists: {destination}")
    if not isinstance(y, pd.Series) or not isinstance(metadata, pd.DataFrame):
        raise TypeError("y must be a Series and metadata must be a DataFrame.")
    if not isinstance(matrix, np.ndarray) and not sp.issparse(matrix):
        raise TypeError("matrix must be a NumPy array or SciPy sparse matrix.")
    if len(matrix.shape) != 2 or matrix.shape[0] != len(y) or len(y) != len(metadata):
        raise ValueError("Feature, target, and metadata row counts must match.")
    if len(feature_names) != matrix.shape[1] or len(set(feature_names)) != len(feature_names):
        raise ValueError("Feature names must be unique and match the transformed matrix width.")
    if not y.index.equals(metadata.index):
        raise ValueError("Target and metadata indices must match to guarantee row alignment.")
    if pd.isna(y).any():
        raise ValueError("Transformed target contains missing labels.")
    if target_name in metadata.columns:
        raise ValueError("Target must be stored separately from row metadata.")
    matrix_values = matrix.data if sp.issparse(matrix) else matrix
    if not np.isfinite(matrix_values).all():
        raise ValueError("Transformed matrix contains NaN or infinity.")
    root = destination.parent
    root.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=f".{destination.name}.stage-", dir=root))
    try:
        if sp.issparse(matrix):
            matrix_path = staging / "features.npz"
            save_npz(matrix_path, matrix, compressed=True)
            representation = "scipy_sparse_npz"
        else:
            matrix_path = staging / "features.npy"
            np.save(matrix_path, np.asarray(matrix), allow_pickle=False)
            representation = "dense_npy"
        rows = metadata.reset_index(drop=True).copy()
        rows.insert(0, target_name, y.reset_index(drop=True).to_numpy())
        rows_path = staging / "rows.parquet"
        rows.to_parquet(rows_path, index=False)
        (staging / "feature_names.json").write_text(
            json.dumps(list(feature_names), ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        manifest = {
            "representation": representation,
            "rows": int(matrix.shape[0]),
            "features": int(matrix.shape[1]),
            "matrix_file": matrix_path.name,
            "row_metadata_file": rows_path.name,
            "feature_names_file": "feature_names.json",
            "matrix_sha256": _sha256(matrix_path),
            "row_metadata_sha256": _sha256(rows_path),
        }
        (staging / "manifest.json").write_text(
            json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        if destination.exists():
            raise FileExistsError(f"Transformed dataset already exists: {destination}")
        staging.rename(destination)
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    return destination


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()
