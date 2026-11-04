"""Deterministic training-only backgrounds for supervised and anomaly SHAP."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
import pyarrow.parquet as pq

from intrusion_intelligence.explainability.schemas import ExplainabilityError
from intrusion_intelligence.feature_engineering import FeatureContract
from intrusion_intelligence.multiclass.data import (
    inspect_parquet_dataset,
    iter_partition_batches,
)
from intrusion_intelligence.multiclass.splitting import (
    make_three_way_split,
    stratified_training_sample,
)


@dataclass(frozen=True, slots=True)
class TrainingBackground:
    features: pd.DataFrame
    dataset_id: str
    partition: str
    strategy: str
    row_count: int
    configured_sample_size: int
    seed: int
    target_used_for_sampling: str
    source_files: tuple[str, ...]

    def metadata(self) -> dict[str, Any]:
        return {
            "dataset_id": self.dataset_id,
            "partition": self.partition,
            "sampling_strategy": self.strategy,
            "observations": self.row_count,
            "configured_sample_size": int(self.configured_sample_size),
            "random_seed": self.seed,
            "target_used_for_sampling": self.target_used_for_sampling,
            "source_files": list(self.source_files),
            "target_values_in_features": False,
        }


def load_training_background(
    dataset_directory: str | Path,
    contract: FeatureContract,
    *,
    model_family: str,
    sample_size: int,
    random_seed: int,
    batch_size: int = 5000,
) -> TrainingBackground:
    """Select background rows strictly from the model's documented training partition."""
    if sample_size <= 0 or batch_size <= 0:
        raise ExplainabilityError("Background sample and batch sizes must be positive.")
    root = Path(dataset_directory).expanduser().resolve()
    files = tuple(sorted(root.glob("*.parquet")))
    if not files:
        raise ExplainabilityError(f"No Phase 04 Parquet files found under {root}.")
    if model_family.startswith("multiclass_"):
        return _multiclass_background(files, root, contract, sample_size, random_seed, batch_size)
    if model_family in {"binary_random_forest", "binary_logistic_regression", "anomaly"}:
        return _capture_day_background(files, root, contract, model_family, sample_size, random_seed, batch_size)
    raise ExplainabilityError(f"No training-background policy is defined for {model_family!r}.")


def _multiclass_background(
    files: tuple[Path, ...],
    root: Path,
    contract: FeatureContract,
    sample_size: int,
    random_seed: int,
    batch_size: int,
) -> TrainingBackground:
    inventory = inspect_parquet_dataset(root, contract)
    split = make_three_way_split(
        inventory.labels,
        inventory.groups,
        random_seed=random_seed,
        strategy="group_aware",
        allow_stratified_fallback=True,
    )
    if split.audit["used_strategy"] != "stratified_row_fallback":
        raise ExplainabilityError(
            "Background sampling split policy differs from the persisted Phase 07 fallback; refusing an unverified partition."
        )
    selected = stratified_training_sample(
        split.train,
        inventory.labels,
        maximum_rows=sample_size,
        random_seed=random_seed,
        retain_all_if_count_at_most=50,
    )
    feature_frames = [
        X for X, _ in iter_partition_batches(files, selected, contract, batch_size=batch_size)
    ]
    if not feature_frames:
        raise ExplainabilityError("No training rows were selected for the multi-class SHAP background.")
    features = pd.concat(feature_frames, ignore_index=True)
    if len(features) != len(selected) or list(features.columns) != list(contract.predictive_features):
        raise ExplainabilityError("Multi-class background rows lost alignment or feature order.")
    return TrainingBackground(
        features=features,
        dataset_id=f"cic-phase07-train-{split.audit['used_strategy']}-seed-{random_seed}",
        partition="Phase 07 training rows only",
        strategy="deterministic stratified sample from recomputed Phase 07 training partition",
        row_count=len(features),
        configured_sample_size=sample_size,
        seed=random_seed,
        target_used_for_sampling="original class labels used only to stratify training indices",
        source_files=tuple(sorted({path.name for path in files})),
    )


def _capture_day_background(
    files: tuple[Path, ...],
    root: Path,
    contract: FeatureContract,
    model_family: str,
    sample_size: int,
    random_seed: int,
    batch_size: int,
) -> TrainingBackground:
    training_days = ("monday", "tuesday", "wednesday")
    label_parts: list[np.ndarray] = []
    selected_files: list[Path] = []
    all_row_offsets: list[int] = []
    offset = 0
    for path in files:
        row_count = pq.ParquetFile(path).metadata.num_rows
        if path.name.lower().startswith(training_days):
            labels = pq.read_table(path, columns=[contract.target_name])[contract.target_name].to_numpy(zero_copy_only=False)
            label_parts.append(np.asarray(labels, dtype=object))
            selected_files.append(path)
            all_row_offsets.append(offset)
        offset += row_count
    if not selected_files:
        raise ExplainabilityError("No Monday–Wednesday files were found for the training-only background.")

    labels = np.concatenate(label_parts)
    if model_family == "anomaly":
        candidates = np.flatnonzero(labels == "BENIGN")
        strata = np.asarray(labels, dtype=object)
        target_policy = "BENIGN target used only to restrict the Phase 08 training background"
        strategy = "deterministic sample of BENIGN Monday–Wednesday training rows"
    else:
        candidates = np.arange(len(labels), dtype=np.int64)
        strata = np.where(labels == "BENIGN", "BENIGN", "ATTACK")
        target_policy = "binary target used only for stratified sampling within training capture days"
        strategy = "deterministic binary-class-stratified sample of Monday–Wednesday training rows"
    if not len(candidates):
        raise ExplainabilityError("No rows are eligible for the configured training-only background.")
    selected_local = _stratified_indices(candidates, strata, sample_size, random_seed)

    # Convert the capture-day-relative indices back to the global sorted-file index space.
    local_offsets = np.cumsum([0, *[pq.ParquetFile(path).metadata.num_rows for path in selected_files]])
    global_indices: list[np.ndarray] = []
    for file_index, path in enumerate(selected_files):
        lower, upper = int(local_offsets[file_index]), int(local_offsets[file_index + 1])
        local = selected_local[(selected_local >= lower) & (selected_local < upper)] - lower
        if len(local):
            global_indices.append(local + all_row_offsets[file_index])
    indices = np.sort(np.concatenate(global_indices))
    feature_frames = [X for X, _ in iter_partition_batches(files, indices, contract, batch_size=batch_size)]
    features = pd.concat(feature_frames, ignore_index=True) if feature_frames else pd.DataFrame()
    if len(features) != len(indices) or list(features.columns) != list(contract.predictive_features):
        raise ExplainabilityError("Capture-day background rows lost alignment or feature order.")
    return TrainingBackground(
        features=features,
        dataset_id=f"cic-phase06-08-train-{model_family}-seed-{random_seed}",
        partition="Monday–Wednesday training capture days only",
        strategy=strategy,
        row_count=len(features),
        configured_sample_size=sample_size,
        seed=random_seed,
        target_used_for_sampling=target_policy,
        source_files=tuple(path.name for path in selected_files),
    )


def _stratified_indices(
    candidate_indices: np.ndarray,
    strata: np.ndarray,
    maximum_rows: int,
    random_seed: int,
) -> np.ndarray:
    if len(candidate_indices) <= maximum_rows:
        return candidate_indices.copy()
    labels = strata[candidate_indices]
    classes, counts = np.unique(labels, return_counts=True)
    if maximum_rows < len(classes):
        raise ExplainabilityError("Background sample size must retain at least one row from each stratum.")
    allocation = np.ones(len(classes), dtype=np.int64)
    remainder = maximum_rows - len(classes)
    capacity = counts - 1
    if capacity.sum() > 0:
        quotas = remainder * capacity / capacity.sum()
        allocation += np.floor(quotas).astype(np.int64)
        leftover = maximum_rows - int(allocation.sum())
        order = np.argsort(-(quotas - np.floor(quotas)))
        for position in order:
            if leftover == 0:
                break
            if allocation[position] < counts[position]:
                allocation[position] += 1
                leftover -= 1
    rng = np.random.default_rng(random_seed)
    sampled: list[np.ndarray] = []
    for label, quota in zip(classes, allocation):
        members = candidate_indices[labels == label]
        sampled.append(members if quota >= len(members) else rng.choice(members, size=int(quota), replace=False))
    return np.sort(np.concatenate(sampled).astype(np.int64))
