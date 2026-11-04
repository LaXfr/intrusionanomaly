"""Group-aware and stratified fallback splits with explicit integrity audits."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import numpy as np
import pandas as pd
from sklearn.model_selection import GroupShuffleSplit, train_test_split


class SplitError(ValueError):
    """Raised when a requested split cannot satisfy its stated constraints."""


@dataclass(frozen=True, slots=True)
class DataSplit:
    """Row indices and a machine-readable report for three partitions."""

    train: np.ndarray
    validation: np.ndarray
    test: np.ndarray
    audit: dict[str, Any]


def make_three_way_split(
    labels: np.ndarray | pd.Series,
    groups: np.ndarray | pd.Series,
    *,
    train_fraction: float = 0.70,
    validation_fraction: float = 0.15,
    test_fraction: float = 0.15,
    random_seed: int = 42,
    strategy: str = "group_aware",
    allow_stratified_fallback: bool = True,
    group_search_attempts: int = 24,
) -> DataSplit:
    """Prefer group-disjoint partitions, falling back only with a recorded reason."""
    y = np.asarray(labels, dtype=object)
    group_values = np.asarray(groups, dtype=object)
    if y.ndim != 1 or group_values.ndim != 1 or len(y) != len(group_values) or not len(y):
        raise SplitError("Labels and groups must be non-empty one-dimensional arrays of equal length.")
    if pd.isna(y).any() or pd.isna(group_values).any():
        raise SplitError("Labels and groups cannot contain null values.")
    if any(not str(value).strip() for value in y):
        raise SplitError("Labels cannot contain blank values.")
    fractions = np.asarray([train_fraction, validation_fraction, test_fraction], dtype=float)
    if np.any(fractions <= 0) or not np.isclose(fractions.sum(), 1.0):
        raise SplitError("Train, validation, and test fractions must be positive and sum to 1.")
    if strategy not in {"group_aware", "stratified_row"}:
        raise SplitError(f"Unsupported split strategy: {strategy!r}.")

    group_counts = _class_group_counts(y, group_values)
    fallback_reason: str | None = None
    partitions: tuple[np.ndarray, np.ndarray, np.ndarray] | None = None
    used_strategy = strategy
    if strategy == "group_aware":
        if any(count < 3 for count in group_counts.values()):
            unsupported = {label: count for label, count in group_counts.items() if count < 3}
            fallback_reason = (
                "Group-disjoint train/validation/test coverage is impossible for every class: "
                f"these labels occur in fewer than three groups: {unsupported}."
            )
        else:
            partitions = _search_group_split(
                y,
                group_values,
                fractions,
                random_seed=random_seed,
                attempts=group_search_attempts,
            )
            if partitions is None:
                fallback_reason = "No tested group-disjoint assignment provided every class in all three partitions."
        if partitions is None:
            if not allow_stratified_fallback:
                raise SplitError(fallback_reason or "A valid group-aware split could not be formed.")
            used_strategy = "stratified_row_fallback"
            partitions = _stratified_split(y, fractions, random_seed)
    else:
        partitions = _stratified_split(y, fractions, random_seed)

    train, validation, test = (np.sort(partition.astype(np.int64)) for partition in partitions)
    if len(set(np.concatenate([train, validation, test]).tolist())) != len(y):
        raise SplitError("Partitions overlap or omit rows.")
    audit = _build_audit(
        y,
        group_values,
        train,
        validation,
        test,
        requested_strategy=strategy,
        used_strategy=used_strategy,
        fallback_reason=fallback_reason,
        class_group_counts=group_counts,
        fractions=fractions,
    )
    return DataSplit(train=train, validation=validation, test=test, audit=audit)


def stratified_training_sample(
    training_indices: np.ndarray,
    labels: np.ndarray | pd.Series,
    *,
    maximum_rows: int,
    random_seed: int = 42,
    retain_all_if_count_at_most: int = 50,
) -> np.ndarray:
    """Select from training rows, retaining every member of very small classes."""
    indices = np.asarray(training_indices, dtype=np.int64)
    y = np.asarray(labels, dtype=object)
    if maximum_rows <= 0:
        raise SplitError("maximum_rows must be a positive integer.")
    if retain_all_if_count_at_most < 1:
        raise SplitError("retain_all_if_count_at_most must be positive.")
    if len(indices) <= maximum_rows:
        return indices.copy()
    selected_labels = y[indices]
    classes, counts = np.unique(selected_labels, return_counts=True)
    if maximum_rows < len(classes):
        raise SplitError("Training sample is too small to retain at least one observation per class.")
    allocation = np.ones(len(classes), dtype=np.int64)
    rare_mask = counts <= retain_all_if_count_at_most
    allocation[rare_mask] = counts[rare_mask]
    remaining = maximum_rows - int(allocation.sum())
    capacity = counts - allocation
    if remaining < 0:
        raise SplitError(
            "The training sample limit is smaller than the total rows reserved for rare classes."
        )
    if remaining and capacity.sum():
        quotas = remaining * capacity / capacity.sum()
        extra = np.minimum(np.floor(quotas).astype(np.int64), capacity)
        allocation += extra
        leftover = maximum_rows - int(allocation.sum())
        order = np.argsort(-(quotas - np.floor(quotas)))
        for index in order:
            if leftover == 0:
                break
            if allocation[index] < counts[index]:
                allocation[index] += 1
                leftover -= 1
        while leftover:
            eligible = np.flatnonzero(allocation < counts)
            if not len(eligible):
                break
            allocation[eligible[0]] += 1
            leftover -= 1
    if int(allocation.sum()) != maximum_rows:
        raise SplitError("Unable to allocate the configured stratified training sample size.")
    rng = np.random.default_rng(random_seed)
    sampled: list[np.ndarray] = []
    for label, count in zip(classes, allocation):
        class_indices = indices[selected_labels == label]
        if count == len(class_indices):
            sampled.append(class_indices)
        else:
            sampled.append(rng.choice(class_indices, size=int(count), replace=False))
    return np.sort(np.concatenate(sampled).astype(np.int64))


def _stratified_split(
    y: np.ndarray,
    fractions: np.ndarray,
    random_seed: int,
) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    counts = pd.Series(y).value_counts()
    if (counts < 3).any():
        rare = counts[counts < 3].to_dict()
        raise SplitError(f"Three-way stratification requires at least three rows per class: {rare}.")
    indices = np.arange(len(y), dtype=np.int64)
    train, remainder = train_test_split(
        indices,
        train_size=float(fractions[0]),
        random_state=random_seed,
        stratify=y,
    )
    validation_share = fractions[1] / (fractions[1] + fractions[2])
    validation, test = train_test_split(
        remainder,
        train_size=float(validation_share),
        random_state=random_seed + 1,
        stratify=y[remainder],
    )
    return train, validation, test


def _search_group_split(
    y: np.ndarray,
    groups: np.ndarray,
    fractions: np.ndarray,
    *,
    random_seed: int,
    attempts: int,
) -> tuple[np.ndarray, np.ndarray, np.ndarray] | None:
    """Search group-disjoint candidates and choose the closest feasible sizes."""
    target_labels = set(y.tolist())
    outer = GroupShuffleSplit(
        n_splits=attempts,
        test_size=float(fractions[1] + fractions[2]),
        random_state=random_seed,
    )
    best: tuple[float, tuple[np.ndarray, np.ndarray, np.ndarray]] | None = None
    row_placeholder = np.empty((len(y), 0), dtype=np.uint8)
    for train, remainder in outer.split(row_placeholder, y, groups):
        inner = GroupShuffleSplit(
            n_splits=max(4, attempts // 2),
            test_size=float(fractions[2] / (fractions[1] + fractions[2])),
            random_state=random_seed + 1,
        )
        for validation_local, test_local in inner.split(
            np.empty((len(remainder), 0), dtype=np.uint8), y[remainder], groups[remainder]
        ):
            validation = remainder[validation_local]
            test = remainder[test_local]
            if any(set(y[part].tolist()) != target_labels for part in (train, validation, test)):
                continue
            observed = np.asarray([len(train), len(validation), len(test)], dtype=float) / len(y)
            score = float(np.abs(observed - fractions).sum())
            if best is None or score < best[0]:
                best = (score, (train.copy(), validation.copy(), test.copy()))
    return None if best is None else best[1]


def _class_group_counts(y: np.ndarray, groups: np.ndarray) -> dict[str, int]:
    frame = pd.DataFrame({"label": y, "group": groups}).drop_duplicates()
    return {str(label): int(count) for label, count in frame.groupby("label", sort=False)["group"].nunique().items()}


def _build_audit(
    y: np.ndarray,
    groups: np.ndarray,
    train: np.ndarray,
    validation: np.ndarray,
    test: np.ndarray,
    *,
    requested_strategy: str,
    used_strategy: str,
    fallback_reason: str | None,
    class_group_counts: dict[str, int],
    fractions: np.ndarray,
) -> dict[str, Any]:
    all_groups = set(groups.tolist())
    partitions = {"train": train, "validation": validation, "test": test}
    group_sets = {name: set(groups[index].tolist()) for name, index in partitions.items()}
    classes = sorted(set(y.tolist()))
    class_counts = {
        name: {str(label): int(np.count_nonzero(y[index] == label)) for label in classes}
        for name, index in partitions.items()
    }
    row_counts = {name: int(len(index)) for name, index in partitions.items()}
    overlaps = {
        "train_validation": sorted(map(str, group_sets["train"] & group_sets["validation"])),
        "train_test": sorted(map(str, group_sets["train"] & group_sets["test"])),
        "validation_test": sorted(map(str, group_sets["validation"] & group_sets["test"])),
    }
    return {
        "requested_strategy": requested_strategy,
        "used_strategy": used_strategy,
        "group_disjoint": not any(overlaps.values()),
        "fallback_reason": fallback_reason,
        "requested_fractions": {
            "train": float(fractions[0]),
            "validation": float(fractions[1]),
            "test": float(fractions[2]),
        },
        "observed_fractions": {name: count / len(y) for name, count in row_counts.items()},
        "row_counts": row_counts,
        "class_counts": class_counts,
        "class_group_counts": class_group_counts,
        "groups_per_partition": {name: len(value) for name, value in group_sets.items()},
        "all_source_groups": sorted(map(str, all_groups)),
        "group_overlaps": overlaps,
        "unseen_classes": {
            name: sorted(
                label for label, count in class_counts[name].items() if count == 0
            )
            for name in partitions
        },
    }
