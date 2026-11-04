"""Explicit capture-day partitions and duplicate-feature overlap audits."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import numpy as np
import pandas as pd
import pyarrow.parquet as pq

from intrusion_intelligence.anomaly.data import (
    AnomalyDatasetInventory,
    AnomalyDataError,
    BENIGN_LABEL,
    CAPTURE_DAYS,
)
from intrusion_intelligence.feature_engineering import FeatureContract


class AnomalySplitError(ValueError):
    """Raised when explicit group partitions are invalid or incomplete."""


@dataclass(frozen=True, slots=True)
class AnomalySplit:
    """Row indices and a complete day/source/label split audit."""

    train: np.ndarray
    validation: np.ndarray
    test: np.ndarray
    day_to_partition: dict[str, str]
    audit: dict[str, Any]


def make_capture_day_split(
    inventory: AnomalyDatasetInventory,
    config: dict[str, Any],
    *,
    benign_label: str = BENIGN_LABEL,
) -> AnomalySplit:
    """Assign whole collection days to partitions; never fall back to row splits."""
    split_config = config.get("split", config)
    day_to_partition: dict[str, str] = {}
    for partition in ("train", "validation", "test"):
        days = split_config.get(f"{partition}_days", ())
        if not days:
            raise AnomalySplitError(f"The {partition} capture-day partition is empty.")
        for day in days:
            if day not in inventory.capture_days:
                raise AnomalySplitError(f"Configured capture day {day!r} is not present in the dataset.")
            if day in day_to_partition:
                raise AnomalySplitError(f"Capture day {day!r} is assigned to multiple partitions.")
            day_to_partition[day] = partition
    if set(day_to_partition) != set(inventory.capture_days):
        missing = sorted(set(inventory.capture_days) - set(day_to_partition))
        raise AnomalySplitError(f"Every observed capture day must be assigned exactly once; missing {missing}.")

    day_values = np.asarray([CAPTURE_DAYS[int(code)] for code in inventory.capture_day_codes], dtype=object)
    partitions = {
        name: np.flatnonzero(np.isin(day_values, [day for day, assigned in day_to_partition.items() if assigned == name]))
        .astype(np.int64)
        for name in ("train", "validation", "test")
    }
    if any(not len(indices) for indices in partitions.values()):
        raise AnomalySplitError("Each explicit capture-day partition must contain rows.")
    for name, indices in partitions.items():
        selected_labels = inventory.labels[indices]
        if not np.any(selected_labels == benign_label):
            raise AnomalySplitError(f"The {name} partition must contain benign traffic.")
    test_labels = set(inventory.labels[partitions["test"]].tolist())
    if test_labels == {benign_label}:
        raise AnomalySplitError("The held-out test partition must include both benign and malicious rows.")

    group_sets = {
        name: set(day_values[indices].tolist())
        for name, indices in partitions.items()
    }
    overlaps = {
        "train_validation": sorted(group_sets["train"] & group_sets["validation"]),
        "train_test": sorted(group_sets["train"] & group_sets["test"]),
        "validation_test": sorted(group_sets["validation"] & group_sets["test"]),
    }
    if any(overlaps.values()):
        raise AnomalySplitError("Capture-day groups overlap between partitions.")
    source_overlap = _source_file_overlap(inventory, partitions)
    class_counts = {
        name: {
            label: int(np.count_nonzero(inventory.labels[indices] == label))
            for label in inventory.taxonomy.labels
        }
        for name, indices in partitions.items()
    }
    benign_counts = {name: counts.get(benign_label, 0) for name, counts in class_counts.items()}
    audit: dict[str, Any] = {
        "strategy": "capture_day_holdout",
        "random_seed": int(split_config.get("random_seed", config.get("random_seed", 42))),
        "partition_days": {
            name: sorted(day for day, assigned in day_to_partition.items() if assigned == name)
            for name in partitions
        },
        "partition_rows": {name: int(len(indices)) for name, indices in partitions.items()},
        "partition_benign_rows": benign_counts,
        "partition_attack_rows": {
            name: int(len(indices) - benign_counts[name]) for name, indices in partitions.items()
        },
        "class_counts": class_counts,
        "unseen_attack_categories": {
            name: [label for label in inventory.taxonomy.labels if label != benign_label and class_counts[name][label] == 0]
            for name in partitions
        },
        "capture_day_group_counts": {name: len(groups) for name, groups in group_sets.items()},
        "capture_day_group_overlap": overlaps,
        "capture_day_groups_disjoint": not any(overlaps.values()),
        "source_file_counts": {
            name: sorted(inventory.source_files[code] for code in _source_codes(inventory, indices))
            for name, indices in partitions.items()
        },
        "source_file_group_overlap": source_overlap,
        "source_files_disjoint": not any(source_overlap.values()),
        "source_file_class_counts": {
            name: {
                source: inventory.class_counts_by_source_file[source]
                for source in audit_sources
            }
            for name, audit_sources in {
                part: sorted(inventory.source_files[code] for code in _source_codes(inventory, indices))
                for part, indices in partitions.items()
            }.items()
        },
        "total_benign_training_rows": benign_counts["train"],
        "total_benign_validation_rows": benign_counts["validation"],
        "total_benign_test_rows": benign_counts["test"],
        "malicious_test_rows": int(len(partitions["test"]) - benign_counts["test"]),
        "row_level_fallback_used": False,
        "limitation": (
            "Attack categories are tied to capture days; several categories are absent from the held-out Friday test partition. "
            "A separate duplicate-feature audit quantifies repeated feature vectors crossing day boundaries."
        ),
    }
    return AnomalySplit(
        train=partitions["train"],
        validation=partitions["validation"],
        test=partitions["test"],
        day_to_partition=day_to_partition,
        audit=audit,
    )


def select_benign_training_sample(
    training_indices: np.ndarray,
    labels: np.ndarray,
    *,
    benign_label: str = BENIGN_LABEL,
    maximum_rows: int,
    random_seed: int,
) -> np.ndarray:
    """Return a reproducible sample containing benign training indices only."""
    indices = np.asarray(training_indices, dtype=np.int64)
    y = np.asarray(labels, dtype=object)
    if not len(indices) or maximum_rows <= 0:
        raise AnomalySplitError("Benign training indices and maximum_rows must be non-empty and positive.")
    if indices.min() < 0 or indices.max() >= len(y):
        raise AnomalySplitError("Training indices fall outside the label inventory.")
    benign = indices[y[indices] == benign_label]
    if not len(benign):
        raise AnomalySplitError("The training partition contains no benign observations.")
    rng = np.random.default_rng(random_seed)
    selected = benign if len(benign) <= maximum_rows else rng.choice(benign, size=maximum_rows, replace=False)
    selected = np.sort(selected.astype(np.int64))
    if not np.all(y[selected] == benign_label):
        raise AnomalySplitError("Benign training sample unexpectedly contains a non-benign label.")
    return selected


def audit_duplicate_feature_overlap(
    inventory: AnomalyDatasetInventory,
    contract: FeatureContract,
    day_to_partition: dict[str, str],
    *,
    batch_size: int = 25000,
) -> dict[str, Any]:
    """Hash validated feature vectors out of core and audit duplicate split overlap.

    Two independent keyed 64-bit Pandas row hashes are paired, matching the
    Phase 04 duplicate-audit collision-resistance approach. Labels and
    provenance are deliberately excluded from the fingerprint.
    """
    if batch_size <= 0:
        raise AnomalyDataError("Duplicate-audit batch_size must be positive.")
    hash_a: list[np.ndarray] = []
    hash_b: list[np.ndarray] = []
    for path in inventory.files:
        parquet_file = pq.ParquetFile(path)
        for batch in parquet_file.iter_batches(batch_size=batch_size, columns=list(contract.predictive_features)):
            features = batch.to_pandas()
            hash_a.append(
                pd.util.hash_pandas_object(features, index=False, hash_key="0123456789abcdef")
                .to_numpy(dtype=np.uint64)
            )
            hash_b.append(
                pd.util.hash_pandas_object(features, index=False, hash_key="fedcba9876543210")
                .to_numpy(dtype=np.uint64)
            )
    first = np.concatenate(hash_a)
    second = np.concatenate(hash_b)
    if len(first) != len(inventory.labels):
        raise AnomalySplitError("Feature fingerprint rows do not align with the label inventory.")
    order = np.lexsort((second, first))
    sorted_first, sorted_second = first[order], second[order]
    boundaries = np.r_[
        0,
        np.flatnonzero((sorted_first[1:] != sorted_first[:-1]) | (sorted_second[1:] != sorted_second[:-1])) + 1,
        len(order),
    ]
    pair_counts = {"train_validation": 0, "train_test": 0, "validation_test": 0}
    repeated_groups = cross_day_groups = cross_partition_groups = conflicting_label_groups = 0
    rows_in_cross_partition_groups = 0
    day_parent = list(range(len(CAPTURE_DAYS)))

    def find(value: int) -> int:
        while day_parent[value] != value:
            day_parent[value] = day_parent[day_parent[value]]
            value = day_parent[value]
        return value

    def union(left: int, right: int) -> None:
        root_left, root_right = find(left), find(right)
        if root_left != root_right:
            day_parent[root_right] = root_left

    for left, right in zip(boundaries[:-1], boundaries[1:]):
        if right - left < 2:
            continue
        repeated_groups += 1
        row_indices = order[left:right]
        day_codes = np.unique(inventory.capture_day_codes[row_indices])
        if len(day_codes) <= 1:
            continue
        cross_day_groups += 1
        partition_names = {day_to_partition[CAPTURE_DAYS[int(code)]] for code in day_codes}
        if len(partition_names) > 1:
            cross_partition_groups += 1
            rows_in_cross_partition_groups += int(right - left)
            labels = set(inventory.labels[row_indices].tolist())
            if len(labels) > 1:
                conflicting_label_groups += 1
            for pair, roles in {
                "train_validation": {"train", "validation"},
                "train_test": {"train", "test"},
                "validation_test": {"validation", "test"},
            }.items():
                if roles.issubset(partition_names):
                    pair_counts[pair] += 1
        for other in day_codes[1:]:
            union(int(day_codes[0]), int(other))
    components: dict[int, list[str]] = {}
    for index, day in enumerate(CAPTURE_DAYS):
        if day in day_to_partition:
            components.setdefault(find(index), []).append(day)
    return {
        "fingerprint_method": "paired independent 64-bit Pandas hashes over the 78 predictive features; labels and metadata excluded",
        "hash_collision_risk": "negligible but non-zero, consistent with the Phase 04 audit",
        "rows_hashed": int(len(first)),
        "repeated_feature_vector_groups": int(repeated_groups),
        "repeated_feature_vector_groups_crossing_capture_days": int(cross_day_groups),
        "repeated_feature_vector_groups_crossing_partitions": int(cross_partition_groups),
        "groups_crossing_partition_pairs": pair_counts,
        "rows_in_groups_crossing_partitions": int(rows_in_cross_partition_groups),
        "cross_partition_groups_with_different_original_labels": int(conflicting_label_groups),
        "duplicate_groups_disjoint": cross_partition_groups == 0,
        "capture_days_connected_by_duplicate_feature_groups": list(components.values()),
        "joint_capture_day_and_duplicate_disjoint_three_way_split_possible": len(components) >= 3,
    }


def _source_file_overlap(
    inventory: AnomalyDatasetInventory,
    partitions: dict[str, np.ndarray],
) -> dict[str, list[str]]:
    sets = {
        name: {inventory.source_files[int(code)] for code in _source_codes(inventory, indices)}
        for name, indices in partitions.items()
    }
    return {
        "train_validation": sorted(sets["train"] & sets["validation"]),
        "train_test": sorted(sets["train"] & sets["test"]),
        "validation_test": sorted(sets["validation"] & sets["test"]),
    }


def _source_codes(inventory: AnomalyDatasetInventory, indices: np.ndarray) -> set[int]:
    return set(map(int, np.unique(inventory.source_file_codes[indices])))
