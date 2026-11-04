"""Split governance, schema, group overlap, and duplicate audit helpers."""

from __future__ import annotations

from typing import Any, Iterable, Mapping

import numpy as np
import pandas as pd


def classify_evidence(*, partition: str, used_for_selection: bool, results_inspected: bool, reused_by_later_phase: bool = False) -> str:
    """Assign the strongest evidence label justified by recorded usage."""
    if partition == "train":
        return "training_evaluation"
    if partition == "validation":
        return "validation_evaluation"
    if partition in {"test", "held_out_test", "friday_test"}:
        if not results_inspected and not used_for_selection and not reused_by_later_phase:
            return "fresh_held_out_evaluation"
        return "previously_inspected_test_evaluation"
    raise ValueError(f"Unknown evaluation partition category {partition!r}.")


def partition_integrity(partitions: Mapping[str, Iterable[Any]], groups: Mapping[str, Iterable[Any]] | None = None) -> dict[str, Any]:
    """Count row and source-group overlap without assuming split validity."""
    row_sets = {name: set(values) for name, values in partitions.items()}
    names = list(row_sets)
    pairwise_rows = {}
    for left_index, left in enumerate(names):
        for right in names[left_index + 1:]:
            pairwise_rows[f"{left}:{right}"] = len(row_sets[left] & row_sets[right])
    group_sets = {name: set(values) for name, values in (groups or {}).items()}
    pairwise_groups = {}
    for left_index, left in enumerate(group_sets):
        for right in list(group_sets)[left_index + 1:]:
            pairwise_groups[f"{left}:{right}"] = sorted(map(str, group_sets[left] & group_sets[right]))
    return {
        "partition_sizes": {name: len(values) for name, values in row_sets.items()},
        "pairwise_row_overlap_counts": pairwise_rows,
        "group_partition_sizes": {name: len(values) for name, values in group_sets.items()},
        "pairwise_group_overlap": pairwise_groups,
        "row_partitions_disjoint": all(value == 0 for value in pairwise_rows.values()),
        "groups_disjoint": all(not value for value in pairwise_groups.values()),
    }


def prediction_schema_audit(frame: pd.DataFrame, *, feature_names: Iterable[str], target_name: str, forbidden_names: Iterable[str]) -> dict[str, Any]:
    """Validate feature boundary and prediction target/provenance separation."""
    expected = list(map(str, feature_names))
    forbidden = set(map(str, forbidden_names)) | {str(target_name)}
    present_forbidden = sorted(forbidden & set(map(str, frame.columns)))
    return {
        "feature_columns_exact_and_ordered": [name for name in frame.columns if name in expected] == expected,
        "target_in_feature_names": target_name in expected,
        "forbidden_columns_in_prediction_matrix": present_forbidden,
        "target_column_present_separately": target_name in frame.columns,
        "metadata_columns_present": sorted((set(map(str, frame.columns)) & forbidden) - {str(target_name)}),
        "passed": not present_forbidden and [name for name in frame.columns if name in expected] == expected and target_name not in expected,
    }


def duplicate_group_summary(rows: int, duplicate_group_count: int, cross_partition_group_count: int, cross_partition_rows: int, conflicting_label_groups: int) -> dict[str, Any]:
    """Summarize recorded duplicate audit measurements with clear scope."""
    return {
        "rows": int(rows), "duplicate_group_count": int(duplicate_group_count),
        "cross_partition_group_count": int(cross_partition_group_count),
        "cross_partition_rows": int(cross_partition_rows),
        "conflicting_label_groups": int(conflicting_label_groups),
        "limitation": "Repeated features can provide overlapping predictive information; they do not by themselves prove target leakage.",
    }
