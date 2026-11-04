"""Memory-conscious Parquet inspection and split-partition batch loading."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator

import numpy as np
import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq

from intrusion_intelligence.feature_engineering import FeatureContract, separate_features_target_metadata
from intrusion_intelligence.multiclass.taxonomy import ClassTaxonomy, TaxonomyError


class DatasetError(ValueError):
    """Raised when cleaned Parquet files violate the multi-class contract."""


@dataclass(frozen=True, slots=True)
class DatasetInventory:
    """Label, group, and schema information loaded without predictive columns."""

    files: tuple[Path, ...]
    labels: np.ndarray
    groups: np.ndarray
    group_names: tuple[str, ...]
    class_counts: dict[str, int]
    class_source_counts: dict[str, dict[str, int]]
    rows_per_file: dict[str, int]
    taxonomy: ClassTaxonomy

    def distribution_records(self) -> list[dict[str, Any]]:
        total = len(self.labels)
        return [
            {
                "class_id": class_id,
                "label": label,
                "count": self.class_counts[label],
                "percent": self.class_counts[label] / total * 100.0,
                "source_group_count": sum(
                    1 for counts in self.class_source_counts.values() if counts.get(label, 0) > 0
                ),
            }
            for class_id, label in enumerate(self.taxonomy.labels)
        ]


def inspect_parquet_dataset(
    directory: str | Path,
    contract: FeatureContract,
    *,
    mapping_version: str = "1.0.0",
) -> DatasetInventory:
    """Validate schemas and discover the exact original target taxonomy."""
    root = Path(directory)
    files = tuple(sorted(root.glob("*.parquet")))
    if not files:
        raise DatasetError(f"No Parquet files found under {root}.")
    required = set(contract.predictive_features) | {contract.target_name, "__source_file"}
    reference_columns: list[str] | None = None
    label_parts: list[np.ndarray] = []
    group_parts: list[np.ndarray] = []
    class_counts: dict[str, int] = {}
    source_counts: dict[str, dict[str, int]] = {}
    rows_per_file: dict[str, int] = {}
    group_names: list[str] = []
    observed_values: list[str] = []
    total_rows = 0
    for group_id, path in enumerate(files):
        parquet_file = pq.ParquetFile(path)
        columns = parquet_file.schema_arrow.names
        if reference_columns is None:
            reference_columns = columns
        elif columns != reference_columns:
            raise DatasetError(f"Parquet schema differs from other files: {path.name}.")
        missing = sorted(required - set(columns))
        if missing:
            raise DatasetError(f"Parquet file {path.name} is missing contract columns: {missing}.")
        frame = pq.read_table(path, columns=[contract.target_name]).to_pandas()
        labels = frame[contract.target_name]
        if labels.isna().any():
            raise DatasetError(f"Null target labels found in {path.name}.")
        text_labels = labels.astype("string")
        if text_labels.str.strip().eq("").any():
            raise DatasetError(f"Blank target labels found in {path.name}.")
        values = text_labels.astype(str).to_numpy(dtype=object)
        counts = pd.Series(values).value_counts(sort=False).to_dict()
        file_name = path.name
        group_names.append(file_name)
        total_rows += len(values)
        rows_per_file[file_name] = int(len(values))
        label_parts.append(values)
        group_parts.append(np.full(len(values), group_id, dtype=np.int16))
        source_counts[file_name] = {str(label): int(count) for label, count in counts.items()}
        for label, count in counts.items():
            key = str(label)
            class_counts[key] = class_counts.get(key, 0) + int(count)
        observed_values.extend(str(label) for label in counts)
    try:
        taxonomy = ClassTaxonomy.from_labels(
            observed_values,
            allowed_labels=contract.target_values,
            version=mapping_version,
        )
    except TaxonomyError as exc:
        raise DatasetError(str(exc)) from exc
    labels_all = np.concatenate(label_parts)
    groups_all = np.concatenate(group_parts)
    if len(labels_all) != len(groups_all) or len(labels_all) != total_rows:
        raise DatasetError("Label and source-group inventories are not row-aligned.")
    return DatasetInventory(
        files=files,
        labels=labels_all,
        groups=groups_all,
        group_names=tuple(group_names),
        class_counts=class_counts,
        class_source_counts=source_counts,
        rows_per_file=rows_per_file,
        taxonomy=taxonomy,
    )


def iter_partition_batches(
    files: tuple[Path, ...],
    indices: np.ndarray,
    contract: FeatureContract,
    *,
    batch_size: int,
) -> Iterator[tuple[pd.DataFrame, pd.Series]]:
    """Yield only requested global row indices while reading bounded Arrow batches."""
    selected = np.sort(np.asarray(indices, dtype=np.int64))
    if not len(selected):
        return
    offset = 0
    feature_columns = list(contract.predictive_features)
    columns = [*feature_columns, contract.target_name]
    selected_count = 0
    for path in files:
        parquet_file = pq.ParquetFile(path)
        row_count = parquet_file.metadata.num_rows
        start_position = int(np.searchsorted(selected, offset, side="left"))
        end_position = int(np.searchsorted(selected, offset + row_count, side="left"))
        local_indices = selected[start_position:end_position] - offset
        if len(local_indices):
            row_offset = 0
            for batch in parquet_file.iter_batches(batch_size=batch_size, columns=columns):
                batch_end = row_offset + batch.num_rows
                left = int(np.searchsorted(local_indices, row_offset, side="left"))
                right = int(np.searchsorted(local_indices, batch_end, side="left"))
                if right > left:
                    take_indices = (local_indices[left:right] - row_offset).astype(np.int64)
                    selected_batch = batch.take(pa.array(take_indices, type=pa.int64()))
                    source = selected_batch.to_pandas()
                    X, y, _ = separate_features_target_metadata(source, contract)
                    selected_count += len(y)
                    yield X, y.reset_index(drop=True)
                row_offset = batch_end
        offset += row_count
    if selected_count != len(selected):
        raise DatasetError(f"Requested {len(selected)} rows but loaded {selected_count} from Parquet.")


def collect_partition(
    files: tuple[Path, ...],
    indices: np.ndarray,
    contract: FeatureContract,
    *,
    batch_size: int,
) -> tuple[pd.DataFrame, pd.Series]:
    """Collect a bounded training sample from batches into one feature matrix."""
    feature_frames: list[pd.DataFrame] = []
    targets: list[pd.Series] = []
    for features, labels in iter_partition_batches(files, indices, contract, batch_size=batch_size):
        feature_frames.append(features)
        targets.append(labels)
    if not feature_frames:
        raise DatasetError("Selected partition contains no rows.")
    X = pd.concat(feature_frames, ignore_index=True)
    y = pd.concat(targets, ignore_index=True)
    if len(X) != len(indices) or len(y) != len(indices):
        raise DatasetError("Collected feature rows and labels do not match selected indices.")
    return X, y
