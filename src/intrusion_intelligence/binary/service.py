"""Capture-day-held-out binary experiment using the Phase 05 contract."""

from __future__ import annotations

import json
import sqlite3
import tempfile
import time
from contextlib import closing
from pathlib import Path
from typing import Any, Iterator

import numpy as np
import pandas as pd
import pyarrow.parquet as pq
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    balanced_accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)

from intrusion_intelligence.binary.artifacts import save_binary_bundle
from intrusion_intelligence.feature_engineering import FeatureContract, separate_features_target_metadata
from intrusion_intelligence.multiclass.data import inspect_parquet_dataset, iter_partition_batches
from intrusion_intelligence.multiclass.splitting import stratified_training_sample
from intrusion_intelligence.preprocessing.config import load_preprocessing_config
from intrusion_intelligence.preprocessing.pipeline import build_preprocessor


class BinaryExperimentError(ValueError):
    """Raised when the observed CIC data cannot support the requested split."""


def run_binary_experiment(config_path: str | Path = "configs/binary.toml") -> dict[str, Any]:
    config = _load_config(config_path)
    contract = FeatureContract.from_file(config["dataset"]["feature_schema"])
    inventory = inspect_parquet_dataset(config["dataset"]["parquet_directory"], contract)
    labels = np.where(inventory.labels == "BENIGN", "BENIGN", "ATTACK").astype(object)
    day_by_group = [_capture_day(name) for name in inventory.group_names]
    split_by_day = {day: part for part, days in config["split"].items() for day in days}
    unknown_days = sorted(set(day_by_group) - set(split_by_day))
    if unknown_days:
        raise BinaryExperimentError(f"No partition is configured for capture days: {unknown_days}.")
    assignments = np.asarray([split_by_day[day_by_group[int(group)]] for group in inventory.groups], dtype=object)
    split_indices = {name: np.flatnonzero(assignments == name) for name in ("train", "validation", "test")}
    split_counts = {name: _label_counts(labels[indices]) for name, indices in split_indices.items()}
    for name, counts in split_counts.items():
        if set(counts) != {"BENIGN", "ATTACK"}:
            raise BinaryExperimentError(f"Capture-day {name} partition lacks binary class coverage: {counts}.")

    train_sample = stratified_training_sample(
        split_indices["train"], labels,
        maximum_rows=int(config["training"]["maximum_rows"]),
        random_seed=int(config["random_seed"]),
        retain_all_if_count_at_most=1,
    )
    with tempfile.TemporaryDirectory(prefix="intrusion-binary-duplicates-") as temporary:
        with closing(sqlite3.connect(Path(temporary) / "heldout-signatures.sqlite")) as database:
            database.execute("CREATE TABLE signatures (signature TEXT PRIMARY KEY)")
            test_signatures = _scan_partition_signatures(
                database, inventory.files, split_indices["test"], contract,
                int(config["training"]["batch_size"]), exclude_test=False,
            )
            validation_indices, validation_test_collisions = _filter_partition(
                database, inventory.files, split_indices["validation"], contract,
                int(config["training"]["batch_size"]), against_existing=True, add_new=True,
            )
            if not len(validation_indices) or not set(labels[validation_indices]) == {"BENIGN", "ATTACK"}:
                raise BinaryExperimentError("Removing duplicate feature vectors shared with the final test partition removes validation class coverage.")
            sample_X, original_sample_labels = _collect(inventory.files, train_sample, contract, int(config["training"]["batch_size"]))
            sample_y = _binary_labels(original_sample_labels)
            sample_signatures = _signatures(sample_X)
            eligible_mask = _query_collisions(database, sample_signatures)
            excluded_training_duplicate_rows = int(eligible_mask.sum())
            X_train = sample_X.loc[~eligible_mask].reset_index(drop=True)
            y_train_text = sample_y.loc[~eligible_mask].reset_index(drop=True)
            counts_before_filter = _label_counts(sample_y.to_numpy())
            counts_after_filter = _label_counts(y_train_text.to_numpy())
            excluded_by_label = _label_counts(sample_y.loc[eligible_mask].to_numpy())
            if set(y_train_text.astype(str)) != {"BENIGN", "ATTACK"}:
                raise BinaryExperimentError(
                    "Duplicate screening removed a binary training class; no fallback split was used. "
                    f"Sample counts before/after screening: {counts_before_filter}/{counts_after_filter}; "
                    f"removed by binary label: {excluded_by_label}."
                )

    y_train = y_train_text.map({"BENIGN": 0, "ATTACK": 1}).to_numpy(dtype=np.uint8)
    preprocessor = build_preprocessor(str(config["training"]["preprocessing_profile"]), contract=contract)
    before_fit = time.perf_counter()
    preprocessor.fit(X_train)
    transformed_train = preprocessor.transform(X_train, mode="training")
    preprocessing_seconds = time.perf_counter() - before_fit
    model = RandomForestClassifier(
        n_estimators=int(config["training"]["estimators"]),
        max_depth=int(config["training"]["max_depth"]),
        min_samples_leaf=int(config["training"]["min_samples_leaf"]),
        max_features=config["training"]["max_features"],
        class_weight="balanced",
        random_state=int(config["random_seed"]),
        n_jobs=int(config["training"]["n_jobs"]),
    )
    fit_started = time.perf_counter()
    model.fit(transformed_train, y_train)
    fit_seconds = time.perf_counter() - fit_started
    del transformed_train

    validation = _evaluate(model, preprocessor, inventory.files, validation_indices, labels, contract, int(config["training"]["batch_size"]))
    test = _evaluate(model, preprocessor, inventory.files, split_indices["test"], labels, contract, int(config["training"]["batch_size"]))
    run_id = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    split_audit = {
        "strategy": "capture_day_holdout",
        "day_assignment": config["split"],
        "rows_before_duplicate_screening": {name: int(len(indices)) for name, indices in split_indices.items()},
        "binary_class_counts_before_screening": split_counts,
        "validation_rows_removed_for_shared_feature_vectors_with_test": validation_test_collisions,
        "training_sample_candidate_rows": int(len(train_sample)),
        "training_sample_rows_removed_for_feature_vectors_in_evaluation": excluded_training_duplicate_rows,
        "training_sample_binary_class_counts_before_duplicate_screening": counts_before_filter,
        "training_sample_rows_removed_by_binary_class": excluded_by_label,
        "training_rows_by_binary_class_after_screening": counts_after_filter,
        "training_rows_after_screening": int(len(X_train)),
        "test_feature_vectors_scanned": int(test_signatures),
        "source_file_partitions": {
            name: [inventory.group_names[i] for i, day in enumerate(day_by_group) if split_by_day[day] == name]
            for name in ("train", "validation", "test")
        },
        "source_files_are_disjoint": True,
        "feature_vector_cross_partition_overlap_after_screening": 0,
        "fingerprint_method": "two independent 64-bit Pandas row hashes combined into one 128-bit signature",
        "fingerprint_collision_limitation": "negligible but nonzero collision probability",
        "threshold_selected_using_validation_or_test": False,
        "decision_threshold": 0.5,
    }
    metadata = {
        "experiment_run_id": run_id,
        "dataset_rows": int(len(labels)),
        "dataset_label_counts": _label_counts(labels),
        "binary_target_mapping": {"BENIGN": 0, "ATTACK": 1},
        "source_attack_labels_mapped_to_attack": sorted(str(value) for value in np.unique(inventory.labels) if value != "BENIGN"),
        "original_multiclass_labels_preserved_in_source": True,
        "split_audit": split_audit,
        "training_rows_by_binary_class": _label_counts(y_train_text.astype(str).to_numpy()),
        "validation_metrics": validation["metrics"],
        "held_out_test_metrics": test["metrics"],
        "validation_support": validation["support"],
        "test_support": test["support"],
        "preprocessing_fit_seconds": preprocessing_seconds,
        "classifier_fit_seconds": fit_seconds,
        "preprocessing_fit_partition": "training only",
        "threshold_policy": "fixed at 0.5 before held-out evaluation; not selected on validation/test",
        "score_calibration": "not calibrated; predict_proba score is not a compromise probability",
        "ground_truth_in_feature_matrix": False,
    }
    artifact = save_binary_bundle(model, preprocessor, config["artifacts"]["directory"], version=str(config["artifacts"]["version"]), metadata=metadata)
    report_root = Path(config["reports"]["directory"]) / run_id
    report_root.mkdir(parents=True, exist_ok=False)
    summary = {"run_id": run_id, "model_id": f"binary-random_forest-v{config['artifacts']['version']}", "artifact": str(artifact), **metadata}
    (report_root / "binary_experiment.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (report_root / "binary_experiment.md").write_text(_render_report(summary), encoding="utf-8")
    (report_root / "configuration.json").write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")
    return {"report_directory": str(report_root), "artifact_directory": str(artifact), "summary": summary}


def _load_config(path: str | Path) -> dict[str, Any]:
    import tomllib

    with Path(path).open("rb") as stream:
        config = tomllib.load(stream)
    for key in ("dataset", "split", "training", "artifacts", "reports"):
        if key not in config:
            raise BinaryExperimentError(f"Binary configuration is missing [{key}].")
    if config["split"] != {"train": config["split"].get("train", []), "validation": config["split"].get("validation", []), "test": config["split"].get("test", [])}:
        raise BinaryExperimentError("Split config must define exactly train, validation, and test capture-day lists.")
    return config


def _capture_day(filename: str) -> str:
    lower = filename.lower()
    for day in ("monday", "tuesday", "wednesday", "thursday", "friday"):
        if lower.startswith(day):
            return day.title()
    raise BinaryExperimentError(f"Cannot determine capture day from source filename {filename!r}.")


def _label_counts(labels: Any) -> dict[str, int]:
    values, counts = np.unique(np.asarray(labels, dtype=object), return_counts=True)
    return {str(value): int(count) for value, count in zip(values, counts)}


def _binary_labels(labels: pd.Series) -> pd.Series:
    """Map source labels to the documented binary target without changing source labels."""
    values = labels.astype("string")
    if values.isna().any() or values.str.strip().eq("").any():
        raise BinaryExperimentError("Source labels contain missing or empty values; refusing to map them to ATTACK.")
    return pd.Series(np.where(values.to_numpy() == "BENIGN", "BENIGN", "ATTACK"), index=labels.index, name="binary_target")


def _signatures(frame: pd.DataFrame) -> np.ndarray:
    first = pd.util.hash_pandas_object(frame, index=False, hash_key="0123456789123456").to_numpy(dtype=np.uint64)
    second = pd.util.hash_pandas_object(frame, index=False, hash_key="6543210987654321").to_numpy(dtype=np.uint64)
    return np.char.add(np.char.mod("%016x", first), np.char.mod("%016x", second))


def _query_collisions(database: sqlite3.Connection, signatures: np.ndarray) -> np.ndarray:
    collisions = np.zeros(len(signatures), dtype=bool)
    for start in range(0, len(signatures), 500):
        part = signatures[start:start + 500]
        rows = database.execute(
            f"SELECT signature FROM signatures WHERE signature IN ({','.join('?' for _ in part)})",
            tuple(map(str, part)),
        ).fetchall()
        if rows:
            matched = {row[0] for row in rows}
            collisions[start:start + len(part)] = [str(value) in matched for value in part]
    return collisions


def _scan_partition_signatures(database: sqlite3.Connection, files: tuple[Path, ...], indices: np.ndarray, contract: FeatureContract, batch_size: int, *, exclude_test: bool) -> int:
    del exclude_test
    selected = set(np.asarray(indices, dtype=np.int64).tolist())
    offset = 0
    signatures_count = 0
    columns = list(contract.predictive_features)
    for path in files:
        row_count = pq.ParquetFile(path).metadata.num_rows
        if selected.intersection(range(offset, offset + row_count)):
            for batch in pq.ParquetFile(path).iter_batches(batch_size=batch_size, columns=columns):
                frame = batch.to_pandas()
                values = _signatures(frame)
                database.executemany("INSERT OR IGNORE INTO signatures(signature) VALUES(?)", ((str(value),) for value in values))
                signatures_count += len(values)
        offset += row_count
    database.commit()
    return signatures_count


def _filter_partition(database: sqlite3.Connection, files: tuple[Path, ...], indices: np.ndarray, contract: FeatureContract, batch_size: int, *, against_existing: bool, add_new: bool) -> tuple[np.ndarray, int]:
    selected = np.sort(np.asarray(indices, dtype=np.int64))
    kept: list[int] = []
    removed = 0
    offset = 0
    columns = list(contract.predictive_features)
    for path in files:
        row_count = pq.ParquetFile(path).metadata.num_rows
        left = int(np.searchsorted(selected, offset, side="left"))
        right = int(np.searchsorted(selected, offset + row_count, side="left"))
        local = selected[left:right] - offset
        if len(local):
            row_offset = 0
            parquet = pq.ParquetFile(path)
            for batch in parquet.iter_batches(batch_size=batch_size, columns=columns):
                batch_end = row_offset + batch.num_rows
                lo = int(np.searchsorted(local, row_offset, side="left"))
                hi = int(np.searchsorted(local, batch_end, side="left"))
                if hi > lo:
                    positions = local[lo:hi]
                    frame = batch.slice(int(positions[0] - row_offset), int(positions[-1] - positions[0] + 1)).to_pandas()
                    # Selected indices may have gaps inside this range.
                    offsets = (positions - positions[0]).astype(np.int64)
                    frame = frame.iloc[offsets].reset_index(drop=True)
                    signatures = _signatures(frame)
                    collision = _query_collisions(database, signatures) if against_existing else np.zeros(len(frame), dtype=bool)
                    kept.extend((positions[~collision] + offset).tolist())
                    removed += int(collision.sum())
                    if add_new:
                        database.executemany("INSERT OR IGNORE INTO signatures(signature) VALUES(?)", ((str(value),) for value in signatures))
                row_offset = batch_end
        offset += row_count
    database.commit()
    return np.asarray(kept, dtype=np.int64), removed


def _collect(files: tuple[Path, ...], indices: np.ndarray, contract: FeatureContract, batch_size: int) -> tuple[pd.DataFrame, pd.Series]:
    feature_parts: list[pd.DataFrame] = []
    label_parts: list[pd.Series] = []
    for features, labels in iter_partition_batches(files, indices, contract, batch_size=batch_size):
        feature_parts.append(features)
        label_parts.append(labels)
    if not feature_parts:
        raise BinaryExperimentError("Selected binary partition is empty.")
    return pd.concat(feature_parts, ignore_index=True), pd.concat(label_parts, ignore_index=True)


def _evaluate(model: Any, preprocessor: Any, files: tuple[Path, ...], indices: np.ndarray, labels: np.ndarray, contract: FeatureContract, batch_size: int) -> dict[str, Any]:
    truth: list[np.ndarray] = []
    predicted: list[np.ndarray] = []
    scores: list[np.ndarray] = []
    for X, y_text in iter_partition_batches(files, indices, contract, batch_size=batch_size):
        # Keep ground truth outside X and the fitted transformation/model calls.
        y = _binary_labels(y_text).map({"BENIGN": 0, "ATTACK": 1}).to_numpy(dtype=np.uint8)
        transformed = preprocessor.transform(X, mode="inference")
        score = model.predict_proba(transformed)[:, list(model.classes_).index(1)]
        truth.append(y)
        scores.append(score)
        predicted.append((score >= 0.5).astype(np.uint8))
    y_true = np.concatenate(truth)
    y_pred = np.concatenate(predicted)
    y_score = np.concatenate(scores)
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    metrics = {
        "threshold": 0.5,
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "balanced_accuracy": float(balanced_accuracy_score(y_true, y_pred)),
        "precision_attack": float(precision_score(y_true, y_pred, zero_division=0)),
        "recall_attack": float(recall_score(y_true, y_pred, zero_division=0)),
        "f1_attack": float(f1_score(y_true, y_pred, zero_division=0)),
        "false_positive_rate": float(fp / (fp + tn)) if (fp + tn) else None,
        "roc_auc": float(roc_auc_score(y_true, y_score)) if len(np.unique(y_true)) == 2 else None,
        "average_precision_attack": float(average_precision_score(y_true, y_score)) if len(np.unique(y_true)) == 2 else None,
        "confusion_matrix_labels": ["BENIGN", "ATTACK"],
        "confusion_matrix": [[int(tn), int(fp)], [int(fn), int(tp)]],
        "score_interpretation": "uncalibrated model ranking score; not a probability of compromise",
    }
    return {"metrics": metrics, "support": _label_counts(np.where(y_true == 0, "BENIGN", "ATTACK"))}


def _render_report(summary: dict[str, Any]) -> str:
    return "\n".join([
        "# Binary CIC-IDS2017 experiment",
        "",
        f"Run: `{summary['run_id']}`; model: `{summary['model_id']}`.",
        "",
        "Target mapping is BENIGN=0 and every preserved non-BENIGN source label=ATTACK. The classifier is independent of the Phase 07 multiclass model.",
        "",
        "## Split and leakage controls",
        "",
        "Capture-day holdout: Monday–Wednesday train, Thursday validation, Friday final test. Preprocessing is fit on the training-only sample. Duplicate feature vectors shared across partitions are excluded from training and validation; no test threshold tuning is performed.",
        "",
        "```json",
        json.dumps(summary["split_audit"], indent=2),
        "```",
        "",
        "## Validation metrics",
        "",
        "```json",
        json.dumps(summary["validation_metrics"], indent=2),
        "```",
        "",
        "## Held-out test metrics",
        "",
        "```json",
        json.dumps(summary["held_out_test_metrics"], indent=2),
        "```",
        "",
        "This is capture-day-held-out evidence on CIC-IDS2017, not external-dataset or deployment validation. Predictive scores are uncalibrated and are not compromise probabilities.",
        "",
    ])
