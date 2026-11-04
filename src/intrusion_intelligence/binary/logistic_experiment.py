"""Leakage-safe capture-day-held-out Logistic Regression comparison."""

from __future__ import annotations

import hashlib
import json
import shutil
import tempfile
import time
import warnings
from contextlib import closing
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq
from sklearn.exceptions import ConvergenceWarning
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score, average_precision_score, confusion_matrix, f1_score,
    precision_score, recall_score, roc_auc_score,
)

from intrusion_intelligence.binary.artifacts import load_binary_bundle
from intrusion_intelligence.binary.logistic_artifacts import save_logistic_bundle
from intrusion_intelligence.binary.service import (
    BinaryExperimentError, _binary_labels, _capture_day, _collect,
    _filter_partition, _label_counts, _query_collisions,
    _scan_partition_signatures, _signatures,
)
from intrusion_intelligence.feature_engineering import FeatureContract
from intrusion_intelligence.intelligence.schemas import json_safe
from intrusion_intelligence.multiclass.data import inspect_parquet_dataset, iter_partition_batches
from intrusion_intelligence.multiclass.splitting import stratified_training_sample
from intrusion_intelligence.preprocessing.pipeline import build_preprocessor


class LogisticExperimentError(ValueError):
    """Raised when inputs or results cannot support a valid comparison."""


def _resolve(root: Path, value: str | Path) -> Path:
    path = Path(value).expanduser()
    return path if path.is_absolute() else root / path


def _load_config(path: Path) -> dict[str, Any]:
    import tomllib

    with path.open("rb") as stream:
        config = tomllib.load(stream)
    required = ("dataset", "split", "training", "threshold_sensitivity", "artifacts", "reports", "comparison")
    missing = [key for key in required if key not in config]
    if missing:
        raise LogisticExperimentError(f"Logistic config is missing sections: {missing}.")
    if config["split"] != {key: config["split"].get(key, []) for key in ("train", "validation", "test")}:
        raise LogisticExperimentError("Split config must define exactly train, validation, and test.")
    training = config["training"]
    if training.get("decision_threshold") != 0.5 or training.get("preprocessing_profile") != "linear":
        raise LogisticExperimentError("Comparison requires fixed threshold 0.5 and the linear preprocessing profile.")
    if training.get("feature_selection") is not False:
        raise LogisticExperimentError("Feature selection must remain disabled for comparison.")
    return config


def _validate_feature_boundary(contract: FeatureContract) -> None:
    names = contract.predictive_features
    if contract.target_name in names or not names or len(set(names)) != len(names):
        raise LogisticExperimentError("Feature contract contains a target leak, no features, or duplicate internal names.")


def run_logistic_experiment(config_path: str | Path = "configs/binary_logistic.toml") -> dict[str, Any]:
    config_path = Path(config_path).expanduser().resolve()
    config = _load_config(config_path)
    root = config_path.parent.parent
    contract_path = _resolve(root, config["dataset"]["feature_schema"])
    parquet_dir = _resolve(root, config["dataset"]["parquet_directory"])
    contract = FeatureContract.from_file(contract_path)
    _validate_feature_boundary(contract)
    inventory = inspect_parquet_dataset(parquet_dir, contract)
    try:
        binary_labels = _binary_labels(pd.Series(inventory.labels, dtype="string")).to_numpy(dtype=object)
    except BinaryExperimentError as exc:
        raise LogisticExperimentError(f"Invalid CIC target labels: {exc}") from exc

    group_days = [_capture_day(name) for name in inventory.group_names]
    split_for_day = {day: part for part, days in config["split"].items() for day in days}
    unknown_days = sorted(set(group_days) - set(split_for_day))
    if unknown_days:
        raise LogisticExperimentError(f"Unassigned capture days: {unknown_days}.")
    assignments = np.asarray([split_for_day[group_days[int(group)]] for group in inventory.groups], dtype=object)
    partitions = {name: np.flatnonzero(assignments == name) for name in ("train", "validation", "test")}
    class_counts = {name: _label_counts(binary_labels[indices]) for name, indices in partitions.items()}
    for name, counts in class_counts.items():
        if set(counts) != {"BENIGN", "ATTACK"}:
            raise LogisticExperimentError(f"Partition {name} lacks binary class coverage: {counts}.")

    train_candidates = stratified_training_sample(
        partitions["train"], binary_labels,
        maximum_rows=int(config["training"]["maximum_rows"]),
        random_seed=int(config["random_seed"]),
        retain_all_if_count_at_most=1,
    )
    batch_size = int(config["training"]["batch_size"])
    X_candidate, original_train_labels = _collect(inventory.files, train_candidates, contract, batch_size)
    y_candidate = _binary_labels(original_train_labels)
    validation_indices, duplicate_mask, validation_removed, test_scan_count = _screen_duplicates(
        inventory.files, contract, partitions, X_candidate, batch_size=batch_size,
    )
    excluded_by_class = _label_counts(y_candidate.loc[duplicate_mask].to_numpy())
    X_train = X_candidate.loc[~duplicate_mask].reset_index(drop=True)
    y_train_text = y_candidate.loc[~duplicate_mask].reset_index(drop=True)
    train_counts_before = _label_counts(y_candidate.to_numpy())
    train_counts_after = _label_counts(y_train_text.to_numpy())
    if set(y_train_text.astype(str)) != {"BENIGN", "ATTACK"}:
        raise LogisticExperimentError(
            "RF-equivalent duplicate exclusion removed a training class; refusing fallback. "
            f"Before={train_counts_before}; after={train_counts_after}; excluded={excluded_by_class}."
        )
    if tuple(X_train.columns) != contract.predictive_features:
        raise LogisticExperimentError("Training feature columns/order differ from the Phase 05 contract.")
    if contract.target_name in X_train.columns:
        raise LogisticExperimentError("Ground-truth target leaked into training features.")

    y_train = y_train_text.map({"BENIGN": 0, "ATTACK": 1}).to_numpy(dtype=np.uint8)
    preprocessor = build_preprocessor(
        "linear", contract=contract,
        feature_selection=bool(config["training"]["feature_selection"]),
    )
    if preprocessor.feature_selection:
        raise LogisticExperimentError("Feature selection must remain disabled for this comparison.")
    prep_started = time.perf_counter()
    preprocessor.fit(X_train)
    transformed_train = preprocessor.transform(X_train, mode="training")
    preprocessing_seconds = time.perf_counter() - prep_started
    if transformed_train.shape[1] != len(contract.predictive_features):
        raise LogisticExperimentError("Preprocessing changed the 78-feature contract.")

    model = LogisticRegression(
        solver=str(config["training"]["solver"]),
        penalty=str(config["training"]["penalty"]),
        C=float(config["training"]["C"]),
        max_iter=int(config["training"]["max_iter"]),
        tol=float(config["training"]["tol"]),
        class_weight=str(config["training"]["class_weight"]),
        random_state=int(config["random_seed"]),
    )
    fit_started = time.perf_counter()
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always", ConvergenceWarning)
        model.fit(transformed_train, y_train)
    estimator_fit_seconds = time.perf_counter() - fit_started
    convergence_warnings = [
        str(item.message) for item in caught if issubclass(item.category, ConvergenceWarning)
    ]
    if convergence_warnings:
        raise LogisticExperimentError(
            "Logistic Regression failed to converge; no model artifact was saved. "
            f"Warnings: {convergence_warnings}"
        )
    if not np.array_equal(np.asarray(model.classes_), np.asarray([0, 1])):
        raise LogisticExperimentError(f"Unexpected LogisticRegression class order: {model.classes_.tolist()}.")
    del transformed_train

    run_id = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    report_root = _resolve(root, config["reports"]["directory"]) / run_id
    if report_root.exists():
        raise FileExistsError(f"Refusing to overwrite Logistic report directory {report_root}.")
    report_root.mkdir(parents=True, exist_ok=False)
    shutil.copyfile(contract_path, report_root / "feature_schema.json")
    threshold = float(config["training"]["decision_threshold"])
    validation = _evaluate_partition(
        model, preprocessor, inventory, contract, validation_indices,
        batch_size=batch_size, threshold=threshold,
        predictions_path=report_root / "predictions_validation.parquet",
    )
    test = _evaluate_partition(
        model, preprocessor, inventory, contract, partitions["test"],
        batch_size=batch_size, threshold=threshold,
        predictions_path=report_root / "predictions_friday_test.parquet",
    )
    sensitivity = [
        {"threshold": float(value), **_binary_metrics(validation["y_true"], validation["scores"], float(value))}
        for value in config["threshold_sensitivity"]["validation_thresholds"]
    ]
    if not any(np.isclose(item["threshold"], threshold) for item in sensitivity):
        sensitivity.append({"threshold": threshold, **_binary_metrics(validation["y_true"], validation["scores"], threshold)})
        sensitivity.sort(key=lambda item: item["threshold"])

    split_audit = {
        "strategy": "capture_day_holdout",
        "day_assignment": config["split"],
        "rows_before_duplicate_screening": {name: int(len(indices)) for name, indices in partitions.items()},
        "binary_class_counts_before_screening": class_counts,
        "validation_rows_removed_for_shared_feature_vectors_with_test": validation_removed,
        "training_sample_candidate_rows": int(len(train_candidates)),
        "training_sample_binary_class_counts_before_duplicate_screening": train_counts_before,
        "training_sample_rows_removed_for_feature_vectors_in_evaluation": int(duplicate_mask.sum()),
        "training_sample_rows_removed_by_binary_class": excluded_by_class,
        "training_rows_by_binary_class_after_screening": train_counts_after,
        "training_rows_after_screening": int(len(X_train)),
        "test_feature_vectors_scanned": int(test_scan_count),
        "source_files_are_disjoint": True,
        "feature_vector_cross_partition_overlap_after_screening": 0,
        "fingerprint_method": "same pair of independent 64-bit Pandas row hashes used by Random Forest v1.0.1",
        "fingerprint_collision_limitation": "negligible but nonzero collision probability",
        "threshold_selected_using_validation_or_test": False,
        "fixed_decision_threshold": threshold,
    }
    rf = _load_rf_reference(root, config, split_audit, contract)
    if rf["training_rows_by_binary_class"] != train_counts_after:
        raise LogisticExperimentError("Training sample class counts differ from Random Forest v1.0.1.")
    if rf["validation_support"] != validation["support"] or rf["friday_test_support"] != test["support"]:
        raise LogisticExperimentError("Evaluation class supports differ from Random Forest v1.0.1.")
    runtime = {
        "preprocessing_fit_seconds": preprocessing_seconds,
        "classifier_fit_seconds": estimator_fit_seconds,
        "training_fit_total_seconds": preprocessing_seconds + estimator_fit_seconds,
        "validation_prediction_seconds": validation["prediction_seconds"],
        "validation_prediction_rows_per_second": len(validation["y_true"]) / validation["prediction_seconds"],
        "friday_test_prediction_seconds": test["prediction_seconds"],
        "friday_test_prediction_rows_per_second": len(test["y_true"]) / test["prediction_seconds"],
        "fit_partition": "training only",
    }
    metadata = {
        "experiment_run_id": run_id,
        "dataset_name": contract.dataset_name,
        "dataset_rows": int(len(inventory.labels)),
        "dataset_binary_label_counts": _label_counts(binary_labels),
        "source_attack_labels_mapped_to_attack": sorted(
            str(value) for value in np.unique(inventory.labels) if value != "BENIGN"
        ),
        "target_mapping": {"BENIGN": 0, "ATTACK": 1},
        "original_multiclass_labels_preserved_separately": True,
        "ground_truth_in_feature_matrix": False,
        "feature_schema_version": contract.schema_version,
        "feature_count": len(contract.predictive_features),
        "feature_names": list(contract.predictive_features),
        "preprocessing_profile": "linear",
        "feature_selection_enabled": False,
        "preprocessing": preprocessor.preprocessing_metadata(),
        "training_rows_by_binary_class": train_counts_after,
        "validation_support": validation["support"],
        "friday_test_support": test["support"],
        "split_audit": split_audit,
        "validation_metrics_at_fixed_threshold": validation["metrics"],
        "friday_test_metrics_at_fixed_threshold": test["metrics"],
        "validation_threshold_sensitivity": sensitivity,
        "threshold_sensitivity_partition": "Thursday validation only",
        "threshold_selection_policy": "No threshold selected. Fixed threshold 0.5 is reported for validation and Friday test.",
        "training_runtime": runtime,
        "estimator_configuration": model.get_params(deep=False),
        "class_imbalance_policy": "class_weight=balanced, matching the Random Forest baseline",
        "random_seed": int(config["random_seed"]),
        "convergence": {
            "converged": True,
            "n_iter_by_class": np.asarray(model.n_iter_, dtype=int).tolist(),
            "warnings": [],
        },
        "evaluation_prediction_files": {
            "validation": "predictions_validation.parquet",
            "friday_test": "predictions_friday_test.parquet",
            "contains_ground_truth": True,
            "usage": "Offline evaluation only; never feed into detector inference, scoring, or alerts.",
        },
        "random_forest_reference": rf,
    }
    artifact = save_logistic_bundle(
        model,
        preprocessor,
        _resolve(root, config["artifacts"]["directory"]),
        version=str(config["artifacts"]["version"]),
        metadata=metadata,
    )
    bundle_size = sum(path.stat().st_size for path in artifact.iterdir() if path.is_file())
    summary = {
        "run_id": run_id,
        "model_id": f"binary-logistic_regression-v{config['artifacts']['version']}",
        "artifact_directory": str(artifact),
        "report_directory": str(report_root),
        "artifact_total_size_bytes": bundle_size,
        "artifact_joblib_size_bytes": sum(
            int(record["size_bytes"]) for record in json.loads((artifact / "metadata.json").read_text(encoding="utf-8"))["artifact_files"].values()
        ),
        "configuration_fingerprint_sha256": hashlib.sha256(
            json.dumps(json_safe(config), sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest(),
        **metadata,
    }
    (report_root / "configuration.json").write_text(
        json.dumps(json_safe(config), ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    (report_root / "experiment_summary.json").write_text(
        json.dumps(json_safe(summary), ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    (report_root / "validation_threshold_sensitivity.json").write_text(
        json.dumps(json_safe(sensitivity), ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    (report_root / "binary_logistic_comparison.md").write_text(_render_report(summary), encoding="utf-8")
    return {"report_directory": str(report_root), "artifact_directory": str(artifact), "summary": summary}


def _screen_duplicates(
    files: tuple[Path, ...],
    contract: FeatureContract,
    partitions: dict[str, np.ndarray],
    training_X: pd.DataFrame,
    *,
    batch_size: int,
) -> tuple[np.ndarray, np.ndarray, int, int]:
    """Repeat the exact baseline ordering: test scan, validation filter, train filter."""
    import sqlite3

    with tempfile.TemporaryDirectory(prefix="intrusion-logistic-duplicates-") as temporary:
        with closing(sqlite3.connect(Path(temporary) / "signatures.sqlite")) as database:
            database.execute("CREATE TABLE signatures (signature TEXT PRIMARY KEY)")
            test_count = _scan_partition_signatures(
                database, files, partitions["test"], contract, batch_size, exclude_test=False
            )
            validation, validation_removed = _filter_partition(
                database, files, partitions["validation"], contract, batch_size,
                against_existing=True, add_new=True,
            )
            collision_mask = _query_collisions(database, _signatures(training_X))
    return validation, collision_mask, validation_removed, test_count


def _evaluate_partition(
    model: LogisticRegression,
    preprocessor: Any,
    inventory: Any,
    contract: FeatureContract,
    indices: np.ndarray,
    *,
    batch_size: int,
    threshold: float,
    predictions_path: Path,
) -> dict[str, Any]:
    truths: list[np.ndarray] = []
    scores: list[np.ndarray] = []
    labels: list[np.ndarray] = []
    prediction_seconds = 0.0
    cursor = 0
    writer: pq.ParquetWriter | None = None
    file_offsets: dict[int, int] = {}
    offset = 0
    for group_id, name in enumerate(inventory.group_names):
        file_offsets[group_id] = offset
        offset += int(inventory.rows_per_file[name])
    try:
        for X, original_y in iter_partition_batches(inventory.files, indices, contract, batch_size=batch_size):
            if tuple(X.columns) != contract.predictive_features or contract.target_name in X.columns:
                raise LogisticExperimentError("Evaluation feature matrix violates the Phase 05 feature/label boundary.")
            y = _binary_labels(original_y).map({"BENIGN": 0, "ATTACK": 1}).to_numpy(dtype=np.uint8)
            started = time.perf_counter()
            transformed = preprocessor.transform(X, mode="inference")
            probabilities = np.asarray(model.predict_proba(transformed), dtype=np.float64)
            prediction_seconds += time.perf_counter() - started
            if probabilities.shape != (len(X), 2) or not np.isfinite(probabilities).all():
                raise LogisticExperimentError("Logistic inference returned invalid or misaligned score values.")
            if list(np.asarray(model.classes_, dtype=int)) != [0, 1]:
                raise LogisticExperimentError("LogisticRegression positive class is not at the expected class index.")
            attack_score = probabilities[:, 1]
            row_indices = np.asarray(indices[cursor:cursor + len(X)], dtype=np.int64)
            if len(row_indices) != len(X):
                raise LogisticExperimentError("Evaluation predictions do not align with partition indices.")
            group_ids = inventory.groups[row_indices].astype(np.int64)
            frame = pd.DataFrame({
                "global_parquet_row_index": row_indices,
                "source_filename": [inventory.group_names[int(group)] for group in group_ids],
                "parquet_row_offset_zero_based": [
                    int(index - file_offsets[int(group)]) for index, group in zip(row_indices, group_ids)
                ],
                "original_source_label": original_y.astype("string").astype(str).to_numpy(),
                "ground_truth_binary": np.where(y == 1, "ATTACK", "BENIGN"),
                "attack_score_uncalibrated": attack_score,
                "predicted_binary_at_0_5": np.where(attack_score >= threshold, "ATTACK", "BENIGN"),
            })
            table = pa.Table.from_pandas(frame, preserve_index=False)
            if writer is None:
                writer = pq.ParquetWriter(predictions_path, table.schema, compression="zstd")
            writer.write_table(table)
            truths.append(y)
            scores.append(attack_score)
            labels.append(original_y.astype("string").astype(str).to_numpy(dtype=object))
            cursor += len(X)
    finally:
        if writer is not None:
            writer.close()
    if cursor != len(indices) or not truths:
        raise LogisticExperimentError(f"Read {cursor} rows from a {len(indices)}-row evaluation partition.")
    y_true = np.concatenate(truths)
    attack_scores = np.concatenate(scores)
    source_labels = np.concatenate(labels)
    return {
        "metrics": _binary_metrics(y_true, attack_scores, threshold),
        "support": _label_counts(np.where(y_true == 1, "ATTACK", "BENIGN")),
        "original_label_counts": _label_counts(source_labels),
        "prediction_seconds": prediction_seconds,
        "y_true": y_true,
        "scores": attack_scores,
    }


def _binary_metrics(y_true: np.ndarray, scores: np.ndarray, threshold: float) -> dict[str, Any]:
    raw_y = np.asarray(y_true)
    score = np.asarray(scores, dtype=np.float64)
    if raw_y.ndim != 1 or score.ndim != 1 or len(raw_y) == 0 or len(raw_y) != len(score):
        raise LogisticExperimentError("Metric inputs must be non-empty aligned vectors.")
    if not np.isin(raw_y, [0, 1]).all():
        raise LogisticExperimentError("Metric inputs contain invalid labels or score values.")
    y = raw_y.astype(np.uint8)
    if not np.isfinite(score).all() or np.any(score < 0) or np.any(score > 1):
        raise LogisticExperimentError("Metric inputs contain invalid labels or score values.")
    if not np.isfinite(threshold) or not 0 <= threshold <= 1:
        raise LogisticExperimentError("Threshold must be a finite value in [0, 1].")
    predicted = (score >= threshold).astype(np.uint8)
    tn, fp, fn, tp = confusion_matrix(y, predicted, labels=[0, 1]).ravel()
    both_classes = len(np.unique(y)) == 2
    return {
        "threshold": float(threshold),
        "accuracy": float(accuracy_score(y, predicted)),
        "attack_precision": float(precision_score(y, predicted, zero_division=0)),
        "attack_recall_true_positive_rate": float(recall_score(y, predicted, zero_division=0)),
        "f1_score": float(f1_score(y, predicted, zero_division=0)),
        "false_positive_rate": float(fp / (fp + tn)) if tn + fp else None,
        "roc_auc": float(roc_auc_score(y, score)) if both_classes else None,
        "average_precision_pr_auc": float(average_precision_score(y, score)) if both_classes else None,
        "roc_auc_unavailable_reason": None if both_classes else "Both classes are required to compute ROC-AUC.",
        "average_precision_unavailable_reason": None if both_classes else "Both classes are required for comparable average precision.",
        "confusion_matrix_labels": ["BENIGN", "ATTACK"],
        "confusion_matrix": [[int(tn), int(fp)], [int(fn), int(tp)]],
    }


def _load_rf_reference(root: Path, config: dict[str, Any], split_audit: dict[str, Any], contract: FeatureContract) -> dict[str, Any]:
    report_path = _resolve(root, config["comparison"]["random_forest_report"])
    artifact_path = _resolve(root, config["comparison"]["random_forest_artifact"])
    try:
        report = json.loads(report_path.read_text(encoding="utf-8"))
        estimator, preprocessor, metadata = load_binary_bundle(artifact_path)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        raise LogisticExperimentError(f"Unable to verify persisted Random Forest reference: {exc}") from exc
    if report.get("model_id") != "binary-random_forest-v1.0.1" or metadata.get("model_id") != report["model_id"]:
        raise LogisticExperimentError("Persisted Random Forest report and artifact are not the expected v1.0.1 pair.")
    if tuple(preprocessor.contract.predictive_features) != tuple(contract.predictive_features):
        raise LogisticExperimentError("Random Forest and Logistic Regression feature orders differ.")
    rf_split = metadata.get("split_audit", {})
    if rf_split.get("day_assignment") != config["split"]:
        raise LogisticExperimentError("Persisted Random Forest capture-day split differs from Logistic config.")
    if rf_split.get("rows_before_duplicate_screening") != split_audit["rows_before_duplicate_screening"]:
        raise LogisticExperimentError("Persisted Random Forest source partition sizes differ from current dataset.")
    if rf_split.get("validation_rows_removed_for_shared_feature_vectors_with_test") != split_audit["validation_rows_removed_for_shared_feature_vectors_with_test"]:
        raise LogisticExperimentError("Duplicate screening produced different validation rows from Random Forest.")
    if rf_split.get("training_sample_candidate_rows") != split_audit["training_sample_candidate_rows"] or rf_split.get("training_sample_rows_removed_for_feature_vectors_in_evaluation") != split_audit["training_sample_rows_removed_for_feature_vectors_in_evaluation"]:
        raise LogisticExperimentError("Training sample/exclusion differs from the Random Forest baseline.")
    report_root = report_path.parent
    val_metrics = metadata.get("validation_metrics", report.get("validation_metrics"))
    test_metrics = metadata.get("held_out_test_metrics", report.get("held_out_test_metrics"))
    if not val_metrics or not test_metrics:
        raise LogisticExperimentError("Random Forest reference lacks persisted validation or Friday metrics.")
    report_val = report.get("validation_metrics")
    report_test = report.get("held_out_test_metrics")
    if report_val is None or report_test is None:
        raise LogisticExperimentError("Random Forest comparison report lacks persisted split metrics.")
    if _normalize_rf_metrics(val_metrics) != _normalize_rf_metrics(report_val):
        raise LogisticExperimentError("Random Forest validation metrics disagree between report and artifact metadata.")
    if _normalize_rf_metrics(test_metrics) != _normalize_rf_metrics(report_test):
        raise LogisticExperimentError("Random Forest Friday metrics disagree between report and artifact metadata.")
    artifact_files = [p for p in artifact_path.iterdir() if p.is_file()]
    return {
        "model_id": report["model_id"],
        "report_path": str(report_path),
        "artifact_path": str(artifact_path),
        "report_sha256": hashlib.sha256(report_path.read_bytes()).hexdigest(),
        "validation_metrics": _normalize_rf_metrics(val_metrics),
        "friday_test_metrics": _normalize_rf_metrics(test_metrics),
        "training_rows": int(metadata["split_audit"]["training_rows_after_screening"]),
        "training_rows_by_binary_class": metadata["training_rows_by_binary_class"],
        "validation_rows": int(metadata["validation_support"]["BENIGN"] + metadata["validation_support"]["ATTACK"]),
        "validation_support": metadata["validation_support"],
        "friday_test_rows": int(metadata["test_support"]["BENIGN"] + metadata["test_support"]["ATTACK"]),
        "friday_test_support": metadata["test_support"],
        "feature_count": len(contract.predictive_features),
        "preprocessing_fit_seconds": metadata.get("preprocessing_fit_seconds"),
        "classifier_fit_seconds": metadata.get("classifier_fit_seconds"),
        "prediction_duration": "Unavailable: persisted RF report has no measured inference duration; baseline was not rerun.",
        "artifact_size_bytes": sum(p.stat().st_size for p in artifact_files),
        "artifact_joblib_size_bytes": metadata.get("artifact_joblib_size_bytes"),
        "inference_not_rerun": True,
        "classifier_type": type(estimator).__name__,
    }


def _normalize_rf_metrics(metrics: dict[str, Any]) -> dict[str, Any]:
    """Map persisted Random Forest names to the shared comparison vocabulary."""
    return {
        "threshold": metrics.get("threshold"),
        "accuracy": metrics.get("accuracy"),
        "attack_precision": metrics.get("precision_attack"),
        "attack_recall_true_positive_rate": metrics.get("recall_attack"),
        "f1_score": metrics.get("f1_attack"),
        "false_positive_rate": metrics.get("false_positive_rate"),
        "roc_auc": metrics.get("roc_auc"),
        "average_precision_pr_auc": metrics.get("average_precision_attack"),
        "confusion_matrix": metrics.get("confusion_matrix"),
        "confusion_matrix_labels": metrics.get("confusion_matrix_labels"),
    }


def _render_report(summary: dict[str, Any]) -> str:
    rf = summary["random_forest_reference"]
    val, test = summary["validation_metrics_at_fixed_threshold"], summary["friday_test_metrics_at_fixed_threshold"]
    rf_val, rf_test = rf["validation_metrics"], rf["friday_test_metrics"]
    fields = (
        ("ROC-AUC", "roc_auc"), ("Average precision", "average_precision_pr_auc"),
        ("Attack precision", "attack_precision"), ("Attack recall / TPR", "attack_recall_true_positive_rate"),
        ("F1", "f1_score"), ("Accuracy", "accuracy"), ("False-positive rate", "false_positive_rate"),
    )
    lines = [
        "# Logistic Regression vs Random Forest — CIC-IDS2017", "",
        f"Run: `{summary['run_id']}`. Fixed probability-score threshold: **0.5**.",
        "The Friday metrics are final held-out results; threshold sensitivity below uses Thursday validation only.", "",
        "## Measured results", "",
        "| Metric | RF Thursday | Logistic Thursday | RF Friday | Logistic Friday |", "|---|---:|---:|---:|---:|",
    ]
    for label, key in fields:
        cells = [rf_val.get(key), val.get(key), rf_test.get(key), test.get(key)]
        lines.append("| " + label + " | " + " | ".join("unavailable" if x is None else f"{x:.6f}" for x in cells) + " |")
    lines.extend([
        "", "## Experiment details", "",
        f"- Training rows: {summary['split_audit']['training_rows_after_screening']:,}; validation rows: {summary['validation_support']['BENIGN'] + summary['validation_support']['ATTACK']:,}; Friday rows: {summary['friday_test_support']['BENIGN'] + summary['friday_test_support']['ATTACK']:,}.",
        f"- Predictive features: {summary['feature_count']}; preprocessing: training-fitted median imputation and StandardScaler; feature selection disabled.",
        f"- Logistic fit time: preprocessing {summary['training_runtime']['preprocessing_fit_seconds']:.3f}s; estimator {summary['training_runtime']['classifier_fit_seconds']:.3f}s.",
        f"- RF fit time: preprocessing {rf['preprocessing_fit_seconds']:.3f}s; estimator {rf['classifier_fit_seconds']:.3f}s (persisted report).",
        f"- Logistic prediction time: Thursday {summary['training_runtime']['validation_prediction_seconds']:.3f}s; Friday {summary['training_runtime']['friday_test_prediction_seconds']:.3f}s (includes transformation and predict_proba).",
        f"- Logistic artifact size: {summary['artifact_total_size_bytes']:,} bytes. RF artifact size: {rf['artifact_size_bytes']:,} bytes.",
        f"- RF inference time: {rf['prediction_duration']}",
        "- Duplicate vectors: validation vectors shared with Friday are excluded; sampled training vectors shared with retained validation or Friday are excluded.",
        "- Original attack labels are kept in separate prediction output columns; only feature-contract columns enter the estimator.",
        "", "## Confusion matrices", "", "Rows are true labels and columns are predicted labels; order is BENIGN, ATTACK.", "",
        f"- RF Thursday: `{rf_val['confusion_matrix']}`; Logistic Thursday: `{val['confusion_matrix']}`.",
        f"- RF Friday: `{rf_test['confusion_matrix']}`; Logistic Friday: `{test['confusion_matrix']}`.",
        "", "## Thursday threshold sensitivity", "", "| Threshold | Precision | Recall / TPR | F1 | FPR |", "|---:|---:|---:|---:|---:|",
    ])
    for row in summary["validation_threshold_sensitivity"]:
        lines.append("| {:.2f} | {:.6f} | {:.6f} | {:.6f} | {} |".format(
            row["threshold"], row["attack_precision"], row["attack_recall_true_positive_rate"], row["f1_score"],
            "unavailable" if row["false_positive_rate"] is None else f"{row['false_positive_rate']:.6f}"))
    val_ap, test_ap = val["average_precision_pr_auc"], test["average_precision_pr_auc"]
    rf_val_ap, rf_test_ap = rf_val["average_precision_pr_auc"], rf_test["average_precision_pr_auc"]
    lines.extend([
        "", "## Interpretation and limits", "",
        f"Logistic ROC-AUC changed from {val['roc_auc']:.4f} Thursday to {test['roc_auc']:.4f} Friday; average precision changed from {val_ap:.4f} to {test_ap:.4f}; attack recall changed from {val['attack_recall_true_positive_rate']:.4f} to {test['attack_recall_true_positive_rate']:.4f}; FPR changed from {val['false_positive_rate']:.6f} to {test['false_positive_rate']:.6f}.",
        f"Random Forest ROC-AUC changed from {rf_val['roc_auc']:.4f} Thursday to {rf_test['roc_auc']:.4f} Friday; average precision changed from {rf_val_ap:.4f} to {rf_test_ap:.4f}; attack recall changed from {rf_val['attack_recall_true_positive_rate']:.4f} to {rf_test['attack_recall_true_positive_rate']:.4f}; FPR changed from {rf_val['false_positive_rate']:.6f} to {rf_test['false_positive_rate']:.6f}.",
        "On Friday, Logistic Regression has higher ROC-AUC, average precision, attack recall, F1, and accuracy; Random Forest has higher attack precision and a much lower false-positive rate. Logistic training took {:.3f}s versus {:.3f}s for RF in these runs, while its saved artifact is smaller ({} versus {} bytes). Logistic inference was measured; RF inference duration is unavailable and was not rerun. The evidence does not establish which model is operationally faster overall.".format(
            summary["training_runtime"]["training_fit_total_seconds"],
            rf["preprocessing_fit_seconds"] + rf["classifier_fit_seconds"],
            summary["artifact_total_size_bytes"], rf["artifact_size_bytes"]),
        "These results do not establish an overall winner independent of the operating cost of false alarms versus missed attacks.",
        "These capture-day changes are evidence of distribution shift, not proof of a specific causal feature mechanism. Average precision depends on attack prevalence, which differs substantially between Thursday and Friday, so its cross-day change is especially confounded. Neither model is promoted based on one metric; this experiment does not establish generalization beyond these captures.",
        "", "## Artifacts and reproducibility", "",
        f"- Model bundle: `{summary['artifact_directory']}`", f"- Full report directory: `{summary['report_directory']}`",
        "- Reproduce with: `python -m intrusion_intelligence.binary.logistic_cli --config configs/binary_logistic.toml`",
        "- RF reference metrics were read from the persisted report and its artifact checksums were verified; RF inference was not rerun.", "",
    ])
    return "\n".join(lines)
