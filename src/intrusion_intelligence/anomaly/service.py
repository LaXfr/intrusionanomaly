"""End-to-end benign-baseline Isolation Forest experiment orchestration."""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
import json
import logging
from pathlib import Path
import time
from typing import Any

import numpy as np
import pandas as pd
import sklearn

from intrusion_intelligence.anomaly.artifacts import save_anomaly_bundle
from intrusion_intelligence.anomaly.calibration import calibrate_operating_points
from intrusion_intelligence.anomaly.config import load_anomaly_config
from intrusion_intelligence.anomaly.data import (
    AnomalyDataError,
    AnomalyDatasetInventory,
    capture_day_from_source,
    inspect_anomaly_dataset,
    validate_original_labels,
)
from intrusion_intelligence.anomaly.evaluation import evaluate_operating_point, per_attack_category_summary
from intrusion_intelligence.anomaly.inference import AnomalyPredictor
from intrusion_intelligence.anomaly.reporting import write_anomaly_reports
from intrusion_intelligence.anomaly.scoring import higher_is_more_anomalous
from intrusion_intelligence.anomaly.splitting import (
    AnomalySplit,
    audit_duplicate_feature_overlap,
    make_capture_day_split,
    select_benign_training_sample,
)
from intrusion_intelligence.anomaly.training import fit_isolation_forest
from intrusion_intelligence.feature_engineering import FeatureContract
from intrusion_intelligence.multiclass.data import collect_partition, iter_partition_batches
from intrusion_intelligence.preprocessing import build_preprocessor
from intrusion_intelligence.preprocessing.config import load_preprocessing_config

logger = logging.getLogger(__name__)


def run_anomaly_experiment(config_path: str | Path | None = None) -> dict[str, Any]:
    """Fit benign-only Isolation Forest, calibrate, evaluate, and save outputs."""
    config = load_anomaly_config(config_path) if config_path else load_anomaly_config()
    model_destination = config["artifacts"]["model_directory"] / config["artifacts"]["model_version"]
    preprocessor_destination = (
        config["artifacts"]["preprocessor_directory"] / "anomaly" / config["artifacts"]["preprocessor_version"]
    )
    if model_destination.exists() or preprocessor_destination.exists():
        raise FileExistsError(
            "Configured anomaly artifact version already exists. Choose unused model and preprocessor versions; "
            "existing artifacts are never overwritten."
        )
    contract = FeatureContract.from_file(config["dataset"]["feature_schema"])
    if config["dataset"]["benign_label"] not in contract.target_values:
        raise AnomalyDataError("The configured benign label is not allowed by the Phase 05 feature contract.")
    inventory = inspect_anomaly_dataset(
        config["dataset"]["parquet_directory"],
        contract,
        benign_label=config["dataset"]["benign_label"],
    )
    split = make_capture_day_split(
        inventory,
        config["split"],
        benign_label=config["dataset"]["benign_label"],
    )
    benign_label = config["dataset"]["benign_label"]
    training_benign_count = split.audit["total_benign_training_rows"]
    validation_benign_count = split.audit["total_benign_validation_rows"]
    if training_benign_count < config["training"]["minimum_benign_training_rows"]:
        raise AnomalyDataError(
            f"Only {training_benign_count} benign training rows are available; configured minimum is "
            f"{config['training']['minimum_benign_training_rows']}."
        )
    if validation_benign_count < config["training"]["minimum_benign_validation_rows"]:
        raise AnomalyDataError(
            f"Only {validation_benign_count} benign validation rows are available; configured minimum is "
            f"{config['training']['minimum_benign_validation_rows']}."
        )

    duplicate_audit = audit_duplicate_feature_overlap(
        inventory,
        contract,
        split.day_to_partition,
        batch_size=config["training"]["batch_size"],
    )
    split.audit["duplicate_feature_audit"] = duplicate_audit
    selected_training_indices = select_benign_training_sample(
        split.train,
        inventory.labels,
        benign_label=benign_label,
        maximum_rows=config["training"]["max_benign_training_rows"],
        random_seed=config["split"]["random_seed"],
    )
    train_X, train_y = collect_partition(
        inventory.files,
        selected_training_indices,
        contract,
        batch_size=config["training"]["batch_size"],
    )
    train_labels = validate_original_labels(train_y.to_numpy(), contract.target_values, benign_label=benign_label)
    if not np.all(train_labels == benign_label):
        raise AnomalyDataError("Non-benign observations reached the anomaly training population.")

    preprocessing_config = load_preprocessing_config(config["dataset"]["preprocessing_config"])
    preprocessor = build_preprocessor(
        "anomaly",
        contract=contract,
        config=preprocessing_config,
        feature_selection=False,
    )
    preprocessing_fit_started = time.perf_counter()
    preprocessor.fit(train_X)
    preprocessing_fit_seconds = time.perf_counter() - preprocessing_fit_started
    transformed_train = preprocessor.transform(train_X, mode="training")
    estimator, effective_model_config, training_seconds = fit_isolation_forest(
        transformed_train,
        config["model"]["isolation_forest"],
    )
    del transformed_train, train_X, train_y, train_labels

    benign_validation_indices = split.validation[
        inventory.labels[split.validation] == benign_label
    ]
    validation_scores, validation_score_seconds = _score_benign_partition(
        inventory,
        benign_validation_indices,
        contract,
        preprocessor,
        estimator,
        batch_size=config["training"]["batch_size"],
    )
    if len(validation_scores) != validation_benign_count:
        raise AnomalyDataError("Benign validation score count does not match the split audit.")
    calibration = calibrate_operating_points(
        validation_scores,
        config["calibration"]["operating_points"],
        quantile_method=config["calibration"].get("quantile_method", "higher"),
        minimum_observations=config["training"]["minimum_benign_validation_rows"],
    )
    default_operating_point = config["calibration"]["default_operating_point"]
    default_threshold = float(calibration["operating_points"][default_operating_point]["threshold"])

    test_started = time.perf_counter()
    test_labels, test_scores, test_source_codes, error_samples, false_positive_source_counts = _score_test_partition(
        inventory,
        split.test,
        contract,
        preprocessor,
        estimator,
        default_threshold=default_threshold,
        batch_size=config["training"]["batch_size"],
        max_error_sample_rows=config["reports"]["error_feature_sample_rows"],
        random_seed=config["split"]["random_seed"],
    )
    test_score_seconds = time.perf_counter() - test_started
    test_labels = validate_original_labels(test_labels, contract.target_values, benign_label=benign_label)
    if len(test_labels) != len(split.test) or len(test_scores) != len(test_labels):
        raise AnomalyDataError("Held-out test labels and anomaly scores are not aligned.")

    test_metrics = {
        point_id: evaluate_operating_point(
            test_labels,
            test_scores,
            point["threshold"],
            allowed_labels=contract.target_values,
            benign_label=benign_label,
        )
        for point_id, point in calibration["operating_points"].items()
    }
    per_attack_rows = per_attack_category_summary(
        test_labels,
        test_scores,
        default_threshold,
        allowed_labels=contract.target_values,
        benign_label=benign_label,
    )
    sensitivity_rows = _sensitivity_rows(calibration, test_metrics)
    false_positive_by_source = _false_positive_summary(
        inventory,
        test_labels,
        test_scores,
        test_source_codes,
        default_threshold,
        false_positive_source_counts,
    )
    error_feature_medians = _error_feature_medians(error_samples)

    run_id = _new_run_id(config)
    evaluation_dir = config["reports"]["evaluation_directory"] / run_id
    figure_dir = config["reports"]["figure_directory"] / run_id
    experiment_dir = config["reports"]["experiment_directory"] / run_id
    experiment_dir.mkdir(parents=True, exist_ok=False)
    (experiment_dir / "configuration.json").write_text(
        json.dumps(config, ensure_ascii=False, indent=2, default=_json_default) + "\n",
        encoding="utf-8",
    )
    preparation_report = inventory.preparation_report()
    evaluation_dir.mkdir(parents=True, exist_ok=False)
    (evaluation_dir / "benign_data_preparation.json").write_text(
        json.dumps(preparation_report, ensure_ascii=False, indent=2, default=_json_default) + "\n",
        encoding="utf-8",
    )
    (evaluation_dir / "split_audit.json").write_text(
        json.dumps(split.audit, ensure_ascii=False, indent=2, default=_json_default) + "\n",
        encoding="utf-8",
    )

    model_metadata = {
        "default_operating_point": default_operating_point,
        "model_configuration": effective_model_config,
        "training_population": {
            "fit_population": "BENIGN only",
            "capture_days": sorted(config["split"]["train_days"]),
            "benign_training_rows_available": int(training_benign_count),
            "benign_training_rows_used": int(len(selected_training_indices)),
            "training_sample_seed": int(config["split"]["random_seed"]),
            "threshold_calibration_labels_used": False,
            "test_labels_used_for_model_or_threshold_selection": False,
        },
        "preprocessing_fit_population": "BENIGN training sample only",
        "preprocessing_fit_seconds": float(preprocessing_fit_seconds),
        "training_seconds": float(training_seconds),
        "training_score_method": "IsolationForest.score_samples",
        "calibration_summary": calibration,
        "validation_benign_scoring_seconds": float(validation_score_seconds),
        "dataset_rows": int(len(inventory.labels)),
        "training_capture_groups": sorted(config["split"]["train_days"]),
        "seed": int(config["split"]["random_seed"]),
        "library_versions": {"scikit_learn": sklearn.__version__},
    }
    model_path, preprocessor_path = save_anomaly_bundle(
        estimator,
        preprocessor,
        model_root=config["artifacts"]["model_directory"],
        preprocessor_root=config["artifacts"]["preprocessor_directory"],
        model_version=config["artifacts"]["model_version"],
        preprocessor_version=config["artifacts"]["preprocessor_version"],
        metadata=model_metadata,
        calibration=calibration,
    )
    model_size = (model_path / "model.joblib").stat().st_size
    preprocessor_size = (preprocessor_path / "preprocessor.joblib").stat().st_size
    predictor = AnomalyPredictor(model_path)
    first_test_batch = _first_feature_batch(
        inventory,
        split.test,
        contract,
        batch_size=config["training"]["batch_size"],
        maximum_rows=10,
    )
    smoke = predictor.predict(first_test_batch)
    smoke_path = evaluation_dir / "prediction_interface_smoke.json"
    smoke.head(10).to_json(smoke_path, orient="records", indent=2)

    summary: dict[str, Any] = {
        "run_id": run_id,
        "experiment_status": "completed",
        "created_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "dataset_rows": int(len(inventory.labels)),
        "class_counts": inventory.class_counts,
        "benign_training_rows": int(training_benign_count),
        "training_sample_rows": int(len(selected_training_indices)),
        "benign_validation_rows": int(len(validation_scores)),
        "test_rows": int(len(test_labels)),
        "test_benign_rows": int(np.count_nonzero(test_labels == benign_label)),
        "test_attack_rows": int(np.count_nonzero(test_labels != benign_label)),
        "feature_count": len(contract.predictive_features),
        "feature_schema_version": contract.schema_version,
        "split": split.audit,
        "duplicate_audit": duplicate_audit,
        "preprocessing_profile": preprocessor.preprocessing_metadata(),
        "preprocessing_fit_seconds": float(preprocessing_fit_seconds),
        "model_configuration": effective_model_config,
        "training_time_seconds": float(training_seconds),
        "validation_benign_scoring_seconds": float(validation_score_seconds),
        "test_prediction_time_seconds": float(test_score_seconds),
        "model_size_bytes": int(model_size),
        "preprocessor_size_bytes": int(preprocessor_size),
        "default_operating_point": default_operating_point,
        "calibration": calibration,
        "test_metrics": test_metrics,
        "per_attack_category": per_attack_rows,
        "false_positive_by_source_file": false_positive_by_source,
        "error_feature_medians": error_feature_medians,
        "artifacts": {
            "model": str(model_path),
            "preprocessor": str(preprocessor_path),
            "model_id": predictor.metadata["model_id"],
            "preprocessor_version": predictor.metadata["preprocessor_version"],
        },
        "prediction_interface_smoke": {
            "rows": int(len(smoke)),
            "status": "passed",
            "output": str(smoke_path),
        },
        "library_versions": {"scikit_learn": sklearn.__version__},
    }
    outputs = write_anomaly_reports(
        evaluation_dir,
        figure_dir,
        summary=summary,
        calibration=calibration,
        per_attack_rows=per_attack_rows,
        sensitivity_rows=sensitivity_rows,
        false_positive_by_source=false_positive_by_source,
        error_feature_medians=error_feature_medians,
        validation_benign_scores=validation_scores,
        test_labels=test_labels,
        test_scores=test_scores,
        threshold=default_threshold,
        allowed_labels=contract.target_values,
    )
    summary["outputs"] = {name: str(path) for name, path in outputs.items()}
    (experiment_dir / "experiment_summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2, default=_json_default) + "\n",
        encoding="utf-8",
    )
    logger.info("Completed anomaly experiment %s", run_id)
    return summary


def _score_benign_partition(
    inventory: AnomalyDatasetInventory,
    indices: np.ndarray,
    contract: FeatureContract,
    preprocessor: Any,
    estimator: Any,
    *,
    batch_size: int,
) -> tuple[np.ndarray, float]:
    scores: list[np.ndarray] = []
    started = time.perf_counter()
    for X, labels in iter_partition_batches(inventory.files, indices, contract, batch_size=batch_size):
        label_values = validate_original_labels(labels.to_numpy(), contract.target_values)
        benign_mask = label_values == "BENIGN"
        if not benign_mask.any():
            continue
        transformed = preprocessor.transform(X.loc[benign_mask], mode="inference")
        _, anomaly_scores = higher_is_more_anomalous(estimator, transformed)
        scores.append(anomaly_scores)
    if not scores:
        raise AnomalyDataError("No benign validation scores were generated.")
    return np.concatenate(scores), float(time.perf_counter() - started)


def _score_test_partition(
    inventory: AnomalyDatasetInventory,
    indices: np.ndarray,
    contract: FeatureContract,
    preprocessor: Any,
    estimator: Any,
    *,
    default_threshold: float,
    batch_size: int,
    max_error_sample_rows: int,
    random_seed: int,
) -> tuple[np.ndarray, np.ndarray, np.ndarray, dict[str, pd.DataFrame], Counter[str]]:
    score_parts: list[np.ndarray] = []
    label_parts: list[np.ndarray] = []
    source_code_parts: list[np.ndarray] = []
    reservoir = {"false_positive": pd.DataFrame(), "false_negative": pd.DataFrame()}
    priorities = {"false_positive": np.empty(0), "false_negative": np.empty(0)}
    fp_source_counts: Counter[str] = Counter()
    rng = np.random.default_rng(random_seed)
    rows_seen = 0
    for X, labels in iter_partition_batches(inventory.files, indices, contract, batch_size=batch_size):
        label_values = validate_original_labels(labels.to_numpy(), contract.target_values)
        transformed = preprocessor.transform(X, mode="inference")
        _, scores = higher_is_more_anomalous(estimator, transformed)
        batch_indices = indices[rows_seen : rows_seen + len(labels)]
        source_codes = inventory.source_file_codes[batch_indices]
        predicted_anomaly = scores > default_threshold
        benign_mask = label_values == "BENIGN"
        fp_mask = benign_mask & predicted_anomaly
        fn_mask = (~benign_mask) & (~predicted_anomaly)
        for code in np.unique(source_codes[fp_mask]):
            fp_source_counts[inventory.source_files[int(code)]] += int(np.count_nonzero(fp_mask & (source_codes == code)))
        _update_frame_reservoir(reservoir, priorities, "false_positive", X.loc[fp_mask], max_error_sample_rows, rng)
        _update_frame_reservoir(reservoir, priorities, "false_negative", X.loc[fn_mask], max_error_sample_rows, rng)
        score_parts.append(scores)
        label_parts.append(label_values)
        source_code_parts.append(source_codes)
        rows_seen += len(labels)
    if rows_seen != len(indices):
        raise AnomalyDataError(f"Scored {rows_seen} test rows, expected {len(indices)}.")
    return (
        np.concatenate(label_parts),
        np.concatenate(score_parts),
        np.concatenate(source_code_parts),
        reservoir,
        fp_source_counts,
    )


def _update_frame_reservoir(
    reservoirs: dict[str, pd.DataFrame],
    priorities: dict[str, np.ndarray],
    name: str,
    rows: pd.DataFrame,
    limit: int,
    rng: np.random.Generator,
) -> None:
    if rows.empty or limit <= 0:
        return
    current = reservoirs[name]
    scores = np.concatenate([priorities[name], rng.random(len(rows))])
    combined = pd.concat([current, rows], ignore_index=True)
    if len(combined) > limit:
        chosen = np.argpartition(scores, limit - 1)[:limit]
        combined = combined.iloc[chosen].reset_index(drop=True)
        scores = scores[chosen]
    reservoirs[name] = combined.reset_index(drop=True)
    priorities[name] = scores


def _sensitivity_rows(calibration: dict[str, Any], test_metrics: dict[str, Any]) -> list[dict[str, Any]]:
    records = []
    for point_id, point in calibration["operating_points"].items():
        metric = test_metrics[point_id]
        records.append(
            {
                "operating_point": point_id,
                "target_fpr": point["target_fpr"],
                "threshold": point["threshold"],
                "validation_actual_fpr": point["achieved_validation_fpr"],
                "test_false_positive_rate": metric["false_positive_rate"],
                "test_attack_recall": metric["attack_recall"],
                "test_attack_precision": metric["attack_precision"],
                "test_attack_f1": metric["attack_f1"],
                "test_false_negative_rate": metric["false_negative_rate"],
            }
        )
    return records


def _false_positive_summary(
    inventory: AnomalyDatasetInventory,
    labels: np.ndarray,
    scores: np.ndarray,
    source_codes: np.ndarray,
    threshold: float,
    false_positive_counts: Counter[str],
) -> list[dict[str, Any]]:
    records = []
    benign = labels == "BENIGN"
    predicted = scores > threshold
    present_codes = np.unique(source_codes)
    for code in present_codes:
        source = inventory.source_files[int(code)]
        selected = (source_codes == code) & benign
        benign_count = int(np.count_nonzero(selected))
        fp_count = int(false_positive_counts.get(source, 0))
        selected_scores = scores[selected]
        records.append(
            {
                "source_file": source,
                "capture_day": capture_day_from_source(source),
                "benign_test_rows": benign_count,
                "false_positives": fp_count,
                "false_positive_rate": fp_count / benign_count if benign_count else None,
                "median_benign_score": float(np.median(selected_scores)) if benign_count else None,
                "mean_benign_score": float(np.mean(selected_scores)) if benign_count else None,
                "benign_rows_above_threshold": int(np.count_nonzero(selected & predicted)),
            }
        )
    return records


def _error_feature_medians(samples: dict[str, pd.DataFrame]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for error_type, frame in samples.items():
        if frame.empty:
            continue
        medians = frame.median(numeric_only=True)
        rows.extend(
            {"error_type": error_type, "sample_rows": int(len(frame)), "feature": feature, "median": float(value)}
            for feature, value in medians.items()
        )
    return rows


def _first_feature_batch(
    inventory: AnomalyDatasetInventory,
    indices: np.ndarray,
    contract: FeatureContract,
    *,
    batch_size: int,
    maximum_rows: int,
) -> pd.DataFrame:
    for features, _labels in iter_partition_batches(inventory.files, indices, contract, batch_size=batch_size):
        return features.head(maximum_rows).copy()
    raise AnomalyDataError("Held-out test partition contains no features for inference smoke testing.")


def _new_run_id(config: dict[str, Any]) -> str:
    base = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    identifier = base
    counter = 1
    while any(
        (config["reports"][key] / identifier).exists()
        for key in ("evaluation_directory", "figure_directory", "experiment_directory")
    ):
        counter += 1
        identifier = f"{base}-{counter}"
    return identifier


def _json_default(value: Any) -> Any:
    if isinstance(value, np.generic):
        return value.item()
    if isinstance(value, np.ndarray):
        return value.tolist()
    if isinstance(value, Path):
        return str(value)
    raise TypeError(f"Cannot serialize {type(value).__name__} to JSON.")
