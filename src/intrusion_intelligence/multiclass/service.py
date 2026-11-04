"""Reproducible multi-class training, evaluation, persistence, and reporting."""

from __future__ import annotations

import gc
import json
import logging
import time
import warnings
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.exceptions import ConvergenceWarning
from sklearn.linear_model import LogisticRegression

from intrusion_intelligence.feature_engineering import FeatureContract
from intrusion_intelligence.multiclass.artifacts import save_model_bundle
from intrusion_intelligence.multiclass.config import load_multiclass_config
from intrusion_intelligence.multiclass.data import (
    DatasetInventory,
    collect_partition,
    inspect_parquet_dataset,
    iter_partition_batches,
)
from intrusion_intelligence.multiclass.evaluation import align_class_scores, evaluate_multiclass
from intrusion_intelligence.multiclass.inference import MultiClassPredictor
from intrusion_intelligence.multiclass.reporting import (
    write_distribution_outputs,
    write_evaluation_outputs,
    write_json,
    write_model_importance,
)
from intrusion_intelligence.multiclass.splitting import (
    DataSplit,
    make_three_way_split,
    stratified_training_sample,
)
from intrusion_intelligence.preprocessing import build_preprocessor, training_class_distribution

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class TrainedCandidate:
    """One fitted model and its independent preprocessing profile."""

    name: str
    model_id: str
    estimator: Any
    preprocessor: Any
    configuration: dict[str, Any]
    preprocessing_fit_seconds: float
    classifier_fit_seconds: float
    validation: dict[str, Any]
    prediction_seconds: float
    training_class_summary: dict[str, Any]
    warnings: list[str]


def run_multiclass_experiment(config_path: str | Path | None = None) -> dict[str, Any]:
    """Run a configured Phase 07 experiment against cleaned Parquet inputs."""
    config = load_multiclass_config(config_path) if config_path else load_multiclass_config()
    contract = FeatureContract.from_file(config["dataset"]["feature_schema"])
    inventory = inspect_parquet_dataset(
        config["dataset"]["parquet_directory"],
        contract,
        mapping_version=str(config["training"]["mapping_version"]),
    )
    taxonomy = inventory.taxonomy
    split_options = config["split"]
    split = make_three_way_split(
        inventory.labels,
        inventory.groups,
        train_fraction=float(split_options["train_fraction"]),
        validation_fraction=float(split_options["validation_fraction"]),
        test_fraction=float(split_options["test_fraction"]),
        random_seed=int(config["training"]["random_seed"]),
        strategy=str(split_options["strategy"]),
        allow_stratified_fallback=bool(split_options["allow_stratified_fallback"]),
        group_search_attempts=int(split_options["group_search_attempts"]),
    )
    _humanize_group_audit(split.audit, inventory.group_names)
    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    evaluation_directory = Path(config["reports"]["evaluation_directory"]) / run_id
    figure_directory = Path(config["reports"]["figure_directory"]) / run_id
    experiment_directory = Path(config["reports"]["experiment_directory"]) / run_id
    for directory in (evaluation_directory, figure_directory, experiment_directory):
        directory.mkdir(parents=True, exist_ok=False)

    distribution = inventory.distribution_records()
    source_distribution = _source_distribution_frame(inventory)
    write_distribution_outputs(
        distribution=distribution,
        source_distribution=source_distribution,
        split_audit=split.audit,
        evaluation_directory=evaluation_directory,
        figure_directory=figure_directory,
    )
    class_distribution_summary = _class_distribution_summary(distribution)
    train_sample_indices = stratified_training_sample(
        split.train,
        inventory.labels,
        maximum_rows=int(config["training"]["max_training_rows"]),
        random_seed=int(config["training"]["random_seed"]),
        retain_all_if_count_at_most=int(config["training"]["retain_all_class_rows_below"]),
    )
    y_train_full_ids = np.asarray(taxonomy.encode(inventory.labels[split.train]), dtype=np.int32)
    full_training_summary = training_class_distribution(y_train_full_ids, class_weight="balanced")
    full_training_summary["class_counts_by_label"] = {
        taxonomy.labels[int(class_id)]: count
        for class_id, count in full_training_summary["class_counts"].items()
    }
    full_training_summary["balanced_weights_by_label"] = {
        taxonomy.labels[int(class_id)]: weight
        for class_id, weight in (full_training_summary["class_weights"] or {}).items()
    }
    balanced_weights_by_id = {
        int(class_id): float(weight)
        for class_id, weight in (full_training_summary["class_weights"] or {}).items()
    }
    X_train, y_train = collect_partition(
        inventory.files,
        train_sample_indices,
        contract,
        batch_size=int(config["training"]["batch_size"]),
    )
    y_train_ids = np.asarray(taxonomy.encode(y_train), dtype=np.int32)
    if set(y_train_ids.tolist()) != set(range(len(taxonomy.labels))):
        missing = sorted(set(range(len(taxonomy.labels))) - set(y_train_ids.tolist()))
        raise ValueError(f"Training sample does not represent all supported classes: {missing}.")
    candidates: list[TrainedCandidate] = []
    enabled_models = [
        name
        for name in ("logistic_regression", "random_forest")
        if config["models"].get(name, {}).get("enabled", False)
    ]
    if not enabled_models:
        raise ValueError("No supported multi-class models are enabled.")
    for name in enabled_models:
        logger.info("Fitting %s on %s stratified training rows.", name, len(X_train))
        candidate = _fit_candidate(
            name,
            config["models"][name],
            X_train,
            y_train_ids,
            inventory,
            contract,
            split,
            config,
            full_training_summary,
            balanced_weights_by_id,
            evaluation_directory,
            figure_directory,
        )
        logger.info(
            "%s validation macro F1 %.5f, balanced accuracy %.5f.",
            name,
            candidate.validation["metrics"]["macro_f1"],
            candidate.validation["metrics"]["balanced_accuracy"],
        )
        candidates.append(candidate)
        gc.collect()

    selected = max(
        candidates,
        key=lambda item: (
            item.validation["metrics"]["macro_f1"],
            item.validation["metrics"]["balanced_accuracy"],
            item.name,
        ),
    )
    logger.info("Selected %s by validation macro F1; evaluating the held-out test once.", selected.name)
    test_result, test_seconds, y_test_ids, _, test_scores = _evaluate_partition(
        selected.estimator,
        selected.preprocessor,
        taxonomy,
        inventory,
        split.test,
        contract,
        batch_size=int(config["training"]["batch_size"]),
        partition="held_out_test",
    )
    selected_test = test_result
    write_evaluation_outputs(
        model_name=selected.name,
        partition="held_out_test",
        result=test_result,
        y_true=y_test_ids,
        scores=test_scores,
        taxonomy=taxonomy,
        evaluation_directory=evaluation_directory,
        figure_directory=figure_directory,
    )
    representative_errors = _representative_error_features(
        selected.estimator,
        selected.preprocessor,
        taxonomy,
        inventory,
        split.test,
        contract,
        selected_test["frequent_confusion_pairs"][:5],
        batch_size=int(config["training"]["batch_size"]),
        random_seed=int(config["training"]["random_seed"]),
    )
    write_json(evaluation_directory / "selected_test_error_feature_summaries.json", representative_errors)

    importance = write_model_importance(
        estimators={candidate.name: candidate.estimator for candidate in candidates},
        feature_names=selected.preprocessor.get_feature_names_out().tolist(),
        evaluation_directory=evaluation_directory,
        figure_directory=figure_directory,
    )
    comparison = _model_comparison(candidates, selected.name, selected_test, test_seconds)
    comparison.to_csv(evaluation_directory / "model_comparison.csv", index=False)
    write_json(evaluation_directory / "model_comparison.json", comparison.to_dict(orient="records"))

    artifact_paths: dict[str, str] = {}
    for candidate in candidates:
        artifact_metadata = {
            "training_configuration": candidate.configuration,
            "training_rows_full_partition": int(len(split.train)),
            "classifier_training_rows": int(len(train_sample_indices)),
            "training_sample_strategy": (
                "reproducible proportional allocation from training partition; all observations retained "
                "for classes with training support at or below retain_all_class_rows_below"
            ),
            "training_class_counts": candidate.training_class_summary["class_counts_by_label"],
            "class_weight_strategy": candidate.configuration.get("class_weight"),
            "class_weights": candidate.training_class_summary["balanced_weights_by_label"],
            "preprocessing_fit_seconds": candidate.preprocessing_fit_seconds,
            "classifier_fit_seconds": candidate.classifier_fit_seconds,
            "validation_metrics": candidate.validation["metrics"],
            "held_out_test_metrics": selected_test["metrics"] if candidate.name == selected.name else None,
            "test_partition_id": f"{run_id}-test" if candidate.name == selected.name else None,
            "split_audit": split.audit,
            "training_warnings": candidate.warnings,
        }
        artifact_path = save_model_bundle(
            candidate.estimator,
            candidate.preprocessor,
            taxonomy,
            config["artifacts"]["directory"],
            model_name=candidate.name,
            version=str(config["artifacts"]["version"]),
            metadata=artifact_metadata,
        )
        artifact_paths[candidate.name] = str(artifact_path)

    selected_artifact = artifact_paths[selected.name]
    predictor = MultiClassPredictor(selected_artifact)
    reload_smoke = predictor.predict(X_train.iloc[: min(5, len(X_train))])
    write_json(evaluation_directory / "prediction_interface_smoke.json", reload_smoke)

    xgboost_config = config["models"].get("xgboost", {})
    model_records = [
        {
            "model": "xgboost",
            "status": "unavailable",
            "reason": xgboost_config.get("reason", "XGBoost package is unavailable."),
            "validation_metrics": None,
            "held_out_test_metrics": None,
        }
    ]
    experiment_summary = {
        "run_id": run_id,
        "dataset": "CIC-IDS2017",
        "dataset_validation": {
            "file_count": len(inventory.files),
            "rows": int(len(inventory.labels)),
            "class_count": len(taxonomy.labels),
            "class_labels": list(taxonomy.labels),
            "benign_present": "BENIGN" in taxonomy.labels,
            "rows_per_source_file": inventory.rows_per_file,
            "class_distribution": distribution,
            "class_distribution_summary": class_distribution_summary,
        },
        "split_audit": split.audit,
        "evaluation_status": "exploratory_stratified_row_baseline_with_source_group_overlap",
        "models": [],
        "selected_by_validation_macro_f1": selected.name,
        "selected_held_out_test_metrics": selected_test["metrics"],
        "test_partition_id": f"{run_id}-test",
        "artifacts": artifact_paths,
        "reports": {
            "evaluation_directory": str(evaluation_directory),
            "figure_directory": str(figure_directory),
            "experiment_directory": str(experiment_directory),
        },
        "feature_importance": importance,
        "selected_test_error_feature_summaries": representative_errors,
        "limitations": [
            "Phase 06 binary classification remains not implemented or validated on this dataset.",
            "Source-file-disjoint three-way evaluation cannot represent all 15 classes because most attack labels occur in only one source file.",
            "The permitted stratified-row fallback has source-group overlap and likely duplicate-flow overlap; it is exploratory and not evidence of cross-capture generalization.",
            f"Classifiers used a stratified training-only subset of {len(train_sample_indices):,} rows from a {len(split.train):,}-row training partition.",
            "The real dataset has severe class imbalance and several classes have very small held-out test support.",
            "XGBoost is not installed and was not trained.",
        ],
    }
    for candidate in candidates:
        model_records.append(
            {
                "model": candidate.name,
                "status": "trained",
                "training_configuration": candidate.configuration,
                "training_rows": int(len(train_sample_indices)),
                "validation_metrics": candidate.validation["metrics"],
                "held_out_test_metrics": selected_test["metrics"] if candidate.name == selected.name else None,
                "preprocessing_fit_seconds": candidate.preprocessing_fit_seconds,
                "classifier_fit_seconds": candidate.classifier_fit_seconds,
                "validation_prediction_seconds": candidate.prediction_seconds,
                "held_out_test_prediction_seconds": test_seconds if candidate.name == selected.name else None,
                "warnings": candidate.warnings,
                "artifact_path": artifact_paths[candidate.name],
            }
        )
    experiment_summary["models"] = model_records
    write_json(experiment_directory / "experiment_summary.json", experiment_summary)
    write_json(experiment_directory / "configuration.json", _jsonable(config))
    report_path = evaluation_directory / "multiclass_classification_report.md"
    report_path.write_text(
        _render_markdown_report(
            run_id=run_id,
            inventory=inventory,
            distribution_summary=class_distribution_summary,
            split=split,
            candidates=candidates,
            selected=selected,
            test_metrics=selected_test["metrics"],
            test_seconds=test_seconds,
            artifact_paths=artifact_paths,
            xgboost_config=xgboost_config,
            report_directory=evaluation_directory,
            figure_directory=figure_directory,
        ),
        encoding="utf-8",
    )
    summary = {
        "run_id": run_id,
        "report": str(report_path),
        "experiment_summary": str(experiment_directory / "experiment_summary.json"),
        "evaluation_directory": str(evaluation_directory),
        "figure_directory": str(figure_directory),
        "selected_model": selected.name,
        "selected_artifact": selected_artifact,
        "validation_macro_f1": selected.validation["metrics"]["macro_f1"],
        "test_macro_f1": selected_test["metrics"]["macro_f1"],
        "test_balanced_accuracy": selected_test["metrics"]["balanced_accuracy"],
        "rows": int(len(inventory.labels)),
        "classes": len(taxonomy.labels),
    }
    write_json(evaluation_directory / "run_summary.json", summary)
    del X_train, y_train, y_train_ids, train_sample_indices, test_scores
    gc.collect()
    return summary


def _fit_candidate(
    name: str,
    model_config: dict[str, Any],
    X_train: pd.DataFrame,
    y_train_ids: np.ndarray,
    inventory: DatasetInventory,
    contract: FeatureContract,
    split: DataSplit,
    config: dict[str, Any],
    full_training_summary: dict[str, Any],
    balanced_weights_by_id: dict[int, float],
    evaluation_directory: Path,
    figure_directory: Path,
) -> TrainedCandidate:
    profile = str(model_config["profile"])
    preprocessor = build_preprocessor(profile, contract=contract)
    before_preprocess = time.perf_counter()
    preprocessor.fit(X_train)
    transformed = preprocessor.transform(X_train, mode="training")
    preprocessing_seconds = time.perf_counter() - before_preprocess
    estimator, estimator_config = _create_estimator(
        name,
        model_config,
        int(config["training"]["random_seed"]),
        balanced_weights_by_id,
    )
    caught: list[str] = []
    before_fit = time.perf_counter()
    with warnings.catch_warnings(record=True) as warning_records:
        warnings.simplefilter("always")
        estimator.fit(transformed, y_train_ids)
    fit_seconds = time.perf_counter() - before_fit
    caught = [f"{record.category.__name__}: {record.message}" for record in warning_records]
    if isinstance(estimator, LogisticRegression) and np.any(estimator.n_iter_ >= estimator.max_iter):
        caught.append(
            f"ConvergenceWarning: Logistic Regression reached max_iter={estimator.max_iter}; inspect coefficients and increase iterations before relying on this fit."
        )
    if caught:
        logger.warning("%s emitted training warnings: %s", name, caught)
    validation, prediction_seconds, validation_y_true, _, validation_scores = _evaluate_partition(
        estimator,
        preprocessor,
        inventory.taxonomy,
        inventory,
        split.validation,
        contract,
        batch_size=int(config["training"]["batch_size"]),
        partition="validation",
    )
    # Preserve evaluation diagnostics as files while keeping large score arrays transient.
    write_evaluation_outputs(
        model_name=name,
        partition="validation",
        result=validation,
        y_true=validation_y_true,
        scores=validation_scores,
        taxonomy=inventory.taxonomy,
        evaluation_directory=evaluation_directory,
        figure_directory=figure_directory,
    )
    del transformed, validation_scores
    gc.collect()
    train_summary = dict(full_training_summary)
    train_summary["sample_rows"] = int(len(y_train_ids))
    return TrainedCandidate(
        name=name,
        model_id=f"multiclass-{name}-v{config['artifacts']['version']}",
        estimator=estimator,
        preprocessor=preprocessor,
        configuration=estimator_config,
        preprocessing_fit_seconds=preprocessing_seconds,
        classifier_fit_seconds=fit_seconds,
        validation=validation,
        prediction_seconds=prediction_seconds,
        training_class_summary=train_summary,
        warnings=caught,
    )


def _create_estimator(
    name: str,
    model_config: dict[str, Any],
    random_seed: int,
    balanced_weights_by_id: dict[int, float],
) -> tuple[Any, dict[str, Any]]:
    weight_strategy = str(model_config.get("class_weight", "balanced"))
    weight_values: Any = balanced_weights_by_id if weight_strategy == "balanced" else weight_strategy
    if name == "logistic_regression":
        options = {
            "C": float(model_config["regularization_c"]),
            "solver": str(model_config["solver"]),
            "max_iter": int(model_config["max_iterations"]),
            "class_weight": weight_values,
            "random_state": random_seed,
        }
        return LogisticRegression(**options), {
            **options,
            "class_weight": weight_strategy,
            "class_weight_values_by_class_id": balanced_weights_by_id if weight_strategy == "balanced" else None,
            "multiclass_strategy": "multinomial default for lbfgs under installed Scikit-learn; multi_class parameter omitted",
        }
    if name == "random_forest":
        options = {
            "n_estimators": int(model_config["estimators"]),
            "max_depth": int(model_config["max_depth"]),
            "min_samples_split": int(model_config["min_samples_split"]),
            "min_samples_leaf": int(model_config["min_samples_leaf"]),
            "max_features": model_config["max_features"],
            "class_weight": weight_values,
            "random_state": random_seed,
            "n_jobs": int(model_config["n_jobs"]),
        }
        return RandomForestClassifier(**options), {
            **options,
            "class_weight": weight_strategy,
            "class_weight_values_by_class_id": balanced_weights_by_id if weight_strategy == "balanced" else None,
        }
    raise ValueError(f"Unsupported model name: {name!r}.")


def _evaluate_partition(
    estimator: Any,
    preprocessor: Any,
    taxonomy: Any,
    inventory: DatasetInventory,
    indices: np.ndarray,
    contract: FeatureContract,
    *,
    batch_size: int,
    partition: str,
) -> tuple[dict[str, Any], float, np.ndarray, np.ndarray, np.ndarray | None]:
    true_batches: list[np.ndarray] = []
    pred_batches: list[np.ndarray] = []
    score_batches: list[np.ndarray] = []
    start = time.perf_counter()
    for X_batch, y_batch in iter_partition_batches(
        inventory.files,
        indices,
        contract,
        batch_size=batch_size,
    ):
        transformed = preprocessor.transform(X_batch, mode="inference")
        prediction = np.asarray(estimator.predict(transformed), dtype=np.int64)
        true_batches.append(np.asarray(taxonomy.encode(y_batch), dtype=np.int64))
        pred_batches.append(prediction)
        if hasattr(estimator, "predict_proba"):
            raw_scores = estimator.predict_proba(transformed)
            score_batches.append(align_class_scores(raw_scores, estimator.classes_, taxonomy))
    prediction_seconds = time.perf_counter() - start
    y_true = np.concatenate(true_batches)
    y_pred = np.concatenate(pred_batches)
    scores = np.concatenate(score_batches) if score_batches else None
    result = evaluate_multiclass(
        y_true,
        y_pred,
        taxonomy,
        scores=scores,
        learned_class_ids=np.asarray(estimator.classes_, dtype=np.int64),
        partition=partition,
    )
    return result, prediction_seconds, y_true, y_pred, scores


def _source_distribution_frame(inventory: DatasetInventory) -> pd.DataFrame:
    rows = [
        {"source_file": source, "label": label, "count": count}
        for source, labels in inventory.class_source_counts.items()
        for label, count in labels.items()
    ]
    return pd.DataFrame(rows).sort_values(["source_file", "label"], ignore_index=True)


def _representative_error_features(
    estimator: Any,
    preprocessor: Any,
    taxonomy: Any,
    inventory: DatasetInventory,
    indices: np.ndarray,
    contract: FeatureContract,
    confusion_pairs: list[dict[str, Any]],
    *,
    batch_size: int,
    random_seed: int,
    error_sample_limit: int = 100,
    reference_sample_limit: int = 1000,
) -> list[dict[str, Any]]:
    """Summarize feature medians for sampled errors versus their true-class peers."""
    if not confusion_pairs:
        return []
    id_by_label = taxonomy.class_to_id
    selected_pairs = [
        (id_by_label[item["true_label"]], id_by_label[item["predicted_label"]], item)
        for item in confusion_pairs
        if item["true_label"] in id_by_label and item["predicted_label"] in id_by_label
    ]
    error_samples: dict[tuple[int, int], list[np.ndarray]] = { (true_id, pred_id): [] for true_id, pred_id, _ in selected_pairs }
    error_seen = {key: 0 for key in error_samples}
    reference_samples: dict[int, list[np.ndarray]] = {
        true_id: [] for true_id, _, _ in selected_pairs
    }
    reference_seen = {key: 0 for key in reference_samples}
    rng = np.random.default_rng(random_seed)
    for X_batch, y_batch in iter_partition_batches(
        inventory.files,
        indices,
        contract,
        batch_size=batch_size,
    ):
        transformed = preprocessor.transform(X_batch, mode="inference")
        predictions = np.asarray(estimator.predict(transformed), dtype=np.int64)
        truth = np.asarray(taxonomy.encode(y_batch), dtype=np.int64)
        numeric_values = X_batch.to_numpy(dtype=float, na_value=np.nan)
        for true_id in reference_samples:
            for row in numeric_values[truth == true_id]:
                seen = reference_seen[true_id] + 1
                reference_seen[true_id] = seen
                sample = reference_samples[true_id]
                if len(sample) < reference_sample_limit:
                    sample.append(row.copy())
                else:
                    replace_at = int(rng.integers(0, seen))
                    if replace_at < reference_sample_limit:
                        sample[replace_at] = row.copy()
        for true_id, pred_id, _ in selected_pairs:
            key = (true_id, pred_id)
            mask = (truth == true_id) & (predictions == pred_id)
            for row in numeric_values[mask]:
                seen = error_seen[key] + 1
                error_seen[key] = seen
                sample = error_samples[key]
                if len(sample) < error_sample_limit:
                    sample.append(row.copy())
                else:
                    replace_at = int(rng.integers(0, seen))
                    if replace_at < error_sample_limit:
                        sample[replace_at] = row.copy()
    summaries: list[dict[str, Any]] = []
    for true_id, pred_id, pair in selected_pairs:
        error_values = error_samples[(true_id, pred_id)]
        reference_values = reference_samples[true_id]
        if not error_values or not reference_values:
            continue
        error_medians = pd.DataFrame(error_values, columns=contract.predictive_features).median()
        reference_medians = pd.DataFrame(reference_values, columns=contract.predictive_features).median()
        differences = (error_medians - reference_medians).abs().dropna().sort_values(ascending=False)
        feature_summary = [
            {
                "feature": feature,
                "misclassified_sample_median": float(error_medians[feature]),
                "true_class_reference_median": float(reference_medians[feature]),
            }
            for feature in differences.head(10).index
        ]
        summaries.append(
            {
                **pair,
                "sample_method": "deterministic-seed reservoir sample of held-out rows; descriptive only",
                "misclassified_rows_summarized": len(error_values),
                "true_class_reference_rows_summarized": len(reference_values),
                "largest_median_feature_differences": feature_summary,
            }
        )
    return summaries


def _class_distribution_summary(records: list[dict[str, Any]]) -> dict[str, Any]:
    ordered = sorted(records, key=lambda row: row["count"])
    total = sum(row["count"] for row in records)
    return {
        "supported_classes": len(records),
        "total_observations": total,
        "majority_class": ordered[-1]["label"],
        "majority_count": ordered[-1]["count"],
        "minority_class": ordered[0]["label"],
        "minority_count": ordered[0]["count"],
        "majority_to_minority_ratio": ordered[-1]["count"] / ordered[0]["count"],
        "classes_below_100_rows": [row["label"] for row in ordered if row["count"] < 100],
        "classes_below_1000_rows": [row["label"] for row in ordered if row["count"] < 1000],
        "imbalance_interpretation": (
            "Accuracy and weighted F1 are dominated by frequent classes; macro F1 and balanced accuracy "
            "give minority classes more influence. Per-class recall and support must be reviewed together."
        ),
    }


def _model_comparison(
    candidates: list[TrainedCandidate],
    selected_name: str,
    test: dict[str, Any],
    test_seconds: float,
) -> pd.DataFrame:
    rows: list[dict[str, Any]] = []
    for candidate in candidates:
        metrics = candidate.validation["metrics"]
        selected = candidate.name == selected_name
        rows.append(
            {
                "model": candidate.name,
                "status": "trained",
                "validation_accuracy": metrics["accuracy"],
                "validation_balanced_accuracy": metrics["balanced_accuracy"],
                "validation_macro_precision": metrics["macro_precision"],
                "validation_macro_recall": metrics["macro_recall"],
                "validation_macro_f1": metrics["macro_f1"],
                "validation_weighted_precision": metrics["weighted_precision"],
                "validation_weighted_recall": metrics["weighted_recall"],
                "validation_weighted_f1": metrics["weighted_f1"],
                "validation_roc_auc_ovr_macro": metrics["multiclass_roc_auc_ovr_macro"],
                "validation_average_precision_macro": metrics["multiclass_average_precision_macro"],
                "preprocessing_fit_seconds": candidate.preprocessing_fit_seconds,
                "classifier_fit_seconds": candidate.classifier_fit_seconds,
                "validation_prediction_seconds": candidate.prediction_seconds,
                "held_out_test_macro_f1": test["metrics"]["macro_f1"] if selected else None,
                "held_out_test_balanced_accuracy": test["metrics"]["balanced_accuracy"] if selected else None,
                "held_out_test_prediction_seconds": test_seconds if selected else None,
                "selected_by_validation_macro_f1": selected,
            }
        )
    rows.append(
        {
            "model": "xgboost",
            "status": "unavailable_not_installed",
            "validation_accuracy": None,
            "validation_balanced_accuracy": None,
            "validation_macro_precision": None,
            "validation_macro_recall": None,
            "validation_macro_f1": None,
            "validation_weighted_precision": None,
            "validation_weighted_recall": None,
            "validation_weighted_f1": None,
            "validation_roc_auc_ovr_macro": None,
            "validation_average_precision_macro": None,
            "preprocessing_fit_seconds": None,
            "classifier_fit_seconds": None,
            "validation_prediction_seconds": None,
            "held_out_test_macro_f1": None,
            "held_out_test_balanced_accuracy": None,
            "held_out_test_prediction_seconds": None,
            "selected_by_validation_macro_f1": False,
        }
    )
    return pd.DataFrame(rows)


def _render_markdown_report(
    *,
    run_id: str,
    inventory: DatasetInventory,
    distribution_summary: dict[str, Any],
    split: DataSplit,
    candidates: list[TrainedCandidate],
    selected: TrainedCandidate,
    test_metrics: dict[str, Any],
    test_seconds: float,
    artifact_paths: dict[str, str],
    xgboost_config: dict[str, Any],
    report_directory: Path,
    figure_directory: Path,
) -> str:
    lines = [
        "# CIC-IDS2017 Multi-class Classification Report",
        "",
        f"**Run:** `{run_id}`  ",
        f"**Rows:** {len(inventory.labels):,}  ",
        f"**Supported labels:** {len(inventory.taxonomy.labels)}  ",
        f"**Split:** `{split.audit['used_strategy']}`  ",
        f"**Selected validation model:** `{selected.name}` by macro F1",
        "",
        "## Dataset and class imbalance",
        "",
        f"Majority class: `{distribution_summary['majority_class']}` ({distribution_summary['majority_count']:,}); "
        f"minority class: `{distribution_summary['minority_class']}` ({distribution_summary['minority_count']:,}); "
        f"majority-to-minority ratio: {distribution_summary['majority_to_minority_ratio']:,.1f}:1.",
        "",
        f"Classes below 100 rows: {', '.join(f'`{label}`' for label in distribution_summary['classes_below_100_rows']) or 'none'}.",
        "",
        "See `class_distribution.csv` and `class_distribution_by_source_file.csv`. The distribution chart uses a log scale because of the long tail.",
        "",
        "## Split integrity and limitations",
        "",
        f"Requested strategy: `{split.audit['requested_strategy']}`. Used strategy: `{split.audit['used_strategy']}`.",
        "",
        f"Group-aware reason: {split.audit.get('fallback_reason') or 'group-disjoint split succeeded'}",
        "",
        f"Group overlap: `{split.audit['group_overlaps']}`. The stratified-row fallback is exploratory only; related flows and source files cross partitions, so these metrics do not establish cross-capture generalization.",
        "",
        f"Full training partition: {split.audit['row_counts']['train']:,}; stratified training sample used by each classifier: {selected.training_class_summary['sample_rows']:,}; validation: {split.audit['row_counts']['validation']:,}; test: {split.audit['row_counts']['test']:,}.",
        "",
        "Phase 06 binary classification was not implemented or validated before this phase. No binary results or synthetic results are represented as real classification performance.",
        "",
        "## Validation comparison",
        "",
        "| Model | Accuracy | Balanced accuracy | Macro F1 | Weighted F1 | ROC-AUC OVR macro | Fit (s) | Predict validation (s) |",
        "|---|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for candidate in candidates:
        metric = candidate.validation["metrics"]
        lines.append(
            f"| {candidate.name} | {metric['accuracy']:.4f} | {metric['balanced_accuracy']:.4f} | "
            f"{metric['macro_f1']:.4f} | {metric['weighted_f1']:.4f} | "
            f"{_format_optional(metric['multiclass_roc_auc_ovr_macro'])} | "
            f"{candidate.classifier_fit_seconds:.2f} | {candidate.prediction_seconds:.2f} |"
        )
    minority_labels = set(distribution_summary["classes_below_1000_rows"])
    minority_scores = {
        candidate.name: [
            row["recall"]
            for row in candidate.validation["per_class"]
            if row["label"] in minority_labels and row["recall"] is not None
        ]
        for candidate in candidates
    }
    mean_minority_recall = {
        name: float(np.mean(values)) for name, values in minority_scores.items() if values
    }
    best_weighted = max(candidates, key=lambda item: item.validation["metrics"]["weighted_f1"])
    best_balanced = max(candidates, key=lambda item: item.validation["metrics"]["balanced_accuracy"])
    best_minority = max(mean_minority_recall, key=mean_minority_recall.get) if mean_minority_recall else None
    selected_lowest_recall = sorted(
        (
            row for row in selected.validation["per_class"]
            if row["recall"] is not None and row["support"] > 0
        ),
        key=lambda row: (row["recall"], row["support"], row["label"]),
    )[:5]
    lowest_recall_text = ", ".join(
        f"`{row['label']}` {row['recall']:.3f} (n={row['support']:,})"
        for row in selected_lowest_recall
    ) or "none"
    lines.extend(
        [
            f"| XGBoost | unavailable | unavailable | unavailable | unavailable | unavailable | — | — |",
            "",
            f"XGBoost was not trained: {xgboost_config.get('reason', 'not installed')}.",
            "",
            f"Validation summary: macro F1 leader `{selected.name}`; weighted F1 leader `{best_weighted.name}`; balanced-accuracy leader `{best_balanced.name}`; mean validation recall across classes below 1,000 total rows is "
            + (f"highest for `{best_minority}` ({mean_minority_recall[best_minority]:.4f})." if best_minority else "undefined."),
            f"Selected-model lowest validation recalls: {lowest_recall_text}.",
            "",
            "## Selected model held-out test results",
            "",
            f"Selected using validation macro F1 only: `{selected.name}`. Test prediction time: {test_seconds:.2f}s. Held-out test metrics were computed once after selection; a separate deterministic pass generated aggregate error-feature summaries without changing the model.",
            "",
            "| Metric | Held-out test result |",
            "|---|---:|",
        ]
    )
    for key in (
        "accuracy",
        "balanced_accuracy",
        "macro_precision",
        "macro_recall",
        "macro_f1",
        "weighted_precision",
        "weighted_recall",
        "weighted_f1",
        "multiclass_roc_auc_ovr_macro",
        "multiclass_average_precision_macro",
    ):
        lines.append(f"| {key} | {_format_optional(test_metrics.get(key))} |")
    test_per_class_path = report_directory / f"{selected.name}_held_out_test_per_class.csv"
    lines.extend(
        [
            "",
            f"Per-class metrics and confusion pairs are in `{test_per_class_path.name}` and `{selected.name}_held_out_test_confusion_pairs.csv`. Aggregate error-feature summaries are in `selected_test_error_feature_summaries.json`. Undefined precision/recall and classes unseen during training are explicitly marked in per-class output.",
            "",
            "## Interpretation and minority classes",
            "",
            "Macro F1 gives each represented class equal weight; weighted F1 follows class frequency. Balanced accuracy averages recall across represented classes. Accuracy can remain high when majority traffic dominates, so every attack class must be read with its support and recall.",
            "",
            "Classes below 100 full-data rows are not automatically removed. Their test support is small, making estimates unstable. The model has only the categories observed during training; low confidence is not an unknown-attack detector.",
            "",
            "## Feature importance and artifacts",
            "",
            "Random Forest importance is impurity-based; Logistic Regression importance is mean absolute coefficient magnitude across classes. Neither measure implies causation.",
            "",
        ]
    )
    for name, path in artifact_paths.items():
        lines.append(f"- `{name}` artifact: `{path}`")
    lines.extend(
        [
            "",
            f"Figures are under `{figure_directory}`. This row-stratified experiment is a research baseline, not a validated production or cross-capture classifier. Phase 11 remains responsible for broader system validation.",
            "",
        ]
    )
    return "\n".join(lines)


def _humanize_group_audit(audit: dict[str, Any], group_names: tuple[str, ...]) -> None:
    def resolve(value: str) -> str:
        try:
            index = int(value)
        except ValueError:
            return value
        return group_names[index] if 0 <= index < len(group_names) else value

    audit["all_source_groups"] = [resolve(value) for value in audit["all_source_groups"]]
    for overlap_name, values in audit["group_overlaps"].items():
        audit["group_overlaps"][overlap_name] = [resolve(value) for value in values]


def _format_optional(value: Any) -> str:
    return "undefined" if value is None or not np.isfinite(value) else f"{float(value):.4f}"


def _jsonable(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(item) for item in value]
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, np.generic):
        return value.item()
    return value
