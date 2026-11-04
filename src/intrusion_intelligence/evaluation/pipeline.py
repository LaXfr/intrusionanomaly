"""Reproducible Phase 11 evaluation over saved project evidence."""

from __future__ import annotations

import json
import platform
import sys
import tomllib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
import sklearn

from intrusion_intelligence.evaluation.audit import classify_evidence
from intrusion_intelligence.evaluation.benchmark import benchmark_warm_inference
from intrusion_intelligence.evaluation.metrics import binary_calibration, binary_metrics, threshold_metrics
from intrusion_intelligence.evaluation.robustness import run_input_stress
from intrusion_intelligence.evaluation.uncertainty import cluster_bootstrap_interval
from intrusion_intelligence.explainability.model_registry import load_explainable_models
from intrusion_intelligence.feature_engineering import FeatureContract


def _read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(_json_safe(value), indent=2, ensure_ascii=False, allow_nan=False) + "\n", encoding="utf-8")


def _json_safe(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(item) for item in value]
    if isinstance(value, np.ndarray):
        return _json_safe(value.tolist())
    if isinstance(value, np.generic):
        return _json_safe(value.item())
    if isinstance(value, float) and not np.isfinite(value):
        return None
    return value


def _status(state: str, reason: str, **details: Any) -> dict[str, Any]:
    return {"status": state, "reason": reason, **details}


def run_evaluation(config_path: str | Path) -> Path:
    """Build a dated evaluation bundle; existing test results remain marked reused."""
    config_path = Path(config_path).resolve()
    root = config_path.parent.parent
    config = tomllib.loads(config_path.read_text(encoding="utf-8"))
    inputs = {name: root / path for name, path in config["inputs"].items()}
    analysis = config["analysis"]
    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out = root / config["reports"]["directory"] / run_id
    figure_dir = root / config["reports"]["figure_directory"] / run_id
    benchmark_dir = root / config["reports"]["benchmark_directory"] / run_id
    out.mkdir(parents=True, exist_ok=False)
    contract = FeatureContract.from_file(root / "configs/feature_schema.json")

    # Load saved evidence and establish provenance without presenting reused results as fresh.
    binary_rf = _read_json(inputs["binary_rf_report"])
    binary_lr_dir = inputs["binary_logistic_directory"]
    multiclass_dir = root / "reports/evaluation/multiclass/20261103T134128Z"
    multiclass_run = _read_json(root / "reports/experiments/multiclass/20261103T134128Z/experiment_summary.json")
    multiclass_rf = _read_json(multiclass_dir / "random_forest_held_out_test_metrics.json")
    multiclass_classes = pd.read_csv(multiclass_dir / "random_forest_held_out_test_per_class.csv").to_dict(orient="records")
    anomaly = _read_json(root / "reports/evaluation/anomaly_detection/20261103T141439Z/anomaly_evaluation_summary.json")
    anomaly_raw = anomaly["test_metrics"][anomaly["default_operating_point"]]
    anomaly_test_metrics = {**anomaly_raw, "precision": anomaly_raw["attack_precision"], "recall": anomaly_raw["attack_recall"],
        "f1": anomaly_raw["attack_f1"], "average_precision": anomaly_raw["average_precision"],
        "target_validation_fpr": anomaly.get("calibration", {}).get("operating_points", {}).get(anomaly["default_operating_point"], {}).get("achieved_validation_fpr")}
    lr_test = pd.read_parquet(binary_lr_dir / "predictions_friday_test.parquet")
    lr_val = pd.read_parquet(binary_lr_dir / "predictions_validation.parquet")
    score_name = "attack_score_uncalibrated"
    label_name = "ground_truth_binary"
    val_y = lr_val[label_name].eq("ATTACK").astype(int).to_numpy()
    val_score = lr_val[score_name].to_numpy(dtype=float)
    test_y = lr_test[label_name].eq("ATTACK").astype(int).to_numpy()
    test_score = lr_test[score_name].to_numpy(dtype=float)
    binary_lr = {
        "model_id": "binary-logistic_regression-v1.0.2",
        "positive_class": "ATTACK",
        "validation_evidence": classify_evidence(partition="validation", used_for_selection=True, results_inspected=True),
        "previous_test_evidence": classify_evidence(partition="test", used_for_selection=True, results_inspected=True, reused_by_later_phase=True),
        "validation_metrics_at_0_5": binary_metrics(val_y, val_score, threshold=0.5),
        "previous_test_metrics_at_0_5": binary_metrics(test_y, test_score, threshold=0.5),
        "validation_threshold_sensitivity": threshold_metrics(val_y, val_score, analysis["thresholds"]),
        "validation_calibration": binary_calibration(val_y, val_score, bins=analysis["calibration_bins"]),
        "previous_test_calibration_descriptive_only": binary_calibration(test_y, test_score, bins=analysis["calibration_bins"]),
        "threshold_selection": "0.5 persisted before the current reanalysis; threshold grid is descriptive and is not selected here.",
    }
    _write_json(out / "binary_scorecard.json", {"random_forest_saved_metrics": binary_rf, "logistic_regression_reanalysis": binary_lr,
        "xgboost": _status("not_trained", "No XGBoost model artifact or trained-model report is available.")})

    # Binary capture-file analysis from persisted Logistic Regression predictions.
    by_capture = []
    for source, frame in lr_test.groupby("source_filename", sort=True):
        m = binary_metrics(frame[label_name].eq("ATTACK").astype(int), frame[score_name], threshold=0.5)
        by_capture.append({"source_filename": source, **m})

    _write_json(out / "binary_capture_breakdown.json", {"evidence": binary_lr["previous_test_evidence"], "groups": by_capture})
    multiclass = {
        "model_id": multiclass_rf.get("model_id", "multiclass-random_forest-v1.0.0"),
        "evidence": classify_evidence(partition="held_out_test", used_for_selection=True, results_inspected=True, reused_by_later_phase=True),
        "split_strategy": multiclass_run.get("split", {}).get("strategy", "stratified row split"),
        "metrics": multiclass_rf, "per_class": multiclass_classes,
        "class_mapping": multiclass_run.get("dataset_validation", {}).get("class_labels", []),
        "logistic_regression": _status("metrics_available", "Saved validation results are present; no held-out probability/prediction file is available for uniform reanalysis.", artifact="multiclass-logistic_regression-v1.0.0"),
        "group_aware_split": _status("not_feasible", "Each attack category occurs in a single capture file, so a class-complete capture-group split cannot be constructed."),
        "probability_calibration": _status("not_evaluated", "No saved held-out class probability matrix is available."),
    }
    _write_json(out / "multiclass_scorecard.json", multiclass)

    anomaly_result = {
        "model_id": "isolation-forest-v1.0.0", "evidence": classify_evidence(partition="test", used_for_selection=True, results_inspected=True, reused_by_later_phase=True),
        "training_integrity": {"benign_only_training": True, "benign_only_preprocessor_fit": True,
            "threshold_calibration_population": "Thursday benign validation", "score_orientation": "higher is more anomalous",
            "caveat": "Based on persisted run configuration and reports; not independently reconstructed from training row IDs."},
        "test_metrics": anomaly_test_metrics,
        "per_attack_category": pd.read_csv(root / "reports/evaluation/anomaly_detection/20261103T141439Z/false_negative_by_attack_category.csv").to_dict(orient="records"),
        "threshold_sensitivity": pd.read_csv(root / "reports/evaluation/anomaly_detection/20261103T141439Z/threshold_sensitivity.csv").to_dict(orient="records"),
    }
    _write_json(out / "anomaly_scorecard.json", anomaly_result)

    # Versioned artifact inventory, including actual load checks against the current contract.
    models, _ = load_explainable_models(root / "configs/explainability.toml", contract=contract)
    artifact_inventory = [{"registry_key": key, "model_id": model.model_id, "family": model.family,
        "version": model.model_version, "artifact_directory": str(model.artifact_directory.relative_to(root)),
        "artifact_loadable": True, "preprocessor_fitted": bool(getattr(model.preprocessor, "is_fitted_", False)),
        "input_feature_count": len(model.metadata["input_feature_names"]), "transformed_feature_count": len(model.feature_names)} for key, model in models.items()]
    version_inventory = []
    for metadata_path in sorted(root.glob("models/**/metadata.json")):
        metadata = _read_json(metadata_path)
        version_inventory.append({"metadata_path": str(metadata_path.relative_to(root)), "model_id": metadata.get("model_id"), "artifact_version": metadata.get("artifact_version")})
    _write_json(out / "evaluation_inventory.json", {"dataset": "CIC-IDS2017", "dataset_rows": 2_830_743,
        "predictive_feature_count": len(contract.predictive_features), "class_count": 15,
        "trained_artifacts_loadable": artifact_inventory, "all_versioned_metadata": version_inventory,
        "implementation_only_or_missing": {"xgboost": "not installed and no artifact", "external_datasets": "not present; no downloads performed"},
        "fresh_independent_test": _status("unavailable", "Existing Thursday/Friday and Phase 07 held-out partitions were inspected and reused in previous phase reports."),
        "evidence_policy": "All old test partitions are labeled previously inspected; this run is reproducible reanalysis, not a fresh independent test."})

    binary_split = binary_rf.get("split_audit", {})
    multi_split = _read_json(multiclass_dir / "split_audit.json")
    anomaly_split = _read_json(root / "reports/evaluation/anomaly_detection/20261103T141439Z/split_audit.json")
    leakage = {
        "binary": {"split_strategy": binary_split.get("strategy"), "source_files_disjoint": binary_split.get("source_files_are_disjoint"),
            "same_feature_vectors_after_documented_screening": binary_split.get("feature_vector_cross_partition_overlap_after_screening"),
            "validation_rows_removed_for_test_overlap": binary_split.get("validation_rows_removed_for_shared_feature_vectors_with_test"),
            "train_rows_removed_for_eval_overlap": binary_split.get("training_sample_rows_removed_for_feature_vectors_in_evaluation"),
            "target_and_metadata_exclusion": "Contract excludes target and provenance metadata; saved model input names match the feature contract.",
            "threshold_selection": binary_split.get("decision_threshold")},
        "multiclass": multi_split, "anomaly": anomaly_split,
        "known_duplicate_caveat": "Anomaly split audit reports 28,644 cross-partition duplicate feature-vector groups (132,348 rows) and 633 conflicting-label groups. Repeated predictive information is a leakage risk but does not alone establish target leakage.",
        "preprocessing": "Persisted bundles load with matching fitted preprocessors; prior reports describe training-only fitting. Full row lineage cannot be reconstructed from current artifacts.",
        "test_governance": "Previously inspected test results; no fresh independent evaluation claim.",
    }
    _write_json(out / "leakage_audit.json", leakage)
    _write_json(out / "generalization.json", {
        "binary_capture_day_holdout": {"train_days": ["Monday", "Tuesday", "Wednesday"], "validation_days": ["Thursday"], "test_days": ["Friday"], "test_capture_files": 3,
            "result_status": "cross-group exploratory result; previously inspected; repeated/related flows remain possible"},
        "multiclass": {"strategy": multi_split.get("strategy", "stratified row split"), "capture_group_overlap": "source groups overlap between row partitions", "result_status": "not group-independent"},
        "anomaly": {"strategy": anomaly_split.get("strategy", "capture_day_holdout"), "cross_partition_duplicate_groups": 28644, "result_status": "cross-group exploratory result; previously inspected"},
        "temporal": _status("not_supported", "Original timestamps were removed during cleaning; source file/day metadata does not provide within-capture chronology."),
        "external": _status("unavailable", "CIC-IDS2018 and UNSW-NB15 are not present locally; downloads were not requested."),
    })
    _write_json(out / "feature_ablation.json", {"status": "utility_implemented_real_experiment_unavailable",
        "implemented_groups": ["full approved feature set", "ports removed where present", "protocol removed where present", "configured feature groups"],
        "current_contract": {"destination_port_present": "destination_port" in contract.predictive_features,
            "source_port_present": "source_port" in contract.predictive_features, "protocol_present": "protocol" in contract.predictive_features},
        "reason": "No untouched independent group remains for a defensible real-data ablation; the refit utility is available for a future reserved cohort.",
        "production_artifacts_modified": False})

    # Actual-model robustness and warm inference checks on a deterministic feature-only sample.
    friday = root / config["dataset"]["parquet_directory"] / "Friday-WorkingHours-Morning.pcap_ISCX.parquet"
    try:
        import pyarrow.parquet as pq
        parquet = pq.ParquetFile(friday)
        batch = next(parquet.iter_batches(batch_size=int(analysis["robustness_sample_size"]), columns=list(contract.predictive_features)))
        sample = batch.to_pandas().loc[:, list(contract.predictive_features)]
        stress_results = [run_input_stress(model, sample, contract) for model in models.values()]
        benchmark_results = [benchmark_warm_inference(model, sample, batch_sizes=analysis["benchmark_batch_sizes"], repeats=analysis["benchmark_repeats"]) for model in models.values()]
        _write_json(out / "robustness.json", {"synthetic_inputs": True, "actual_feature_sample": {"source_file": friday.name, "rows": len(sample), "labels_loaded": False}, "models": stress_results})
        _write_json(out / "performance_benchmark.json", {"environment": {"python": sys.version, "platform": platform.platform(), "scikit_learn": sklearn.__version__},
            "method": "Warm repeated preprocessing and estimator calls; medians; model loading excluded; 64 feature rows from saved capture parquet; no production throughput claim.", "models": benchmark_results})
        _write_json(benchmark_dir / "warm_inference.json", {"environment": {"python": sys.version, "platform": platform.platform(), "scikit_learn": sklearn.__version__}, "models": benchmark_results})
    except Exception as exc:
        _write_json(out / "robustness.json", {"status": "blocked_by_runtime_data_or_artifact_error", "error_type": type(exc).__name__, "error": str(exc)})
        _write_json(out / "performance_benchmark.json", {"status": "blocked_by_runtime_data_or_artifact_error", "error_type": type(exc).__name__, "error": str(exc)})

    _write_json(out / "calibration.json", {"binary_logistic_regression_validation": binary_lr["validation_calibration"],
        "binary_logistic_previous_test_descriptive_only": binary_lr["previous_test_calibration_descriptive_only"],
        "binary_random_forest": _status("unavailable", "No saved row-level Random Forest scores or probabilities."),
        "multiclass": _status("unavailable", "No saved held-out class probability matrix."),
        "anomaly": _status("not_probability", "Isolation Forest scores are anomaly ranks, not calibrated probabilities.")})
    ci = cluster_bootstrap_interval([0, 1], ["capture_a", "capture_b"], lambda values: float(np.mean(values)), iterations=500, random_seed=42, minimum_groups=8)
    _write_json(out / "confidence_intervals.json", {"status": "not_reliable", "reason": "Only three Friday capture groups are represented and row dependence/duplicate flows undermine row bootstrap; group-aware intervals need more independent groups.", "cluster_bootstrap_implementation_smoke": ci})

    intelligence = _read_json(inputs["intelligence_summary"])
    _write_json(out / "threat_intelligence.json", {"evidence": "Previously inspected Friday sample; ground truth used to stratify a 3,000-flow evaluation sample and only for post-inference metrics.",
        "summary": intelligence, "limitations": ["Original timestamps and endpoint identities are unavailable, so real event correlation is not measurable.", "Threat score is a heuristic, not a calibrated compromise probability.", "No incident-level truth or independently adjudicated alerts are available."],
        "correlation_validation": "Synthetic fixtures in the Phase 09 suite cover relationship, boundary, missing-metadata, and deduplication rules."})

    explanation_report = _read_json(inputs["explainability_report"])
    diagnostics = []
    for line in inputs["explainability_records"].read_text(encoding="utf-8").splitlines():
        if line.strip():
            diagnostics.append(json.loads(line).get("additivity_diagnostic", {}))
    passed = sum(bool(item.get("passed", False)) for item in diagnostics)
    _write_json(out / "explainability_validation.json", {"report": explanation_report, "saved_record_count": len(diagnostics),
        "additivity_passed": passed, "additivity_failed_or_unmarked": len(diagnostics) - passed,
        "model_preprocessor_compatibility": "All configured bundles loaded and matched the feature contract.",
        "interpretation": "Additivity checks reconstruction for configured outputs and samples; it does not establish causal explanations."})

    _make_figures(figure_dir, val_y, val_score, multiclass_classes, by_capture, binary_lr["validation_threshold_sensitivity"],
        binary_lr["validation_calibration"]["reliability_bins"], anomaly_result["threshold_sensitivity"])
    scorecards = {"binary": "See binary_scorecard.json; ATTACK is positive; test results previously inspected.",
        "multiclass": "See multiclass_scorecard.json; 15-class row split; reused held-out rows.",
        "anomaly": "See anomaly_scorecard.json; benign-only Isolation Forest, reused Friday test.",
        "threat_intelligence": "Heuristic flow scoring metrics only; incident/correlation truth unavailable.",
        "explainability": f"{len(diagnostics)} saved records; {passed} additivity diagnostics passed."}
    _write_json(out / "component_scorecards.json", scorecards)
    statuses = {"inventory": "complete", "binary": "complete_from_saved_scores_and_reports", "multiclass": "complete_from_saved_reports", "anomaly": "complete_from_saved_reports",
        "leakage_and_split_audit": "complete_from_saved_audits", "robustness": "actual_model_synthetic_stress_attempted", "probability_calibration": "binary_logistic_only",
        "uncertainty": "limited_by_independent_group_count", "threat_intelligence": "flow_level_only", "explainability": "saved_record_consistency_audited",
        "performance": "actual_warm_sample_benchmark_attempted", "fresh_independent_test": "unavailable", "feature_ablation_real_data": "not_evaluated"}
    _write_json(out / "evaluation_status.json", {"run_id": run_id, "scope": "Phase 11 evaluation only", "overall_status": "completed_with_explicit_unavailable_components", "components": statuses})
    _write_report(out / "comprehensive_evaluation.md", run_id, binary_rf, binary_lr, multiclass, anomaly_result, leakage, scorecards, statuses)
    return out


def _make_figures(figure_dir: Path, y: np.ndarray, scores: np.ndarray, per_class: list[dict[str, Any]], captures: list[dict[str, Any]], thresholds: list[dict[str, Any]], calibration_bins: list[dict[str, Any]], anomaly_thresholds: list[dict[str, Any]]) -> None:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    from sklearn.metrics import PrecisionRecallDisplay, RocCurveDisplay
    figure_dir.mkdir(parents=True, exist_ok=True)
    fig, axes = plt.subplots(1, 2, figsize=(10, 4))
    RocCurveDisplay.from_predictions(y, scores, ax=axes[0], name="Logistic Regression")
    PrecisionRecallDisplay.from_predictions(y, scores, ax=axes[1], name="Logistic Regression")
    fig.suptitle("Binary Logistic Regression — previously inspected partitions")
    fig.tight_layout(); fig.savefig(figure_dir / "binary_validation_roc_pr.png", dpi=140); plt.close(fig)
    fig, ax = plt.subplots(figsize=(10, 4))
    ax.plot([r["threshold"] for r in thresholds], [r["recall"] for r in thresholds], label="Recall")
    ax.plot([r["threshold"] for r in thresholds], [r["precision"] for r in thresholds], label="Precision")
    ax.plot([r["threshold"] for r in thresholds], [r["false_positive_rate"] for r in thresholds], label="False-positive rate")
    ax.set(xlabel="Threshold", ylabel="Rate", title="Validation threshold sensitivity (descriptive)"); ax.legend(); fig.tight_layout(); fig.savefig(figure_dir / "binary_threshold_sensitivity.png", dpi=140); plt.close(fig)
    fig, ax = plt.subplots(figsize=(12, 4))
    ordered = sorted(per_class, key=lambda r: r.get("class_id", 0))
    ax.bar([r.get("label", r.get("class_name", str(r.get("class_id")))) for r in ordered], [float(r.get("recall", 0)) for r in ordered])
    ax.tick_params(axis="x", labelrotation=70); ax.set(ylabel="Recall", title="Multi-class RF per-class recall — reused test rows"); fig.tight_layout(); fig.savefig(figure_dir / "multiclass_per_class_recall.png", dpi=140); plt.close(fig)
    fig, ax = plt.subplots(figsize=(9, 4))
    ax.bar([r["source_filename"].replace(".pcap_ISCX.parquet", "") for r in captures], [r["recall"] for r in captures])
    ax.tick_params(axis="x", labelrotation=35); ax.set(ylabel="Attack recall", title="Binary Logistic Regression by Friday capture"); fig.tight_layout(); fig.savefig(figure_dir / "binary_capture_recall.png", dpi=140); plt.close(fig)
    fig, ax = plt.subplots(figsize=(5, 5))
    ax.plot([0, 1], [0, 1], linestyle="--", color="gray", label="Ideal")
    ax.plot([r["mean_score"] for r in calibration_bins], [r["observed_positive_rate"] for r in calibration_bins], marker="o", label="Logistic Regression")
    ax.set(xlabel="Mean predicted score", ylabel="Observed ATTACK rate", title="Validation reliability (uncalibrated score)", xlim=(0, 1), ylim=(0, 1)); ax.legend(); fig.tight_layout(); fig.savefig(figure_dir / "binary_validation_calibration.png", dpi=140); plt.close(fig)
    fig, ax = plt.subplots(figsize=(7, 4))
    ordered_thresholds = sorted(anomaly_thresholds, key=lambda r: float(r["target_fpr"]))
    ax.plot([r["target_fpr"] for r in ordered_thresholds], [r["validation_actual_fpr"] for r in ordered_thresholds], marker="o", label="Thursday benign validation")
    ax.plot([r["target_fpr"] for r in ordered_thresholds], [r["test_false_positive_rate"] for r in ordered_thresholds], marker="o", label="Friday previously inspected")
    ax.plot([0, max(float(r["target_fpr"]) for r in ordered_thresholds)], [0, max(float(r["target_fpr"]) for r in ordered_thresholds)], linestyle="--", color="gray", label="Target")
    ax.set(xlabel="Configured target FPR", ylabel="Observed false-positive rate", title="Isolation Forest operating-point sensitivity"); ax.legend(); fig.tight_layout(); fig.savefig(figure_dir / "anomaly_fpr_sensitivity.png", dpi=140); plt.close(fig)


def _write_report(path: Path, run_id: str, binary_rf: dict[str, Any], binary_lr: dict[str, Any], multiclass: dict[str, Any], anomaly: dict[str, Any], leakage: dict[str, Any], scorecards: dict[str, Any], statuses: dict[str, Any]) -> None:
    rf = binary_rf.get("held_out_test_metrics", {})
    lr = binary_lr["previous_test_metrics_at_0_5"]
    mc = multiclass["metrics"]
    am = anomaly["test_metrics"]
    lines = [f"# Comprehensive Model Evaluation — {run_id}", "", "This run reanalyzes saved Phase 06–10 evidence and performs bounded model input stress and warm inference checks. Existing Thursday/Friday/test results were previously inspected; no fresh independent test is available.", "",
        "## Binary classification", "", f"Random Forest (saved; ATTACK positive, threshold {rf.get('threshold', 0.5)}): ROC-AUC {rf.get('roc_auc')}, AP {rf.get('average_precision_attack')}, precision {rf.get('precision_attack')}, recall {rf.get('recall_attack')}, F1 {rf.get('f1_attack')}, FPR {rf.get('false_positive_rate')}.",
        f"Logistic Regression (recomputed from saved Friday predictions, threshold 0.5): ROC-AUC {lr['roc_auc']:.6f}, AP {lr['average_precision']:.6f}, precision {lr['precision']:.6f}, recall {lr['recall']:.6f}, F1 {lr['f1']:.6f}, FPR {lr['false_positive_rate']:.6f}.",
        "Both are previously inspected capture-day results, not fresh final test evidence.", "", "## Multi-class classification", "", f"Random Forest reused row-split test: accuracy {mc.get('accuracy')}, balanced accuracy {mc.get('balanced_accuracy')}, macro F1 {mc.get('macro_f1')}, weighted F1 {mc.get('weighted_f1')}. Attack classes are capture-file-specific and source groups overlap across the row split.", "",
        "## Anomaly detection", "", f"Isolation Forest reused Friday test at saved threshold {am.get('threshold')}: ROC-AUC {am.get('roc_auc')}, AP {am.get('average_precision')}, precision {am.get('precision')}, recall {am.get('recall')}, F1 {am.get('f1')}, FPR {am.get('false_positive_rate')}. Higher score means more anomalous.", "",
        "## Leakage, generalization, and scope", "", f"Binary duplicate screening removed {leakage['binary'].get('validation_rows_removed_for_test_overlap')} validation rows and {leakage['binary'].get('train_rows_removed_for_eval_overlap')} candidate training rows. Anomaly audit reports 28,644 cross-partition duplicate groups and 633 conflicting-label groups. These are overlap risks, not proof of target leakage.",
        "Temporal analysis is unsupported because timestamps were removed. External data is unavailable locally. Cluster confidence intervals are withheld because the effective independent group count is too small. Real-data ablation is not run without a reserved cohort.", "",
        "## Component statuses", "", "| Component | Status |", "|---|---|", *[f"| {name.replace('_', ' ')} | {status} |" for name, status in statuses.items()], "",
        "## Artifacts", "", "Structured scorecards and audits are stored beside this report; figures are under `reports/figures/evaluation/` and timing measurements under `reports/benchmarks/`.", ""]
    path.write_text("\n".join(lines), encoding="utf-8")

