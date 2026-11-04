"""Machine-readable anomaly evaluation reports and reproducible figures."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.metrics import precision_recall_curve, roc_curve


def write_anomaly_reports(
    evaluation_directory: str | Path,
    figure_directory: str | Path,
    *,
    summary: dict[str, Any],
    calibration: dict[str, Any],
    per_attack_rows: list[dict[str, Any]],
    sensitivity_rows: list[dict[str, Any]],
    false_positive_by_source: list[dict[str, Any]],
    error_feature_medians: list[dict[str, Any]],
    validation_benign_scores: np.ndarray,
    test_labels: np.ndarray,
    test_scores: np.ndarray,
    threshold: float,
    allowed_labels: tuple[str, ...],
) -> dict[str, Path]:
    """Write actual-run summaries, tables, a human report, and figures."""
    evaluation = Path(evaluation_directory)
    figures = Path(figure_directory)
    evaluation.mkdir(parents=True, exist_ok=True)
    figures.mkdir(parents=True, exist_ok=True)
    outputs = {
        "summary": evaluation / "anomaly_evaluation_summary.json",
        "calibration": evaluation / "threshold_calibration.json",
        "per_attack": evaluation / "per_attack_category.csv",
        "false_negatives": evaluation / "false_negative_by_attack_category.csv",
        "sensitivity": evaluation / "threshold_sensitivity.csv",
        "false_positive_groups": evaluation / "false_positive_by_source_file.csv",
        "error_feature_medians": evaluation / "error_feature_medians.csv",
        "error_analysis": evaluation / "error_analysis.json",
        "confusion_matrix": evaluation / "test_confusion_matrix.csv",
        "model_comparison": evaluation / "model_comparison.csv",
        "report": evaluation / "anomaly_detection_report.md",
    }
    outputs["summary"].write_text(json.dumps(summary, ensure_ascii=False, indent=2, default=_json_default) + "\n", encoding="utf-8")
    outputs["calibration"].write_text(json.dumps(calibration, ensure_ascii=False, indent=2, default=_json_default) + "\n", encoding="utf-8")
    pd.DataFrame(per_attack_rows).to_csv(outputs["per_attack"], index=False, encoding="utf-8")
    false_negative_rows = [
        {
            "original_label": row["original_label"],
            "test_support": row["test_support"],
            "false_negatives": row["classified_as_normal"],
            "false_negative_rate": (row["classified_as_normal"] / row["test_support"]) if row["test_support"] else None,
            "mean_anomaly_score": row["mean_anomaly_score"],
            "status": row["status"],
        }
        for row in per_attack_rows
    ]
    pd.DataFrame(false_negative_rows).to_csv(outputs["false_negatives"], index=False, encoding="utf-8")
    pd.DataFrame(sensitivity_rows).to_csv(outputs["sensitivity"], index=False, encoding="utf-8")
    pd.DataFrame(false_positive_by_source).to_csv(outputs["false_positive_groups"], index=False, encoding="utf-8")
    pd.DataFrame(error_feature_medians).to_csv(outputs["error_feature_medians"], index=False, encoding="utf-8")
    default_metric = summary["test_metrics"][summary["default_operating_point"]]
    pd.DataFrame(
        default_metric["confusion_matrix"],
        index=default_metric["confusion_matrix_labels"],
        columns=["predicted_normal", "predicted_anomalous"],
    ).to_csv(outputs["confusion_matrix"], index_label="actual_class", encoding="utf-8")
    outputs["error_analysis"].write_text(
        json.dumps(
            {
                "false_positive_by_source_file": false_positive_by_source,
                "false_negative_by_attack_category": false_negative_rows,
                "feature_median_sample_rows": {
                    row["error_type"]: row["sample_rows"] for row in error_feature_medians
                },
                "raw_identifiers_included": False,
            },
            ensure_ascii=False,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    comparison = pd.DataFrame([_comparison_row(summary)])
    comparison.to_csv(outputs["model_comparison"], index=False, encoding="utf-8")
    figure_paths = _write_figures(
        figures,
        calibration=calibration,
        sensitivity_rows=sensitivity_rows,
        per_attack_rows=per_attack_rows,
        test_labels=test_labels,
        test_scores=test_scores,
        threshold=threshold,
        allowed_labels=allowed_labels,
        validation_benign_scores=validation_benign_scores,
    )
    outputs.update(figure_paths)
    outputs["report"].write_text(
        _markdown_report(summary, calibration, per_attack_rows, sensitivity_rows, false_positive_by_source),
        encoding="utf-8",
    )
    return outputs


def _write_figures(
    directory: Path,
    *,
    calibration: dict[str, Any],
    sensitivity_rows: list[dict[str, Any]],
    per_attack_rows: list[dict[str, Any]],
    test_labels: np.ndarray,
    test_scores: np.ndarray,
    threshold: float,
    allowed_labels: tuple[str, ...],
    validation_benign_scores: np.ndarray,
) -> dict[str, Path]:
    outputs: dict[str, Path] = {}
    operating_points = calibration["operating_points"]
    fig, ax = plt.subplots(figsize=(11, 6))
    ax.hist(validation_benign_scores, bins=100, color="#3572A5", alpha=0.8, log=True)
    for point_id, point in operating_points.items():
        ax.axvline(point["threshold"], label=f"{point_id}; actual validation FPR={point['achieved_validation_fpr']:.3%}")
    ax.set(title="Benign validation anomaly scores and frozen thresholds", xlabel="Anomaly score (higher is more anomalous)", ylabel="Count (log scale)")
    ax.legend(fontsize=8)
    outputs["validation_scores_figure"] = _save_figure(fig, directory / "benign_validation_scores_thresholds.png")

    sensitivity = pd.DataFrame(sensitivity_rows)
    fig, ax = plt.subplots(figsize=(8, 6))
    ax.plot(sensitivity["target_fpr"], sensitivity["test_false_positive_rate"], "o-", label="Test FPR")
    ax.plot(sensitivity["target_fpr"], sensitivity["test_attack_recall"], "s-", label="Test attack recall")
    ax.set_xscale("log")
    ax.set_ylim(0, 1.02)
    ax.set(title="Threshold sensitivity from benign validation quantiles", xlabel="Configured benign validation target FPR", ylabel="Rate")
    ax.grid(True, alpha=0.25)
    ax.legend()
    outputs["sensitivity_figure"] = _save_figure(fig, directory / "threshold_sensitivity.png")

    truth = (test_labels != "BENIGN").astype(np.uint8)
    predictions = (test_scores > threshold).astype(np.uint8)
    cm = np.array([
        [np.count_nonzero((truth == 0) & (predictions == 0)), np.count_nonzero((truth == 0) & (predictions == 1))],
        [np.count_nonzero((truth == 1) & (predictions == 0)), np.count_nonzero((truth == 1) & (predictions == 1))],
    ])
    fig, ax = plt.subplots(figsize=(6, 5))
    image = ax.imshow(cm, cmap="Blues")
    ax.set_xticks([0, 1], labels=["NORMAL", "ANOMALOUS"])
    ax.set_yticks([0, 1], labels=["BENIGN", "ATTACK"])
    ax.set(title="Held-out test confusion matrix", xlabel="Predicted", ylabel="Evaluation truth")
    for (row, column), value in np.ndenumerate(cm):
        ax.text(column, row, f"{value:,}", ha="center", va="center", color="black")
    fig.colorbar(image, ax=ax, fraction=0.046)
    outputs["confusion_figure"] = _save_figure(fig, directory / "held_out_test_confusion_matrix.png")

    if len(np.unique(truth)) == 2:
        fpr, tpr, _ = roc_curve(truth, test_scores)
        precision, recall, _ = precision_recall_curve(truth, test_scores)
        fig, ax = plt.subplots(figsize=(7, 6))
        ax.plot(fpr, tpr, label="Isolation Forest")
        ax.plot([0, 1], [0, 1], linestyle="--", color="gray", linewidth=1)
        ax.set(title="Held-out test ROC curve", xlabel="False-positive rate", ylabel="Attack recall", xlim=(0, 1), ylim=(0, 1.02))
        ax.legend()
        outputs["roc_figure"] = _save_figure(fig, directory / "held_out_test_roc_curve.png")
        fig, ax = plt.subplots(figsize=(7, 6))
        ax.plot(recall, precision, label="Isolation Forest")
        ax.set(title="Held-out test precision-recall curve", xlabel="Attack recall", ylabel="Anomalous prediction precision", xlim=(0, 1), ylim=(0, 1.02))
        ax.legend()
        outputs["pr_figure"] = _save_figure(fig, directory / "held_out_test_precision_recall_curve.png")

    represented = [row for row in per_attack_rows if row["test_support"]]
    if represented:
        ordered = sorted(represented, key=lambda row: row["detection_recall"] if row["detection_recall"] is not None else -1)
        fig, ax = plt.subplots(figsize=(10, max(4, len(ordered) * 0.45)))
        ax.barh([row["original_label"] for row in ordered], [row["detection_recall"] for row in ordered], color="#C35B45")
        ax.set(xlim=(0, 1), title="Attack-category detection recall at the configured operating point", xlabel="Recall")
        ax.grid(axis="x", alpha=0.2)
        outputs["per_attack_recall_figure"] = _save_figure(fig, directory / "per_attack_detection_recall.png")
    categories = [label for label in allowed_labels if np.any(test_labels == label)]
    values = [test_scores[test_labels == label] for label in categories]
    if values:
        fig, ax = plt.subplots(figsize=(max(10, len(categories) * 0.8), 6))
        ax.boxplot(values, tick_labels=categories, showfliers=False, whis=(5, 95))
        ax.axhline(threshold, label="Default calibrated threshold", color="#B22222", linestyle="--")
        ax.set(title="Held-out test anomaly score by original label", ylabel="Anomaly score (higher is more anomalous)")
        ax.tick_params(axis="x", labelrotation=60)
        ax.legend()
        outputs["score_by_category_figure"] = _save_figure(fig, directory / "test_score_by_original_category.png")
    return outputs


def _save_figure(figure: Any, path: Path) -> Path:
    figure.tight_layout()
    figure.savefig(path, dpi=150, bbox_inches="tight")
    plt.close(figure)
    return path


def _comparison_row(summary: dict[str, Any]) -> dict[str, Any]:
    metric = summary["test_metrics"][summary["default_operating_point"]]
    return {
        "model": "IsolationForest",
        "implementation_status": "trained_and_evaluated",
        "training_time_seconds": summary["training_time_seconds"],
        "test_prediction_time_seconds": summary["test_prediction_time_seconds"],
        "validation_fpr": summary["calibration"]["operating_points"][summary["default_operating_point"]]["achieved_validation_fpr"],
        "test_fpr": metric["false_positive_rate"],
        "attack_recall": metric["attack_recall"],
        "precision": metric["attack_precision"],
        "f1": metric["attack_f1"],
        "roc_auc": metric["roc_auc"],
        "average_precision": metric["average_precision"],
        "model_size_bytes": summary["model_size_bytes"],
        "OneClassSVM_status": "not_implemented: RBF kernel scaling is not justified for the 1.4M-row benign baseline",
        "LocalOutlierFactor_status": "not_implemented: neighbor index memory and full novelty query cost are not justified for this baseline",
    }


def _markdown_report(
    summary: dict[str, Any],
    calibration: dict[str, Any],
    per_attack: list[dict[str, Any]],
    sensitivity: list[dict[str, Any]],
    false_positive_groups: list[dict[str, Any]],
) -> str:
    default = summary["default_operating_point"]
    selected_calibration = calibration["operating_points"][default]
    metrics = summary["test_metrics"][default]
    table = _markdown_table(per_attack) if per_attack else "No attack categories were available."
    sensitivity_table = _markdown_table(sensitivity) if sensitivity else "No sensitivity values."
    fp_table = _markdown_table(false_positive_groups) if false_positive_groups else "No false positives were observed."
    test_days = ", ".join(summary["split"]["partition_days"]["test"])
    linked_components = summary["duplicate_audit"]["capture_days_connected_by_duplicate_feature_groups"]
    return f"""# CIC-IDS2017 benign-baseline anomaly detection

## Experiment and data split

- Run ID: `{summary['run_id']}`.
- Training is unsupervised and uses only BENIGN observations from {', '.join(summary['split']['partition_days']['train'])}.
- Preprocessing is fit on the same benign-only training sample; the model receives only transformed feature values.
- Thresholds are calibrated using only BENIGN validation scores from {', '.join(summary['split']['partition_days']['validation'])}. Validation attack labels are not passed to calibration.
- Final labelled evaluation uses the held-out {test_days} capture days. The configured threshold is frozen before test scoring.
- Capture-day and source-file groups are disjoint. However, {summary['duplicate_audit']['repeated_feature_vector_groups_crossing_partitions']:,} repeated feature-vector groups cross partitions ({summary['duplicate_audit']['rows_in_groups_crossing_partitions']:,} rows in those groups). Duplicate-feature links connect {sum(len(component) for component in linked_components)} capture days into {len(linked_components)} connected component(s), so a joint capture-day- and duplicate-disjoint three-way split is impossible in this extract.

## Benign baseline and Isolation Forest

- Full benign population in training days: {summary['benign_training_rows']:,}.
- Benign observations used to fit preprocessing and Isolation Forest: {summary['training_sample_rows']:,}.
- Benign validation observations used for threshold calibration: {summary['benign_validation_rows']:,}.
- Test rows: {summary['test_rows']:,}, including {summary['test_benign_rows']:,} BENIGN and {summary['test_attack_rows']:,} attack observations.
- Isolation Forest configuration: `{json.dumps(summary['model_configuration'], ensure_ascii=False)}`.
- Training time: {summary['training_time_seconds']:.2f} s; test transform and scoring time: {summary['test_prediction_time_seconds']:.2f} s.
- Score convention: raw `score_samples` is higher for inliers; the common anomaly score is its negation, so higher means more anomalous. It is not a probability of compromise.

## Threshold calibration

Default operating point `{default}` targets benign validation FPR {selected_calibration['target_fpr']:.3%}. Its empirical validation FPR was {selected_calibration['achieved_validation_fpr']:.3%} using {selected_calibration['benign_validation_observations']:,} benign validation scores. The decision rule is strictly `score > threshold`; ties are NORMAL. Threshold {selected_calibration['threshold']:.8f}; validation ties at threshold: {selected_calibration['threshold_tie_observations']:,}. This target is an operating configuration, not a guarantee for future traffic.

| Test metric | Result |
|---|---:|
| Attack precision | {_fmt(metrics['attack_precision'])} |
| Attack recall | {_fmt(metrics['attack_recall'])} |
| Attack F1 | {_fmt(metrics['attack_f1'])} |
| False-positive rate | {_fmt(metrics['false_positive_rate'])} |
| False-negative rate | {_fmt(metrics['false_negative_rate'])} |
| Specificity | {_fmt(metrics['specificity'])} |
| Balanced accuracy | {_fmt(metrics['balanced_accuracy'])} |
| Accuracy | {_fmt(metrics['accuracy'])} |
| ROC-AUC | {_fmt(metrics['roc_auc'])} |
| Average Precision | {_fmt(metrics['average_precision'])} |

## Per-attack-category analysis

{table}

Classes not observed in the {test_days} test partition are explicitly marked as unavailable in `per_attack_category.csv`; this capture-day split does not claim to evaluate every CIC-IDS2017 attack family.

## Threshold sensitivity

Every threshold below comes from a benign-validation upper quantile. Attack labels did not choose any threshold.

{sensitivity_table}

## False-positive investigation by source file

{fp_table}

Feature medians for bounded deterministic samples of false positives and false negatives are saved in `error_feature_medians.csv`. Reports omit raw record IDs and endpoints. A benign flow above threshold is unusual relative to the fitted baseline; it is not automatically malicious. A malicious flow below threshold resembles the observed benign baseline; it is not classified as benign by identity.

## Limitations

The files contain no timestamp, endpoints, Flow ID, protocol, or standalone source port. The {test_days} holdout evaluates only attack families present on those capture days. Repeated feature vectors cross the capture-day partitions, including some conflicting-label groups; this can make benchmark results optimistic and is reported rather than hidden. The {summary['training_sample_rows']:,}-row benign fit is a deterministic sample of the {summary['benign_training_rows']:,} available benign training rows. Isolation Forest identifies deviations from the available benign training sample, not attack identities, malicious intent, or guaranteed zero-day threats. Phase 06 binary classification was not completed before this phase. No Phase 09 threat scoring or alert integration is included.
"""


def _fmt(value: Any) -> str:
    return "undefined" if value is None else f"{float(value):.4f}"


def _markdown_table(records: list[dict[str, Any]]) -> str:
    """Render small report tables without an optional tabulate dependency."""
    columns = list(records[0])

    def cell(value: Any) -> str:
        if value is None:
            return ""
        if isinstance(value, (float, np.floating)):
            return f"{float(value):.4f}"
        return str(value).replace("|", "\\|").replace("\n", " ")

    lines = ["| " + " | ".join(columns) + " |", "| " + " | ".join("---" for _ in columns) + " |"]
    lines.extend("| " + " | ".join(cell(row.get(column)) for column in columns) + " |" for row in records)
    return "\n".join(lines)


def _json_default(value: Any) -> Any:
    if isinstance(value, np.generic):
        return value.item()
    if isinstance(value, np.ndarray):
        return value.tolist()
    if isinstance(value, Path):
        return str(value)
    raise TypeError(f"Cannot serialize {type(value).__name__} to JSON.")
