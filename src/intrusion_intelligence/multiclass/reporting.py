"""Machine-readable and visual outputs for multi-class experiments."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.metrics import average_precision_score, precision_recall_curve, roc_curve, auc

from intrusion_intelligence.multiclass.taxonomy import ClassTaxonomy


def write_json(path: Path, document: Any) -> None:
    """Write UTF-8 structured experiment data."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(document, ensure_ascii=False, indent=2, default=_json_default) + "\n", encoding="utf-8")


def write_distribution_outputs(
    *,
    distribution: list[dict[str, Any]],
    source_distribution: pd.DataFrame,
    split_audit: dict[str, Any],
    evaluation_directory: Path,
    figure_directory: Path,
) -> None:
    """Persist full-data counts, source-group coverage, and a log-scale chart."""
    evaluation_directory.mkdir(parents=True, exist_ok=True)
    figure_directory.mkdir(parents=True, exist_ok=True)
    pd.DataFrame(distribution).to_csv(evaluation_directory / "class_distribution.csv", index=False)
    source_distribution.to_csv(evaluation_directory / "class_distribution_by_source_file.csv", index=False)
    write_json(evaluation_directory / "split_audit.json", split_audit)
    frame = pd.DataFrame(distribution)
    fig, ax = plt.subplots(figsize=(13, 7))
    bars = ax.barh(frame["label"], frame["count"], color="#356a9a")
    ax.set_xscale("log")
    ax.set_xlabel("Rows (log scale)")
    ax.set_title("CIC-IDS2017 multi-class label distribution (complete cleaned dataset)")
    ax.invert_yaxis()
    ax.grid(axis="x", alpha=0.25)
    for bar, count, pct in zip(bars, frame["count"], frame["percent"]):
        ax.text(max(bar.get_width(), 1) * 1.05, bar.get_y() + bar.get_height() / 2, f"{int(count):,} ({pct:.3f}%)", va="center", fontsize=8)
    fig.tight_layout()
    fig.savefig(figure_directory / "class_distribution_log.png", dpi=160)
    plt.close(fig)


def write_evaluation_outputs(
    *,
    model_name: str,
    partition: str,
    result: dict[str, Any],
    y_true: np.ndarray,
    scores: np.ndarray | None,
    taxonomy: ClassTaxonomy,
    evaluation_directory: Path,
    figure_directory: Path,
) -> None:
    """Persist metrics, class reports, confusion tables, pairs, and score curves."""
    prefix = f"{model_name}_{partition}"
    evaluation_directory.mkdir(parents=True, exist_ok=True)
    figure_directory.mkdir(parents=True, exist_ok=True)
    write_json(evaluation_directory / f"{prefix}_metrics.json", result["metrics"])
    pd.DataFrame(result["per_class"]).to_csv(evaluation_directory / f"{prefix}_per_class.csv", index=False)
    labels = list(taxonomy.labels)
    pd.DataFrame(result["confusion_matrix"], index=labels, columns=labels).to_csv(
        evaluation_directory / f"{prefix}_confusion_matrix_counts.csv", encoding="utf-8-sig"
    )
    pd.DataFrame(result["normalized_confusion_matrix"], index=labels, columns=labels).to_csv(
        evaluation_directory / f"{prefix}_confusion_matrix_normalized.csv", encoding="utf-8-sig"
    )
    pairs = result["frequent_confusion_pairs"]
    pd.DataFrame(pairs).to_csv(evaluation_directory / f"{prefix}_confusion_pairs.csv", index=False)
    _plot_confusion(
        np.asarray(result["confusion_matrix"]),
        labels,
        figure_directory / f"{prefix}_confusion_matrix_counts.png",
        normalized=False,
    )
    _plot_confusion(
        np.asarray(result["normalized_confusion_matrix"]),
        labels,
        figure_directory / f"{prefix}_confusion_matrix_normalized.png",
        normalized=True,
    )
    if scores is not None:
        _plot_curves(y_true, scores, taxonomy, figure_directory, prefix)


def write_model_importance(
    *,
    estimators: dict[str, Any],
    feature_names: list[str],
    evaluation_directory: Path,
    figure_directory: Path,
    top_n: int = 25,
) -> dict[str, list[dict[str, Any]]]:
    """Save RF impurity importance and multi-class logistic coefficient magnitudes."""
    summaries: dict[str, list[dict[str, Any]]] = {}
    for name, estimator in estimators.items():
        if hasattr(estimator, "feature_importances_"):
            importance = np.asarray(estimator.feature_importances_, dtype=float)
            measure = "mean_decrease_in_impurity"
        elif hasattr(estimator, "coef_"):
            importance = np.mean(np.abs(np.asarray(estimator.coef_, dtype=float)), axis=0)
            measure = "mean_absolute_coefficient_across_classes"
        else:
            continue
        if len(importance) != len(feature_names):
            continue
        order = np.argsort(importance)[::-1][:top_n]
        rows = [
            {"rank": rank, "feature": feature_names[index], "importance": float(importance[index]), "measure": measure}
            for rank, index in enumerate(order, start=1)
        ]
        summaries[name] = rows
        pd.DataFrame(rows).to_csv(evaluation_directory / f"{name}_feature_importance.csv", index=False)
        fig, ax = plt.subplots(figsize=(11, 8))
        display = list(reversed(rows))
        ax.barh([row["feature"] for row in display], [row["importance"] for row in display], color="#4d8a6a")
        ax.set_xlabel(measure.replace("_", " "))
        ax.set_title(f"{name.replace('_', ' ').title()} — top {len(rows)} transformed features")
        fig.tight_layout()
        fig.savefig(figure_directory / f"{name}_feature_importance.png", dpi=160)
        plt.close(fig)
    return summaries


def _plot_confusion(matrix: np.ndarray, labels: list[str], path: Path, *, normalized: bool) -> None:
    fig, ax = plt.subplots(figsize=(13, 11))
    image = ax.imshow(matrix, interpolation="nearest", cmap="Blues", aspect="auto")
    ax.figure.colorbar(image, ax=ax, fraction=0.046, pad=0.04)
    ax.set(
        xticks=np.arange(len(labels)),
        yticks=np.arange(len(labels)),
        xticklabels=labels,
        yticklabels=labels,
        xlabel="Predicted class",
        ylabel="True class",
        title="Row-normalized confusion matrix" if normalized else "Confusion matrix counts",
    )
    plt.setp(ax.get_xticklabels(), rotation=55, ha="right", rotation_mode="anchor", fontsize=8)
    plt.setp(ax.get_yticklabels(), fontsize=8)
    if len(labels) <= 20:
        for row in range(matrix.shape[0]):
            for column in range(matrix.shape[1]):
                value = matrix[row, column]
                text = f"{value:.1%}" if normalized else f"{int(value):,}"
                ax.text(column, row, text, ha="center", va="center", fontsize=6, color="black")
    fig.tight_layout()
    fig.savefig(path, dpi=160)
    plt.close(fig)


def _plot_curves(y_true: np.ndarray, scores: np.ndarray, taxonomy: ClassTaxonomy, directory: Path, prefix: str) -> None:
    fig, ax = plt.subplots(figsize=(10, 8))
    valid = 0
    for class_id, label in enumerate(taxonomy.labels):
        binary = (y_true == class_id).astype(np.uint8)
        positives = int(binary.sum())
        if positives == 0 or positives == len(binary):
            continue
        precision, recall, _ = precision_recall_curve(binary, scores[:, class_id])
        ap = float(average_precision_score(binary, scores[:, class_id]))
        ax.plot(recall, precision, linewidth=1, label=f"{label} (AP={ap:.3f})")
        valid += 1
    ax.set(xlabel="Recall", ylabel="Precision", title=f"One-vs-rest precision-recall curves — {prefix}", xlim=(0, 1), ylim=(0, 1.02))
    if valid:
        ax.legend(fontsize=7, loc="best")
    ax.grid(alpha=0.25)
    fig.tight_layout()
    fig.savefig(directory / f"{prefix}_precision_recall_curves.png", dpi=160)
    plt.close(fig)

    fig, ax = plt.subplots(figsize=(10, 8))
    for class_id, label in enumerate(taxonomy.labels):
        binary = (y_true == class_id).astype(np.uint8)
        if binary.sum() == 0 or binary.sum() == len(binary):
            continue
        false_positive, true_positive, _ = roc_curve(binary, scores[:, class_id])
        ax.plot(false_positive, true_positive, linewidth=1, label=f"{label} (AUC={auc(false_positive, true_positive):.3f})")
    ax.plot([0, 1], [0, 1], linestyle="--", color="grey", linewidth=0.8)
    ax.set(xlabel="False positive rate", ylabel="True positive rate", title=f"One-vs-rest ROC curves — {prefix}", xlim=(0, 1), ylim=(0, 1.02))
    ax.legend(fontsize=7, loc="best")
    ax.grid(alpha=0.25)
    fig.tight_layout()
    fig.savefig(directory / f"{prefix}_roc_curves.png", dpi=160)
    plt.close(fig)


def _json_default(value: Any) -> Any:
    if isinstance(value, np.generic):
        return value.item()
    if isinstance(value, np.ndarray):
        return value.tolist()
    if isinstance(value, Path):
        return str(value)
    raise TypeError(f"Cannot encode {type(value).__name__} as JSON.")
