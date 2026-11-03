"""Render EDA findings and focused Matplotlib figures to project reports."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

import matplotlib

matplotlib.use("Agg", force=True)

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

from intrusion_intelligence.eda.analysis import EDAResult

logger = logging.getLogger(__name__)

_FIGURE_NAMES = (
    "label_distribution.png",
    "benign_malicious_distribution.png",
    "per_file_label_distribution.png",
    "missing_values.png",
    "numeric_feature_distributions.png",
    "correlation_heatmap.png",
    "feature_label_comparisons.png",
    "destination_port_distribution.png",
    "duplicate_sample_summary.png",
    "feature_quality_summary.png",
)


def write_eda_outputs(
    result: EDAResult,
    *,
    report_directory: str | Path,
    figure_directory: str | Path,
) -> tuple[Path, Path, tuple[Path, ...]]:
    """Write structured JSON, a readable Markdown report, and analysis figures."""
    reports = Path(report_directory)
    figures = Path(figure_directory)
    reports.mkdir(parents=True, exist_ok=True)
    figures.mkdir(parents=True, exist_ok=True)

    generated_figures = _write_figures(result, figures)
    summary = result.summary
    summary["generated_outputs"] = {
        "report_directory": _display_path(reports),
        "figure_directory": _display_path(figures),
        "figures": [path.name for path in generated_figures],
    }
    json_path = reports / f"{summary['dataset_name']}_eda.json"
    markdown_path = reports / f"{summary['dataset_name']}_eda.md"
    json_path.write_text(
        json.dumps(summary, ensure_ascii=False, indent=2, allow_nan=False),
        encoding="utf-8",
    )
    markdown_path.write_text(
        render_eda_report(summary, generated_figures),
        encoding="utf-8",
    )
    logger.info("Wrote EDA summary to %s", _display_path(json_path))
    logger.info("Wrote EDA report to %s", _display_path(markdown_path))
    return json_path, markdown_path, tuple(generated_figures)


def render_eda_report(summary: dict[str, Any], figures: list[Path]) -> str:
    """Return a concise report based only on computed analysis values."""
    overview = summary["dataset_overview"]
    labels = summary["label_distribution"]
    quality = summary["data_quality"]
    imbalance = labels["class_imbalance"]
    figures_by_name = {path.name: path.name for path in figures}
    lines = [
        f"# Exploratory data analysis: {summary['dataset_name']}",
        "",
        f"- **Analysis time (UTC):** {summary['analysis_timestamp_utc']}",
        f"- **Source:** {summary['source_reference']}",
        f"- **Coverage:** complete chunked scan ({overview['rows_full']:,} rows)",
        f"- **Files and columns:** {overview['files_count']} files; "
        f"{overview['columns_count']} source columns "
        f"({overview['feature_columns_count']} features and one label)",
        f"- **Chunk size:** {summary['analysis_method']['chunk_size']:,}",
        f"- **Uniform sample:** {summary['analysis_method']['sample_size_actual']:,} rows; "
        f"seed {summary['analysis_method']['sample_seed']}",
        "",
        "Source header whitespace and the duplicate ` Fwd Header Length` fields are "
        "preserved by the Phase 02 ingestion layer; position-specific aliases keep both "
        "columns addressable.",
        "",
        "Full-scan counts, label proportions, missingness, numeric moments, infinities, "
        "and available destination-port counts are exact. Quantiles, correlations, "
        "feature plots, duplicate rates, and near-constant indicators use the stated "
        "deterministic samples. Raw CSV files were read only.",
        "",
        "## Key findings",
        "",
    ]
    lines.extend(f"- {finding}" for finding in summary["key_findings"])
    lines.extend(
        [
            "",
            "## Label distribution",
            "",
            "| Original label | Rows (full scan) | Share |",
            "|---|---:|---:|",
        ]
    )
    for label, count in labels["counts"].items():
        lines.append(f"| {_escape_table(label)} | {count:,} | {labels['percentages'][label]:.4f}% |")
    lines.extend(
        [
            "",
            "### Label support across source files",
            "",
            "| Original label | Files present | Dominant file share |",
            "|---|---:|---:|",
        ]
    )
    for label, support in imbalance["per_label_file_support"].items():
        lines.append(
            f"| {_escape_table(label)} | {support['files_present']} | "
            f"{support['dominant_file_share_percent']:.3f}% |"
        )
    lines.extend(
        [
            "",
            f"Benign: {labels['benign_malicious']['BENIGN']:,} "
            f"({labels['benign_malicious']['benign_percent']:.3f}%). "
            f"All other original labels: {labels['benign_malicious']['MALICIOUS']:,} "
            f"({labels['benign_malicious']['malicious_percent']:.3f}%).",
            "",
            "## Per-file scan",
            "",
            "| File | Rows | Source columns | Top observed label |",
            "|---|---:|---:|---|",
        ]
    )
    for item in overview["files"]:
        top = max(item["label_counts_full"], key=item["label_counts_full"].get)
        lines.append(
            f"| {_escape_table(item['file'])} | {item['rows_full']:,} | "
            f"{item['columns']} | {_escape_table(top)} |"
        )
    lines.extend(
        [
            "",
            "## Data quality",
            "",
            f"- Rows with at least one blank or common textual NA token: "
            f"{overview['rows_with_missing_full']:,} "
            f"({overview['rows_with_missing_percent_full']:.4f}%).",
            f"- Missing cells: {quality['missing_cells_full']:,}.",
            f"- Positive/negative infinite numeric values: "
            f"{quality['infinite_value_count_full']:,}.",
            f"- Negative numeric values: "
            f"{quality['negative_numeric_value_count_full']:,}; flagged for review, "
            "not treated as errors by assumption.",
            f"- Numeric columns: {overview['numeric_columns_count']}; "
            f"non-numeric or mixed columns: "
            f"{overview['non_numeric_or_mixed_columns_count']}.",
            f"- Schema inspection warnings: "
            f"{'; '.join(overview['schema_warnings']) or 'none'}.",
            "",
            "### Columns with missing values",
            "",
        ]
    )
    missing = [
        item for item in quality["missing_by_column_full"] if item["count_full"] > 0
    ]
    if missing:
        lines.extend(["| Column | Count | Share of rows |", "|---|---:|---:|"])
        for item in missing:
            lines.append(
                f"| {_escape_table(item['column'])} | {item['count_full']:,} | "
                f"{item['percent_full']:.4f}% |"
            )
    else:
        lines.append("No missing cells were observed under the documented missing-token rule.")
    if quality["numeric_value_issues_full"]:
        lines.extend(
            [
                "",
                "### Numeric anomalies and negative values",
                "",
                "| Feature | +Infinity | -Infinity | Parse failures | Negative values |",
                "|---|---:|---:|---:|---:|",
            ]
        )
        for item in quality["numeric_value_issues_full"]:
            lines.append(
                f"| {_escape_table(item['column'])} | "
                f"{item['positive_infinity_full']:,} | "
                f"{item['negative_infinity_full']:,} | "
                f"{item['nonnumeric_count_full']:,} | "
                f"{item['negative_count_full']:,} |"
            )
    negative_fields = quality["negative_numeric_features_full"][:15]
    if negative_fields:
        lines.extend(
            [
                "",
                "### Features containing negative values",
                "",
                "| Feature | Negative values | Minimum (full scan) |",
                "|---|---:|---:|",
            ]
        )
        for item in negative_fields:
            lines.append(
                f"| {_escape_table(item['column'])} | {item['count']:,} | "
                f"{_fmt(item['minimum'])} |"
            )
    lines.extend(
        [
            "",
            "## Numerical statistics",
            "",
            "Full-scan mean, sample standard deviation, minimum, maximum, zero rates, and "
            "invalid-value counts are exact for numeric features. Quantiles, skewness, "
            "kurtosis, and unique-value counts below are from the uniform sample.",
            "",
            "| Feature | Mean (full) | Median (sample) | Min (full) | Max (full) | Zero share (full) | Skew (sample) |",
            "|---|---:|---:|---:|---:|---:|---:|",
        ]
    )
    for item in summary["numeric_statistics"]:
        lines.append(
            f"| {_escape_table(item['column'])} | {_fmt(item['mean_full'])} | "
            f"{_fmt(item['median_sample'])} | {_fmt(item['min_full'])} | "
            f"{_fmt(item['max_full'])} | {item['zero_percent_full']:.3f}% | "
            f"{_fmt(item['skew_sample'])} |"
        )
    lines.extend(
        [
            "",
            "## Correlation, duplicates, and feature quality",
            "",
            f"Pearson and Spearman correlations use {summary['correlations']['sample_rows']:,} "
            "uniformly sampled rows after masking positive and negative infinity. "
            "Pairs at absolute correlation 0.95 or above are listed in the JSON output; "
            "correlation is not proof of leakage or causality.",
            "",
        ]
    )
    for item in summary["correlations"]["pearson_high_pairs"][:20]:
        lines.append(
            f"- Pearson: {_escape_table(item['feature_a'])} / "
            f"{_escape_table(item['feature_b'])}: {item['correlation']:.4f}."
        )
    if not summary["correlations"]["pearson_high_pairs"]:
        lines.append("No Pearson pair crossed the absolute 0.95 threshold in the sample.")
    duplicates = summary["duplicate_analysis"]
    lines.extend(
        [
            "",
            f"Duplicate checks cover a deterministic uniform sample of "
            f"{duplicates['sample_rows']:,} rows: {duplicates['duplicate_rows']:,} "
            f"exact duplicate rows, {duplicates['duplicate_feature_rows']:,} rows in "
            f"repeated feature-vector groups, {duplicates['conflicting_label_groups']:,} "
            "conflicting-label groups, and "
            f"{duplicates['cross_file_duplicate_groups']:,} groups repeated across files.",
            "",
            f"Exact constant numeric features: "
            f"{', '.join(summary['feature_quality']['constant_features_exact_full']) or 'none'}.",
            "Potentially dominant or high-cardinality features are sample indicators "
            "in the JSON output; no columns were removed.",
            "",
            "## Network fields, time, and leakage considerations",
            "",
            f"Available fields: {', '.join(name for name, present in summary['network_fields']['presence'].items() if present) or 'none of the checked fields' }.",
            summary["network_fields"]["protocol_analysis"],
            summary["network_fields"]["source_port_analysis"],
            summary["temporal_analysis"]["reason"],
            "The source filename remains available in per-file summaries and can act as a "
            "collection-scenario proxy. Keep it as provenance for EDA and assess it before "
            "any future predictive use. This phase did not split data or remove features.",
            "",
            "## Figures",
            "",
        ]
    )
    for name in figures_by_name:
        lines.append(f"- [{name}](../figures/eda/{name})")
    lines.extend(
        [
            "",
            "## Recommendations for later phases",
            "",
            "### Phase 04 — Data Cleaning & Leakage Prevention",
            "",
            "- Review only the full-scan missing, infinity, parse-failure, and negative-value "
            "counts; decide handling rules without changing raw source files.",
            "- Investigate repeated feature vectors and any conflicting labels with a full "
            "external-memory workflow before deciding whether rows should be excluded.",
            "- Keep file identity as provenance; do not assume random row splits represent "
            "independent collection scenarios.",
            "",
            "### Phase 05 — Feature Engineering & Preprocessing",
            "",
            "- Consider scaling and robust summaries for heavy-tailed flow measurements.",
            "- Evaluate redundancy flagged by the sampled correlation analysis, without "
            "automatically dropping correlated features.",
            "- Plan per-class evaluation around the observed minority counts; report recall, "
            "precision, F1, and confusion matrices rather than accuracy alone.",
            "- Keep label-derived, file, and future identifier metadata separate from model "
            "features until leakage risks have been tested.",
            "",
            "## Limitations and provenance",
            "",
        ]
    )
    lines.extend(f"- {item}" for item in summary["limitations"])
    lines.append("")
    return "\n".join(lines)


def _write_figures(result: EDAResult, output: Path) -> list[Path]:
    """Create one focused figure per analytical question, avoiding plot floods."""
    summary = result.summary
    figures: list[Path] = []
    figures.append(_plot_labels(summary, output / _FIGURE_NAMES[0]))
    figures.append(_plot_binary_labels(summary, output / _FIGURE_NAMES[1]))
    figures.append(_plot_file_labels(summary, output / _FIGURE_NAMES[2]))
    figures.append(_plot_missing(summary, output / _FIGURE_NAMES[3]))
    figures.append(_plot_distributions(result, output / _FIGURE_NAMES[4]))
    figures.append(_plot_correlations(result, output / _FIGURE_NAMES[5]))
    figures.append(_plot_label_features(result, output / _FIGURE_NAMES[6]))
    port_path = _plot_ports(summary, output / _FIGURE_NAMES[7])
    if port_path:
        figures.append(port_path)
    figures.append(_plot_duplicates(summary, output / _FIGURE_NAMES[8]))
    figures.append(_plot_quality(summary, output / _FIGURE_NAMES[9]))
    return figures


def _plot_labels(summary: dict[str, Any], path: Path) -> Path:
    labels = summary["label_distribution"]["counts"]
    names = list(labels)
    counts = [labels[name] for name in names]
    figure, axis = plt.subplots(figsize=(11, max(5, len(names) * 0.42)))
    axis.barh(names[::-1], counts[::-1], color="#336699")
    axis.set_title("CIC-IDS2017 original label counts (full scan)")
    axis.set_xlabel("Rows")
    axis.set_ylabel("Original label")
    axis.xaxis.set_major_formatter(plt.FuncFormatter(lambda value, _: f"{value:,.0f}"))
    figure.tight_layout()
    return _save(figure, path)


def _plot_binary_labels(summary: dict[str, Any], path: Path) -> Path:
    binary = summary["label_distribution"]["benign_malicious"]
    labels = ["BENIGN", "MALICIOUS"]
    values = [binary["BENIGN"], binary["MALICIOUS"]]
    figure, axis = plt.subplots(figsize=(7, 5))
    bars = axis.bar(labels, values, color=["#4c956c", "#bc4749"])
    axis.set_title("Benign and malicious row counts (derived grouping)")
    axis.set_ylabel("Rows; full scan")
    axis.yaxis.set_major_formatter(plt.FuncFormatter(lambda value, _: f"{value:,.0f}"))
    for bar, value in zip(bars, values):
        axis.text(bar.get_x() + bar.get_width() / 2, bar.get_height(), f"{value:,}", ha="center", va="bottom")
    figure.tight_layout()
    return _save(figure, path)


def _plot_file_labels(summary: dict[str, Any], path: Path) -> Path:
    labels = list(summary["label_distribution"]["counts"])
    files = summary["label_distribution"]["per_file"]
    matrix = np.array(
        [
            [files[name]["counts"].get(label, 0) * 100.0 / files[name]["rows"] for label in labels]
            for name in files
        ],
        dtype=float,
    )
    figure, axis = plt.subplots(figsize=(14, 7))
    image = axis.imshow(matrix, aspect="auto", cmap="magma")
    axis.set_yticks(np.arange(len(files)), labels=[Path(name).name for name in files])
    axis.set_xticks(np.arange(len(labels)), labels=labels, rotation=50, ha="right")
    axis.set_title("Per-file label proportions (full scan; row-normalized)")
    axis.set_xlabel("Original label")
    axis.set_ylabel("Source file")
    figure.colorbar(image, ax=axis, label="Percent of file rows")
    figure.tight_layout()
    return _save(figure, path)


def _plot_missing(summary: dict[str, Any], path: Path) -> Path:
    missing = [
        item
        for item in summary["data_quality"]["missing_by_column_full"]
        if item["count_full"]
    ][:20]
    figure, axis = plt.subplots(figsize=(10, max(4, min(10, len(missing) * 0.35))))
    if missing:
        axis.barh(
            [item["column"] for item in missing][::-1],
            [item["count_full"] for item in missing][::-1],
            color="#d99a2b",
        )
        axis.set_xlabel("Missing values; full scan")
    else:
        axis.text(0.5, 0.5, "No blank or common textual NA tokens observed", ha="center", va="center")
        axis.set_axis_off()
    axis.set_title("Missing values by feature")
    figure.tight_layout()
    return _save(figure, path)


def _plot_distributions(result: EDAResult, path: Path) -> Path:
    sample = result.uniform_sample
    display_names = {
        item["internal_column"]: item["display_name"]
        for item in result.summary["dataset_overview"]["columns"]
    }
    chosen = _choose_plot_features(result)
    figure, axes = plt.subplots(2, 3, figsize=(16, 9))
    for axis, column in zip(axes.flat, chosen):
        values = pd.to_numeric(sample[column], errors="coerce").to_numpy(
            dtype=float, na_value=np.nan
        )
        values = values[np.isfinite(values)]
        transformed, label = _visual_values(values)
        axis.hist(transformed, bins=45, color="#457b9d", alpha=0.85)
        axis.set_title(display_names.get(column, column))
        axis.set_xlabel(label)
        axis.set_ylabel("Sample rows")
    for axis in axes.flat[len(chosen) :]:
        axis.set_visible(False)
    figure.suptitle(
        f"Selected flow-feature distributions (uniform sample, n={len(sample):,})"
    )
    figure.tight_layout()
    return _save(figure, path)


def _plot_correlations(result: EDAResult, path: Path) -> Path:
    selected = result.summary["correlations"]["heatmap_features"]
    matrix = _corr_for_plot(result.uniform_sample, selected)
    figure, axis = plt.subplots(figsize=(max(12, len(selected) * 0.38), max(10, len(selected) * 0.34)))
    image = axis.imshow(matrix, cmap="coolwarm", vmin=-1, vmax=1, aspect="auto")
    short_names = [
        _short_name(result.summary, column, 27) for column in selected
    ]
    axis.set_xticks(np.arange(len(selected)), labels=short_names, rotation=70, ha="right", fontsize=7)
    axis.set_yticks(np.arange(len(selected)), labels=short_names, fontsize=7)
    axis.set_title(
        f"Pearson correlations: {len(selected)} highest-variance features "
        f"(uniform sample, n={len(result.uniform_sample):,})"
    )
    figure.colorbar(image, ax=axis, label="Pearson r")
    figure.tight_layout()
    return _save(figure, path)


def _plot_label_features(result: EDAResult, path: Path) -> Path:
    sample = result.stratified_sample
    label_column = result.label_column
    labels = list(result.summary["label_distribution"]["counts"])
    sample_labels = set(sample[label_column].astype(str)) if len(sample) else set()
    plotted_labels = [label for label in labels if label in sample_labels][:6]
    features = [
        column
        for column in _choose_plot_features(result)
        if column in result.numeric_columns
    ][:4]
    figure, axes = plt.subplots(2, 2, figsize=(16, 11))
    for axis, column in zip(axes.flat, features):
        values_by_label = []
        labels_for_axis = []
        for label in plotted_labels:
            values = pd.to_numeric(
                sample.loc[sample[label_column].astype(str) == label, column],
                errors="coerce",
            ).to_numpy(dtype=float, na_value=np.nan)
            values = values[np.isfinite(values)]
            if values.size:
                transformed, _ = _visual_values(values)
                values_by_label.append(transformed)
                labels_for_axis.append(label)
        if values_by_label:
            label_argument = (
                "tick_labels"
                if tuple(int(part) for part in matplotlib.__version__.split(".")[:2])
                >= (3, 9)
                else "labels"
            )
            axis.boxplot(
                values_by_label,
                showfliers=False,
                **{label_argument: labels_for_axis},
            )
            axis.tick_params(axis="x", labelrotation=40, labelsize=7)
        axis.set_title(_short_name(result.summary, column, 45))
        axis.set_ylabel("Visualization transform (signed log where needed)")
    for axis in axes.flat[len(features) :]:
        axis.set_visible(False)
    figure.suptitle(
        "Selected flow features by original label "
        f"(stratified sample, at most 1,000 rows per label; plotted labels={len(plotted_labels)})"
    )
    figure.tight_layout()
    return _save(figure, path)


def _plot_ports(summary: dict[str, Any], path: Path) -> Path | None:
    ports = summary["network_fields"]["destination_port"]["top_ports_full"]
    if not ports:
        return None
    names = [int(item["port"]) for item in ports[:20]][::-1]
    counts = [item["count"] for item in ports[:20]][::-1]
    figure, axis = plt.subplots(figsize=(9, 6))
    positions = np.arange(len(names))
    axis.barh(positions, counts, color="#6a4c93")
    axis.set_yticks(positions, labels=[str(port) for port in names])
    axis.set_title("Most frequent destination ports (full scan)")
    axis.set_xlabel("Rows")
    axis.set_ylabel("Destination port")
    axis.xaxis.set_major_formatter(plt.FuncFormatter(lambda value, _: f"{value:,.0f}"))
    figure.tight_layout()
    return _save(figure, path)


def _plot_duplicates(summary: dict[str, Any], path: Path) -> Path:
    duplicate = summary["duplicate_analysis"]
    labels = ["Exact duplicate rows", "Repeated feature-vector rows", "Conflicting-label groups"]
    values = [
        duplicate["duplicate_rows"],
        duplicate["duplicate_feature_rows"],
        duplicate["conflicting_label_groups"],
    ]
    figure, axis = plt.subplots(figsize=(9, 5))
    axis.bar(labels, values, color=["#2a9d8f", "#e9c46a", "#e76f51"])
    axis.set_title(f"Duplicate diagnostics (uniform sample, n={duplicate['sample_rows']:,})")
    axis.set_ylabel("Sample rows or groups; see category labels")
    axis.tick_params(axis="x", labelrotation=20)
    figure.tight_layout()
    return _save(figure, path)


def _plot_quality(summary: dict[str, Any], path: Path) -> Path:
    flagged = summary["feature_quality"]["potentially_uninformative_or_high_cardinality_sample"]
    figure, axis = plt.subplots(figsize=(10, max(4, min(9, len(flagged) * 0.38))))
    if flagged:
        axis.barh(
            [item["column"] for item in flagged][::-1],
            [item["sample_dominant_value_percent"] for item in flagged][::-1],
            color="#577590",
        )
        axis.set_xlabel("Share of most common value in sample (%)")
    else:
        axis.text(0.5, 0.5, "No dominant or cardinality flags in the uniform sample", ha="center", va="center")
        axis.set_axis_off()
    axis.set_title("Sample-based feature-quality flags")
    figure.tight_layout()
    return _save(figure, path)


def _choose_plot_features(result: EDAResult) -> list[str]:
    """Choose a small network-relevant set, then fill by sampled variance."""
    display = {
        item["internal_column"]: item["display_name"].strip().casefold()
        for item in result.summary["dataset_overview"]["columns"]
    }
    preferred = [
        "flow duration",
        "total fwd packets",
        "flow bytes/s",
        "flow packets/s",
        "packet length mean",
        "flow iat mean",
        "average packet size",
    ]
    chosen = [
        column
        for target in preferred
        for column in result.numeric_columns
        if display.get(column) == target
    ]
    for column in _variance_rank(result.uniform_sample, result.numeric_columns):
        if column not in chosen:
            chosen.append(column)
        if len(chosen) >= 6:
            break
    return chosen[:6]


def _variance_rank(sample: pd.DataFrame, columns: tuple[str, ...]) -> list[str]:
    variances = {}
    for column in columns:
        values = pd.to_numeric(sample[column], errors="coerce").replace(
            [np.inf, -np.inf], np.nan
        )
        variance = values.var()
        if pd.notna(variance):
            variances[column] = float(variance)
    return sorted(variances, key=variances.get, reverse=True)


def _corr_for_plot(sample: pd.DataFrame, columns: list[str]) -> np.ndarray:
    frame = pd.DataFrame(index=sample.index)
    for column in columns:
        values = pd.to_numeric(sample[column], errors="coerce")
        frame[column] = values.replace([np.inf, -np.inf], np.nan)
    return frame.corr(method="pearson").to_numpy()


def _visual_values(values: np.ndarray) -> tuple[np.ndarray, str]:
    """Apply an explicitly display-only transform for heavy-tailed values."""
    if values.size == 0:
        return values, "Feature value"
    magnitude = float(np.nanpercentile(np.abs(values), 99))
    if magnitude > 10_000:
        return np.sign(values) * np.log10(np.abs(values) + 1.0), "signed log10(|x| + 1); display only"
    return values, "Feature value; sample"


def _short_name(summary: dict[str, Any], column: str, limit: int) -> str:
    for item in summary["dataset_overview"]["columns"]:
        if item["internal_column"] == column:
            name = item["display_name"]
            return name if len(name) <= limit else name[: limit - 1] + "…"
    return column[:limit]


def _save(figure: plt.Figure, path: Path) -> Path:
    figure.savefig(path, dpi=180, bbox_inches="tight")
    plt.close(figure)
    return path


def _display_path(path: Path) -> str:
    """Use a project-relative output path whenever possible."""
    try:
        return path.resolve().relative_to(Path.cwd().resolve()).as_posix()
    except ValueError:
        return path.name


def _escape_table(value: Any) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def _fmt(value: Any) -> str:
    if value is None:
        return "n/a"
    try:
        number = float(value)
    except (TypeError, ValueError):
        return str(value)
    if not np.isfinite(number):
        return "n/a"
    return f"{number:,.4g}"
