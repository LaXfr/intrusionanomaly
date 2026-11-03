"""Machine-readable and human-readable data-quality reports."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def write_quality_report(report: dict[str, Any], base_path: str | Path) -> tuple[Path, Path]:
    """Write one full quality report as UTF-8 JSON and Markdown."""
    base = Path(base_path)
    base.parent.mkdir(parents=True, exist_ok=True)
    json_path = base.with_suffix(".json")
    markdown_path = base.with_suffix(".md")
    json_path.write_text(
        json.dumps(report, ensure_ascii=False, indent=2, default=_json_default) + "\n",
        encoding="utf-8",
    )
    markdown_path.write_text(_quality_markdown(report), encoding="utf-8")
    return json_path, markdown_path


def write_cleaning_report(report: dict[str, Any], base_path: str | Path) -> tuple[Path, Path]:
    """Write the cleaning run, its policy, verification, and outputs."""
    base = Path(base_path)
    base.parent.mkdir(parents=True, exist_ok=True)
    json_path = base.with_suffix(".json")
    markdown_path = base.with_suffix(".md")
    json_path.write_text(
        json.dumps(report, ensure_ascii=False, indent=2, default=_json_default) + "\n",
        encoding="utf-8",
    )
    markdown_path.write_text(_cleaning_markdown(report), encoding="utf-8")
    return json_path, markdown_path


def _quality_markdown(report: dict[str, Any]) -> str:
    overview = report["dataset_overview"]
    quality = report["quality_summary"]
    duplicate = report["duplicate_analysis"]
    lines = [
        f"# Data quality assessment: {report['dataset_name']}",
        "",
        f"- **Generated:** {report['generated_at_utc']}",
        f"- **Coverage:** {report['coverage']} ({overview['rows']:,} rows)",
        f"- **Files:** {overview['files_count']}; source columns: {overview['source_columns']}; feature columns: {overview['feature_columns']}",
        f"- **Chunk size:** {report['method']['chunk_size']:,}",
        f"- **Input values changed:** {report['method']['source_values_modified']}",
        "",
        "## Dataset and schema",
        "",
        f"Schema compatible: **{report['schema']['compatible']}**; distinct source header sequences: **{report['schema']['distinct_source_header_sequences']}**.",
        "",
        "| File | Rows | Bytes | SHA-256 |",
        "|---|---:|---:|---|",
    ]
    for name, item in report["files"].items():
        lines.append(f"| {name} | {item['rows']:,} | {item['size_bytes']:,} | {item['sha256']} |")
    lines.extend(
        [
            "",
            "## Label distribution",
            "",
            "| Original label | Rows | Percent |",
            "|---|---:|---:|",
        ]
    )
    for label, count in overview["label_counts"].items():
        lines.append(f"| {label or '(empty label)'} | {count:,} | {overview['label_percentages'][label]:.5f}% |")
    lines.extend(
        [
            "",
            "## Full-scan quality counts",
            "",
            "| Measure | Count |",
            "|---|---:|",
        ]
    )
    for name, count in quality["counts"].items():
        lines.append(f"| {name.replace('_', ' ').title()} | {count:,} |")
    lines.extend(
        [
            "",
            "Finding classifications are counts of affected source feature cells, not counts of unique records:",
            "",
        ]
    )
    for name, count in quality.get("findings_by_classification", {}).items():
        lines.append(f"- {name}: {count:,}")
    lines.extend(
        [
            "",
            "## Feature-level findings",
            "",
            "Missingness, parsing, infinity, zero, negative and finite range values are full-scan counts. Quantiles, IQR/MAD fences, sample cardinality and dominant-value rates are estimates from the deterministic systematic sample.",
            "",
            "| Position | Source header | Missing | Invalid numeric | +Inf | -Inf | Negative | Finite min | Finite max |",
            "|---:|---|---:|---:|---:|---:|---:|---:|---:|",
        ]
    )
    for item in sorted(report["features"].values(), key=lambda value: value["source_position"]):
        lines.append(
            f"| {item['source_position']} | {item['source_header']} | "
            f"{item['counts']['missing_total']:,} | {item['counts']['invalid_numeric']:,} | "
            f"{item['counts']['positive_infinity']:,} | {item['counts']['negative_infinity']:,} | "
            f"{item['counts']['negative']:,} | {_fmt(item['minimum_finite'])} | {_fmt(item['maximum_finite'])} |"
        )
    lines.extend(["", "## Negative-value semantics", ""])
    for item in quality["negative_features"]:
        lines.append(
            f"- **{item['source_header']}** ({item['count']:,}; {item['percentage']:.5f}%): "
            f"{item['assessment']['classification']}. {item['assessment']['reason']}"
        )
        feature = report["features"][item["internal_column"]]
        by_file = {
            name: values.get("negative", 0)
            for name, values in feature["by_file"].items()
            if values.get("negative", 0)
        }
        by_label = {
            name: values.get("negative", 0)
            for name, values in feature["by_label"].items()
            if values.get("negative", 0)
        }
        lines.append(f"  Per file: {by_file}; per label: {by_label}.")
    lines.extend(["", "## Infinities in flow-rate fields", ""])
    for item in report["features"].values():
        if item["counts"]["positive_infinity"] or item["counts"]["negative_infinity"]:
            lines.append(
                f"- **{item['source_header']}**: +Inf={item['counts']['positive_infinity']:,}, "
                f"-Inf={item['counts']['negative_infinity']:,}; "
                f"with Flow Duration == 0: {item['infinity_with_zero_flow_duration']:,}; "
                f"with nonzero or unavailable duration: "
                f"{item['infinity_with_nonzero_or_missing_flow_duration']:,}."
            )
            lines.append(
                f"  Per file: {item['by_file']}; per label: {item['by_label']}."
            )
    lines.extend(
        [
            "",
            "## Duplicate investigation",
            "",
            f"Fingerprint analysis available: **{duplicate['computed']}**; "
            f"repeated after-output scan: **{duplicate.get('scan_repeated_after_write', 'not applicable')}**. "
            f"Method: {duplicate['method']}",
        ]
    )
    if duplicate.get("computed"):
        for key, title in (
            ("exact_complete_row_duplicates", "Complete-row duplicates"),
            ("feature_vector_duplicates", "Feature-vector duplicates"),
        ):
            item = duplicate[key]
            lines.append(
                f"- {title}: {item['duplicate_excess_rows']:,} excess rows in "
                f"{item['repeated_fingerprint_groups']:,} groups; "
                f"{item['within_source_duplicate_excess_rows']:,} within-file excess rows; "
                f"{item['across_source_groups']:,} groups span source files."
            )
        lines.append(
            f"- Feature-vector groups with different labels: "
            f"{duplicate['feature_vector_duplicates']['groups_with_different_labels']:,}."
        )
        for label, count in duplicate["feature_vector_duplicates"].get(
            "conflicting_groups_by_label", {}
        ).items():
            lines.append(f"- Conflicting feature-vector groups containing label {label}: {count:,}.")
        lines.extend(
            [
                "",
                "| Source file | Exact duplicate excess rows | Feature-vector duplicate excess rows |",
                "|---|---:|---:|",
            ]
        )
        for source, item in duplicate.get("by_source_file", {}).items():
            lines.append(
                f"| {source} | {item['exact_duplicate_excess_rows']:,} | "
                f"{item['feature_vector_duplicate_excess_rows']:,} |"
            )
    lines.extend(
        [
            "",
            "No duplicates were removed. Fingerprint collision probability is negligible but nonzero; the scan does not claim byte-level proof for a fingerprint match.",
            "",
            "## Constant features",
            "",
            ", ".join(quality["constant_features"]) or "None detected.",
            "",
            "Sampled low-cardinality features: "
            + (", ".join(quality["low_cardinality_features_sample"]) or "none"),
            "",
            "Sampled near-constant features: "
            + (", ".join(quality["near_constant_features_sample"]) or "none"),
            "",
            "Numeric representation classifications: "
            + str(quality["numeric_representation_counts"]),
            "",
            "## Outlier diagnostics",
            "",
            f"{report['outlier_diagnostics']['sample_rows']:,} rows were sampled. Per-feature Tukey/IQR and median absolute deviation diagnostics are in JSON; estimates are sample-based and did not trigger removals.",
            "",
            "## Method and limitations",
            "",
            *[f"- {limitation}" for limitation in report["limitations"]],
            "",
        ]
    )
    return "\n".join(lines)


def _cleaning_markdown(report: dict[str, Any]) -> str:
    lines = [
        f"# Cleaning run: {report['dataset_name']}",
        "",
        f"- **Run status:** {report['status']}",
        f"- **Generated:** {report['generated_at_utc']}",
        f"- **Processing ID:** {report['processing_id']}",
        f"- **Output format:** {report['configuration']['output_format']}",
        f"- **Policy version:** {report['policy']['version']}",
        f"- **Input rows:** {report['records']['input']:,}",
        f"- **Output rows:** {report['records']['output']:,}",
        f"- **Excluded rows:** {report['records']['excluded']:,}",
        f"- **Raw files unchanged:** {report['validation']['raw_files_unchanged']}",
        f"- **Quarantine file:** {report['quarantine']['path']}",
        "",
        "## Operations applied",
        "",
    ]
    transformations = report["transformations"]
    lines.extend(
        [
            f"- Headers normalized for {len(transformations['header_mapping'])} source columns; collisions received position suffixes.",
            f"- Numeric features: {len(transformations['numeric_columns'])}; categorical columns: {len(transformations['categorical_columns'])}.",
            f"- Missing values canonicalized: {sum(transformations['missing_values_canonicalized_by_column'].values()):,}.",
            f"- Positive/negative infinities replaced with missing values: {sum(transformations['positive_infinities_replaced_by_column'].values()) + sum(transformations['negative_infinities_replaced_by_column'].values()):,}.",
            f"- Failed numeric conversions recorded: {sum(transformations['numeric_conversion_failures_by_column'].values()):,}.",
            f"- Label whitespace changes: {sum(item['rows'] for item in report['records']['label_mapping'] if item['original'] != item['normalized']):,}.",
            f"- Exact duplicate rows removed: {transformations['rows_removed_as_exact_duplicates']:,}.",
            "- Negative finite measurements and extreme values were preserved without clipping.",
            "- Original labels remain in `__source_label`; source file, row number, and record ID are provenance metadata.",
            "",
            "## Exclusions and label mapping",
            "",
            "| Rejection reason | Rows |",
            "|---|---:|",
        ]
    )
    for reason, count in sorted(report["records"]["excluded_by_reason"].items()):
        lines.append(f"| {reason} | {count:,} |")
    if not report["records"]["excluded_by_reason"]:
        lines.append("| None | 0 |")
    lines.extend(
        [
            "",
            "| Original label | Normalized label | Rows |",
            "|---|---|---:|",
        ]
    )
    for item in report["records"]["label_mapping"]:
        lines.append(
            f"| {_escape_markdown(item['original'])} | {_escape_markdown(item['normalized'])} | {item['rows']:,} |"
        )
    lines.extend(
        [
            "",
            "## Transformations",
            "",
            "Numeric feature cells were safely parsed. Common missing tokens and non-finite numerical values are represented as Parquet nulls; no values were imputed. Invalid numeric representations were coerced to null only after their counts and example strings were captured in this report. Labels were trimmed, while the decoded original label is retained separately. Exact duplicates are preserved by default; repeated feature vectors and conflicting labels are not removed.",
            "",
            f"- Candidate predictive features: {len(report['transformations']['numeric_columns']) + len(report['transformations']['categorical_columns'])}",
            f"- Target column: `{report['transformations']['target_column']}`",
            f"- Source header mapping: `{report.get('artifacts', {}).get('manifest', 'metadata/manifest.json')}`",
            f"- Feature policy: `{report.get('artifacts', {}).get('feature_policy', 'metadata/feature_policy.json')}`",
            f"- Policy copy: `{report.get('artifacts', {}).get('cleaning_policy', 'metadata/data_quality_policy.toml')}`",
            "",
            "## Output files",
            "",
            "| Source | Processed Parquet | Retained | Quarantined | SHA-256 |",
            "|---|---|---:|---:|---|",
        ]
    )
    for item in report["outputs"]:
        lines.append(
            f"| {item['source_file']} | {item['path']} | {item['rows_retained']:,} | {item['rows_quarantined']:,} | {item['sha256']} |"
        )
    lines.extend(["", "## Validation", ""])
    for name, value in report["validation"].items():
        lines.append(f"- **{name.replace('_', ' ').title()}:** {value}")
    lines.extend(
        [
            "",
            "## Quarantine",
            "",
            f"- Rows: {report['quarantine']['rows']:,}",
            f"- Reasons: {json.dumps(report['quarantine']['rejection_counts'], ensure_ascii=False)}",
            f"- SHA-256: `{report['quarantine']['sha256']}`",
            "",
            "## Quality reports",
            "",
            f"- Before: `{report['quality_reports']['before_markdown']}`",
            f"- After: `{report['quality_reports']['after_markdown']}`",
        ]
    )
    lines.extend(["", "## Limitations", ""])
    lines.extend(f"- {value}" for value in report["limitations"])
    lines.append("")
    return "\n".join(lines)


def _fmt(value: Any) -> str:
    return "n/a" if value is None else f"{value:.8g}"


def _escape_markdown(value: Any) -> str:
    return str(value).replace("|", "\\|").replace("\r", " ").replace("\n", " ")


def _json_default(value: Any) -> Any:
    if hasattr(value, "item"):
        return value.item()
    raise TypeError(f"Object of type {type(value).__name__} is not JSON serializable.")
