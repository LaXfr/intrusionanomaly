"""Structured, local reports for flow events and security alerts."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

from intrusion_intelligence.intelligence.schemas import json_safe


def write_intelligence_outputs(
    result: dict[str, Any],
    *,
    intelligence_directory: str | Path,
    figure_directory: str | Path,
    run_id: str,
) -> dict[str, str]:
    """Persist traceable nested JSON and compact flat summaries."""
    intelligence_root = Path(intelligence_directory) / run_id
    figure_root = Path(figure_directory) / run_id
    intelligence_root.mkdir(parents=True, exist_ok=False)
    figure_root.mkdir(parents=True, exist_ok=False)
    outputs = {
        "flow_events_jsonl": intelligence_root / "flow_detection_events.jsonl",
        "correlated_groups_json": intelligence_root / "correlated_event_groups.json",
        "alerts_json": intelligence_root / "security_alerts.json",
        "summary_json": intelligence_root / "threat_intelligence_summary.json",
        "summary_markdown": intelligence_root / "threat_intelligence_report.md",
        "flow_events_csv": intelligence_root / "flow_detection_events.csv",
        "alerts_csv": intelligence_root / "security_alerts_summary.csv",
    }
    with outputs["flow_events_jsonl"].open("w", encoding="utf-8", newline="\n") as stream:
        for event in result["events"]:
            stream.write(json.dumps(json_safe(event), ensure_ascii=False, separators=(",", ":")) + "\n")
    outputs["correlated_groups_json"].write_text(json.dumps(json_safe(result["correlated_event_groups"]), ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    outputs["alerts_json"].write_text(json.dumps(json_safe(result["alerts"]), ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    outputs["summary_json"].write_text(json.dumps(json_safe(result["summary"]), ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    pd.DataFrame([_event_flat_row(event) for event in result["events"]]).to_csv(outputs["flow_events_csv"], index=False, encoding="utf-8")
    pd.DataFrame([_alert_flat_row(alert) for alert in result["alerts"]]).to_csv(outputs["alerts_csv"], index=False, encoding="utf-8")
    outputs["summary_markdown"].write_text(_report_markdown(result["summary"], result["alerts"]), encoding="utf-8")
    figures = _write_figures(figure_root, result["events"], result["alerts"])
    outputs.update(figures)
    result["summary"]["outputs"] = {name: str(path.resolve()) for name, path in outputs.items()}
    outputs["summary_json"].write_text(json.dumps(json_safe(result["summary"]), ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    outputs["summary_markdown"].write_text(_report_markdown(result["summary"], result["alerts"]), encoding="utf-8")
    return {name: str(path.resolve()) for name, path in outputs.items()}


def _event_flat_row(event: dict[str, Any]) -> dict[str, Any]:
    multi = event.get("normalized_evidence", {}).get("multiclass", {})
    anomaly = event.get("normalized_evidence", {}).get("anomaly", {})
    binary = event.get("normalized_evidence", {}).get("binary", {})
    return {
        "event_id": event.get("event_id"),
        "flow_record_reference": event.get("flow_record_reference"),
        "source_filename": event.get("source_filename"),
        "source_row_number": event.get("source_row_number"),
        "timestamp_utc": event.get("timestamp_utc"),
        "event_status": event.get("event_status"),
        "threat_score": event.get("threat_score"),
        "severity": event.get("severity"),
        "binary_status": binary.get("availability_status"),
        "multiclass_prediction": multi.get("details", {}).get("predicted_label"),
        "multiclass_attack_evidence": multi.get("normalized_value"),
        "anomaly_decision": anomaly.get("details", {}).get("decision"),
        "anomaly_percentile": anomaly.get("normalized_value"),
        "detector_disagreements": ";".join(event.get("detector_disagreements", [])),
    }


def _alert_flat_row(alert: dict[str, Any]) -> dict[str, Any]:
    return {
        "alert_id": alert["alert_id"],
        "alert_type": alert["alert_type"],
        "status": alert["status"],
        "severity": alert["severity"],
        "threat_score": alert["threat_score"],
        "mean_threat_score": alert["mean_threat_score"],
        "related_event_count": alert["related_event_count"],
        "related_flow_count": alert["related_flow_count"],
        "attack_categories": ";".join(alert["attack_categories"]),
        "correlation_rules": ";".join(alert["correlation_rules"]),
        "first_observed_utc": alert["first_observed_utc"],
        "last_observed_utc": alert["last_observed_utc"],
        "supporting_event_ids": ";".join(alert["supporting_event_ids"]),
        "title": alert["title"],
    }


def _report_markdown(summary: dict[str, Any], alerts: list[dict[str, Any]]) -> str:
    top_alerts = sorted(alerts, key=lambda item: (-item["threat_score"], item["alert_id"]))[:10]
    top_rows = "\n".join(
        f"| {alert['alert_id']} | {alert['severity']} | {alert['threat_score']:.2f} | {alert['related_flow_count']} | {', '.join(alert['attack_categories']) or 'None'} | {_markdown_cell(alert['title'])} |"
        for alert in top_alerts
    ) or "| — | — | — | — | — | No qualifying alerts were generated. |"
    metadata = summary.get("network_metadata_rows_present", {})
    return f"""# Threat intelligence run

- Processed at: `{summary['processed_at_utc']}`
- Pipeline version: `{summary['pipeline_version']}`; scoring config: `{summary['scoring_config_version']}`; severity policy: `{summary['severity_policy_version']}`.
- Analyzed flows: {summary['total_analyzed_flows']:,}; with usable detector evidence: {summary['flows_with_usable_detection_evidence']:,}.
- Flow events by status: `{json.dumps(summary['flow_events_by_status'], ensure_ascii=False)}`.
- Alerts: {summary['generated_alert_count']:,}; by severity: `{json.dumps(summary['alerts_by_severity'], ensure_ascii=False)}`.
- Alerts by predicted category: `{json.dumps(summary['alerts_by_predicted_attack_category'], ensure_ascii=False)}`.
- Correlated groups: {summary['correlated_group_count']:,}; correlation audit: `{json.dumps(summary['correlation_audit'], ensure_ascii=False)}`.
- Detector availability: `{json.dumps(summary['detector_availability'], ensure_ascii=False)}`.
- Detector disagreements: `{json.dumps(summary['detector_disagreement_counts'], ensure_ascii=False)}`.
- Network metadata rows present: `{json.dumps(metadata, ensure_ascii=False)}`.
- Configured signal weights: `{json.dumps(summary['weights'], ensure_ascii=False)}`. Missing evidence is excluded and remaining weights are renormalized.

Threat scores are heuristic prioritization values, not probabilities of compromise. Class scores from supervised models are not necessarily calibrated. Events and alert records preserve model output and provenance; no ground-truth labels are used to generate scores, events, groups, or alerts.

## Highest-scoring alerts

| Alert ID | Severity | Score | Flows | Predicted category | Title |
|---|---|---:|---:|---|---|
{top_rows}

Alerts start in `NEW`. The offline workflow does not acknowledge or resolve alerts and does not take enforcement actions.
"""


def _write_figures(directory: Path, events: list[dict[str, Any]], alerts: list[dict[str, Any]]) -> dict[str, Path]:
    outputs: dict[str, Path] = {}
    scores = np.asarray([event["threat_score"] for event in events if event.get("threat_score") is not None], dtype=float)
    figure, axis = plt.subplots(figsize=(8, 5))
    if len(scores):
        axis.hist(scores, bins=np.linspace(0, 100, 21), color="#4978A8", edgecolor="white")
    else:
        axis.text(0.5, 0.5, "No usable threat scores", ha="center", va="center", transform=axis.transAxes)
    axis.set(title="Flow-level heuristic threat score distribution", xlabel="Threat score (0–100; not a probability)", ylabel="Flow events")
    outputs["score_distribution_figure"] = _save(figure, directory / "threat_score_distribution.png")

    severity_counts = Counter(alert.get("severity", "UNSCORED") for alert in alerts)
    order = ["LOW", "MEDIUM", "HIGH", "CRITICAL", "UNSCORED"]
    figure, axis = plt.subplots(figsize=(7, 5))
    axis.bar([name for name in order if severity_counts[name]], [severity_counts[name] for name in order if severity_counts[name]], color="#C35B45")
    if not alerts:
        axis.text(0.5, 0.5, "No qualifying alerts", ha="center", va="center", transform=axis.transAxes)
    axis.set(title="Security alerts by severity", xlabel="Severity policy band", ylabel="Alerts")
    outputs["severity_figure"] = _save(figure, directory / "alert_severity_distribution.png")

    agreement = Counter()
    for event in events:
        available = [
            name for name, item in event.get("normalized_evidence", {}).items()
            if item.get("availability_status") == "available"
        ]
        positive = []
        for name in available:
            details = event["normalized_evidence"][name].get("details", {})
            positive.append(bool(details.get("malicious_prediction") or details.get("predicted_attack") or details.get("decision") == "ANOMALOUS"))
        if not available:
            label = "no evidence"
        elif len(set(positive)) == 1:
            label = "agreement: positive" if positive[0] else "agreement: negative"
        else:
            label = "disagreement"
        agreement[label] += 1
    figure, axis = plt.subplots(figsize=(8, 5))
    labels = sorted(agreement)
    axis.bar(labels, [agreement[label] for label in labels], color="#588A76")
    axis.set(title="Detector agreement using available hard decisions", xlabel="Decision relationship", ylabel="Flow events")
    axis.tick_params(axis="x", labelrotation=20)
    outputs["agreement_figure"] = _save(figure, directory / "detector_agreement.png")
    return outputs


def _save(figure: Any, path: Path) -> Path:
    figure.tight_layout()
    figure.savefig(path, dpi=150, bbox_inches="tight")
    plt.close(figure)
    return path


def _markdown_cell(value: Any) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")
