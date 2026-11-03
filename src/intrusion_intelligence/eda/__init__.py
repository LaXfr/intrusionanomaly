"""Reusable exploratory-analysis utilities for network-flow datasets."""

from intrusion_intelligence.eda.analysis import (
    EDAResult,
    analyze_dataset,
    correlation_summary,
    duplicate_summary,
    label_distribution,
    missing_value_summary,
    numeric_feature_summary,
)
from intrusion_intelligence.eda.reporting import render_eda_report, write_eda_outputs
from intrusion_intelligence.eda.service import EDAOutputs, run_eda

__all__ = [
    "EDAOutputs",
    "EDAResult",
    "analyze_dataset",
    "correlation_summary",
    "duplicate_summary",
    "label_distribution",
    "missing_value_summary",
    "numeric_feature_summary",
    "render_eda_report",
    "run_eda",
    "write_eda_outputs",
]
