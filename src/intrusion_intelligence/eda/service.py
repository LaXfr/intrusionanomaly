"""Run reproducible EDA and persist its report and figures."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path

from intrusion_intelligence.config import ProjectConfig
from intrusion_intelligence.eda.analysis import EDAResult, analyze_dataset
from intrusion_intelligence.eda.reporting import write_eda_outputs

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class EDAOutputs:
    """Paths to the generated EDA artifacts."""

    json_report: Path
    markdown_report: Path
    figures: tuple[Path, ...]


def run_eda(
    config: ProjectConfig,
    *,
    chunk_size: int | None = None,
    sample_size: int = 20_000,
    max_per_label: int = 1_000,
    seed: int | None = None,
) -> tuple[EDAResult, EDAOutputs]:
    """Analyze the configured dataset and write reports under configured paths."""
    result = analyze_dataset(
        config,
        chunk_size=chunk_size,
        sample_size=sample_size,
        max_per_label=max_per_label,
        seed=seed,
    )
    json_report, markdown_report, figures = write_eda_outputs(
        result,
        report_directory=config.paths.eda_reports,
        figure_directory=config.paths.report_figures / "eda",
    )
    return result, EDAOutputs(json_report, markdown_report, figures)
