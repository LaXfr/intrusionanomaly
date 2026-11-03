"""Command-line interface for reproducible CIC-IDS2017 EDA."""

from __future__ import annotations

import argparse
import logging
from collections.abc import Sequence
from pathlib import Path

from intrusion_intelligence.config import load_config
from intrusion_intelligence.errors import ProjectError
from intrusion_intelligence.eda.service import run_eda
from intrusion_intelligence.logging_config import configure_logging

logger = logging.getLogger(__name__)


def build_parser() -> argparse.ArgumentParser:
    """Create focused command-line options for the EDA workflow."""
    parser = argparse.ArgumentParser(
        prog="intrusion-eda",
        description="Run chunked EDA and generate a report and focused figures.",
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=Path("configs/project.toml"),
        help="Project TOML configuration path.",
    )
    parser.add_argument(
        "--chunk-size",
        type=int,
        default=None,
        help="Rows per input chunk; defaults to the ingestion configuration.",
    )
    parser.add_argument(
        "--sample-size",
        type=int,
        default=20_000,
        help="Uniform rows used for plots, correlations, and duplicate estimates.",
    )
    parser.add_argument(
        "--max-per-label",
        type=int,
        default=1_000,
        help="Maximum stratified rows per original label for comparisons.",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=None,
        help="Override the configured reproducibility seed.",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the configured analysis and return a process status code."""
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        config = load_config(args.config)
        configure_logging(config.logging)
        result, outputs = run_eda(
            config,
            chunk_size=args.chunk_size,
            sample_size=args.sample_size,
            max_per_label=args.max_per_label,
            seed=args.seed,
        )
    except (ProjectError, OSError, ValueError) as exc:
        logger.error("EDA failed: %s", exc)
        return 2

    summary = result.summary
    print(
        f"EDA complete: {summary['dataset_overview']['rows_full']:,} full-scan rows, "
        f"{summary['dataset_overview']['files_count']} files, "
        f"{len(summary['label_distribution']['counts'])} original labels."
    )
    print(f"Uniform sample: {len(result.uniform_sample):,} rows (seed {summary['analysis_method']['sample_seed']}).")
    print(f"JSON report: {_relative(outputs.json_report, config.project_root)}")
    print(f"Markdown report: {_relative(outputs.markdown_report, config.project_root)}")
    print(f"Figures: {len(outputs.figures)} in reports/figures/eda/")
    return 0


def _relative(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.name
