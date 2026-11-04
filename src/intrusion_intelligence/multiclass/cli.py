"""Command-line entry point for the Phase 07 multi-class experiment."""

from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path
from typing import Sequence

from intrusion_intelligence.multiclass.config import DEFAULT_MULTICLASS_CONFIG
from intrusion_intelligence.multiclass.service import run_multiclass_experiment


def build_parser() -> argparse.ArgumentParser:
    """Create a minimal training command with centralized TOML settings."""
    parser = argparse.ArgumentParser(
        prog="intrusion-multiclass",
        description="Train and evaluate exploratory CIC-IDS2017 multi-class baselines.",
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=DEFAULT_MULTICLASS_CONFIG,
        help="Path to the multi-class TOML configuration.",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run training and return an operating-system status code."""
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        summary = run_multiclass_experiment(args.config)
    except (OSError, ValueError, RuntimeError) as exc:
        logging.getLogger(__name__).error("Multi-class experiment failed: %s", exc)
        return 2
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0
