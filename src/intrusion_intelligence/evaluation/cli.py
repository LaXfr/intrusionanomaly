"""Command line entry point for comprehensive model evaluation."""

from __future__ import annotations

import argparse
from pathlib import Path

from intrusion_intelligence.evaluation.pipeline import run_evaluation


def main() -> None:
    parser = argparse.ArgumentParser(description="Reanalyze saved model evidence and create a Phase 11 evaluation bundle.")
    parser.add_argument("--config", type=Path, default=Path("configs/evaluation.toml"), help="Evaluation TOML configuration.")
    args = parser.parse_args()
    print(run_evaluation(args.config))


if __name__ == "__main__":
    main()
