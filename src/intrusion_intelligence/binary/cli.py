"""Command-line entry point for the binary classification experiment."""

from __future__ import annotations

import argparse
import json

from intrusion_intelligence.binary.service import run_binary_experiment


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Train and evaluate the binary CIC-IDS2017 detector.")
    parser.add_argument("--config", default="configs/binary.toml")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    result = run_binary_experiment(args.config)
    print(json.dumps(result, ensure_ascii=True, indent=2))
    return 0
