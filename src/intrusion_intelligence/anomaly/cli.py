"""Command-line interface for the benign-baseline anomaly experiment."""

from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path

from intrusion_intelligence.anomaly.config import DEFAULT_ANOMALY_CONFIG
from intrusion_intelligence.anomaly.service import run_anomaly_experiment
from intrusion_intelligence.config import LoggingSettings
from intrusion_intelligence.logging_config import configure_logging


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Train and evaluate a benign-baseline CIC-IDS2017 anomaly detector.")
    parser.add_argument("--config", type=Path, default=DEFAULT_ANOMALY_CONFIG, help="Path to anomaly_detection.toml")
    parser.add_argument("--log-level", default="INFO", choices=("DEBUG", "INFO", "WARNING", "ERROR"))
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    configure_logging(LoggingSettings(level=args.log_level))
    try:
        summary = run_anomaly_experiment(args.config)
    except Exception as exc:
        logging.getLogger(__name__).exception("Anomaly detection experiment failed: %s", exc)
        return 1
    print(json.dumps({
        "run_id": summary["run_id"],
        "status": summary["experiment_status"],
        "model_id": summary["artifacts"]["model_id"],
        "default_operating_point": summary["default_operating_point"],
        "default_test_metrics": summary["test_metrics"][summary["default_operating_point"]],
        "report": summary["outputs"]["report"],
    }, ensure_ascii=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
