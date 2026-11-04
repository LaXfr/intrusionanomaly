"""Command-line interface for an offline threat-intelligence run."""

from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path
from typing import Any

from intrusion_intelligence.config import LoggingSettings
from intrusion_intelligence.intelligence.config import DEFAULT_INTELLIGENCE_CONFIG
from intrusion_intelligence.intelligence.service import run_intelligence_experiment
from intrusion_intelligence.logging_config import configure_logging


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Combine persisted network-flow detector outputs into local security alerts.")
    parser.add_argument("--config", type=Path, default=DEFAULT_INTELLIGENCE_CONFIG, help="Path to intelligence.toml")
    parser.add_argument("--log-level", default="INFO", choices=("DEBUG", "INFO", "WARNING", "ERROR"))
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    configure_logging(LoggingSettings(level=args.log_level))
    try:
        result = run_intelligence_experiment(args.config)
    except Exception as exc:
        logging.getLogger(__name__).exception("Threat-intelligence run failed: %s", exc)
        return 1
    summary = result["summary"]
    print(json.dumps({
        "run_id": summary["experiment_run_id"],
        "flows": summary["total_analyzed_flows"],
        "flow_events_by_status": summary["flow_events_by_status"],
        "correlated_groups": summary["correlated_group_count"],
        "alerts": summary["generated_alert_count"],
        "alerts_by_severity": summary["alerts_by_severity"],
        "summary_report": summary["outputs"]["summary_markdown"],
    }, ensure_ascii=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
