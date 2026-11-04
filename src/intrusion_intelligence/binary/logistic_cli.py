"""Command line entry point for the isolated Logistic Regression comparison."""

from __future__ import annotations

import argparse
import json

from intrusion_intelligence.binary.logistic_experiment import run_logistic_experiment


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the Phase 06 Logistic Regression comparison.")
    parser.add_argument("--config", default="configs/binary_logistic.toml", help="Experiment TOML path.")
    args = parser.parse_args()
    result = run_logistic_experiment(args.config)
    print(json.dumps({"report_directory": result["report_directory"], "artifact_directory": result["artifact_directory"]}, indent=2))
    print(json.dumps({
        "validation_metrics": result["summary"]["validation_metrics_at_fixed_threshold"],
        "friday_test_metrics": result["summary"]["friday_test_metrics_at_fixed_threshold"],
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
