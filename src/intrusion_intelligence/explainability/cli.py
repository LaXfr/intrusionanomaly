"""Command line interface for persisted-model SHAP analysis."""

from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path

from intrusion_intelligence.explainability.pipeline import run_explainability


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Explain persisted intrusion models with SHAP.")
    parser.add_argument("--config", type=Path, default=Path("configs/explainability.toml"))
    parser.add_argument("--log-level", default="INFO", choices=("DEBUG", "INFO", "WARNING", "ERROR"))
    args = parser.parse_args(argv)
    logging.basicConfig(level=getattr(logging, args.log_level))
    try:
        result = run_explainability(args.config)
    except Exception as exc:
        logging.getLogger(__name__).exception("Explainability run failed: %s", exc)
        return 1
    # PowerShell on Windows may use cp1252 even when the JSON is valid UTF-8.
    print(json.dumps({
        "run_id": result["run_id"],
        "execution_seconds": round(result["execution_seconds"], 2),
        "models": list(result["models"]),
        "explanations": result["explanation_count"],
        "global_importance_rows": result["global_importance_rows"],
        "events_enriched": result["events_enriched"],
        "alerts_enriched": result["alerts_enriched"],
        "output_directory": result["output_directory"],
        "figure_directory": result["figure_directory"],
    }, ensure_ascii=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
