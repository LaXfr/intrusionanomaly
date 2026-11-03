"""CLI for data-quality assessment and preservation-first cleaning."""

from __future__ import annotations

import argparse
import json
import logging
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from intrusion_intelligence.config import load_config
from intrusion_intelligence.errors import ProjectError
from intrusion_intelligence.logging_config import configure_logging
from intrusion_intelligence.preprocessing.assessment import assess_dataset
from intrusion_intelligence.preprocessing.policy import (
    DEFAULT_POLICY_PATH,
    load_policy,
)
from intrusion_intelligence.preprocessing.reporting import write_quality_report
from intrusion_intelligence.preprocessing.service import clean_dataset

logger = logging.getLogger(__name__)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m intrusion_intelligence.preprocessing",
        description="Assess CIC-IDS2017 quality and produce provenance-preserving processed CSVs.",
    )
    parser.add_argument("--config", type=Path, default=Path("configs/project.toml"))
    subparsers = parser.add_subparsers(dest="command", required=True)

    assess = subparsers.add_parser("assess", help="Run a chunked quality assessment.")
    assess.add_argument("--chunk-size", type=int, default=None)
    assess.add_argument("--sample-stride", type=int, default=100)
    assess.add_argument("--no-duplicates", action="store_true")
    assess.add_argument("--dataset-directory", type=Path, default=None)

    clean = subparsers.add_parser("clean", help="Create verified processed CSV outputs.")
    clean.add_argument("--chunk-size", type=int, default=None)
    clean.add_argument("--sample-stride", type=int, default=100)
    clean.add_argument("--output-dir", type=Path, default=None)
    clean.add_argument("--policy", type=Path, default=None)
    clean.add_argument("--dry-run", action="store_true")

    policy = subparsers.add_parser("policy", help="Inspect or validate the cleaning policy.")
    policy.add_argument("policy_command", choices=("validate",))
    policy.add_argument("--path", type=Path, default=None)

    summary = subparsers.add_parser("summary", help="Summarize a prior cleaning manifest.")
    summary.add_argument("--manifest", type=Path, default=None)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        config = load_config(args.config)
        configure_logging(config.logging)
        if args.command == "assess":
            report = assess_dataset(
                config,
                dataset_directory=args.dataset_directory,
                chunk_size=args.chunk_size,
                sample_stride=args.sample_stride,
                compute_duplicates=not args.no_duplicates,
            )
            base = config.paths.eda_reports.parent / "data_quality" / (
                f"{config.dataset.name}_quality_report"
            )
            json_path, markdown_path = write_quality_report(report, base)
            print(
                f"Assessment complete: {report['dataset_overview']['rows']:,} rows, "
                f"{len(report['files'])} files, "
                f"{len(report['dataset_overview']['label_counts'])} labels."
            )
            print(f"JSON: {json_path}")
            print(f"Markdown: {markdown_path}")
            print(
                f"Duplicate scan: {report['duplicate_analysis']['computed']}; "
                f"sample rows: {report['outlier_diagnostics']['sample_rows']:,}."
            )
            return 0
        if args.command == "clean":
            result = clean_dataset(
                config,
                chunk_size=args.chunk_size,
                sample_stride=args.sample_stride,
                output_directory=args.output_dir,
                policy_path=args.policy,
                dry_run=args.dry_run,
            )
            if args.dry_run:
                print("Dry run only: cleaning was not executed and no processed CSVs were written.")
                print(f"Planned output: {result['output_directory']}")
                for item in result["planned_transformations"]:
                    print(f"- {item}")
            else:
                print(
                    f"Cleaning {result['status']}: "
                    f"{result['records']['output']:,} rows retained; "
                    f"{result['records']['excluded']:,} excluded."
                )
                print(f"Processed files: {len(result['outputs'])}")
                print(f"Manifest: {result['artifacts']['manifest']}")
                print(f"Report: {result['artifacts']['cleaning_report_markdown']}")
            return 0
        if args.command == "policy":
            selected = args.path or (config.project_root / DEFAULT_POLICY_PATH)
            policy_document = load_policy(selected)
            print(f"Cleaning policy valid: {selected}")
            print(json.dumps(policy_document, ensure_ascii=True, indent=2))
            return 0
        if args.command == "summary":
            manifest_path = args.manifest or (
                config.paths.processed_data
                / f"{config.dataset.name}-phase04-v2"
                / "metadata"
                / "manifest.json"
            )
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            print(f"Status: {manifest['run_status']}")
            print(f"Inputs: {len(manifest['input_files'])}")
            print(f"Outputs: {len(manifest['output_files'])}")
            print(f"Rows: {manifest['input_rows']:,} -> {manifest['output_rows']:,}")
            print(f"Excluded: {manifest['excluded_rows']:,}")
            print(f"Raw files unchanged: {manifest['raw_files_unchanged']}")
            return 0
    except (ProjectError, OSError, ValueError, KeyError) as exc:
        logger.error("Preprocessing command failed: %s", exc)
        return 2
    parser.error("Unknown command.")
    return 2
