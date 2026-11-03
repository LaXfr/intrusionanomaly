"""Command-line interface for CIC-IDS2017 dataset inspection and loading."""

from __future__ import annotations

import argparse
import logging
from collections.abc import Sequence
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from intrusion_intelligence.config import ProjectConfig, load_config
from intrusion_intelligence.errors import (
    DataLoadingError,
    ProjectError,
)
from intrusion_intelligence.ingestion.discovery import discover_dataset_files
from intrusion_intelligence.ingestion.loader import (
    iter_dataset_chunks,
    load_dataset,
    preview_dataset_file,
)
from intrusion_intelligence.ingestion.metadata import (
    write_ingestion_report,
    write_metadata,
)
from intrusion_intelligence.ingestion.models import (
    DatasetInspectionResult,
    FileLoadStats,
    LabelSummary,
    LoadingMetadata,
)
from intrusion_intelligence.ingestion.service import inspect_dataset
from intrusion_intelligence.ingestion.summary import summarize_labels
from intrusion_intelligence.logging_config import configure_logging

logger = logging.getLogger(__name__)


def build_parser() -> argparse.ArgumentParser:
    """Create argument parsing for the focused Phase 02 CLI."""
    parser = argparse.ArgumentParser(
        prog="intrusion-ingest",
        description="Inspect and load labelled network-flow CSV datasets.",
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=Path("configs/project.toml"),
        help="Project TOML configuration path.",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("inspect", help="Inspect files and write metadata/report.")
    commands.add_parser(
        "validate",
        help="Inspect files and return a failing status for invalid schemas.",
    )

    summary_parser = commands.add_parser(
        "summary",
        help="Write metadata; optionally scan label counts in chunks.",
    )
    summary_parser.add_argument(
        "--label-counts",
        action="store_true",
        help="Scan label values using the configured chunk size.",
    )
    summary_parser.add_argument(
        "--max-rows",
        type=int,
        default=None,
        help="Stop after this many rows and mark the summary partial.",
    )
    summary_parser.add_argument(
        "--chunk-size",
        type=int,
        default=None,
        help="Override the configured chunk size for label counting.",
    )

    preview_parser = commands.add_parser(
        "preview",
        help="Read a bounded preview from one CSV file.",
    )
    preview_parser.add_argument(
        "--file", required=True, help="Discovered file name or relative path."
    )
    preview_parser.add_argument(
        "--rows", type=int, default=10, help="Number of preview rows."
    )

    load_parser = commands.add_parser(
        "load",
        help="Load compatible files, or stream them in chunks.",
    )
    load_parser.add_argument(
        "--file",
        nargs="+",
        default=None,
        help=(
            "Optional discovered file names or paths; defaults to all "
            "compatible files."
        ),
    )
    load_parser.add_argument(
        "--strategy",
        choices=("standard", "chunked"),
        default=None,
        help="Override the configured loading strategy.",
    )
    load_parser.add_argument(
        "--chunk-size",
        type=int,
        default=None,
        help=(
            "Chunk size; specifying it selects chunked loading unless strategy is set."
        ),
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run one ingestion command and return a process status code."""
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        config = load_config(args.config)
        configure_logging(config.logging)
        if args.command in {"inspect", "validate"}:
            result = _inspect_and_write(config)
            print(f"Inspection status: {result.status}")
            print(f"Files discovered: {len(result.files)}")
            print(f"Metadata: {_metadata_path(config)}")
            print(f"Report: {_report_path(config)}")
            return 0 if result.status == "valid" else 1
        if args.command == "summary":
            return _run_summary(config, args)
        if args.command == "preview":
            return _run_preview(config, args.file, args.rows)
        if args.command == "load":
            return _run_load(config, args.file, args.strategy, args.chunk_size)
    except ProjectError as exc:
        logger.error("%s", exc)
        return 2
    except (OSError, ValueError) as exc:
        logger.error("Command failed: %s", exc)
        return 2

    parser.error(f"Unsupported command: {args.command}")
    return 2


def _inspect_and_write(
    config: ProjectConfig,
    label_summary: LabelSummary | None = None,
    loading_metadata: LoadingMetadata | None = None,
    *,
    compute_checksums: bool = True,
) -> DatasetInspectionResult:
    """Inspect configured inputs and persist actual JSON/Markdown results."""
    result = inspect_dataset(
        config.dataset.directory,
        dataset_name=config.dataset.name,
        source_reference=config.dataset.source_url,
        supported_extensions=config.dataset.supported_extensions,
        label_candidates=config.dataset.label_candidates,
        recursive=config.dataset.recursive_discovery,
        encoding=config.ingestion.csv_encoding,
        project_root=config.project_root,
        compute_checksums=compute_checksums,
    )
    write_metadata(result, _metadata_path(config), label_summary, loading_metadata)
    write_ingestion_report(
        result,
        _report_path(config),
        label_summary,
        loading_metadata,
    )
    return result


def _run_summary(config: ProjectConfig, args: argparse.Namespace) -> int:
    label_summary = None
    if args.label_counts:
        label_summary = summarize_labels(
            config.dataset.directory,
            chunk_size=(
                args.chunk_size
                if args.chunk_size is not None
                else config.ingestion.chunk_size
            ),
            max_rows=args.max_rows,
            supported_extensions=config.dataset.supported_extensions,
            label_candidates=config.dataset.label_candidates,
            encoding=config.ingestion.csv_encoding,
            recursive=config.dataset.recursive_discovery,
        )
        print(
            f"Label scan: {label_summary.coverage}, "
            f"{label_summary.rows_scanned} exact row(s)"
        )
        for item in label_summary.label_counts:
            print(f"{ascii(item.label)}: {item.count}")
    result = _inspect_and_write(config, label_summary)
    print(f"Inspection status: {result.status}")
    print(f"Metadata: {_metadata_path(config)}")
    print(f"Report: {_report_path(config)}")
    return 0 if result.status == "valid" else 1


def _run_preview(config: ProjectConfig, selector: str, rows: int) -> int:
    files = _select_files(config, [selector])
    frame = preview_dataset_file(
        files[0],
        label_candidates=config.dataset.label_candidates,
        encoding=config.ingestion.csv_encoding,
        row_count=rows,
    )
    print(frame.to_string(index=False))
    return 0


def _run_load(
    config: ProjectConfig,
    selectors: list[str] | None,
    strategy_override: str | None,
    chunk_size: int | None,
) -> int:
    selected_files = _select_files(config, selectors) if selectors else None
    if strategy_override == "standard" and chunk_size is not None:
        raise DataLoadingError(
            "A chunk size cannot be used with the standard loading strategy."
        )
    strategy = strategy_override or (
        "chunked"
        if chunk_size is not None
        else config.ingestion.loading_strategy
    )
    if strategy == "standard":
        loaded = load_dataset(
            config.dataset.directory,
            files=selected_files,
            supported_extensions=config.dataset.supported_extensions,
            label_candidates=config.dataset.label_candidates,
            encoding=config.ingestion.csv_encoding,
            recursive=config.dataset.recursive_discovery,
        )
        print(
            f"Loaded {loaded.metadata.rows_loaded} row(s) from "
            f"{len(loaded.metadata.files)} file(s); "
            f"{len(loaded.metadata.columns)} columns."
        )
        result = _inspect_and_write(
            config,
            loading_metadata=loaded.metadata,
            compute_checksums=False,
        )
        print(f"Metadata: {_metadata_path(config)}")
        print(f"Report: {_report_path(config)}")
        return 0 if result.status == "valid" else 1

    rows_loaded = 0
    started_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    sources = selected_files or discover_dataset_files(
        config.dataset.directory,
        supported_extensions=config.dataset.supported_extensions,
        recursive=config.dataset.recursive_discovery,
    )
    file_rows: Counter[str] = Counter()
    file_names = [
        path.relative_to(config.dataset.directory).as_posix() for path in sources
    ]
    columns: tuple[str, ...] = ()
    selected_chunk_size = (
        chunk_size
        if chunk_size is not None
        else config.ingestion.chunk_size
    )
    for chunk in iter_dataset_chunks(
        config.dataset.directory,
        files=sources,
        chunk_size=selected_chunk_size,
        supported_extensions=config.dataset.supported_extensions,
        label_candidates=config.dataset.label_candidates,
        encoding=config.ingestion.csv_encoding,
        recursive=config.dataset.recursive_discovery,
    ):
        rows_loaded += len(chunk.data)
        file_rows[chunk.source_file] += len(chunk.data)
        if not columns:
            columns = tuple(str(column) for column in chunk.data.columns)
    loading_metadata = LoadingMetadata(
        strategy="chunked",
        started_at_utc=started_at,
        completed_at_utc=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        files=tuple(file_names),
        rows_loaded=rows_loaded,
        columns=columns,
        file_stats=tuple(
            FileLoadStats(file=file_name, rows_loaded=file_rows[file_name])
            for file_name in file_names
        ),
        scan_coverage="complete",
        chunk_size=selected_chunk_size,
    )
    print(
        f"Streamed {rows_loaded} row(s) from {len(file_names)} file(s) "
        f"using chunks of {selected_chunk_size}."
    )
    result = _inspect_and_write(
        config,
        loading_metadata=loading_metadata,
        compute_checksums=False,
    )
    print(f"Metadata: {_metadata_path(config)}")
    print(f"Report: {_report_path(config)}")
    return 0 if result.status == "valid" else 1


def _select_files(config: ProjectConfig, selectors: list[str]) -> tuple[Path, ...]:
    """Resolve CLI selectors only to files discovered beneath the dataset root."""
    discovered = discover_dataset_files(
        config.dataset.directory,
        supported_extensions=config.dataset.supported_extensions,
        recursive=config.dataset.recursive_discovery,
    )
    selected: list[Path] = []
    for selector in selectors:
        requested = Path(selector)
        direct = requested.expanduser().resolve() if requested.is_absolute() else None
        matches = [
            path
            for path in discovered
            if path == direct
            or path.name.casefold() == selector.casefold()
            or path.relative_to(config.dataset.directory).as_posix().casefold()
            == selector.replace("\\", "/").casefold()
        ]
        if not matches:
            raise DataLoadingError(f"Selected file was not discovered: {selector}")
        if len(matches) > 1:
            raise DataLoadingError(
                f"File selector is ambiguous; use a relative path: {selector}"
            )
        selected.append(matches[0])
    return tuple(selected)


def _metadata_path(config: ProjectConfig) -> Path:
    """Return the configured JSON metadata destination."""
    return config.paths.dataset_metadata / (
        f"{_safe_stem(config.dataset.name)}_ingestion.json"
    )


def _report_path(config: ProjectConfig) -> Path:
    """Return the configured Markdown report destination."""
    return config.paths.ingestion_reports / (
        f"{_safe_stem(config.dataset.name)}_ingestion.md"
    )


def _safe_stem(value: str) -> str:
    """Create a conservative filename stem from the dataset display name."""
    cleaned = "".join(
        character if character.isalnum() or character in "-_" else "_"
        for character in value
    )
    return cleaned.strip("-_") or "dataset"
