"""CLI tests over isolated synthetic CSV data only."""

from __future__ import annotations

import csv
import json
from pathlib import Path

import pytest

from intrusion_intelligence import __main__ as package_cli
from intrusion_intelligence.ingestion.cli import main


def _configure_synthetic_dataset(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[Path, Path, Path]:
    """Point CLI configuration at temporary, explicitly synthetic test data."""
    raw_root = tmp_path / "raw"
    dataset_directory = raw_root / "CIC-IDS2017"
    dataset_directory.mkdir(parents=True)
    metadata_directory = tmp_path / "metadata"
    report_directory = tmp_path / "reports"

    monkeypatch.setenv("NII_RAW_DATA_DIR", str(raw_root))
    monkeypatch.setenv("NII_DATASET_DIRECTORY", "CIC-IDS2017")
    monkeypatch.setenv("NII_DATASET_NAME", "Synthetic-Test-Data")
    monkeypatch.setenv("NII_DATASET_METADATA_DIR", str(metadata_directory))
    monkeypatch.setenv("NII_INGESTION_REPORT_DIR", str(report_directory))
    monkeypatch.setenv("NII_SUPPORTED_FILE_EXTENSIONS", ".csv")
    monkeypatch.setenv("NII_LABEL_CANDIDATES", "Label")
    monkeypatch.setenv("NII_CSV_ENCODING", "auto")
    monkeypatch.setenv("NII_CHUNK_SIZE", "2")

    with (dataset_directory / "synthetic.csv").open(
        "w",
        encoding="utf-8",
        newline="",
    ) as output:
        writer = csv.writer(output)
        writer.writerow(["Feature", "Label"])
        writer.writerows(
            [["1", "BENIGN"], ["2", "Synthetic Attack"], ["3", "BENIGN"]]
        )
    return dataset_directory, metadata_directory, report_directory


def test_cli_inspection_writes_json_and_markdown_results(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _, metadata_directory, report_directory = _configure_synthetic_dataset(
        tmp_path,
        monkeypatch,
    )

    exit_code = main(["inspect"])

    metadata_path = metadata_directory / "Synthetic-Test-Data_ingestion.json"
    report_path = report_directory / "Synthetic-Test-Data_ingestion.md"
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    report = report_path.read_text(encoding="utf-8")
    output = capsys.readouterr().out
    assert exit_code == 0
    assert metadata["ingestion_status"] == "valid"
    assert metadata["scan"]["coverage"] == "metadata_only"
    assert metadata["scan"]["rows_scanned"] is None
    assert "Files discovered: 1" in output
    assert "No data rows were scanned" in report


def test_cli_preview_loads_only_requested_rows(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _configure_synthetic_dataset(tmp_path, monkeypatch)

    exit_code = main(["preview", "--file", "synthetic.csv", "--rows", "1"])

    output = capsys.readouterr().out
    assert exit_code == 0
    assert "BENIGN" in output
    assert "Synthetic Attack" not in output


def test_cli_chunked_load_writes_actual_loading_summary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _, metadata_directory, report_directory = _configure_synthetic_dataset(
        tmp_path,
        monkeypatch,
    )

    exit_code = main(["load", "--chunk-size", "1"])

    metadata_path = metadata_directory / "Synthetic-Test-Data_ingestion.json"
    report_path = report_directory / "Synthetic-Test-Data_ingestion.md"
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    report = report_path.read_text(encoding="utf-8")
    output = capsys.readouterr().out
    assert exit_code == 0
    assert metadata["loading"]["strategy"] == "chunked"
    assert metadata["loading"]["rows_loaded"] == 3
    assert metadata["scan"]["coverage"] == "complete"
    assert metadata["scan"]["rows_scanned"] == 3
    assert "Streamed 3 row(s)" in output
    assert "Exact rows loaded:** 3" in report


def test_cli_reports_configuration_errors_without_a_traceback(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    exit_code = main(["--config", str(tmp_path / "missing.toml"), "inspect"])

    assert exit_code == 2
    assert "Unable to read configuration file" in caplog.text
    assert "Traceback" not in caplog.text


def test_package_entrypoint_runs_full_label_summary(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    arguments: list[str] = []

    def capture_arguments(argv: list[str]) -> int:
        arguments.extend(argv)
        return 0

    monkeypatch.setattr(package_cli, "ingestion_main", capture_arguments)

    assert package_cli.main() == 0
    assert arguments == ["summary", "--label-counts"]


def test_cli_escapes_console_unsafe_label_without_changing_metadata(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    dataset_directory, metadata_directory, _ = _configure_synthetic_dataset(
        tmp_path,
        monkeypatch,
    )
    with (dataset_directory / "unicode.csv").open(
        "w",
        encoding="utf-8",
        newline="",
    ) as output:
        writer = csv.writer(output)
        writer.writerow(["Feature", "Label"])
        writer.writerow(["4", "Web Attack \ufffd XSS"])

    exit_code = main(["summary", "--label-counts"])

    output = capsys.readouterr().out
    metadata = json.loads(
        (metadata_directory / "Synthetic-Test-Data_ingestion.json").read_text(
            encoding="utf-8"
        )
    )
    counts = {
        item["label"]: item["count"]
        for item in metadata["scan"]["label_category_counts"]
    }
    assert exit_code == 0
    assert "'Web Attack \\ufffd XSS': 1" in output
    assert counts["Web Attack \ufffd XSS"] == 1
