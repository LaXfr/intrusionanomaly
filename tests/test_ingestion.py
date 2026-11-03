"""Tests using only small synthetic CSV fixtures, never CIC-IDS2017 samples."""

from __future__ import annotations

import csv
import hashlib
import json
from pathlib import Path

import pytest

from intrusion_intelligence.errors import (
    CSVInspectionError,
    DataLoadingError,
    DatasetDirectoryError,
    DatasetDiscoveryError,
    SchemaValidationError,
)
from intrusion_intelligence.ingestion import (
    build_metadata,
    discover_dataset_files,
    inspect_csv_file,
    inspect_dataset,
    iter_dataset_chunks,
    load_dataset,
    preview_dataset_file,
    render_ingestion_report,
    summarize_labels,
    validate_schemas,
    write_ingestion_report,
    write_metadata,
)


def _write_csv(
    path: Path,
    headers: list[str],
    rows: list[list[str]],
    *,
    encoding: str = "utf-8",
) -> Path:
    """Write a clearly synthetic, minimal flow-shaped CSV for one test."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding=encoding, newline="") as output:
        writer = csv.writer(output)
        writer.writerow(headers)
        writer.writerows(rows)
    return path


def _inspect(path: Path, root: Path):
    """Inspect one synthetic CSV relative to its temporary dataset root."""
    return inspect_csv_file(path, dataset_directory=root)


def test_discovery_is_recursive_filtered_and_deterministic(tmp_path: Path) -> None:
    root = tmp_path / "dataset"
    _write_csv(root / "z.csv", ["Feature", "Label"], [["1", "BENIGN"]])
    _write_csv(root / "nested" / "A.CSV", ["Feature", "Label"], [["2", "Attack"]])
    (root / "notes.txt").write_text("not a dataset", encoding="utf-8")
    (root / "ignored-directory").mkdir()

    paths = discover_dataset_files(root)

    assert [path.relative_to(root).as_posix() for path in paths] == [
        "nested/A.CSV",
        "z.csv",
    ]


def test_discovery_can_be_limited_to_top_level(tmp_path: Path) -> None:
    root = tmp_path / "dataset"
    _write_csv(root / "nested" / "inside.csv", ["Feature", "Label"], [["1", "BENIGN"]])

    with pytest.raises(DatasetDiscoveryError, match="No supported dataset files"):
        discover_dataset_files(root, recursive=False)


def test_discovery_reports_missing_and_empty_directories(tmp_path: Path) -> None:
    with pytest.raises(DatasetDirectoryError, match="does not exist"):
        discover_dataset_files(tmp_path / "missing")

    empty = tmp_path / "empty"
    empty.mkdir()
    with pytest.raises(DatasetDiscoveryError, match="No supported dataset files"):
        discover_dataset_files(empty)


def test_inspection_preserves_headers_and_calculates_streamed_checksum(
    tmp_path: Path,
) -> None:
    root = tmp_path / "dataset"
    path = _write_csv(
        root / "flows.csv",
        [" Flow ID ", "Label"],
        [["flow-1", "BENIGN"]],
    )

    result = _inspect(path, root)

    assert result.status == "valid"
    assert result.original_columns == (" Flow ID ", "Label")
    assert result.normalized_columns == ("Flow ID", "Label")
    assert result.label_columns == ("Label",)
    assert result.warnings
    assert result.sha256 == hashlib.sha256(path.read_bytes()).hexdigest()
    assert result.relative_path == "flows.csv"


def test_inspection_handles_bom_and_utf16_encodings(tmp_path: Path) -> None:
    root = tmp_path / "dataset"
    utf8_path = _write_csv(
        root / "utf8.csv",
        ["Feature", "Label"],
        [["1", "BENIGN"]],
        encoding="utf-8-sig",
    )
    utf16_path = _write_csv(
        root / "utf16.csv",
        ["Feature", "Label"],
        [["2", "Attack"]],
        encoding="utf-16",
    )

    assert _inspect(utf8_path, root).detected_encoding == "utf-8-sig"
    assert _inspect(utf16_path, root).detected_encoding == "utf-16"


def test_empty_and_malformed_files_are_reported(tmp_path: Path) -> None:
    empty = tmp_path / "empty.csv"
    empty.touch()
    malformed = tmp_path / "malformed.csv"
    malformed.write_text('Feature,"Label\n1,BENIGN\n', encoding="utf-8")

    empty_result = inspect_csv_file(empty)
    malformed_result = inspect_csv_file(malformed)

    assert empty_result.is_empty
    assert not empty_result.header_readable
    assert empty_result.status == "invalid"
    assert not malformed_result.header_readable
    assert malformed_result.status == "error"


def test_duplicate_and_normalized_collision_headers_get_position_aliases(
    tmp_path: Path,
) -> None:
    duplicate = _write_csv(
        tmp_path / "duplicate.csv",
        ["Feature", "Label", "Feature"],
        [["left", "BENIGN", "right"]],
    )
    collision = _write_csv(
        tmp_path / "collision.csv",
        ["Feature", " Feature ", "Label"],
        [["left", "right", "BENIGN"]],
    )

    duplicate_result = inspect_csv_file(duplicate)
    collision_result = inspect_csv_file(collision)

    assert duplicate_result.status == "valid"
    assert duplicate_result.original_columns == ("Feature", "Label", "Feature")
    assert duplicate_result.exact_duplicate_columns == ("Feature",)
    assert duplicate_result.normalized_collisions == ("Feature",)
    assert duplicate_result.internal_columns == (
        "Feature [source column 1]",
        "Label",
        "Feature [source column 3]",
    )
    assert collision_result.status == "valid"
    assert collision_result.original_columns == ("Feature", " Feature ", "Label")
    assert collision_result.normalized_collisions == ("Feature",)
    assert collision_result.internal_columns == (
        "Feature [source column 1]",
        "Feature [source column 2]",
        "Label",
    )
    assert collision_result.label_column_positions == (3,)


def test_ambiguous_label_collision_remains_invalid(tmp_path: Path) -> None:
    path = _write_csv(
        tmp_path / "ambiguous-label.csv",
        ["Feature", "Label", " Label"],
        [["1", "BENIGN", "Attack"]],
    )

    result = inspect_csv_file(path)

    assert result.status == "invalid"
    assert result.label_columns == ("Label", " Label")
    assert result.label_column_positions == (2, 3)
    assert result.label_column is None
    assert result.internal_label_column is None
    assert any("ambiguous" in message for message in result.errors)


def test_missing_label_column_is_invalid_and_whitespace_label_is_identified(
    tmp_path: Path,
) -> None:
    missing = _write_csv(
        tmp_path / "missing.csv",
        ["Feature", "Category"],
        [["1", "BENIGN"]],
    )
    whitespace_label = _write_csv(
        tmp_path / "whitespace.csv",
        ["Feature", " Label"],
        [["1", "BENIGN"]],
    )

    missing_result = inspect_csv_file(missing)
    label_result = inspect_csv_file(whitespace_label)

    assert missing_result.status == "invalid"
    assert any("No label column" in message for message in missing_result.errors)
    assert label_result.status == "valid"
    assert label_result.label_columns == (" Label",)


def test_nonexistent_inspection_target_raises_clear_error(tmp_path: Path) -> None:
    with pytest.raises(CSVInspectionError, match="does not exist"):
        inspect_csv_file(tmp_path / "missing.csv")


def test_schema_validation_distinguishes_matching_and_order_only_files(
    tmp_path: Path,
) -> None:
    root = tmp_path / "dataset"
    first = _write_csv(root / "a.csv", ["A", "B", "Label"], [["1", "2", "BENIGN"]])
    second = _write_csv(root / "b.csv", ["Label", "A", "B"], [["Attack", "3", "4"]])

    result = validate_schemas([_inspect(first, root), _inspect(second, root)])

    assert result.is_compatible
    assert result.matching_files == ("a.csv",)
    assert result.order_only_files == ("b.csv",)
    assert result.comparisons[1].column_order_differs


def test_schema_validation_reports_missing_and_additional_columns(
    tmp_path: Path,
) -> None:
    root = tmp_path / "dataset"
    first = _write_csv(root / "a.csv", ["A", "B", "Label"], [["1", "2", "BENIGN"]])
    second = _write_csv(root / "b.csv", ["B", "C", "Label"], [["2", "3", "Attack"]])

    result = validate_schemas([_inspect(first, root), _inspect(second, root)])
    comparison = result.comparisons[1]

    assert not result.is_compatible
    assert comparison.missing_columns == ("A",)
    assert comparison.additional_columns == ("C",)
    assert comparison.relation == "different_columns"


def test_schema_validation_reports_cross_file_whitespace_conflicts(
    tmp_path: Path,
) -> None:
    root = tmp_path / "dataset"
    first = _write_csv(root / "a.csv", ["Feature", "Label"], [["1", "BENIGN"]])
    second = _write_csv(root / "b.csv", ["Feature", " Label"], [["2", "Attack"]])

    result = validate_schemas([_inspect(first, root), _inspect(second, root)])

    assert not result.is_compatible
    comparison = result.comparisons[1]
    assert comparison.relation == "conflicting_headers"
    assert comparison.normalized_name_conflicts


def test_duplicate_headers_require_same_source_order_across_files(
    tmp_path: Path,
) -> None:
    root = tmp_path / "dataset"
    first = _write_csv(
        root / "a.csv",
        ["Feature", "Feature", "Label"],
        [["a1", "a2", "BENIGN"]],
    )
    same_schema = _write_csv(
        root / "b.csv",
        ["Feature", "Feature", "Label"],
        [["b1", "b2", "Attack"]],
    )
    reordered = _write_csv(
        root / "c.csv",
        ["Feature", "Label", "Feature"],
        [["c1", "Attack", "c2"]],
    )

    result = validate_schemas(
        [_inspect(first, root), _inspect(same_schema, root), _inspect(reordered, root)]
    )

    assert result.matching_files == ("a.csv", "b.csv")
    assert result.incompatible_files == ("c.csv",)
    assert result.comparisons[2].column_order_differs
    assert any("same source column order" in e for e in result.comparisons[2].errors)


def test_standard_loading_preserves_labels_and_reports_exact_rows(
    tmp_path: Path,
) -> None:
    root = tmp_path / "dataset"
    _write_csv(
        root / "flows.csv",
        ["Feature", "Label"],
        [["1", "BENIGN"], ["2", "NA"], ["3", "Web Attack – XSS"]],
    )

    loaded = load_dataset(root)

    assert loaded.metadata.rows_loaded == 3
    assert loaded.metadata.scan_coverage == "complete"
    assert loaded.metadata.file_stats[0].rows_loaded == 3
    assert loaded.data["Label"].tolist() == ["BENIGN", "NA", "Web Attack – XSS"]


def test_standard_loading_aligns_order_only_files_without_renaming(
    tmp_path: Path,
) -> None:
    root = tmp_path / "dataset"
    _write_csv(root / "a.csv", ["Feature", "Label"], [["1", "BENIGN"]])
    _write_csv(root / "b.csv", ["Label", "Feature"], [["Attack", "2"]])

    loaded = load_dataset(root)

    assert loaded.metadata.rows_loaded == 2
    assert list(loaded.data.columns) == ["Feature", "Label"]
    assert loaded.data.to_dict(orient="records") == [
        {"Feature": 1, "Label": "BENIGN"},
        {"Feature": 2, "Label": "Attack"},
    ]


@pytest.mark.parametrize(
    "headers",
    [
        ["Feature", "Feature", "Label"],
        ["Feature", " Feature", "Label"],
    ],
)
def test_standard_loading_preserves_distinct_values_under_colliding_headers(
    tmp_path: Path,
    headers: list[str],
) -> None:
    root = tmp_path / "dataset"
    _write_csv(
        root / "flows.csv",
        headers,
        [["first value", "different value", "BENIGN"]],
    )

    loaded = load_dataset(root)

    first_internal = "Feature [source column 1]"
    second_internal = "Feature [source column 2]"
    assert loaded.data[first_internal].tolist() == ["first value"]
    assert loaded.data[second_internal].tolist() == ["different value"]
    assert loaded.data["Label"].tolist() == ["BENIGN"]


def test_standard_loading_rejects_incompatible_files(tmp_path: Path) -> None:
    root = tmp_path / "dataset"
    _write_csv(root / "a.csv", ["Feature", "Label"], [["1", "BENIGN"]])
    _write_csv(root / "b.csv", ["Other", "Label"], [["2", "Attack"]])

    with pytest.raises(SchemaValidationError, match="Missing columns"):
        load_dataset(root)


def test_chunked_loading_yields_bounded_sequential_batches(
    tmp_path: Path,
) -> None:
    root = tmp_path / "dataset"
    _write_csv(
        root / "flows.csv",
        ["Label", "Feature"],
        [[f"label-{index}", str(index)] for index in range(5)],
    )

    chunks = list(iter_dataset_chunks(root, chunk_size=2))

    assert [len(chunk.data) for chunk in chunks] == [2, 2, 1]
    assert [chunk.chunk_index for chunk in chunks] == [0, 1, 2]
    assert [chunk.start_row for chunk in chunks] == [0, 2, 4]
    assert all(chunk.label_column == "Label" for chunk in chunks)
    assert chunks[-1].data["Label"].tolist() == ["label-4"]


def test_invalid_chunk_size_and_empty_input_are_rejected(tmp_path: Path) -> None:
    root = tmp_path / "dataset"
    root.mkdir()
    with pytest.raises(DataLoadingError, match="greater than zero"):
        list(iter_dataset_chunks(root, chunk_size=0))
    with pytest.raises(DatasetDiscoveryError, match="No supported dataset files"):
        load_dataset(root)


def test_loading_rejects_invalid_path_and_malformed_rows(tmp_path: Path) -> None:
    root = tmp_path / "dataset"
    root.mkdir()
    with pytest.raises(DataLoadingError, match="does not exist"):
        load_dataset(root, files="missing.csv")

    malformed = root / "malformed.csv"
    malformed.write_text('Feature,Label\n1,BENIGN\n2,"unfinished', encoding="utf-8")
    with pytest.raises(DataLoadingError, match="Unable to read CSV file"):
        load_dataset(root, files=malformed)


def test_preview_reads_only_the_requested_number_of_rows(tmp_path: Path) -> None:
    root = tmp_path / "dataset"
    path = _write_csv(
        root / "flows.csv",
        ["Feature", "Label"],
        [[str(index), f"label-{index}"] for index in range(5)],
    )

    preview = preview_dataset_file(path, row_count=2)

    assert len(preview) == 2
    assert preview["Label"].tolist() == ["label-0", "label-1"]
    with pytest.raises(DataLoadingError, match="greater than zero"):
        preview_dataset_file(path, row_count=0)


def test_label_summaries_mark_complete_and_partial_scans(tmp_path: Path) -> None:
    root = tmp_path / "dataset"
    _write_csv(
        root / "flows.csv",
        ["Feature", "Label"],
        [
            ["1", "BENIGN"],
            ["2", "DoS Hulk"],
            ["3", "BENIGN"],
            ["4", "NA"],
            ["5", "DoS Hulk"],
        ],
    )

    complete = summarize_labels(root, chunk_size=2)
    partial = summarize_labels(root, chunk_size=2, max_rows=3)

    assert complete.coverage == "complete"
    assert complete.rows_scanned == 5
    assert {item.label: item.count for item in complete.label_counts} == {
        "BENIGN": 2,
        "DoS Hulk": 2,
        "NA": 1,
    }
    assert partial.coverage == "partial"
    assert partial.rows_scanned == 3
    assert {item.label: item.count for item in partial.label_counts} == {
        "BENIGN": 2,
        "DoS Hulk": 1,
    }


def test_metadata_and_reports_distinguish_metadata_only_from_row_scans(
    tmp_path: Path,
) -> None:
    root = tmp_path / "dataset"
    _write_csv(root / "flows.csv", ["Feature", "Label"], [["1", "BENIGN"]])
    result = inspect_dataset(
        root,
        dataset_name="Synthetic test fixture",
        project_root=tmp_path,
    )
    metadata_only = build_metadata(result)
    json_path = write_metadata(result, tmp_path / "metadata" / "test.json")
    report_path = write_ingestion_report(result, tmp_path / "reports" / "test.md")
    partial_summary = summarize_labels(root, chunk_size=1, max_rows=1)
    scanned_metadata = build_metadata(result, partial_summary)

    loaded_metadata = json.loads(json_path.read_text(encoding="utf-8"))
    report_text = report_path.read_text(encoding="utf-8")
    assert metadata_only["scan"]["coverage"] == "metadata_only"
    assert metadata_only["scan"]["rows_scanned"] is None
    assert loaded_metadata["files"][0]["sha256"]
    assert loaded_metadata["discovery"]["successfully_inspected_files"] == 1
    assert "No data rows were scanned" in report_text
    assert scanned_metadata["scan"]["coverage"] == "partial"
    assert scanned_metadata["scan"]["rows_scanned"] == 1
    assert "BENIGN" not in report_text


def test_missing_dataset_produces_an_unavailable_not_successful_report(
    tmp_path: Path,
) -> None:
    result = inspect_dataset(tmp_path / "missing", project_root=tmp_path)
    report = render_ingestion_report(result)

    assert result.status == "unavailable"
    assert not result.files
    assert result.schema_validation.reference_file is None
    assert str(tmp_path) not in result.errors[0]
    assert "No supported files discovered" in report
    assert "Files successfully inspected:** 0" in report


def test_metadata_counts_schema_incompatibility_as_rejected_file(
    tmp_path: Path,
) -> None:
    root = tmp_path / "dataset"
    _write_csv(root / "a.csv", ["Feature", "Label"], [["1", "BENIGN"]])
    _write_csv(root / "b.csv", ["Other", "Label"], [["2", "Attack"]])

    result = inspect_dataset(root, project_root=tmp_path, compute_checksums=False)
    metadata = build_metadata(result)

    assert metadata["discovery"]["successfully_inspected_files"] == 2
    assert metadata["discovery"]["rejected_files"] == 1
    assert metadata["schema_validation"]["incompatible_files"] == ["b.csv"]


def test_metadata_preserves_position_trace_for_colliding_headers(
    tmp_path: Path,
) -> None:
    root = tmp_path / "dataset"
    _write_csv(
        root / "flows.csv",
        ["Feature", "Feature", "Label"],
        [["first value", "different value", "BENIGN"]],
    )

    result = inspect_dataset(root, project_root=tmp_path)
    metadata = build_metadata(result)
    file_metadata = metadata["files"][0]

    assert file_metadata["original_columns"] == ["Feature", "Feature", "Label"]
    assert file_metadata["internal_columns"] == [
        "Feature [source column 1]",
        "Feature [source column 2]",
        "Label",
    ]
    assert file_metadata["column_bindings"][1] == {
        "source_position": 2,
        "source_name": "Feature",
        "normalized_name": "Feature",
        "internal_name": "Feature [source column 2]",
    }
