"""Bounded CSV header inspection and streaming file-integrity checks."""

from __future__ import annotations

import codecs
import csv
import hashlib
import json
import logging
from collections import Counter
from pathlib import Path
from typing import Sequence

from intrusion_intelligence.errors import CSVInspectionError
from intrusion_intelligence.ingestion.models import FileInspection

logger = logging.getLogger(__name__)
_CHECKSUM_BLOCK_SIZE = 1024 * 1024
_ENCODING_SAMPLE_SIZE = 64 * 1024


def inspect_csv_file(
    file_path: str | Path,
    *,
    dataset_directory: str | Path | None = None,
    label_candidates: Sequence[str] = ("Label",),
    require_label: bool = True,
    encoding: str = "auto",
    compute_checksum: bool = True,
) -> FileInspection:
    """Inspect a CSV header and optionally hash the file in bounded blocks.

    Header inspection retains every original column name. Whitespace-stripped
    names are included only as a comparison representation; no source file is
    changed and no columns are renamed or discarded.

    Args:
        file_path: CSV file to inspect.
        dataset_directory: Root used to record a relative file path.
        label_candidates: Header names accepted as the dataset label column.
        encoding: ``"auto"`` detects common encodings; another codec name forces it.
        compute_checksum: Hash the entire file incrementally when true.

    Raises:
        CSVInspectionError: If the path does not identify a readable regular file.
    """
    path = Path(file_path).expanduser()
    if not path.exists() or not path.is_file():
        raise CSVInspectionError(f"CSV file does not exist or is not a file: {path}")

    resolved_path = path.resolve()
    try:
        file_size = resolved_path.stat().st_size
    except OSError as exc:
        raise CSVInspectionError(f"Unable to inspect CSV file: {path}") from exc

    relative_path = _relative_path(resolved_path, dataset_directory)
    warnings: list[str] = []
    errors: list[str] = []
    detected_encoding: str | None = None
    checksum: str | None = None
    original_columns: tuple[str, ...] = ()
    normalized_columns: tuple[str, ...] = ()
    internal_columns: tuple[str, ...] = ()
    exact_duplicates: tuple[str, ...] = ()
    normalized_collisions: tuple[str, ...] = ()
    label_columns: tuple[str, ...] = ()
    label_column_positions: tuple[int, ...] = ()
    schema_fingerprint: str | None = None
    header_readable = False
    is_empty = file_size == 0

    logger.info("Inspecting CSV file %s", relative_path)

    try:
        detected_encoding, encoding_warning = _select_encoding(resolved_path, encoding)
        if encoding_warning:
            warnings.append(encoding_warning)
        if compute_checksum:
            checksum = _sha256_file(resolved_path)
    except CSVInspectionError as exc:
        errors.append(str(exc))
    except (OSError, LookupError) as exc:
        errors.append(
            f"Unable to read file integrity metadata: {exc.__class__.__name__}."
        )

    if is_empty:
        errors.append("File contains no bytes.")
    elif detected_encoding is not None:
        try:
            original_columns = _read_header(resolved_path, detected_encoding)
            header_readable = True
        except (csv.Error, OSError, UnicodeError) as exc:
            errors.append(f"CSV header is unreadable ({exc.__class__.__name__}).")

    if header_readable:
        normalized_columns = tuple(column.strip() for column in original_columns)
        internal_columns = _internal_column_names(
            original_columns,
            normalized_columns,
        )
        exact_duplicates = _duplicates(original_columns)
        normalized_collisions = _duplicates(normalized_columns)
        schema_fingerprint = _fingerprint(original_columns)

        if any(
            original != normalized
            for original, normalized in zip(original_columns, normalized_columns)
        ):
            warnings.append(
                "One or more headers contain leading or trailing whitespace."
            )
        if any(not column for column in normalized_columns):
            errors.append(
                "Header contains an empty column name after whitespace normalization."
            )
        if exact_duplicates:
            warnings.append(
                "Duplicate source headers are preserved with position-specific "
                "internal names: "
                + ", ".join(repr(value) for value in exact_duplicates)
            )
        if normalized_collisions:
            warnings.append(
                "Source headers share a whitespace-normalized name and are "
                "preserved with position-specific internal names: "
                + ", ".join(repr(value) for value in normalized_collisions)
            )
        if len(original_columns) < 2:
            errors.append(
                "Header must contain at least one feature column and a label column."
            )

        candidate_keys = {
            candidate.strip().casefold() for candidate in label_candidates
        }
        label_column_positions = tuple(
            position
            for position, normalized in enumerate(normalized_columns, start=1)
            if normalized.casefold() in candidate_keys
        )
        label_columns = tuple(
            original_columns[position - 1]
            for position in label_column_positions
        )
        if not label_columns and require_label:
            errors.append(
                "No label column found; expected one of: "
                + ", ".join(repr(candidate) for candidate in label_candidates)
            )
        elif not label_columns:
            warnings.append("No label column was found; labels are optional for this inspection.")
        elif len(label_columns) > 1:
            errors.append(
                "Label column is ambiguous; matching headers are: "
                + ", ".join(repr(value) for value in label_columns)
            )

    io_error = any(
        message.startswith(
            (
                "Unable to read file integrity metadata",
                "CSV header is unreadable",
            )
        )
        for message in errors
    ) or (not is_empty and detected_encoding is None)
    status = "error" if io_error else ("valid" if not errors else "invalid")
    result = FileInspection(
        path=resolved_path,
        relative_path=relative_path,
        file_name=resolved_path.name,
        size_bytes=file_size,
        extension=resolved_path.suffix.lower(),
        sha256=checksum,
        detected_encoding=detected_encoding,
        is_empty=is_empty,
        header_readable=header_readable,
        original_columns=original_columns,
        normalized_columns=normalized_columns,
        internal_columns=internal_columns,
        exact_duplicate_columns=exact_duplicates,
        normalized_collisions=normalized_collisions,
        label_columns=label_columns,
        label_column_positions=label_column_positions,
        schema_fingerprint=schema_fingerprint,
        status=status,
        warnings=tuple(warnings),
        errors=tuple(errors),
    )
    logger.info(
        "Inspected %s: status=%s columns=%d encoding=%s",
        relative_path,
        status,
        len(original_columns),
        detected_encoding or "unknown",
    )
    return result


def _relative_path(file_path: Path, dataset_directory: str | Path | None) -> str:
    """Return a dataset-relative path, falling back to the filename."""
    if dataset_directory is None:
        return file_path.name
    root = Path(dataset_directory).expanduser().resolve()
    try:
        return file_path.relative_to(root).as_posix()
    except ValueError:
        return file_path.name


def _select_encoding(file_path: Path, requested: str) -> tuple[str, str | None]:
    """Select an encoding using a bounded byte sample and explicit fallback."""
    if requested.strip().lower() != "auto":
        try:
            return codecs.lookup(requested).name, None
        except LookupError as exc:
            raise CSVInspectionError(f"Unknown CSV encoding: {requested}") from exc

    with file_path.open("rb") as source:
        sample = source.read(_ENCODING_SAMPLE_SIZE)

    if sample.startswith(codecs.BOM_UTF8):
        return "utf-8-sig", None
    if sample.startswith(codecs.BOM_UTF32_LE) or sample.startswith(codecs.BOM_UTF32_BE):
        return "utf-32", None
    if sample.startswith(codecs.BOM_UTF16_LE) or sample.startswith(codecs.BOM_UTF16_BE):
        return "utf-16", None

    try:
        sample.decode("utf-8")
        return "utf-8", None
    except UnicodeDecodeError:
        for fallback in ("cp1252", "latin-1"):
            try:
                sample.decode(fallback)
                return (
                    fallback,
                    "UTF-8 decoding failed for the sample; "
                    f"{fallback} was selected as a fallback.",
                )
            except UnicodeDecodeError:
                continue
    return (
        "utf-8",
        "Encoding could not be inferred from the sample; UTF-8 was selected.",
    )


def _read_header(file_path: Path, encoding: str) -> tuple[str, ...]:
    """Read the first non-blank CSV record as the source header."""
    with file_path.open("r", encoding=encoding, newline="") as source:
        reader = csv.reader(source, strict=True)
        for row in reader:
            if row:
                return tuple(row)
    raise csv.Error("No header row was found.")


def _sha256_file(file_path: Path) -> str:
    """Calculate SHA-256 without holding the source file in memory."""
    digest = hashlib.sha256()
    with file_path.open("rb") as source:
        for block in iter(lambda: source.read(_CHECKSUM_BLOCK_SIZE), b""):
            digest.update(block)
    return digest.hexdigest()


def _duplicates(values: Sequence[str]) -> tuple[str, ...]:
    """Return each duplicated value once, in first-seen order."""
    counts = Counter(values)
    return tuple(dict.fromkeys(value for value in values if counts[value] > 1))


def _internal_column_names(
    original_columns: Sequence[str],
    normalized_columns: Sequence[str],
) -> tuple[str, ...]:
    """Disambiguate colliding headers while retaining source names separately.

    Non-colliding names retain their exact source spelling. Every member of a
    whitespace-normalized collision group receives an internal alias tied to
    its 1-based source position. Original names remain available unchanged in
    ``FileInspection.original_columns``.
    """
    normalized_counts = Counter(normalized_columns)
    reserved_names = set(original_columns)
    internal_names: list[str] = []
    used_names: set[str] = set()

    for position, (original, normalized) in enumerate(
        zip(original_columns, normalized_columns),
        start=1,
    ):
        if normalized_counts[normalized] == 1:
            internal = original
        else:
            internal = f"{normalized} [source column {position}]"
            while internal in reserved_names or internal in used_names:
                internal += "_"
        internal_names.append(internal)
        used_names.add(internal)

    return tuple(internal_names)


def _fingerprint(columns: Sequence[str]) -> str:
    """Create a deterministic, source-header-sensitive schema fingerprint."""
    payload = json.dumps(list(columns), ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()
