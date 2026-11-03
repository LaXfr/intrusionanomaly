"""Compare CSV schemas without silently changing source column names."""

from __future__ import annotations

import logging
from collections import Counter
from collections.abc import Sequence

from intrusion_intelligence.ingestion.models import (
    FileInspection,
    SchemaComparison,
    SchemaValidationResult,
)

logger = logging.getLogger(__name__)


def validate_schemas(
    inspections: Sequence[FileInspection],
) -> SchemaValidationResult:
    """Compare inspected CSV headers and separate ordering from schema changes.

    A column-order difference is compatible because loading can reorder frames
    to the reference order by exact source names. Missing or additional raw
    names, invalid headers, and cross-file whitespace name conflicts are
    incompatible and prevent multi-file loading.
    """
    valid_files = [
        inspection for inspection in inspections if inspection.status == "valid"
    ]
    reference = valid_files[0] if valid_files else None
    comparisons: list[SchemaComparison] = []
    matching: list[str] = []
    order_only: list[str] = []
    incompatible: list[str] = []
    warnings: list[str] = []
    errors: list[str] = []

    for inspection in inspections:
        file_name = inspection.relative_path
        if inspection.status != "valid":
            incompatible.append(file_name)
            file_errors = inspection.errors or ("File inspection did not pass.",)
            comparisons.append(
                SchemaComparison(
                    file=file_name,
                    relation="invalid",
                    compatible=False,
                    missing_columns=(),
                    additional_columns=(),
                    column_order_differs=False,
                    normalized_name_conflicts=(),
                    errors=file_errors,
                )
            )
            errors.extend(f"{file_name}: {message}" for message in file_errors)
            continue

        if reference is None:
            continue
        if inspection.path == reference.path:
            comparison = SchemaComparison(
                file=file_name,
                relation="reference",
                compatible=True,
                missing_columns=(),
                additional_columns=(),
                column_order_differs=False,
                normalized_name_conflicts=(),
                errors=(),
            )
            matching.append(file_name)
            comparisons.append(comparison)
            continue

        missing = _multiset_difference(
            reference.original_columns,
            inspection.original_columns,
        )
        additional = _multiset_difference(
            inspection.original_columns,
            reference.original_columns,
        )
        name_conflicts = _normalized_name_conflicts(
            reference.original_columns,
            inspection.original_columns,
        )
        same_names = not missing and not additional
        order_differs = same_names and (
            reference.original_columns != inspection.original_columns
        )
        has_colliding_headers = any(
            item.exact_duplicate_columns or item.normalized_collisions
            for item in (reference, inspection)
        )
        ambiguous_duplicate_order = has_colliding_headers and order_differs
        compatible = (
            same_names
            and not name_conflicts
            and not ambiguous_duplicate_order
        )

        if compatible and order_differs:
            relation = "order_only"
            order_only.append(file_name)
            warnings.append(
                f"{file_name}: column order differs from {reference.relative_path}; "
                "loading will align by exact source header names."
            )
        elif compatible:
            relation = "matching"
            matching.append(file_name)
        elif name_conflicts or ambiguous_duplicate_order:
            relation = "conflicting_headers"
            incompatible.append(file_name)
        else:
            relation = "different_columns"
            incompatible.append(file_name)

        comparison_errors: list[str] = []
        if missing:
            comparison_errors.append(
                "Missing columns: " + ", ".join(repr(column) for column in missing)
            )
        if additional:
            comparison_errors.append(
                "Additional columns: "
                + ", ".join(repr(column) for column in additional)
            )
        if name_conflicts:
            comparison_errors.append(
                "Distinct source headers normalize to the same names: "
                + "; ".join(name_conflicts)
            )
        if ambiguous_duplicate_order:
            comparison_errors.append(
                "Files with duplicate or whitespace-colliding source headers "
                "must retain the same source column order for positional mapping."
            )
        if comparison_errors:
            errors.extend(f"{file_name}: {message}" for message in comparison_errors)

        comparisons.append(
            SchemaComparison(
                file=file_name,
                relation=relation,
                compatible=compatible,
                missing_columns=missing,
                additional_columns=additional,
                column_order_differs=order_differs,
                normalized_name_conflicts=name_conflicts,
                errors=tuple(comparison_errors),
            )
        )

    if not inspections:
        errors.append("No files were inspected.")
    elif reference is None:
        errors.append("No valid file header is available as a schema reference.")

    result = SchemaValidationResult(
        reference_file=reference.relative_path if reference else None,
        matching_files=tuple(matching),
        order_only_files=tuple(order_only),
        incompatible_files=tuple(incompatible),
        comparisons=tuple(comparisons),
        is_compatible=bool(reference) and not incompatible,
        warnings=tuple(warnings),
        errors=tuple(errors),
    )
    logger.info(
        "Schema validation: matching=%d order_only=%d incompatible=%d",
        len(result.matching_files),
        len(result.order_only_files),
        len(result.incompatible_files),
    )
    return result


def _multiset_difference(
    source_columns: Sequence[str],
    target_columns: Sequence[str],
) -> tuple[str, ...]:
    """Return missing source headers while respecting duplicate occurrences."""
    missing_counts = Counter(source_columns) - Counter(target_columns)
    missing: list[str] = []
    for column in source_columns:
        if missing_counts[column] > 0:
            missing.append(column)
            missing_counts[column] -= 1
    return tuple(missing)


def _normalized_name_conflicts(
    reference_columns: Sequence[str],
    file_columns: Sequence[str],
) -> tuple[str, ...]:
    """Find exact source headers that differ but collide after strip()."""
    reference_map = {column.strip(): column for column in reference_columns}
    file_map = {column.strip(): column for column in file_columns}
    conflicts = []
    for normalized in reference_map.keys() & file_map.keys():
        reference_name = reference_map[normalized]
        file_name = file_map[normalized]
        if reference_name != file_name:
            conflicts.append(
                f"{normalized!r}: {reference_name!r} vs {file_name!r}"
            )
    return tuple(sorted(conflicts))
