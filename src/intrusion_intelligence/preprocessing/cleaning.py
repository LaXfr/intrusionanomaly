"""Conservative, auditable transformations for one source CSV chunk."""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Sequence
from typing import Any

import numpy as np
import pandas as pd

MISSING_TOKENS = {"", "na", "n/a", "null", "none", "nan", "+nan", "-nan"}


def standardize_source_headers(
    headers: Sequence[str],
) -> tuple[tuple[str, ...], list[dict[str, Any]]]:
    """Return stable snake-case headers, suffixing every normalized collision."""
    bases = [_header_base(header) for header in headers]
    collisions = Counter(bases)
    names: list[str] = []
    mapping: list[dict[str, Any]] = []
    used: set[str] = set()
    for position, (source, base) in enumerate(zip(headers, bases), start=1):
        candidate = (
            f"{base}__source_col_{position}"
            if collisions[base] > 1
            else base
        )
        if candidate in used:
            candidate = f"{candidate}__source_col_{position}"
        if candidate in used:
            raise ValueError(f"Could not create a unique name for source column {position}.")
        used.add(candidate)
        names.append(candidate)
        mapping.append(
            {
                "source_position": position,
                "source_header": source,
                "normalized_base": base,
                "cleaned_header": candidate,
                "normalized_collision": collisions[base] > 1,
            }
        )
    return tuple(names), mapping


def normalize_missing_mask(values: pd.Series) -> pd.Series:
    """Identify common missing tokens without changing the source series."""
    text = values.astype("string").str.strip().str.casefold()
    return text.isin(MISSING_TOKENS).fillna(False)


def clean_source_chunk(
    source_frame: pd.DataFrame,
    *,
    cleaned_headers: Sequence[str],
    label_position: int,
    expected_labels: Sequence[str],
    categorical_columns: Sequence[str] = (),
    datetime_columns: Sequence[str] = (),
    identifier_columns: Sequence[str] = (),
    source_file: str,
    source_row_numbers: Sequence[int],
    record_ids: Sequence[str],
) -> tuple[pd.DataFrame, pd.DataFrame, dict[str, Any]]:
    """Normalize a chunk and return supervised rows, quarantined labels, and counts.

    Feature values that are blank or use a recognized null token become NaN.
    Numeric values are parsed without clipping; non-finite rates become NaN.
    Labels are trimmed, and missing or unrecognized labels are quarantined with
    their original source text intact.
    """
    if source_frame.shape[1] != len(cleaned_headers):
        raise ValueError("Source frame width does not match the header map.")
    if label_position < 0 or label_position >= source_frame.shape[1]:
        raise ValueError("Label position is outside the source schema.")
    if len(source_row_numbers) != len(source_frame) or len(record_ids) != len(source_frame):
        raise ValueError("Provenance row counts must match the source chunk.")

    raw = source_frame.reset_index(drop=True).copy(deep=False)
    raw.columns = list(cleaned_headers)
    label_column = cleaned_headers[label_position]
    original_labels = raw.iloc[:, label_position].astype("string")
    normalized_labels = original_labels.str.strip()
    label_missing = normalize_missing_mask(original_labels)
    allowed = set(expected_labels)
    label_invalid = ~label_missing & ~normalized_labels.isin(allowed)
    rejected = label_missing | label_invalid

    metadata = {
        "__source_file": pd.Series([source_file] * len(raw), index=raw.index, dtype="string"),
        "__source_row_number": pd.Series(source_row_numbers, index=raw.index, dtype="int64"),
        "__record_id": pd.Series(record_ids, index=raw.index, dtype="string"),
    }
    label_mapping: Counter[tuple[str, str]] = Counter()
    for original, normalized in zip(original_labels, normalized_labels):
        label_mapping[(str(original), str(normalized))] += 1

    transformed = raw.copy()
    transformed[label_column] = normalized_labels
    transformed["__source_label"] = original_labels
    counts: dict[str, Any] = {
        "input_rows": int(len(raw)),
        "missing_label_rows": int(label_missing.sum()),
        "invalid_label_rows": int(label_invalid.sum()),
        "label_mapping": [
            {"original": original, "normalized": normalized, "rows": count}
            for (original, normalized), count in sorted(label_mapping.items())
        ],
        "missing_values_canonicalized": {},
        "positive_infinities_replaced": {},
        "negative_infinities_replaced": {},
        "invalid_numeric_conversions": {},
        "invalid_numeric_examples": {},
    }

    non_numeric = set(categorical_columns) | set(datetime_columns) | set(identifier_columns)
    numeric_columns = [
        name for name in cleaned_headers if name != label_column and name not in non_numeric
    ]
    for name in cleaned_headers:
        if name == label_column:
            continue
        if name in numeric_columns:
            source_values = raw[name].astype("string")
            missing_mask = normalize_missing_mask(source_values)
            numeric = pd.to_numeric(source_values.mask(missing_mask, pd.NA), errors="coerce")
            invalid_mask = ~missing_mask & numeric.isna()
            numeric_float = numeric.astype("float64")
            positive = np.isposinf(numeric_float.to_numpy())
            negative = np.isneginf(numeric_float.to_numpy())
            counts["missing_values_canonicalized"][name] = int(missing_mask.sum())
            counts["positive_infinities_replaced"][name] = int(positive.sum())
            counts["negative_infinities_replaced"][name] = int(negative.sum())
            counts["invalid_numeric_conversions"][name] = int(invalid_mask.sum())
            examples = source_values[invalid_mask].drop_duplicates().head(5).tolist()
            if examples:
                counts["invalid_numeric_examples"][name] = [str(item) for item in examples]
            transformed[name] = numeric_float.mask(positive | negative, np.nan)
        else:
            values = raw[name].astype("string")
            missing_mask = normalize_missing_mask(values)
            counts["missing_values_canonicalized"][name] = int(missing_mask.sum())
            transformed[name] = values.mask(missing_mask, pd.NA)

    transformed["__source_file"] = metadata["__source_file"]
    transformed["__source_row_number"] = metadata["__source_row_number"]
    transformed["__record_id"] = metadata["__record_id"]

    retained = transformed.loc[~rejected].copy()
    quarantined = raw.loc[rejected].copy()
    if len(quarantined):
        quarantined["__source_label"] = original_labels[rejected]
        quarantined["__source_file"] = metadata["__source_file"][rejected]
        quarantined["__source_row_number"] = metadata["__source_row_number"][rejected]
        quarantined["__record_id"] = metadata["__record_id"][rejected]
        reasons = np.where(label_missing[rejected].to_numpy(), "missing_label", "invalid_label")
        quarantined["__rejection_reason"] = pd.Series(reasons, index=quarantined.index, dtype="string")
    else:
        quarantined = pd.DataFrame(
            columns=[
                *cleaned_headers,
                "__source_label",
                "__source_file",
                "__source_row_number",
                "__record_id",
                "__rejection_reason",
            ]
        )
    return retained, quarantined, counts


def _header_base(header: str) -> str:
    text = re.sub(r"\s+", " ", str(header).strip()).casefold()
    name = re.sub(r"[^a-z0-9]+", "_", text).strip("_")
    return name or "unnamed_column"
