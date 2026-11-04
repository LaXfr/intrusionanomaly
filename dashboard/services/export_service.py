"""Local serialization of the alert records returned by the backend."""

from __future__ import annotations

import csv
import io
import json
from collections.abc import Mapping, Sequence
from typing import Any


def _cell(value: Any) -> Any:
    if isinstance(value, (dict, list, tuple)):
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    return value


def csv_bytes(rows: Sequence[Mapping[str, Any]] | None) -> bytes:
    """Serialize real alert rows as UTF-8 CSV without requiring pandas."""
    records = list(rows or [])
    if not records:
        return b""
    if any(not isinstance(row, Mapping) for row in records):
        raise ValueError("CSV export expects a sequence of alert objects.")
    columns = list(dict.fromkeys(key for row in records for key in row))
    output = io.StringIO(newline="")
    writer = csv.DictWriter(output, fieldnames=columns, extrasaction="ignore", lineterminator="\r\n")
    writer.writeheader()
    writer.writerows({key: _cell(value) for key, value in row.items()} for row in records)
    return output.getvalue().encode("utf-8")


def json_bytes(value: Any) -> bytes:
    """Serialize the exact backend response value as readable UTF-8 JSON."""
    return (json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False) + "\n").encode("utf-8")
