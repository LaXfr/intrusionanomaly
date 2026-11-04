"""Configurable score bands for triage severity."""

from __future__ import annotations

import math
from typing import Any, Iterable, Mapping


class SeverityError(ValueError):
    """Raised when a severity policy contains gaps or invalid boundaries."""


DEFAULT_BANDS = (
    {"name": "LOW", "minimum": 0.0, "maximum": 25.0},
    {"name": "MEDIUM", "minimum": 25.0, "maximum": 50.0},
    {"name": "HIGH", "minimum": 50.0, "maximum": 75.0},
    {"name": "CRITICAL", "minimum": 75.0, "maximum": 100.0000001},
)


def validate_severity_bands(bands: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    parsed = sorted(
        ({"name": str(item["name"]).upper(), "minimum": float(item["minimum"]), "maximum": float(item["maximum"])} for item in bands),
        key=lambda item: item["minimum"],
    )
    if not parsed:
        raise SeverityError("At least one severity band is required.")
    if len({item["name"] for item in parsed}) != len(parsed):
        raise SeverityError("Severity band names must be unique.")
    if parsed[0]["minimum"] != 0 or parsed[-1]["maximum"] < 100:
        raise SeverityError("Severity bands must cover the full 0–100 score range.")
    for index, band in enumerate(parsed):
        if not math.isfinite(band["minimum"]) or not math.isfinite(band["maximum"]) or band["minimum"] >= band["maximum"]:
            raise SeverityError(f"Invalid severity band: {band}.")
        if index and not math.isclose(parsed[index - 1]["maximum"], band["minimum"], abs_tol=1e-9):
            raise SeverityError("Severity bands must be contiguous with no overlap or gap.")
    return parsed


def assign_severity(score: float | None, bands: Iterable[Mapping[str, Any]] = DEFAULT_BANDS) -> str:
    if score is None:
        return "UNSCORED"
    value = float(score)
    if not math.isfinite(value) or value < 0 or value > 100:
        raise SeverityError("Threat score must be finite and within 0–100.")
    parsed_bands = validate_severity_bands(bands)
    for index, band in enumerate(parsed_bands):
        if band["minimum"] <= value < band["maximum"] or (index == len(parsed_bands) - 1 and value == 100):
            return str(band["name"])
    raise SeverityError(f"Threat score {value} does not map to a configured severity band.")
