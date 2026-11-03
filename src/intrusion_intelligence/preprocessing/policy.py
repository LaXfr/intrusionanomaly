"""Declarative cleaning policy and guardrails."""

from __future__ import annotations

import tomllib
from pathlib import Path
from typing import Any

from intrusion_intelligence.errors import ProjectError


DEFAULT_POLICY_PATH = Path("configs/data_quality_policy.toml")


def load_policy(path: str | Path) -> dict[str, Any]:
    """Load and validate a policy document without applying transformations."""
    try:
        with Path(path).open("rb") as stream:
            policy = tomllib.load(stream)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ProjectError(f"Unable to read cleaning policy: {path}") from exc
    validate_policy(policy)
    return policy


def validate_policy(policy: dict[str, Any]) -> None:
    """Reject malformed or unsupported data-changing rules before processing."""
    required = ("structural", "missing", "infinity", "numeric", "negative",
                "duplicates", "outliers", "features", "rows", "labels", "column_roles")
    for section in required:
        if not isinstance(policy.get(section), dict):
            raise ProjectError(f"Cleaning policy section {section!r} is required.")

    choices = {
        "structural.header_action": "snake_case_and_suffix_normalized_collisions_by_source_position",
        "missing.action": "canonicalize_to_nan_without_imputation",
        "missing.label_action": "quarantine_missing_or_blank",
        "infinity.action": "replace_positive_and_negative_infinity_with_nan",
        "numeric.action": "parse_numeric_and_audit_coercion_failures",
        "negative.action": "preserve_and_report",
        "outliers.action": "preserve",
        "features.action": "retain_all",
        "rows.action": "exclude_missing_or_invalid_labels",
        "labels.action": "trim_whitespace_and_preserve_original",
        "labels.invalid_action": "quarantine",
    }
    for dotted_key, expected in choices.items():
        section, key = dotted_key.split(".")
        if policy[section].get(key) != expected:
            raise ProjectError(
                f"Unsupported cleaning rule {dotted_key}; expected {expected!r}."
            )
    duplicate_action = policy["duplicates"].get("action")
    if duplicate_action not in {"preserve", "drop_exact_duplicates"}:
        raise ProjectError(
            "duplicates.action must be 'preserve' or 'drop_exact_duplicates'."
        )
    if policy.get("structural", {}).get("add_provenance_columns") is not True:
        raise ProjectError("The policy must preserve stable row provenance.")
    if policy["structural"].get("preserve_original_label") is not True:
        raise ProjectError("The policy must preserve each retained row's original label.")
    expected_labels = policy["labels"].get("expected_values")
    if (
        not isinstance(expected_labels, list)
        or not expected_labels
        or any(not isinstance(value, str) or not value.strip() for value in expected_labels)
        or len(set(expected_labels)) != len(expected_labels)
    ):
        raise ProjectError("labels.expected_values must be a non-empty unique string list.")
    for role in ("categorical", "datetime", "identifiers"):
        values = policy["column_roles"].get(role)
        if not isinstance(values, list) or any(not isinstance(value, str) for value in values):
            raise ProjectError(f"column_roles.{role} must be a list of normalized column names.")
