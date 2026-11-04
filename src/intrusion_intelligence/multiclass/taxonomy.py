"""Validated, versioned multi-class labels for CIC-IDS2017."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable


class TaxonomyError(ValueError):
    """Raised when labels do not match the declared attack taxonomy."""


@dataclass(frozen=True, slots=True)
class ClassTaxonomy:
    """A stable original-label to integer mapping shared by all models."""

    labels: tuple[str, ...]
    version: str = "1.0.0"

    def __post_init__(self) -> None:
        if not self.labels or len(self.labels) != len(set(self.labels)):
            raise TaxonomyError("Taxonomy labels must be non-empty and unique.")
        if "BENIGN" not in self.labels:
            raise TaxonomyError("The observed taxonomy must contain BENIGN.")
        if any(not isinstance(label, str) or not label.strip() for label in self.labels):
            raise TaxonomyError("Taxonomy labels must be non-blank strings.")

    @classmethod
    def from_labels(
        cls,
        labels: Iterable[object],
        *,
        allowed_labels: Iterable[str] | None = None,
        version: str = "1.0.0",
    ) -> "ClassTaxonomy":
        """Build deterministically while preserving each original label value."""
        values = list(labels)
        if any(value is None for value in values):
            raise TaxonomyError("Target contains null labels.")
        observed = {str(value) for value in values}
        if any(not label.strip() for label in observed):
            raise TaxonomyError("Target contains blank labels.")
        if allowed_labels is not None:
            allowed = set(allowed_labels)
            unexpected = sorted(observed - allowed)
            if unexpected:
                raise TaxonomyError(f"Unexpected target labels are not in the contract: {unexpected}.")
        if "BENIGN" not in observed:
            raise TaxonomyError("The observed dataset does not contain BENIGN.")
        ordered = ("BENIGN", *sorted(observed - {"BENIGN"}))
        return cls(labels=ordered, version=version)

    @property
    def class_to_id(self) -> dict[str, int]:
        """Return the stable zero-based encoding."""
        return {label: index for index, label in enumerate(self.labels)}

    @property
    def id_to_class(self) -> dict[int, str]:
        """Return the inverse encoding."""
        return {index: label for index, label in enumerate(self.labels)}

    def encode(self, labels: Iterable[object]) -> list[int]:
        """Encode known labels and reject unknown values without remapping."""
        values = [str(value) for value in labels]
        mapping = self.class_to_id
        unknown = sorted(set(values) - set(mapping))
        if unknown:
            raise TaxonomyError(f"Unknown labels cannot be encoded: {unknown}.")
        return [mapping[value] for value in values]

    def decode(self, identifiers: Iterable[int]) -> list[str]:
        """Decode valid model identifiers to original labels."""
        inverse = self.id_to_class
        result: list[str] = []
        for identifier in identifiers:
            if isinstance(identifier, bool) or int(identifier) != identifier or int(identifier) not in inverse:
                raise TaxonomyError(f"Unknown class identifier: {identifier!r}.")
            result.append(inverse[int(identifier)])
        return result

    def to_dict(self, *, class_counts: dict[str, int] | None = None) -> dict[str, object]:
        """Serialize mapping and optional counts for a model artifact."""
        return {
            "mapping_version": self.version,
            "labels": list(self.labels),
            "class_to_id": self.class_to_id,
            "id_to_class": {str(key): value for key, value in self.id_to_class.items()},
            "class_counts": dict(class_counts or {}),
        }

    @classmethod
    def from_dict(cls, document: dict[str, object]) -> "ClassTaxonomy":
        """Reload and verify an explicit persisted label mapping."""
        raw_labels = document.get("labels")
        if not isinstance(raw_labels, list):
            raise TaxonomyError("Persisted taxonomy is missing its labels list.")
        taxonomy = cls(tuple(str(value) for value in raw_labels), str(document.get("mapping_version", "1.0.0")))
        if document.get("class_to_id") != taxonomy.class_to_id:
            raise TaxonomyError("Persisted class-to-id mapping is inconsistent with its labels.")
        expected_reverse = {str(key): value for key, value in taxonomy.id_to_class.items()}
        if document.get("id_to_class") != expected_reverse:
            raise TaxonomyError("Persisted id-to-class mapping is inconsistent with its labels.")
        return taxonomy
