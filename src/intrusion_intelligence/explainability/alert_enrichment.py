"""Add explanation references to Phase 09 copies without altering detections."""

from __future__ import annotations

from typing import Any


def enrich_phase09_records(events: list[dict[str, Any]], alerts: list[dict[str, Any]], references: dict[str, list[dict[str, Any]]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Return sidecar records with reference-only enrichment."""
    enriched_events = []
    event_ids: dict[str, dict[str, Any]] = {}
    for source in events:
        refs = list(references.get(str(source.get("flow_record_reference")), []))
        row = {**source, "explanation_references": refs, "explanation_availability": "available" if refs else "not_selected"}
        enriched_events.append(row)
        event_ids[str(row.get("event_id"))] = row
    enriched_alerts = []
    for source in alerts:
        refs = [ref for event_id in source.get("supporting_event_ids", []) for ref in event_ids.get(str(event_id), {}).get("explanation_references", [])]
        # Copying preserves scoring, severity, correlation keys/rules, and original explanation text.
        enriched_alerts.append({**source, "explanation_references": refs, "explanation_availability": "available" if refs else "not_selected"})
    return enriched_events, enriched_alerts
