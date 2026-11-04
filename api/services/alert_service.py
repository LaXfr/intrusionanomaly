"""Alert retrieval, safe filtering, and lifecycle transitions."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import cast, func, select, String
from sqlalchemy.orm import Session

from api.core.errors import ApiError
from api.database.models import Alert, AlertEventLink, DetectionEvent

TRANSITIONS = {
    "NEW": {"ACKNOWLEDGED", "DISMISSED"},
    "ACKNOWLEDGED": {"INVESTIGATING", "RESOLVED", "DISMISSED"},
    "INVESTIGATING": {"ACKNOWLEDGED", "RESOLVED", "DISMISSED"},
    "RESOLVED": {"INVESTIGATING"},
    "DISMISSED": set(),
}


class AlertService:
    def list(self, session: Session, *, limit: int, offset: int, severity: str | None = None,
             status: str | None = None, category: str | None = None, start: datetime | None = None,
             end: datetime | None = None, minimum_score: float | None = None,
             sort_by: str = "created_at", order: str = "desc") -> tuple[list[Alert], int]:
        query = select(Alert)
        conditions = []
        if severity:
            conditions.append(Alert.severity == severity.upper())
        if status:
            conditions.append(Alert.status == status.upper())
        if category:
            # Casted JSON filtering remains parameterized and works with the supported SQLite test adapter.
            conditions.append(cast(Alert.predicted_categories, String).contains(category))
        if start:
            conditions.append(Alert.created_at >= start)
        if end:
            conditions.append(Alert.created_at <= end)
        if minimum_score is not None:
            conditions.append(Alert.threat_score >= minimum_score)
        if conditions:
            query = query.where(*conditions)
        total = int(session.scalar(select(func.count()).select_from(query.subquery())) or 0)
        columns = {"created_at": Alert.created_at, "threat_score": Alert.threat_score, "severity": Alert.severity}
        ordering = columns[sort_by].asc() if order == "asc" else columns[sort_by].desc()
        rows = list(session.scalars(query.order_by(ordering, Alert.id).limit(limit).offset(offset)))
        return rows, total

    def get(self, session: Session, alert_id: uuid.UUID) -> Alert:
        alert = session.get(Alert, alert_id)
        if alert is None:
            raise ApiError(404, "ALERT_NOT_FOUND", "Alert was not found.")
        return alert

    def supporting_events(self, session: Session, alert_id: uuid.UUID) -> list[DetectionEvent]:
        return list(session.scalars(select(DetectionEvent).join(AlertEventLink).where(AlertEventLink.alert_id == alert_id).order_by(DetectionEvent.generated_at)))

    def update_status(self, session: Session, alert_id: uuid.UUID, status: str, changed_by: str | None) -> tuple[Alert, str, datetime]:
        alert = self.get(session, alert_id)
        previous = alert.status
        if status == previous:
            return alert, previous, alert.status_changed_at or alert.updated_at
        if status not in TRANSITIONS.get(previous, set()):
            raise ApiError(409, "INVALID_ALERT_TRANSITION", f"Alert status cannot transition from {previous} to {status}.")
        now = datetime.now(timezone.utc)
        audit = list(alert.explanation.get("status_history", []))
        audit.append({"from": previous, "to": status, "changed_at": now.isoformat(), "changed_by": changed_by})
        alert.explanation = {**alert.explanation, "status_history": audit}
        alert.status = status
        alert.status_changed_at = now
        alert.updated_at = now
        session.commit()
        session.refresh(alert)
        return alert, previous, now
