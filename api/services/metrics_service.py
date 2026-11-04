"""Database-side operational metrics and bounded traffic summaries."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from api.database.models import Alert, AnalysisJob, Dataset, DetectionEvent
from api.services.model_service import ModelService


class MetricsService:
    def operational(self, session: Session, models: ModelService) -> dict[str, Any]:
        count = lambda model: int(session.scalar(select(func.count()).select_from(model)) or 0)
        statuses = dict(session.execute(select(AnalysisJob.status, func.count()).group_by(AnalysisJob.status)).all())
        last_job = session.scalar(select(func.max(AnalysisJob.completed_at)))
        model_rows, unavailable = models.list_models()
        return {"registered_datasets": count(Dataset), "analysis_jobs": count(AnalysisJob),
            "completed_jobs": statuses.get("COMPLETED", 0), "failed_jobs": statuses.get("FAILED", 0),
            "queued_jobs": statuses.get("QUEUED", 0), "running_jobs": statuses.get("RUNNING", 0),
            "detection_events": count(DetectionEvent), "security_alerts": count(Alert),
            "last_analysis_at": last_job.isoformat() if last_job else None,
            "engines": {name: any(item["model_type"] == name for item in model_rows) for name in ("binary", "multiclass", "anomaly")}}

    def distributions(self, session: Session, model: Any) -> dict[str, int]:
        return {str(key): int(value) for key, value in session.execute(select(model, func.count()).group_by(model)).all() if key is not None}

    def traffic(self, session: Session, *, dataset_id: uuid.UUID | None, job_id: uuid.UUID | None,
                start: datetime | None, end: datetime | None, event_status: str | None,
                category: str | None, group_by: str, limit: int) -> dict[str, Any]:
        predicates = []
        if dataset_id:
            predicates.append(DetectionEvent.dataset_id == dataset_id)
        if job_id:
            predicates.append(DetectionEvent.analysis_job_id == job_id)
        if start:
            predicates.append(DetectionEvent.generated_at >= start)
        if end:
            predicates.append(DetectionEvent.generated_at <= end)
        if event_status:
            predicates.append(DetectionEvent.event_status == event_status)
        if category:
            predicates.append(DetectionEvent.multiclass_evidence["details"]["predicted_label"].as_string() == category)
        total = int(session.scalar(select(func.count()).select_from(DetectionEvent).where(*predicates)) or 0)
        average = session.scalar(select(func.avg(DetectionEvent.threat_score)).where(*predicates))
        maximum = session.scalar(select(func.max(DetectionEvent.threat_score)).where(*predicates))
        benign_expr = DetectionEvent.binary_evidence["details"]["malicious_prediction"].as_boolean()
        anomaly_expr = DetectionEvent.anomaly_evidence["details"]["decision"].as_string()
        label_expr = DetectionEvent.multiclass_evidence["details"]["predicted_label"].as_string()
        count_where = lambda *extra: int(session.scalar(select(func.count()).select_from(DetectionEvent).where(*predicates, *extra)) or 0)
        benign = count_where(benign_expr.is_(False))
        malicious = count_where(benign_expr.is_(True))
        anomalous = count_where(anomaly_expr == "ANOMALOUS")
        suspicious = count_where(DetectionEvent.event_status.in_(["SUSPICIOUS", "MALICIOUS_PREDICTION", "ANOMALOUS"]))
        event_severity = {str(key): int(value) for key, value in session.execute(
            select(DetectionEvent.severity, func.count()).where(*predicates).group_by(DetectionEvent.severity)).all()}
        categories = {str(key): int(value) for key, value in session.execute(
            select(label_expr, func.count()).where(*predicates, label_expr.is_not(None)).group_by(label_expr)
            .order_by(func.count().desc()).limit(100)).all() if key is not None}
        group_expr = {"severity": DetectionEvent.severity, "event_status": DetectionEvent.event_status,
                      "attack_category": label_expr, "day": func.date(DetectionEvent.generated_at)}[group_by]
        grouped = [{"key": str(key) if key is not None else "UNKNOWN", "count": int(value)} for key, value in
                   session.execute(select(group_expr, func.count()).where(*predicates).group_by(group_expr)
                       .order_by(func.count().desc()).limit(limit)).all()]
        return {"scope": {"dataset_id": str(dataset_id) if dataset_id else None, "analysis_job_id": str(job_id) if job_id else None,
                "start": start.isoformat() if start else None, "end": end.isoformat() if end else None, "group_by": group_by,
                "grouping_limit": limit, "statistics_scope": "exact SQL aggregates over filtered persisted detection events"},
            "total_flows": total, "benign_predictions": benign, "malicious_predictions": malicious, "anomalous_flows": anomalous,
            "suspicious_events": suspicious, "average_threat_score": float(average) if average is not None else None,
            "maximum_threat_score": float(maximum) if maximum is not None else None,
            "predicted_categories": categories, "events_by_severity": event_severity,
            "grouped_items": grouped}
