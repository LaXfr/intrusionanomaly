"""Compact backend records; raw flow matrices remain in file storage."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import DateTime, ForeignKey, Index, Integer, JSON, Numeric, String, Text, UniqueConstraint, Uuid, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from api.database.base import Base

JSON_VALUE = JSON().with_variant(JSONB, "postgresql")


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Dataset(Base):
    __tablename__ = "datasets"
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(240), nullable=False)
    source_filename: Mapped[str] = mapped_column(String(255), nullable=False)
    storage_uri: Mapped[str] = mapped_column(Text, nullable=False)
    checksum: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    file_size_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    schema_version: Mapped[str | None] = mapped_column(String(64))
    row_count: Mapped[int | None] = mapped_column(Integer)
    status: Mapped[str] = mapped_column(String(32), default="VALIDATED", nullable=False)
    dataset_metadata: Mapped[dict[str, Any]] = mapped_column("metadata", JSON_VALUE, default=dict, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False)
    jobs: Mapped[list["AnalysisJob"]] = relationship(back_populates="dataset")


class ModelRegistry(Base):
    __tablename__ = "model_registry"
    __table_args__ = (UniqueConstraint("model_name", "model_version", name="uq_model_name_version"),)
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    model_id: Mapped[str] = mapped_column(String(200), unique=True, nullable=False)
    model_name: Mapped[str] = mapped_column(String(120), nullable=False)
    model_version: Mapped[str] = mapped_column(String(64), nullable=False)
    model_type: Mapped[str] = mapped_column(String(48), nullable=False)
    artifact_uri: Mapped[str] = mapped_column(Text, nullable=False)
    preprocessor_uri: Mapped[str | None] = mapped_column(Text)
    feature_schema_version: Mapped[str] = mapped_column(String(64), nullable=False)
    class_mapping: Mapped[list[Any] | dict[str, Any] | None] = mapped_column(JSON_VALUE)
    threshold_configuration: Mapped[dict[str, Any] | None] = mapped_column(JSON_VALUE)
    metrics: Mapped[dict[str, Any] | None] = mapped_column(JSON_VALUE)
    status: Mapped[str] = mapped_column(String(32), default="READY", nullable=False)
    validated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False)


class AnalysisJob(Base):
    __tablename__ = "analysis_jobs"
    __table_args__ = (
        Index("ix_jobs_status_created", "status", "created_at"),
        Index("uq_active_job_per_dataset", "dataset_id", unique=True,
              postgresql_where=text("status IN ('QUEUED', 'RUNNING')"),
              sqlite_where=text("status IN ('QUEUED', 'RUNNING')")),
    )
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    dataset_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("datasets.id", ondelete="RESTRICT"), index=True)
    status: Mapped[str] = mapped_column(String(16), default="QUEUED", nullable=False, index=True)
    requested_engines: Mapped[list[str]] = mapped_column(JSON_VALUE, nullable=False)
    selected_model_versions: Mapped[dict[str, Any]] = mapped_column(JSON_VALUE, nullable=False)
    configuration: Mapped[dict[str, Any]] = mapped_column(JSON_VALUE, default=dict, nullable=False)
    total_records: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    processed_records: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    successful_records: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    failed_records: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    alerts_generated: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    error_message: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    dataset: Mapped[Dataset | None] = relationship(back_populates="jobs")
    events: Mapped[list["DetectionEvent"]] = relationship(back_populates="job")


class DetectionEvent(Base):
    __tablename__ = "detection_events"
    __table_args__ = (UniqueConstraint("event_fingerprint", name="uq_event_fingerprint"), Index("ix_events_generated_status", "generated_at", "event_status"))
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    analysis_job_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("analysis_jobs.id", ondelete="SET NULL"), index=True)
    dataset_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("datasets.id", ondelete="SET NULL"), index=True)
    source_record_reference: Mapped[str] = mapped_column(String(512), nullable=False)
    event_timestamp: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    flow_metadata: Mapped[dict[str, Any]] = mapped_column(JSON_VALUE, default=dict, nullable=False)
    binary_evidence: Mapped[dict[str, Any] | None] = mapped_column(JSON_VALUE)
    multiclass_evidence: Mapped[dict[str, Any] | None] = mapped_column(JSON_VALUE)
    anomaly_evidence: Mapped[dict[str, Any] | None] = mapped_column(JSON_VALUE)
    threat_score: Mapped[float | None] = mapped_column(Numeric(7, 3))
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    event_status: Mapped[str] = mapped_column(String(48), nullable=False, index=True)
    scoring_breakdown: Mapped[dict[str, Any]] = mapped_column(JSON_VALUE, default=dict, nullable=False)
    explanation_references: Mapped[list[Any]] = mapped_column(JSON_VALUE, default=list, nullable=False)
    explanation_data: Mapped[dict[str, Any] | None] = mapped_column(JSON_VALUE)
    event_fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    generated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    job: Mapped[AnalysisJob | None] = relationship(back_populates="events")
    alert_links: Mapped[list["AlertEventLink"]] = relationship(back_populates="event")


class Alert(Base):
    __tablename__ = "alerts"
    __table_args__ = (UniqueConstraint("alert_fingerprint", name="uq_alert_fingerprint"), Index("ix_alert_severity_status", "severity", "status"), Index("ix_alert_threat_score", "threat_score"))
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    alert_fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    alert_type: Mapped[str] = mapped_column(String(64), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    threat_score: Mapped[float] = mapped_column(Numeric(7, 3), nullable=False)
    status: Mapped[str] = mapped_column(String(24), default="NEW", nullable=False, index=True)
    predicted_categories: Mapped[list[str]] = mapped_column(JSON_VALUE, default=list, nullable=False)
    correlation_rule: Mapped[str | None] = mapped_column(String(64))
    correlation_metadata: Mapped[dict[str, Any]] = mapped_column(JSON_VALUE, default=dict, nullable=False)
    first_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    event_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    explanation: Mapped[dict[str, Any]] = mapped_column(JSON_VALUE, default=dict, nullable=False)
    status_changed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False)
    event_links: Mapped[list["AlertEventLink"]] = relationship(back_populates="alert", cascade="all, delete-orphan")


class AlertEventLink(Base):
    __tablename__ = "alert_event_links"
    alert_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("alerts.id", ondelete="CASCADE"), primary_key=True)
    event_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("detection_events.id", ondelete="RESTRICT"), primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    alert: Mapped[Alert] = relationship(back_populates="event_links")
    event: Mapped[DetectionEvent] = relationship(back_populates="alert_links")
