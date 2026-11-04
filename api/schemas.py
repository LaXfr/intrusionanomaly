"""Validated request and response models for the versioned REST API."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class PublicSchema(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class ErrorResponse(PublicSchema):
    error: dict[str, str]


class EngineName(StrEnum):
    BINARY = "binary"
    MULTICLASS = "multiclass"
    ANOMALY = "anomaly"


class AlertStatus(StrEnum):
    NEW = "NEW"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    INVESTIGATING = "INVESTIGATING"
    RESOLVED = "RESOLVED"
    DISMISSED = "DISMISSED"


class JobStatus(StrEnum):
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class FlowMetadata(PublicSchema):
    source_filename: str | None = Field(default=None, max_length=255)
    source_row_number: int | None = Field(default=None, ge=0)
    flow_record_reference: str | None = Field(default=None, max_length=512)
    timestamp: datetime | None = None
    source_ip: str | None = Field(default=None, max_length=128)
    destination_ip: str | None = Field(default=None, max_length=128)
    source_port: int | None = Field(default=None, ge=0, le=65535)
    destination_port: int | None = Field(default=None, ge=0, le=65535)
    protocol: str | int | None = Field(default=None, max_length=32)
    flow_id: str | None = Field(default=None, max_length=256)
    capture_group: str | None = Field(default=None, max_length=128)


class FlowRecord(PublicSchema):
    features: dict[str, float | int | str | None]
    metadata: FlowMetadata = Field(default_factory=FlowMetadata)

    @field_validator("features")
    @classmethod
    def nonempty_features(cls, values: dict[str, Any]) -> dict[str, Any]:
        if not values:
            raise ValueError("features must contain the contract's predictive fields")
        return values


class AnalysisRequest(PublicSchema):
    records: list[FlowRecord] | None = Field(default=None, min_length=1)
    dataset_id: UUID | None = None
    engines: list[EngineName] = Field(default_factory=lambda: [EngineName.BINARY, EngineName.MULTICLASS, EngineName.ANOMALY])
    model_ids: dict[EngineName, str] = Field(default_factory=dict)
    anomaly_operating_point: str | None = Field(default=None, min_length=1, max_length=64)

    @model_validator(mode="after")
    def exactly_one_source(self) -> "AnalysisRequest":
        if (self.records is None) == (self.dataset_id is None):
            raise ValueError("provide exactly one of records or dataset_id")
        if not self.engines or len(set(self.engines)) != len(self.engines):
            raise ValueError("engines must contain one or more unique detector names")
        unknown = set(self.model_ids) - set(self.engines)
        if unknown:
            raise ValueError("model_ids may only specify requested engines")
        return self


class DetectionEventResponse(PublicSchema):
    id: UUID
    event_fingerprint: str
    source_record_reference: str
    event_timestamp: datetime | None
    threat_score: float | None
    severity: str
    event_status: str
    detector_evidence: dict[str, Any]
    scoring_breakdown: dict[str, Any]


class DetectionEventDetail(DetectionEventResponse):
    dataset_id: UUID | None
    analysis_job_id: UUID | None
    generated_at: datetime
    flow_metadata: dict[str, Any]
    explanation_references: list[Any]


class DetectionEventList(PublicSchema):
    items: list[DetectionEventResponse]
    total: int
    limit: int
    offset: int


class AnalysisResponse(PublicSchema):
    job_id: UUID
    total_records: int
    successful_records: int
    failed_records: int
    generated_event_count: int
    generated_alert_count: int
    requested_engines: list[str]
    event_ids: list[UUID]
    alerts: list[dict[str, Any]]
    summary: dict[str, Any]


class DatasetResponse(PublicSchema):
    id: UUID
    name: str
    source_filename: str
    checksum: str
    file_size_bytes: int
    schema_version: str | None
    row_count: int | None
    status: str
    metadata: dict[str, Any]
    created_at: datetime


class DatasetListResponse(PublicSchema):
    items: list[DatasetResponse]
    total: int
    limit: int
    offset: int


class ModelResponse(PublicSchema):
    model_id: str
    model_name: str
    model_version: str
    model_type: str
    feature_schema_version: str
    input_feature_count: int
    class_mapping: list[str] | dict[str, Any] | None = None
    threshold_configuration: dict[str, Any] | None = None
    status: str
    supported_prediction_types: list[str]
    evaluation_metadata: dict[str, Any] | None = None


class ModelsResponse(PublicSchema):
    items: list[ModelResponse]
    ready_count: int
    unavailable_count: int


class JobCreateRequest(PublicSchema):
    dataset_id: UUID
    engines: list[EngineName] = Field(default_factory=lambda: [EngineName.BINARY, EngineName.MULTICLASS, EngineName.ANOMALY])
    model_ids: dict[EngineName, str] = Field(default_factory=dict)
    anomaly_operating_point: str | None = Field(default=None, max_length=64)

    @model_validator(mode="after")
    def check_engines(self) -> "JobCreateRequest":
        if not self.engines or len(set(self.engines)) != len(self.engines):
            raise ValueError("engines must contain one or more unique detector names")
        if set(self.model_ids) - set(self.engines):
            raise ValueError("model_ids may only specify requested engines")
        return self


class JobResponse(PublicSchema):
    id: UUID
    dataset_id: UUID | None
    status: JobStatus
    requested_engines: list[str]
    selected_model_versions: dict[str, Any]
    total_records: int
    processed_records: int
    successful_records: int
    failed_records: int
    alerts_generated: int
    error_message: str | None
    created_at: datetime
    started_at: datetime | None
    completed_at: datetime | None


class AlertSummary(PublicSchema):
    id: UUID
    alert_fingerprint: str
    title: str
    alert_type: str
    severity: str
    threat_score: float
    status: AlertStatus
    predicted_categories: list[str]
    first_seen: datetime | None
    last_seen: datetime | None
    event_count: int
    created_at: datetime


class AlertDetail(AlertSummary):
    correlation_rule: str | None
    correlation_metadata: dict[str, Any]
    summary: str
    explanation: dict[str, Any]
    supporting_event_ids: list[UUID]


class AlertListResponse(PublicSchema):
    items: list[AlertSummary]
    total: int
    limit: int
    offset: int


class AlertStatusRequest(PublicSchema):
    status: AlertStatus
    changed_by: str | None = Field(default=None, max_length=120)


class AlertStatusResponse(PublicSchema):
    alert: AlertSummary
    previous_status: AlertStatus
    status_changed_at: datetime


class MetricsResponse(PublicSchema):
    operational: dict[str, Any]
    persisted_alerts_by_severity: dict[str, int]
    persisted_alerts_by_status: dict[str, int]
    persisted_events_by_status: dict[str, int]
    models: dict[str, Any]
    historical_evaluation: dict[str, Any] | None = None


class TrafficSummaryResponse(PublicSchema):
    scope: dict[str, Any]
    total_flows: int
    benign_predictions: int
    malicious_predictions: int
    anomalous_flows: int
    suspicious_events: int
    average_threat_score: float | None
    maximum_threat_score: float | None
    predicted_categories: dict[str, int]
    events_by_severity: dict[str, int]
    grouped_items: list[dict[str, Any]]


class HealthResponse(PublicSchema):
    status: str
    service: str
    version: str


class ReadinessResponse(PublicSchema):
    status: str
    checks: dict[str, Any]
