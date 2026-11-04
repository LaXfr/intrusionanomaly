"""Create backend metadata, job, event, alert, and link tables."""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "20261104_0001"
down_revision = None
branch_labels = None
depends_on = None
json_value = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")


def upgrade() -> None:
    op.create_table("datasets",
        sa.Column("id", sa.Uuid(), primary_key=True), sa.Column("name", sa.String(240), nullable=False),
        sa.Column("source_filename", sa.String(255), nullable=False), sa.Column("storage_uri", sa.Text(), nullable=False),
        sa.Column("checksum", sa.String(64), nullable=False), sa.Column("file_size_bytes", sa.Integer(), nullable=False),
        sa.Column("schema_version", sa.String(64)), sa.Column("row_count", sa.Integer()), sa.Column("status", sa.String(32), nullable=False),
        sa.Column("metadata", json_value, nullable=False), sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False), sa.UniqueConstraint("checksum", name="uq_datasets_checksum"))
    op.create_table("model_registry",
        sa.Column("id", sa.Uuid(), primary_key=True), sa.Column("model_id", sa.String(200), nullable=False),
        sa.Column("model_name", sa.String(120), nullable=False), sa.Column("model_version", sa.String(64), nullable=False),
        sa.Column("model_type", sa.String(48), nullable=False), sa.Column("artifact_uri", sa.Text(), nullable=False),
        sa.Column("preprocessor_uri", sa.Text()), sa.Column("feature_schema_version", sa.String(64), nullable=False),
        sa.Column("class_mapping", json_value), sa.Column("threshold_configuration", json_value), sa.Column("metrics", json_value),
        sa.Column("status", sa.String(32), nullable=False), sa.Column("validated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False), sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("model_id", name="uq_model_registry_model_id"),
        sa.UniqueConstraint("model_name", "model_version", name="uq_model_name_version"))
    op.create_table("analysis_jobs",
        sa.Column("id", sa.Uuid(), primary_key=True), sa.Column("dataset_id", sa.Uuid(), sa.ForeignKey("datasets.id", ondelete="RESTRICT")),
        sa.Column("status", sa.String(16), nullable=False), sa.Column("requested_engines", json_value, nullable=False),
        sa.Column("selected_model_versions", json_value, nullable=False), sa.Column("configuration", json_value, nullable=False),
        sa.Column("total_records", sa.Integer(), nullable=False), sa.Column("processed_records", sa.Integer(), nullable=False),
        sa.Column("successful_records", sa.Integer(), nullable=False), sa.Column("failed_records", sa.Integer(), nullable=False),
        sa.Column("alerts_generated", sa.Integer(), nullable=False), sa.Column("error_message", sa.Text()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False), sa.Column("started_at", sa.DateTime(timezone=True)),
        sa.Column("completed_at", sa.DateTime(timezone=True)))
    op.create_index("ix_analysis_jobs_dataset_id", "analysis_jobs", ["dataset_id"])
    op.create_index("ix_analysis_jobs_status", "analysis_jobs", ["status"])
    op.create_index("ix_jobs_status_created", "analysis_jobs", ["status", "created_at"])
    op.create_index("uq_active_job_per_dataset", "analysis_jobs", ["dataset_id"], unique=True,
        postgresql_where=sa.text("status IN ('QUEUED', 'RUNNING')"), sqlite_where=sa.text("status IN ('QUEUED', 'RUNNING')"))
    op.create_table("detection_events",
        sa.Column("id", sa.Uuid(), primary_key=True), sa.Column("analysis_job_id", sa.Uuid(), sa.ForeignKey("analysis_jobs.id", ondelete="SET NULL")),
        sa.Column("dataset_id", sa.Uuid(), sa.ForeignKey("datasets.id", ondelete="SET NULL")),
        sa.Column("source_record_reference", sa.String(512), nullable=False), sa.Column("event_timestamp", sa.DateTime(timezone=True)),
        sa.Column("flow_metadata", json_value, nullable=False), sa.Column("binary_evidence", json_value),
        sa.Column("multiclass_evidence", json_value), sa.Column("anomaly_evidence", json_value),
        sa.Column("threat_score", sa.Numeric(7, 3)), sa.Column("severity", sa.String(16), nullable=False),
        sa.Column("event_status", sa.String(48), nullable=False), sa.Column("scoring_breakdown", json_value, nullable=False),
        sa.Column("explanation_references", json_value, nullable=False), sa.Column("event_fingerprint", sa.String(64), nullable=False),
        sa.Column("generated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("event_fingerprint", name="uq_event_fingerprint"))
    op.create_index("ix_detection_events_analysis_job_id", "detection_events", ["analysis_job_id"])
    op.create_index("ix_detection_events_dataset_id", "detection_events", ["dataset_id"])
    op.create_index("ix_detection_events_event_timestamp", "detection_events", ["event_timestamp"])
    op.create_index("ix_detection_events_event_status", "detection_events", ["event_status"])
    op.create_index("ix_events_generated_status", "detection_events", ["generated_at", "event_status"])
    op.create_table("alerts",
        sa.Column("id", sa.Uuid(), primary_key=True), sa.Column("alert_fingerprint", sa.String(64), nullable=False),
        sa.Column("title", sa.String(300), nullable=False), sa.Column("alert_type", sa.String(64), nullable=False),
        sa.Column("severity", sa.String(16), nullable=False), sa.Column("threat_score", sa.Numeric(7, 3), nullable=False),
        sa.Column("status", sa.String(24), nullable=False), sa.Column("predicted_categories", json_value, nullable=False),
        sa.Column("correlation_rule", sa.String(64)), sa.Column("correlation_metadata", json_value, nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True)), sa.Column("last_seen", sa.DateTime(timezone=True)),
        sa.Column("event_count", sa.Integer(), nullable=False), sa.Column("summary", sa.Text(), nullable=False),
        sa.Column("explanation", json_value, nullable=False), sa.Column("status_changed_at", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False), sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("alert_fingerprint", name="uq_alert_fingerprint"))
    op.create_index("ix_alerts_status", "alerts", ["status"])
    op.create_index("ix_alerts_first_seen", "alerts", ["first_seen"])
    op.create_index("ix_alerts_last_seen", "alerts", ["last_seen"])
    op.create_index("ix_alert_severity_status", "alerts", ["severity", "status"])
    op.create_index("ix_alert_threat_score", "alerts", ["threat_score"])
    op.create_table("alert_event_links",
        sa.Column("alert_id", sa.Uuid(), sa.ForeignKey("alerts.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("event_id", sa.Uuid(), sa.ForeignKey("detection_events.id", ondelete="RESTRICT"), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False))


def downgrade() -> None:
    op.drop_table("alert_event_links")
    op.drop_table("alerts")
    op.drop_table("detection_events")
    op.drop_table("analysis_jobs")
    op.drop_table("model_registry")
    op.drop_table("datasets")
