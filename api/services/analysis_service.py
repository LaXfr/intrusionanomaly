"""Bounded feature validation, existing-model inference, intelligence, and persistence."""

from __future__ import annotations

import logging
import uuid
from datetime import datetime
from typing import Any

import pandas as pd
from sqlalchemy import select
from sqlalchemy.orm import Session

from intrusion_intelligence.feature_engineering import FeatureContract, separate_features_target_metadata
from intrusion_intelligence.intelligence.config import load_intelligence_config
from intrusion_intelligence.intelligence.pipeline import run_intelligence_pipeline

from api.core.config import Settings
from api.core.errors import ApiError
from api.database.models import Alert, AlertEventLink, AnalysisJob, Dataset, DetectionEvent
from api.schemas import AnalysisResponse, EngineName, FlowRecord
from api.services.model_service import ModelService

logger = logging.getLogger(__name__)


def _parse_datetime(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed
    except ValueError:
        return None


class AnalysisService:
    def __init__(self, settings: Settings, models: ModelService) -> None:
        self.settings = settings
        self.models = models
        self.contract = FeatureContract.from_file(settings.feature_schema_path)
        self.intelligence = load_intelligence_config(settings.intelligence_config_path)

    def records_from_frame(self, frame: pd.DataFrame) -> list[dict[str, Any]]:
        X, _, metadata = separate_features_target_metadata(frame, self.contract, require_target=False)
        records = []
        for index in range(len(X)):
            meta = metadata.iloc[index].where(pd.notna(metadata.iloc[index]), None).to_dict()
            features = X.iloc[index].where(pd.notna(X.iloc[index]), None).to_dict()
            records.append({"features": features, "metadata": meta})
        return records

    def analyze_and_persist(self, session: Session, records: list[FlowRecord | dict[str, Any]], *,
                            engines: list[str], model_ids: dict[str, str] | None = None,
                            anomaly_operating_point: str | None = None,
                            dataset_id: uuid.UUID | None = None,
                            job: AnalysisJob | None = None) -> AnalysisResponse:
        if not records or len(records) > self.settings.max_analysis_records and job is None:
            raise ApiError(413, "ANALYSIS_LIMIT_EXCEEDED", "Synchronous analysis exceeds the configured record limit.")
        prepared = [self._record_dict(record) for record in records]
        frame = pd.DataFrame([item["features"] for item in prepared])
        try:
            X, _, _ = separate_features_target_metadata(frame, self.contract, require_target=False)
        except Exception as exc:
            raise ApiError(422, "FEATURE_SCHEMA_MISMATCH", "Input feature rows do not match the approved feature contract.") from exc
        predictions: dict[str, list[dict[str, Any]] | None] = {"binary": None, "multiclass": None, "anomaly": None}
        chosen_models: dict[str, str] = {}
        selected_ids = model_ids or {}
        for engine in engines:
            model_id, output = self.models.infer(engine, X, requested_id=selected_ids.get(engine), operating_point=anomaly_operating_point)
            chosen_models[engine] = model_id
            predictions[engine] = output
        flow_metadata = []
        for item in prepared:
            meta = dict(item.get("metadata") or {})
            flow_metadata.append({key: value for key, value in meta.items() if value is not None})
        config = self.intelligence
        result = run_intelligence_pipeline(
            flow_metadata,
            binary_predictions=predictions["binary"],
            multiclass_predictions=predictions["multiclass"],
            anomaly_predictions=predictions["anomaly"],
            class_labels=self.models.class_labels,
            weights=config["scoring"]["weights"], severity_bands=config["severity"]["bands"],
            correlation_config=config["correlation"], alert_config=config["alerts"],
            scoring_version=config["scoring"]["version"], severity_policy_version=config["severity"]["version"],
            pipeline_version=config["version"], feature_schema_version=self.contract.schema_version,
            # Store validated model IDs, never internal artifact paths.
            model_artifact_references=chosen_models,
        )
        owned_job = job is None
        if job is None:
            job = AnalysisJob(dataset_id=dataset_id, status="RUNNING", requested_engines=engines,
                selected_model_versions=chosen_models, configuration={"mode": "synchronous_records"},
                total_records=len(prepared), successful_records=0, failed_records=0)
            session.add(job)
            session.flush()
        id_mapping: dict[str, uuid.UUID] = {}
        for event in result["events"]:
            row = session.scalar(select(DetectionEvent).where(DetectionEvent.event_fingerprint == event["event_fingerprint"]))
            if row is None:
                evidence = event["normalized_evidence"]
                context = {**event.get("network_context", {}), "source_filename": event.get("source_filename"),
                           "source_row_number": event.get("source_row_number"), "flow_id": event.get("flow_id"),
                           "metadata_provenance": event.get("metadata_provenance", {})}
                row = DetectionEvent(analysis_job_id=job.id, dataset_id=dataset_id,
                    source_record_reference=event["flow_record_reference"], event_timestamp=_parse_datetime(event.get("timestamp_utc")),
                    flow_metadata=context, binary_evidence=evidence.get("binary"), multiclass_evidence=evidence.get("multiclass"),
                    anomaly_evidence=evidence.get("anomaly"), threat_score=event.get("threat_score"), severity=event["severity"],
                    event_status=event["event_status"], scoring_breakdown=event.get("score_breakdown", {}),
                    explanation_references=[], event_fingerprint=event["event_fingerprint"],
                    generated_at=_parse_datetime(event.get("generated_at_utc")) or datetime.now().astimezone())
                session.add(row)
                session.flush()
            id_mapping[event["event_id"]] = row.id

        persisted_alerts = []
        for alert_doc in result["alerts"]:
            row = session.scalar(select(Alert).where(Alert.alert_fingerprint == alert_doc["alert_fingerprint"]))
            if row is None:
                row = Alert(alert_fingerprint=alert_doc["alert_fingerprint"], title=alert_doc["title"],
                    alert_type=alert_doc["alert_type"], severity=alert_doc["severity"], threat_score=alert_doc["threat_score"],
                    status=alert_doc["status"], predicted_categories=alert_doc.get("attack_categories", []),
                    correlation_rule=",".join(alert_doc.get("correlation_rules", [])) or None,
                    correlation_metadata={"keys": alert_doc.get("correlation_keys", []), "network_context": alert_doc.get("network_context", {})},
                    first_seen=_parse_datetime(alert_doc.get("first_observed_utc")), last_seen=_parse_datetime(alert_doc.get("last_observed_utc")),
                    event_count=alert_doc.get("related_event_count", 0), summary=alert_doc.get("explanation", ""),
                    explanation={"investigation_steps": alert_doc.get("investigation_steps", []),
                        "detector_evidence_summary": alert_doc.get("detector_evidence_summary", {}),
                        "detector_disagreements": alert_doc.get("detector_disagreements", []),
                        "scoring_breakdown": alert_doc.get("scoring_breakdown", {}),
                        "limitations": alert_doc.get("known_limitations", [])})
                session.add(row)
                session.flush()
            # A repeated fingerprint may add traceability but does not replace
            # score, severity, evidence, or lifecycle state.
            linked = set(session.scalars(select(AlertEventLink.event_id).where(AlertEventLink.alert_id == row.id)))
            for event_id in alert_doc.get("supporting_event_ids", []):
                db_event_id = id_mapping.get(event_id)
                if db_event_id and db_event_id not in linked:
                    session.add(AlertEventLink(alert_id=row.id, event_id=db_event_id))
                    linked.add(db_event_id)
            persisted_alerts.append(row)

        job.total_records = max(job.total_records, len(prepared))
        job.processed_records += len(prepared) if not owned_job else 0
        job.successful_records += len(prepared) if not owned_job else 0
        job.alerts_generated += len(persisted_alerts)
        if owned_job:
            job.status = "COMPLETED"
            job.started_at = datetime.now().astimezone()
            job.completed_at = datetime.now().astimezone()
            job.processed_records = len(prepared)
            job.successful_records = len(prepared)
        session.commit()
        session.refresh(job)
        return AnalysisResponse(job_id=job.id, total_records=len(prepared), successful_records=len(prepared), failed_records=0,
            generated_event_count=len(result["events"]), generated_alert_count=len(persisted_alerts), requested_engines=engines,
            event_ids=list(id_mapping.values()), alerts=[self._alert_response(item) for item in persisted_alerts],
            summary={**result["summary"], "dataset_scope_truncated": False, "evaluation_labels_used_for_inference": False})

    @staticmethod
    def _record_dict(record: FlowRecord | dict[str, Any]) -> dict[str, Any]:
        if isinstance(record, FlowRecord):
            return record.model_dump(mode="json", exclude_none=True)
        return record

    @staticmethod
    def _alert_response(row: Alert) -> dict[str, Any]:
        return {"id": row.id, "alert_fingerprint": row.alert_fingerprint, "title": row.title,
                "alert_type": row.alert_type, "severity": row.severity, "threat_score": float(row.threat_score),
                "status": row.status, "predicted_categories": row.predicted_categories,
                "event_count": row.event_count, "summary": row.summary}
