"""Bounded in-process analysis jobs with persisted batch progress."""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone

from fastapi import BackgroundTasks
from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from api.core.config import Settings
from api.core.errors import ApiError
from api.database.models import AnalysisJob
from api.database.session import build_session_factory
from api.schemas import EngineName, JobCreateRequest
from api.services.analysis_service import AnalysisService
from api.services.dataset_service import DatasetService
from api.services.model_service import ModelService

logger = logging.getLogger(__name__)


class JobService:
    def __init__(self, settings: Settings, datasets: DatasetService, models: ModelService, analysis: AnalysisService) -> None:
        self.settings, self.datasets, self.models, self.analysis = settings, datasets, models, analysis
        self.session_factory: sessionmaker[Session] | None = None

    def configure_session_factory(self, factory: sessionmaker[Session] | None) -> None:
        self.session_factory = factory

    def create(self, session: Session, request: JobCreateRequest, background: BackgroundTasks) -> AnalysisJob:
        dataset = self.datasets.get(session, request.dataset_id)
        if dataset.status != "VALIDATED":
            raise ApiError(409, "DATASET_NOT_VALIDATED", "Only validated datasets can be analyzed.")
        if dataset.row_count and dataset.row_count > self.settings.max_job_rows:
            raise ApiError(413, "JOB_ROW_LIMIT_EXCEEDED", "Dataset exceeds the configured maximum job row count.")
        active = session.scalar(select(AnalysisJob).where(AnalysisJob.dataset_id == dataset.id, AnalysisJob.status.in_(["QUEUED", "RUNNING"])))
        if active is not None:
            raise ApiError(409, "JOB_ALREADY_ACTIVE", "An analysis job is already queued or running for this dataset.")
        selected = {}
        requested = {}
        for engine in request.engines:
            model_id, _ = self.models.resolve_model(engine.value, request.model_ids.get(engine))
            selected[engine.value] = model_id
            requested[engine.value] = model_id
        job = AnalysisJob(dataset_id=dataset.id, status="QUEUED", requested_engines=[item.value for item in request.engines],
            selected_model_versions=selected, configuration={"anomaly_operating_point": request.anomaly_operating_point,
                "execution": "FastAPI in-process BackgroundTasks; interruption is marked FAILED on restart"},
            total_records=dataset.row_count or 0, processed_records=0, successful_records=0, failed_records=0, alerts_generated=0)
        session.add(job)
        try:
            session.commit()
        except IntegrityError as exc:
            session.rollback()
            raise ApiError(409, "JOB_ALREADY_ACTIVE", "An analysis job is already queued or running for this dataset.") from exc
        session.refresh(job)
        background.add_task(self.run_job, str(job.id))
        logger.info("Queued analysis job id=%s engines=%s", job.id, job.requested_engines)
        return job

    def get(self, session: Session, job_id: uuid.UUID) -> AnalysisJob:
        job = session.get(AnalysisJob, job_id)
        if job is None:
            raise ApiError(404, "JOB_NOT_FOUND", "Analysis job was not found.")
        return job

    def cancel(self, session: Session, job_id: uuid.UUID) -> AnalysisJob:
        job = self.get(session, job_id)
        if job.status not in {"QUEUED", "RUNNING"}:
            raise ApiError(409, "INVALID_JOB_TRANSITION", f"Job cannot be cancelled from {job.status}.")
        job.status = "CANCELLED"
        job.error_message = "Cancellation requested; any active batch may finish before processing stops."
        job.completed_at = datetime.now(timezone.utc)
        session.commit()
        session.refresh(job)
        return job

    def run_job(self, job_id: str) -> None:
        factory = self.session_factory
        if factory is None:
            logger.error("Cannot execute job=%s because the database is not configured", job_id)
            return
        try:
            with factory() as session:
                job = session.get(AnalysisJob, uuid.UUID(job_id))
                if job is None or job.status != "QUEUED":
                    return
                dataset = self.datasets.get(session, job.dataset_id)
                job.status = "RUNNING"
                job.started_at = datetime.now(timezone.utc)
                session.commit()
                batches = self.datasets.iter_batches(dataset, self.settings.job_batch_size, self.settings.max_job_rows)
                processed = 0
                for frame in batches:
                    records = self.analysis.records_from_frame(frame)
                    if not records:
                        continue
                    for offset, record in enumerate(records, start=1):
                        metadata = record.setdefault("metadata", {})
                        row_number = processed + offset
                        metadata.update(source_filename=dataset.source_filename,
                            source_row_number=row_number,
                            flow_record_reference=f"dataset:{dataset.id}#row={row_number}")
                    with factory() as batch_session:
                        current = batch_session.get(AnalysisJob, uuid.UUID(job_id))
                        if current is None or current.status == "CANCELLED":
                            return
                        if current.status != "RUNNING":
                            raise RuntimeError("Analysis job left RUNNING state before a batch completed.")
                        self.analysis.analyze_and_persist(batch_session, records,
                            engines=current.requested_engines, model_ids=current.selected_model_versions,
                            anomaly_operating_point=current.configuration.get("anomaly_operating_point"),
                            dataset_id=current.dataset_id, job=current)
                    processed += len(records)
                    logger.info("Analysis job progress id=%s processed=%s", job_id, processed)
                with factory() as final_session:
                    final = final_session.get(AnalysisJob, uuid.UUID(job_id))
                    if final is not None and final.status == "RUNNING":
                        final.status = "COMPLETED"
                        final.completed_at = datetime.now(timezone.utc)
                        final.total_records = processed
                        final_session.commit()
        except Exception as exc:
            logger.exception("Analysis job failed id=%s", job_id)
            try:
                with factory() as failure_session:
                    failed = failure_session.get(AnalysisJob, uuid.UUID(job_id))
                    if failed is not None and failed.status in {"QUEUED", "RUNNING"}:
                        failed.status = "FAILED"
                        failed.failed_records = max(failed.total_records - failed.processed_records, 0)
                        failed.error_message = "Analysis failed; see server logs for the request correlation identifier."
                        failed.completed_at = datetime.now(timezone.utc)
                        failure_session.commit()
            except Exception:
                logger.exception("Could not persist failed state for job=%s", job_id)

    def mark_interrupted_jobs(self, factory: sessionmaker[Session]) -> int:
        with factory() as session:
            jobs = list(session.scalars(select(AnalysisJob).where(AnalysisJob.status.in_(["QUEUED", "RUNNING"]))))
            for job in jobs:
                job.status = "FAILED"
                job.error_message = "In-process job was interrupted by application shutdown or restart."
                job.completed_at = datetime.now(timezone.utc)
            session.commit()
            return len(jobs)
