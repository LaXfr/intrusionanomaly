"""Backend API tests using isolated SQLite and clearly synthetic detector fixtures."""

from __future__ import annotations

import csv
import asyncio
import io
import json
import uuid
from dataclasses import replace
from pathlib import Path

import pandas as pd
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker

from api.core.config import Settings
from api.database.base import Base
from api.database.models import Alert, AnalysisJob, Dataset, DetectionEvent
from api.main import create_app
from api.services.model_service import ModelService
from intrusion_intelligence.feature_engineering import FeatureContract


# Windows' default Proactor policy can stall while AnyIO creates its loopback
# socket in restricted test runners. The selector policy keeps TestClient's
# in-process ASGI transport deterministic on Windows.
if hasattr(asyncio, "WindowsSelectorEventLoopPolicy"):
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())


class SyntheticModelService:
    """Explicit test-only outputs; production requests use persisted predictors."""

    def __init__(self, settings: Settings):
        contract = FeatureContract.from_file(settings.feature_schema_path)
        self.class_labels = list(contract.target_values)
        self.items = [{"model_id": "binary-random_forest-v1.0.1", "model_name": "binary_random_forest", "model_version": "1.0.1", "model_type": "binary", "feature_schema_version": contract.schema_version, "input_feature_count": 78, "class_mapping": {"BENIGN": 0, "ATTACK": 1}, "threshold_configuration": {"decision_threshold": 0.5}, "status": "READY", "supported_prediction_types": ["binary"], "metrics": None},
            {"model_id": "multiclass-random_forest-v1.0.0", "model_name": "multiclass_random_forest", "model_version": "1.0.0", "model_type": "multiclass", "feature_schema_version": contract.schema_version, "input_feature_count": 78, "class_mapping": self.class_labels, "threshold_configuration": None, "status": "READY", "supported_prediction_types": ["multiclass"], "metrics": None},
            {"model_id": "isolation-forest-v1.0.0", "model_name": "isolation_forest", "model_version": "1.0.0", "model_type": "anomaly", "feature_schema_version": contract.schema_version, "input_feature_count": 78, "class_mapping": None, "threshold_configuration": {"threshold": 0.5}, "status": "READY", "supported_prediction_types": ["anomaly"], "metrics": None}]

    def list_models(self):
        return self.items, {"xgboost": "No trained XGBoost artifact."}

    def sync_database_registry(self, _session):
        return self.items

    def resolve_model(self, engine: str, requested_id=None):
        choices = [item for item in self.items if item["model_type"] == engine]
        chosen = requested_id or choices[0]["model_id"]
        if not any(item["model_id"] == chosen for item in choices):
            from api.core.errors import ApiError
            raise ApiError(404, "MODEL_NOT_FOUND", "Requested test model is unavailable.")
        return chosen, choices[0]

    def infer(self, engine: str, X: pd.DataFrame, *, requested_id=None, operating_point=None):
        choices = [item for item in self.items if item["model_type"] == engine]
        chosen = requested_id or choices[0]["model_id"]
        if not any(item["model_id"] == chosen for item in choices):
            from api.core.errors import ApiError
            raise ApiError(404, "MODEL_NOT_FOUND", "Requested test model is unavailable.")
        if engine == "binary":
            values = [{"predicted_label": "ATTACK", "malicious_score": 0.99, "threshold": 0.5,
                       "score_is_calibrated_probability": False, "model_id": chosen, "model_version": "1.0.1"} for _ in range(len(X))]
        elif engine == "multiclass":
            scores = {label: (0.98 if label == "DDoS" else 0.02 / (len(self.class_labels) - 1)) for label in self.class_labels}
            values = [{"predicted_class": self.class_labels.index("DDoS"), "predicted_label": "DDoS", "class_scores": scores,
                       "model_id": chosen, "model_version": "1.0.0"} for _ in range(len(X))]
        else:
            values = [{"model_id": chosen, "raw_model_score": -0.6, "anomaly_score": 0.6, "threshold": 0.5,
                       "decision": "ANOMALOUS", "operating_point": operating_point or "target-fpr-1pct"} for _ in range(len(X))]
        return chosen, values


@pytest.fixture
def backend(tmp_path):
    db_file = tmp_path / "backend.sqlite"
    settings = replace(Settings.from_env(), database_url=f"sqlite:///{db_file.as_posix()}",
        upload_dir=tmp_path / "uploads", max_upload_bytes=1024 * 1024, max_request_bytes=2 * 1024 * 1024,
        max_analysis_records=10, max_batch_size=10, max_job_rows=100, job_batch_size=5, cors_origins=("http://localhost:8501",))
    engine = create_engine(settings.database_url, connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    app = create_app(settings=settings, session_factory=factory, model_service=SyntheticModelService(settings))
    with TestClient(app) as client:
        yield client, settings, factory
    engine.dispose()


def _feature_columns() -> list[str]:
    return list(FeatureContract.from_file("configs/feature_schema.json").predictive_features)


def _csv_bytes(rows: int = 1) -> bytes:
    frame = pd.DataFrame([{name: 0.0 for name in _feature_columns()} for _ in range(rows)])
    return frame.to_csv(index=False).encode("utf-8")


def _flow_record() -> dict:
    return {"features": {name: 0.0 for name in _feature_columns()},
            "metadata": {"flow_record_reference": "synthetic-test#row=1", "source_filename": "synthetic.csv", "source_row_number": 1}}


def test_model_service_uses_logistic_predictor_for_registered_binary_logistic(monkeypatch):
    # The predictor selection exercises the real registered artifact, independently
    # of any database so this test remains deterministic and isolated.
    monkeypatch.delenv("NII_DATABASE_URL", raising=False)
    settings = Settings.from_env()
    service = ModelService(settings)
    frame = pd.DataFrame([{name: 0.0 for name in _feature_columns()}])

    model_id, predictions = service.infer(
        "binary", frame, requested_id="binary-logistic_regression-v1.0.2"
    )

    assert model_id == "binary-logistic_regression-v1.0.2"
    assert len(predictions) == 1
    assert predictions[0]["model_id"] == model_id
    assert predictions[0]["predicted_label"] in {"BENIGN", "ATTACK"}


def test_app_initialization_openapi_health_readiness_and_cors(backend):
    client, _settings, _factory = backend
    assert client.get("/api/v1/health").json()["status"] == "alive"
    assert client.get("/api/v1/ready").json()["status"] == "ready"
    spec = client.get("/openapi.json").json()
    assert spec["info"]["version"] == "1.0.0"
    assert "/api/v1/analyze" in spec["paths"]
    assert client.options("/api/v1/health", headers={"Origin": "http://localhost:8501", "Access-Control-Request-Method": "GET"}).headers.get("access-control-allow-origin") == "http://localhost:8501"


def test_liveness_does_not_require_database_and_readiness_reports_unavailable(tmp_path):
    settings = replace(Settings.from_env(), database_url="", upload_dir=tmp_path / "uploads")
    app = create_app(settings=settings, model_service=SyntheticModelService(settings))
    with TestClient(app) as client:
        assert client.get("/api/v1/health").status_code == 200
        response = client.get("/api/v1/ready")
        assert response.status_code == 503
        assert response.json()["error"]["code"] == "DATABASE_UNAVAILABLE"
        assert "traceback" not in response.text.lower()


def test_upload_registration_validation_duplicate_pagination_and_safe_metadata(backend):
    client, _settings, _factory = backend
    response = client.post("/api/v1/datasets", files={"file": ("flows.csv", _csv_bytes(), "text/csv")})
    assert response.status_code == 201, response.text
    dataset = response.json()
    assert dataset["status"] == "VALIDATED" and dataset["row_count"] == 1
    assert dataset["metadata"]["inspection_status"] == "valid"
    assert dataset["metadata"]["label_present"] is False
    assert "storage_uri" not in dataset and "C:\\" not in response.text
    assert client.get("/api/v1/datasets?limit=1").json()["total"] == 1
    assert client.get(f"/api/v1/datasets/{dataset['id']}").json()["checksum"] == dataset["checksum"]
    duplicate = client.post("/api/v1/datasets", files={"file": ("same.csv", _csv_bytes(), "text/csv")})
    assert duplicate.status_code == 409
    assert client.post("/api/v1/datasets", files={"file": ("../escape.csv", _csv_bytes(), "text/csv")}).status_code == 400
    assert client.post("/api/v1/datasets", files={"file": ("model.pkl", b"x", "application/octet-stream")}).status_code == 400


def test_upload_size_invalid_csv_and_feature_contract_errors(backend):
    client, _settings, _factory = backend
    too_large = client.post("/api/v1/datasets", files={"file": ("large.csv", b"x" * 1_100_000, "text/csv")})
    assert too_large.status_code == 413
    invalid = client.post("/api/v1/datasets", files={"file": ("bad.csv", b"a,b\n1,2\n", "text/csv")})
    assert invalid.status_code == 422
    invalid_analysis = client.post("/api/v1/analyze", json={"records": [{"features": {"bad_feature": 1.0}}], "engines": ["binary"]})
    assert invalid_analysis.status_code == 422
    assert invalid_analysis.json()["error"]["code"] == "FEATURE_SCHEMA_MISMATCH"


def test_model_registry_analysis_persistence_alert_lifecycle_metrics_and_traffic(backend):
    client, _settings, factory = backend
    models = client.get("/api/v1/models")
    assert models.status_code == 200 and models.json()["ready_count"] == 3
    assert "artifact_uri" not in models.text and "C:\\" not in models.text
    analysis = client.post("/api/v1/analyze", json={"records": [_flow_record()], "engines": ["binary", "multiclass", "anomaly"]})
    assert analysis.status_code == 200, analysis.text
    result = analysis.json()
    assert result["successful_records"] == 1 and result["generated_event_count"] == 1
    assert result["generated_alert_count"] == 1 and result["summary"]["heuristic_score_is_probability"] is False
    with factory() as session:
        assert session.scalar(select(DetectionEvent)) is not None
        alert = session.scalar(select(Alert))
        assert alert is not None and alert.status == "NEW"
        alert_id = str(alert.id)
    listed = client.get("/api/v1/alerts?severity=CRITICAL&status=NEW&limit=10")
    assert listed.status_code == 200 and listed.json()["total"] == 1
    detail = client.get(f"/api/v1/alerts/{alert_id}")
    assert detail.status_code == 200 and len(detail.json()["supporting_event_ids"]) == 1
    changed = client.patch(f"/api/v1/alerts/{alert_id}/status", json={"status": "ACKNOWLEDGED", "changed_by": "test-operator"})
    assert changed.status_code == 200 and changed.json()["previous_status"] == "NEW"
    conflict = client.patch(f"/api/v1/alerts/{alert_id}/status", json={"status": "NEW"})
    assert conflict.status_code == 409
    metrics = client.get("/api/v1/metrics").json()
    assert metrics["operational"]["security_alerts"] == 1
    assert metrics["persisted_alerts_by_status"]["ACKNOWLEDGED"] == 1
    traffic = client.get("/api/v1/traffic/summary?group_by=attack_category").json()
    assert traffic["total_flows"] == 1 and traffic["malicious_predictions"] == 1
    assert traffic["anomalous_flows"] == 1 and traffic["predicted_categories"]["DDoS"] == 1
    events = client.get("/api/v1/events?limit=1&offset=0")
    assert events.status_code == 200 and events.json()["total"] == 1
    event_id = events.json()["items"][0]["id"]
    detail = client.get(f"/api/v1/events/{event_id}")
    assert detail.status_code == 200 and detail.json()["id"] == event_id
    assert detail.json()["detector_evidence"]["binary"]["model_id"] == "binary-random_forest-v1.0.1"
    assert client.get(f"/api/v1/events/{uuid.uuid4()}").status_code == 404
    assert client.get("/api/v1/events/not-a-uuid").status_code == 422
    unavailable = client.get(f"/api/v1/events/{event_id}/explanation?engine=binary")
    assert unavailable.status_code == 200
    assert unavailable.json()["availability_status"] == "unavailable"


def test_dataset_scale_job_is_in_process_bounded_and_persists_progress(backend):
    client, _settings, factory = backend
    uploaded = client.post("/api/v1/datasets", files={"file": ("job.csv", _csv_bytes(2), "text/csv")}).json()
    response = client.post("/api/v1/analysis-jobs", json={"dataset_id": uploaded["id"], "engines": ["binary"]})
    assert response.status_code == 202, response.text
    job = response.json()
    # TestClient runs Starlette BackgroundTasks before returning the response.
    status = client.get(f"/api/v1/analysis-jobs/{job['id']}").json()
    assert status["status"] == "COMPLETED"
    assert status["processed_records"] == status["successful_records"] == 2
    assert status["failed_records"] == 0
    duplicate_running = AnalysisJob(dataset_id=uuid.UUID(uploaded["id"]), status="RUNNING", requested_engines=["binary"],
        selected_model_versions={}, configuration={}, total_records=1)
    with factory() as session:
        session.add(duplicate_running)
        session.commit()
    conflict = client.post("/api/v1/analysis-jobs", json={"dataset_id": uploaded["id"], "engines": ["binary"]})
    assert conflict.status_code == 409
    cancellation = client.post(f"/api/v1/analysis-jobs/{duplicate_running.id}/cancel")
    assert cancellation.status_code == 200 and cancellation.json()["status"] == "CANCELLED"
    assert client.post(f"/api/v1/analysis-jobs/{duplicate_running.id}/cancel").status_code == 409


def test_event_explanation_reports_unconfigured_model_as_unsupported(backend):
    client, _settings, factory = backend
    uploaded = client.post("/api/v1/datasets", files={"file": ("unsupported.csv", _csv_bytes(), "text/csv")})
    assert uploaded.status_code == 201
    analysis = client.post("/api/v1/analyze", json={"dataset_id": uploaded.json()["id"], "engines": ["binary"]})
    assert analysis.status_code == 200
    event_id = analysis.json()["event_ids"][0]
    with factory() as session:
        event = session.get(DetectionEvent, uuid.UUID(event_id))
        event.binary_evidence = {**event.binary_evidence, "model_id": "unregistered-model-v0"}
        session.commit()
    response = client.get(f"/api/v1/events/{event_id}/explanation?engine=binary")
    assert response.status_code == 200
    assert response.json()["availability_status"] == "unsupported"
    assert "No validated SHAP strategy" in response.json()["reason"]


def test_analysis_rejects_unknown_model_and_enforces_record_limit(backend):
    client, _settings, _factory = backend
    wrong_model = client.post("/api/v1/analyze", json={"records": [_flow_record()], "engines": ["binary"], "model_ids": {"binary": "C:/arbitrary.pkl"}})
    assert wrong_model.status_code == 404
    too_many = client.post("/api/v1/analyze", json={"records": [_flow_record() for _ in range(11)], "engines": ["binary"]})
    assert too_many.status_code == 413
    one_engine = client.post("/api/v1/analyze", json={"records": [_flow_record()], "engines": ["binary"]})
    assert one_engine.status_code == 200
    assert one_engine.json()["summary"]["detector_availability"]["multiclass"] == {"unavailable": 1}


def test_alert_filters_sorting_date_range_and_missing_resources(backend):
    client, _settings, _factory = backend
    assert client.get(f"/api/v1/alerts/{uuid.uuid4()}").status_code == 404
    assert client.get(f"/api/v1/analysis-jobs/{uuid.uuid4()}").status_code == 404
    assert client.get(f"/api/v1/events/{uuid.uuid4()}/explanation?engine=invalid").status_code == 422
    assert client.get("/api/v1/alerts?sort_by=untrusted_sql").status_code == 422
    assert client.get("/api/v1/alerts?start=2026-12-02T00:00:00Z&end=2026-11-01T00:00:00Z").status_code == 422


def test_response_errors_are_structured_and_hide_internal_stack(backend):
    client, _settings, _factory = backend
    invalid = client.post("/api/v1/analyze", json={"records": [], "engines": []})
    assert invalid.status_code == 422
    assert invalid.json()["error"]["code"] == "VALIDATION_ERROR"
    assert "traceback" not in invalid.text.lower()
    assert client.get("/not-found").json()["error"]["code"] == "NOT_FOUND"
    assert client.get("/api/v1/health").headers.get("x-request-id")


def test_sqlalchemy_unique_fingerprint_and_transaction_rollback(backend):
    _client, _settings, factory = backend
    row = Dataset(name="d", source_filename="d.csv", storage_uri="/tmp/d.csv", checksum="a" * 64, file_size_bytes=1,
        status="VALIDATED", dataset_metadata={})
    with factory() as session:
        session.add(row)
        session.commit()
        duplicate = Dataset(name="d2", source_filename="d2.csv", storage_uri="/tmp/d2.csv", checksum="a" * 64, file_size_bytes=1,
            status="VALIDATED", dataset_metadata={})
        session.add(duplicate)
        with pytest.raises(IntegrityError):
            session.commit()
        session.rollback()
        assert session.scalar(select(Dataset).where(Dataset.checksum == "a" * 64)).name == "d"

