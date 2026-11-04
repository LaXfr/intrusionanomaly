from __future__ import annotations

import asyncio
import csv
import io
import json
from pathlib import Path

import httpx
import pytest

if hasattr(asyncio, "WindowsSelectorEventLoopPolicy"):
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

from streamlit.testing.v1 import AppTest

from dashboard.api_client import ApiClient, ApiError
from dashboard.services.export_service import csv_bytes, json_bytes


def response(status=200, payload=None, content=None, headers=None):
    body = content if content is not None else json.dumps({} if payload is None else payload).encode()
    return httpx.Response(status, content=body, headers=headers or {"content-type": "application/json"})


def test_get_posts_and_upload_use_actual_http_shapes():
    seen = []

    def handler(request):
        seen.append(request)
        return response(payload={"ok": True})

    client = ApiClient("http://localhost:8000/api/v1/", transport=httpx.MockTransport(handler))
    assert client.datasets(limit=2, offset=4) == {"ok": True}
    assert client.create_job({"dataset_id": "d", "engines": ["binary"]}) == {"ok": True}
    assert client.upload_dataset("flows.csv", b"a,b\r\n1,2\r\n") == {"ok": True}
    assert str(seen[0].url) == "http://localhost:8000/api/v1/datasets?limit=2&offset=4"
    assert json.loads(seen[1].content) == {"dataset_id": "d", "engines": ["binary"]}
    assert seen[1].headers["content-type"] == "application/json"
    assert "multipart/form-data; boundary=" in seen[2].headers["content-type"]
    assert b'name="file"; filename="flows.csv"' in seen[2].content
    assert b"a,b\r\n1,2\r\n" in seen[2].content


def test_api_client_handles_connection_timeout_http_errors_and_invalid_json():
    def fail_with(error_type):
        def handler(request):
            raise error_type("private detail", request=request)
        return ApiClient(transport=httpx.MockTransport(handler))

    with pytest.raises(ApiError, match="ConnectError") as connection:
        fail_with(httpx.ConnectError).health()
    assert "private detail" not in str(connection.value)
    with pytest.raises(ApiError, match="timed out"):
        fail_with(httpx.ReadTimeout).health()

    api_error = ApiClient(transport=httpx.MockTransport(
        lambda _request: response(422, {"error": {"code": "VALIDATION_ERROR", "message": "Request is invalid."}})
    ))
    with pytest.raises(ApiError, match="Request is invalid") as http_error:
        api_error.health()
    assert http_error.value.status_code == 422 and http_error.value.code == "VALIDATION_ERROR"

    html_error = ApiClient(transport=httpx.MockTransport(
        lambda _request: response(503, content=b"<html>unavailable</html>", headers={"content-type": "text/html"})
    ))
    with pytest.raises(ApiError, match="HTTP 503"):
        html_error.health()

    malformed = ApiClient(transport=httpx.MockTransport(
        lambda _request: response(content=b"{bad json", headers={"content-type": "application/json"})
    ))
    with pytest.raises(ApiError, match="invalid JSON"):
        malformed.health()


def test_api_client_rejects_unexpected_shapes_and_sensitive_url_credentials():
    client = ApiClient(transport=httpx.MockTransport(lambda _request: response(payload=[])))
    with pytest.raises(ApiError, match="unexpected response format"):
        client.health()
    with pytest.raises(ValueError, match="must not contain credentials"):
        ApiClient("https://operator:secret@example.test/api/v1")
    assert "secret" not in str(ApiError("Could not connect to the configured backend (ConnectError)."))


def test_alert_exports_are_valid_csv_json_and_empty_safe():
    rows = [
        {"id": "a1", "title": "DDoS, possible", "severity": "HIGH", "categories": ["DDoS"], "explanation": {"score": 70}},
        {"id": "a2", "title": "PortScan", "severity": "MEDIUM", "categories": [], "explanation": {}},
    ]
    output = csv_bytes(rows).decode("utf-8")
    records = list(csv.DictReader(io.StringIO(output, newline="")))
    assert [item["id"] for item in records] == ["a1", "a2"]
    assert records[0]["title"] == "DDoS, possible"
    assert json.loads(records[0]["categories"]) == ["DDoS"]
    assert json.loads(records[0]["explanation"]) == {"score": 70}
    assert csv_bytes([]) == b""
    assert json.loads(json_bytes(rows)) == rows
    assert json.loads(json_bytes([])) == []


class FakeApi:
    def __init__(self, *, fail_metrics=False, malformed=False, with_alerts=False,
                 fail_upload=False, invalid_upload=False, with_dataset=False, fail_job=False, invalid_job=False):
        self.fail_metrics = fail_metrics
        self.malformed = malformed
        self.with_alerts = with_alerts
        self.fail_upload = fail_upload
        self.invalid_upload = invalid_upload
        self.with_dataset = with_dataset
        self.fail_job = fail_job
        self.invalid_job = invalid_job
        self.uploaded = None
        self.created_job = None
        self.requested_job = None

    def metrics(self):
        if self.fail_metrics:
            raise ApiError("Backend unavailable (ConnectError).")
        return {"operational": {}, "persisted_alerts_by_severity": {}, "models": {"available": [], "unavailable": {}}, "historical_evaluation": {}}

    def traffic(self, **_params):
        if self.malformed:
            return {"predicted_categories": "not-a-map", "events_by_severity": None}
        return {"scope": {}, "total_flows": 0, "benign_predictions": 0, "malicious_predictions": 0,
                "anomalous_flows": 0, "suspicious_events": 0, "average_threat_score": None,
                "maximum_threat_score": None, "predicted_categories": {}, "events_by_severity": {}, "grouped_items": []}

    def alerts(self, **_params):
        items = ([{"id": "alert-1", "title": "Synthetic fixture alert", "severity": "HIGH", "status": "NEW"}]
                 if self.with_alerts else [])
        return {"items": items, "total": len(items), "limit": 50, "offset": 0}

    def alert(self, alert_id):
        if self.with_alerts and alert_id == "alert-1":
            return {"id": alert_id, "title": "Synthetic fixture alert", "severity": "HIGH", "status": "NEW"}
        return {}

    def datasets(self, **_params):
        items = ([{"id": "dataset-1", "name": "Fixture dataset", "status": "VALIDATED"}]
                 if self.with_dataset else [])
        return {"items": items, "total": len(items), "limit": 50, "offset": 0}

    def upload_dataset(self, filename, content):
        if self.fail_upload:
            raise ApiError("Upload rejected by the backend (FEATURE_SCHEMA_MISMATCH).", code="FEATURE_SCHEMA_MISMATCH")
        self.uploaded = (filename, content)
        if self.invalid_upload:
            return {}
        return {"id": "dataset-uploaded", "status": "VALIDATED", "row_count": 1}

    def models(self):
        items = ([{"model_type": "binary", "model_id": "binary-fixture-v1"}]
                 if self.with_dataset else [])
        return {"items": items, "ready_count": len(items), "unavailable_count": 0}

    def events(self, **_params):
        return {"items": [], "total": 0, "limit": 50, "offset": 0}

    def create_job(self, payload):
        if self.fail_job:
            raise ApiError("The backend could not queue this job (MODEL_UNAVAILABLE).", code="MODEL_UNAVAILABLE")
        self.created_job = payload
        return {"id": "job-1", "status": "QUEUED"}

    def job(self, job_id):
        self.requested_job = job_id
        return {} if self.invalid_job else {"id": job_id, "status": "COMPLETED", "processed_records": 1}

    def health(self):
        return {"service": "test API", "status": "alive", "version": "test"}

    def readiness(self):
        return {"status": "ready", "checks": {}}


PAGE_TITLES = [
    "Security Overview", "Traffic Analysis", "Attack Analysis", "Detection Alerts",
    "Anomaly Analysis", "Model Performance", "Explainability", "Dataset Management", "System Health",
]


def _launch(monkeypatch, fake):
    import dashboard.components as components

    monkeypatch.setattr(components, "ApiClient", lambda: fake)
    app_path = Path(__file__).resolve().parents[1] / "dashboard" / "app.py"
    return AppTest.from_file(app_path, default_timeout=10).run()


def test_all_nine_pages_navigate_and_render_with_empty_api_data(monkeypatch):
    app = _launch(monkeypatch, FakeApi())
    assert not app.exception
    radio = app.sidebar.radio[0]
    assert radio.options == ["Overview", "Traffic Analysis", "Attack Analysis", "Detection Alerts", "Anomaly Analysis", "Model Performance", "Explainability", "Dataset Management", "System Health"]
    for page, title in zip(radio.options, PAGE_TITLES):
        app.sidebar.radio[0].set_value(page).run()
        assert not app.exception, f"{page}: {[e.message for e in app.exception]}"
        assert any(item.value == title for item in app.title)


def test_all_nine_pages_render_backend_connection_errors_without_crashing(monkeypatch):
    class DisconnectedApi:
        def __getattr__(self, name):
            def fail(*_args, **_kwargs):
                raise ApiError("Backend unavailable (ConnectError).")
            return fail

    app = _launch(monkeypatch, DisconnectedApi())
    radio = app.sidebar.radio[0]
    for page, title in zip(radio.options, PAGE_TITLES):
        radio.set_value(page).run()
        assert not app.exception, f"{page}: {[e.message for e in app.exception]}"
        assert any(item.value == title for item in app.title)
        assert any("Backend unavailable" in item.value for item in app.error), page


def test_dashboard_handles_api_failures_empty_alerts_and_no_event_explanations(monkeypatch):
    app = _launch(monkeypatch, FakeApi(fail_metrics=True))
    app.sidebar.radio[0].set_value("Model Performance").run()
    assert not app.exception
    assert any("Backend unavailable" in item.value for item in app.error)
    app.sidebar.radio[0].set_value("Detection Alerts").run()
    assert not app.exception
    assert any("No alerts match" in item.value for item in app.info)
    app.sidebar.radio[0].set_value("Explainability").run()
    assert not app.exception
    messages = [item.value for item in app.info]
    assert any("No persisted events" in message for message in messages)
    assert len(app.get("plotly_chart")) == 0


def test_alert_page_shows_real_rows_and_both_export_controls(monkeypatch):
    import streamlit as st

    download_calls = []
    original_download_button = st.download_button

    def capture_download_button(*args, **kwargs):
        download_calls.append((args, kwargs))
        return original_download_button(*args, **kwargs)

    monkeypatch.setattr(st, "download_button", capture_download_button)
    app = _launch(monkeypatch, FakeApi(with_alerts=True))
    app.sidebar.radio[0].set_value("Detection Alerts").run()
    assert not app.exception
    buttons = app.get("download_button")
    assert [button.label for button in buttons] == ["Export filtered alerts (CSV)", "Export alerts (JSON)"]
    assert [(call[0][2], call[0][3]) for call in download_calls] == [
        ("alerts.csv", "text/csv"), ("alerts.json", "application/json")
    ]
    assert "Synthetic fixture alert" in str(app.dataframe[0].value)


def test_dataset_upload_success_and_backend_rejection_feedback(monkeypatch):
    fake = FakeApi()
    app = _launch(monkeypatch, fake)
    app.sidebar.radio[0].set_value("Dataset Management").run()
    app.file_uploader[0].set_value(("flows.csv", b"a,b\n1,2\n", "text/csv"))
    app.run()
    app.button[0].click().run()
    assert fake.uploaded == ("flows.csv", b"a,b\n1,2\n")
    assert any("Dataset registered: dataset-uploaded" in item.value for item in app.success)

    rejected = FakeApi(fail_upload=True)
    failed_app = _launch(monkeypatch, rejected)
    failed_app.sidebar.radio[0].set_value("Dataset Management").run()
    failed_app.file_uploader[0].set_value(("bad.csv", b"wrong,schema\n1,2\n", "text/csv"))
    failed_app.run()
    failed_app.button[0].click().run()
    assert any("Upload rejected by the backend" in item.value for item in failed_app.error)
    assert not failed_app.success

    malformed = FakeApi(invalid_upload=True)
    malformed_app = _launch(monkeypatch, malformed)
    malformed_app.sidebar.radio[0].set_value("Dataset Management").run()
    malformed_app.file_uploader[0].set_value(("missing-id.csv", b"a,b\n1,2\n", "text/csv"))
    malformed_app.run()
    malformed_app.button[0].click().run()
    assert any("no usable dataset ID" in item.value for item in malformed_app.error)


def test_analysis_job_submit_status_and_invalid_response_feedback(monkeypatch):
    fake = FakeApi(with_dataset=True)
    app = _launch(monkeypatch, fake)
    app.sidebar.radio[0].set_value("Dataset Management").run()
    app.button[0].click().run()
    assert fake.created_job == {"dataset_id": "dataset-1", "engines": ["binary"], "model_ids": {"binary": "binary-fixture-v1"}}
    assert any("Job job-1 submitted" in item.value for item in app.success)
    app.button[1].click().run()
    assert fake.requested_job == "job-1"
    assert any("COMPLETED" in str(item.value) for item in app.json)

    invalid = FakeApi(with_dataset=True, invalid_job=True)
    invalid_app = _launch(monkeypatch, invalid)
    invalid_app.sidebar.radio[0].set_value("Dataset Management").run()
    invalid_app.button[0].click().run()
    invalid_app.button[1].click().run()
    assert any("invalid analysis-job response" in item.value for item in invalid_app.error)

    failed_job = FakeApi(with_dataset=True, fail_job=True)
    failed_job_app = _launch(monkeypatch, failed_job)
    failed_job_app.sidebar.radio[0].set_value("Dataset Management").run()
    failed_job_app.button[0].click().run()
    assert any("could not queue this job" in item.value for item in failed_job_app.error)


def test_malformed_summary_data_does_not_crash_pages(monkeypatch):
    app = _launch(monkeypatch, FakeApi(malformed=True))
    for page in ("Overview", "Traffic Analysis", "Attack Analysis", "Anomaly Analysis"):
        app.sidebar.radio[0].set_value(page).run()
        assert not app.exception, f"{page}: {[e.message for e in app.exception]}"
