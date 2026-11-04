"""Typed, timeout-bounded client for the existing Phase 12 API contract."""

from __future__ import annotations

from urllib.parse import urlsplit, urlunsplit

import httpx

from dashboard.config import API_BASE_URL, REQUEST_TIMEOUT


class ApiError(RuntimeError):
    """A safe, user-displayable backend request or response error."""

    def __init__(self, message: str, status_code: int | None = None, code: str | None = None):
        super().__init__(message)
        self.status_code = status_code
        self.code = code


class ApiClient:
    """Make JSON calls to the configured `/api/v1` base URL.

    The API contract returns JSON objects for every supported route. This
    client rejects unexpected top-level JSON shapes before page code reads
    them, and never includes request bodies or exception text in errors.
    """

    def __init__(
        self,
        base_url: str | None = None,
        timeout: float | None = None,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        candidate = (base_url or API_BASE_URL).strip()
        parsed = urlsplit(candidate)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("The dashboard backend URL must be an absolute HTTP or HTTPS URL.")
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError("The dashboard backend URL must not contain credentials, a query, or a fragment.")
        self.base_url = urlunsplit((parsed.scheme, parsed.netloc, parsed.path.rstrip("/"), "", ""))
        self.timeout = REQUEST_TIMEOUT if timeout is None else timeout
        if self.timeout <= 0:
            raise ValueError("The dashboard request timeout must be greater than zero.")
        self.transport = transport

    def request(self, method: str, path: str, **kwargs) -> dict:
        try:
            with httpx.Client(timeout=self.timeout, transport=self.transport) as client:
                response = client.request(method, self.base_url + path, **kwargs)
        except httpx.TimeoutException as exc:
            raise ApiError("The backend request timed out. Try again or increase NII_DASHBOARD_TIMEOUT.") from exc
        except httpx.HTTPError as exc:
            raise ApiError(f"Could not connect to the configured backend ({type(exc).__name__}).") from exc

        try:
            payload = response.json()
        except ValueError as exc:
            if not response.is_success:
                raise ApiError(f"The backend returned HTTP {response.status_code} with a non-JSON error response.", response.status_code) from exc
            raise ApiError("The backend returned an invalid JSON response.", response.status_code) from exc

        if not response.is_success:
            error = payload.get("error") if isinstance(payload, dict) else None
            if not isinstance(error, dict):
                raise ApiError(f"The backend returned HTTP {response.status_code}.", response.status_code)
            message = error.get("message")
            code = error.get("code")
            if not isinstance(message, str) or not message.strip():
                message = f"The backend returned HTTP {response.status_code}."
            raise ApiError(message, response.status_code, code if isinstance(code, str) else None)

        if not isinstance(payload, dict):
            raise ApiError("The backend returned an unexpected response format.", response.status_code)
        return payload

    def get(self, path: str, params: dict | None = None) -> dict:
        return self.request("GET", path, params=params)

    def post(self, path: str, **kwargs) -> dict:
        return self.request("POST", path, **kwargs)

    def patch(self, path: str, **kwargs) -> dict:
        return self.request("PATCH", path, **kwargs)

    def health(self) -> dict:
        return self.get("/health")

    def readiness(self) -> dict:
        return self.get("/ready")

    def datasets(self, limit: int = 50, offset: int = 0) -> dict:
        return self.get("/datasets", params={"limit": limit, "offset": offset})

    def dataset(self, dataset_id: str) -> dict:
        return self.get(f"/datasets/{dataset_id}")

    def upload_dataset(self, filename: str, content: bytes) -> dict:
        return self.post("/datasets", files={"file": (filename, content, "text/csv")})

    def models(self) -> dict:
        return self.get("/models")

    def analyze(self, payload: dict) -> dict:
        return self.post("/analyze", json=payload)

    def create_job(self, payload: dict) -> dict:
        return self.post("/analysis-jobs", json=payload)

    def job(self, job_id: str) -> dict:
        return self.get(f"/analysis-jobs/{job_id}")

    def alerts(self, **params) -> dict:
        return self.get("/alerts", params=params)

    def alert(self, alert_id: str) -> dict:
        return self.get(f"/alerts/{alert_id}")

    def update_alert(self, alert_id: str, payload: dict) -> dict:
        return self.patch(f"/alerts/{alert_id}/status", json=payload)

    def metrics(self) -> dict:
        return self.get("/metrics")

    def traffic(self, **params) -> dict:
        return self.get("/traffic/summary", params=params)

    def events(self, **params) -> dict:
        return self.get("/events", params=params)

    def event(self, event_id: str) -> dict:
        return self.get(f"/events/{event_id}")

    def event_explanation(self, event_id: str, engine: str) -> dict:
        return self.get(f"/events/{event_id}/explanation", params={"engine": engine})
