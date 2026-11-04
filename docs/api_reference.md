# Backend API Reference

The local API base URL is `http://127.0.0.1:8000/api/v1`. Interactive OpenAPI documentation is at `/docs`, ReDoc at `/redoc`, and the machine-readable spec at `/openapi.json`. Requests use JSON except CSV uploads. Responses include an `X-Request-ID`; errors use `{ "error": { "code", "message", "request_id", "details?" } }` and do not expose stack traces or database credentials. The saved model bundles were produced with scikit-learn 1.8.0; the `ml` and `preprocessing` extras pin this version so a local or container install does not silently select a newer unverified deserialization runtime.

## Run locally

```powershell
python -m pip install -e ".[data,parquet,preprocessing,api,database,dev]"
Copy-Item .env.example .env
# Configure NII_DATABASE_URL in .env, or start the Compose database.
docker compose up -d db
alembic upgrade head
uvicorn api.main:app --env-file .env --host 127.0.0.1 --port 8000
```

The listener defaults to loopback. Do not set a wildcard CORS origin. Dataset uploads accept bounded CSV files matching the Phase 05 78-feature contract. Identifiers and provenance columns are metadata; they are not sent to model predictors.

## Routes

| Method and path | Purpose |
|---|---|
| `GET /health` | Liveness check; does not require PostgreSQL. |
| `GET /ready` | Database, feature contract, upload directory, and model-registry readiness. Returns 503 if the database cannot be checked. |
| `POST /datasets` | Multipart CSV upload, schema validation, checksum and safe metadata registration. Optional form field: `name`. |
| `GET /datasets?limit=&offset=` | Paginated dataset metadata. |
| `GET /datasets/{dataset_id}` | Dataset validation metadata. |
| `GET /models` | Actual validated model IDs, versions, mappings, thresholds, availability, and historical evaluation evidence. Paths are omitted. |
| `POST /analyze` | Analyze either `records` or a registered `dataset_id` (exactly one). Optional `engines`, `model_ids`, and `anomaly_operating_point`; record count is bounded by configuration. Persists job, events, and alerts. |
| `POST /analysis-jobs` | Start bounded asynchronous-in-process analysis for a registered dataset; returns 202 and a persisted job. |
| `GET /analysis-jobs/{job_id}` | Read persisted status and progress counters. |
| `POST /analysis-jobs/{job_id}/cancel` | Cancel a queued or running job; a currently running batch may finish before the worker stops. Terminal jobs return 409. |
| `GET /events?limit=&offset=&dataset_id=&analysis_job_id=&event_status=&severity=` | Filter and paginate persisted detection events; event payloads omit internal storage paths. |
| `GET /events/{event_id}` | Retrieve detector evidence, scores, event metadata, stable source-row reference, and explanation references; missing IDs return 404 and malformed UUIDs return 422. |
| `GET /events/{event_id}/explanation?engine=binary%7Cmulticlass%7Canomaly` | Compute or retrieve a model-specific local SHAP explanation. Successful explanations are cached on that event row; unsupported or untraceable inputs return explicit `availability_status` and reason fields without substitute values. |
| `GET /alerts` | Filter, sort from an allowlist, and paginate alerts by severity, status, category, date, and minimum score. |
| `GET /alerts/{alert_id}` | Alert details and supporting event IDs. |
| `PATCH /alerts/{alert_id}/status` | Apply a valid lifecycle transition; optional `changed_by` audit label. |
| `GET /metrics` | Database-backed operational counts, model availability, historical metrics, and alert/event distributions. |
| `GET /traffic/summary` | Bounded event summary, optionally scoped by dataset, job, time range, status, or predicted category. `group_by`: `severity`, `event_status`, `attack_category`, or `day`. |

Dataset and alert lists use `limit` plus `offset` pagination and return `total`. Traffic summaries use a bounded `limit` and return grouped counts. Analysis job states are `QUEUED`, `RUNNING`, `COMPLETED`, `FAILED`, and `CANCELLED`; jobs execute in the API process and cancellation is observed at batch boundaries. Alert states are `NEW`, `ACKNOWLEDGED`, `INVESTIGATING`, `RESOLVED`, and `DISMISSED`; allowed lifecycle transitions are validated by the API.

For `POST /analyze`, a record has this shape:

```json
{
  "records": [{
    "features": {"<Phase 05 predictive feature>": 0.0},
    "metadata": {"source_filename": "flows.csv", "source_row_number": 1}
  }],
  "engines": ["binary", "multiclass", "anomaly"]
}
```

Supply every required feature from `configs/feature_schema.json`. The abbreviated example is illustrative and will fail required-feature validation if sent as-is. Use IDs returned by `GET /models`; no user-provided paths or unregistered model files are accepted. Model score semantics are described in the model/evaluation metadata; a threat score is heuristic, not a probability.

`/analysis-jobs` uses in-process background execution and is not a durable queue. Dataset-backed analyses carry stable 1-based source-row references and resolve feature values from the unchanged uploaded CSV on demand. Inline `/analyze` records without a registered dataset can be retrieved as events but have no source feature row for SHAP, so explanation status is `unavailable`. Successful explanations use the exact validated detector artifact and fitted preprocessor, the Phase 10 training-only background policy, and the model's documented output scale; output includes raw/transformed values, contributions, and additivity diagnostics. Explanations are persisted in `detection_events.explanation_data`, with references on that event. A second Alembic migration adds this nullable column. Upload byte limit, synchronous record limit, batch limit, and total job row limit are environment-configurable; see `.env.example`. `/metrics` and `/traffic/summary` report persisted records only, not an invented live traffic feed.
