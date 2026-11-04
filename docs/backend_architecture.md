# Phase 12 Backend Architecture

The backend exposes the existing Phase 06–09 inference and intelligence workflow through a local FastAPI service. It does not capture packets, retrain models, change model thresholds, or claim validated production blocking.

## Request flow

```text
CSV upload or bounded flow JSON
          │
          ├── dataset file validation and metadata ──> local upload directory
          │
          └── API schema + Phase 05 feature contract
                         │
                         ├── trusted cached Phase 06/07/08 predictors
                         ├── Phase 09 evidence/scoring/correlation pipeline
                         └── SQLAlchemy transaction ──> PostgreSQL events, alerts, job state
```

`api/main.py` builds the app and shared services. `api/core` owns environment configuration, request IDs, and safe errors. `api/routes` maps the `/api/v1` endpoints to Pydantic schemas and services. `api/services` performs dataset validation, actual model loading/inference, Phase 09 integration, job processing, alert transitions, and persisted aggregates. `api/database/models.py` defines the SQLAlchemy 2 schema; `alembic/versions` owns schema changes. Raw CSV contents stay in bounded local file storage; the database keeps checksums, provenance, detector evidence, and operational records.

The model service only loads artifact bundles from the configured project model directory through the existing validated Phase 10 registry loader. Requests identify registered model IDs; clients cannot provide artifact paths. Predictor instances are cached in process. The API does not call fit/train methods.

Persisted detection events are individually retrievable through paginated event routes. Dataset-backed analysis stores a stable dataset ID and 1-based source row number, allowing on-demand SHAP to read the exact row from the original uploaded CSV. The explanation service uses the recorded detector model, its matching preprocessor, the Phase 10 training-only background selection, and checks additivity in that detector's output space. Successful results are cached on the event record by Alembic revision `20261104_0002`. Inline flow records without a registered dataset cannot be explained because their features are not persisted; these and unsupported models have explicit availability statuses.

## Persistence and jobs

An analysis job, its event records, alerts, and event-alert links are persisted transactionally. Event and alert fingerprints prevent duplicate records. Alert status changes record an audit entry in the alert explanation. Dataset files are written under UUID-based names after bounded upload validation; file paths are never returned by the API.

Dataset analysis jobs use FastAPI in-process background tasks. They enforce row and batch limits and persist progress, but are not a durable distributed queue: a process restart marks queued/running jobs failed, and deployments needing guaranteed execution should add a separately scoped worker/queue phase.

## Local operation

The default listener is `127.0.0.1`; wildcard CORS is rejected, and public binding requires an explicit environment setting. Docker Compose binds PostgreSQL and the API to loopback addresses. `alembic upgrade head` applies the schema before the API starts. Configuration and startup commands are in [the backend API reference](api_reference.md) and [database guide](database.md).

## Limits inherited from the research pipeline

The API reports the saved model registry and its previously inspected evaluation metadata. Those benchmarks retain the limitations documented in the Phase 06–11 reports: capture shift, row-split or duplicate-group caveats, missing flow timestamps/endpoints in many records, and no independent external validation. Phase 09 can only correlate records when actual time/endpoint evidence exists. A heuristic threat score is not a calibrated probability.
