# Backend Database and Migrations

The API uses SQLAlchemy 2 with the Psycopg 3 PostgreSQL driver. The local Compose service uses PostgreSQL 16. Set `NII_DATABASE_URL` to a `postgresql+psycopg://...` URL; SQLite is supported for isolated tests only. Secrets belong in an ignored `.env` file or the process environment, never in tracked configuration.

## Tables

| Table | Purpose |
|---|---|
| `datasets` | Validated CSV name, checksum, size, schema version, row count, safe validation metadata, and private storage path. |
| `model_registry` | Actual configured model ID/version, relative artifact references, schema version, class mapping, operating-point metadata, and historical evaluation evidence. |
| `analysis_jobs` | Requested engines/model versions, bounded progress counters, state, and sanitized failure message. A partial unique index prevents concurrent active jobs for one dataset. |
| `detection_events` | Phase 09 event status, evidence from each requested detector, score/severity, provenance, explanation references, and unique fingerprint. |
| `alerts` | Correlated alert summary, categories, score/severity, lifecycle state, evidence metadata, and unique fingerprint. |
| `alert_event_links` | Many-to-many association between persisted events and alerts. |

PostgreSQL uses JSONB for structured evidence, UUID keys, foreign keys, indexes, and database uniqueness constraints. File contents and model artifacts stay on disk; PostgreSQL stores references and inference records rather than copies of the original dataset.

## Apply migrations

From the repository root, with the database configured:

```powershell
python -m pip install -e ".[api,database]"
Copy-Item .env.example .env
# Set NII_DATABASE_URL in the ignored .env file.
alembic revision -m "describe schema change"
alembic upgrade head
alembic current
```

Do not use `Base.metadata.create_all()` in deployment. Alembic revision `20261104_0001` creates the initial backend tables and indexes; `20261104_0002` adds nullable persisted event explanation data for on-demand SHAP caching. For Docker Compose, `docker compose up --build` waits for PostgreSQL health and applies migrations in the API container before starting Uvicorn. Run backend and project tests with `pytest -q` from the repository root.

To roll back one migration deliberately, inspect the target first with `alembic history`, then use `alembic downgrade -1`. Back up the database before production schema changes.

Historical Phase 12 validation applied revision `20261104_0001` to PostgreSQL 16 and confirmed it as `head`; the real API smoke check persisted an event using that schema. In Phase 14 validation, PostgreSQL 18.4 on Windows (`postgresql-x64-18`) was verified against the isolated validation database `nii_phase14_validation`. Migrations `20261104_0001` and `20261104_0002` are confirmed applied (`20261104_0002 (head)`). Native PostgreSQL UUID columns, JSONB structured evidence fields, foreign keys, and indexes were verified across all six tables (`datasets`, `model_registry`, `analysis_jobs`, `detection_events`, `alerts`, `alert_event_links`). Real persistence and restart survival were verified for dataset creation, analysis jobs, detection events, and on-demand SHAP explanations across all five supported model families (`binary-random_forest-v1.0.1`, `multiclass-random_forest-v1.0.0`, `isolation-forest-v1.0.0`, `binary-logistic_regression-v1.0.2`, `multiclass-logistic_regression-v1.0.0`). Automated API tests use isolated SQLite fixtures for speed and deterministic isolation, while PostgreSQL integration is verified directly against the running engine.
