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

Historical Phase 12 validation applied revision `20261104_0001` to PostgreSQL 16 and confirmed it as `head`; the real API smoke check persisted an event using that schema. In the 2026-11-04 Phase 14 session, revisions `20261104_0001` and `20261104_0002` were applied to disposable SQLite. PostgreSQL 18.4 is installed locally on Windows. The latest service recheck reported `postgresql-x64-18` Running (Manual), with TCP available on 127.0.0.1:5432. Real `psql` connections failed with `fe_sendauth: no password supplied`; there is no project `.env`, inherited `NII_*`/`PG*` configuration, or standard user `pgpass.conf`. Thus server identity, authentication, disposable database creation, PostgreSQL migrations, and current PostgreSQL integration remain unverified. Docker Engine was also unavailable. Do not infer PostgreSQL success from SQLite checks. Automated API tests use isolated SQLite fixtures for speed and deterministic cleanup.
