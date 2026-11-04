# Integration Readiness Audit

**Audit date:** 2026-11-04  
**Phase:** 14 — Integration, Testing & Deployment  
**Status:** In Progress  
**Scope:** Current-session dashboard installation, event retrieval and explanation integration, real API/SQLite workflow, browser checks, and project tests. Historical phase results are identified separately.

## Current-session results

| Component | Status | Evidence |
|---|---|---|
| Project dashboard environment | Verified | Installed `.[dashboard]` into `.venv`; Streamlit 1.66.1, Plotly 6.9.0, HTTPX 0.28.1; `pip check` reports no broken requirements. |
| Event retrieval API | Verified | `GET /events` pagination/filter tests; `GET /events/{event_id}` detail; 404 missing event and 422 malformed UUID verified. |
| Event source-row traceability | Verified | Dataset-backed analysis stores 1-based row number and dataset reference while leaving the uploaded CSV unchanged. |
| Model-specific event SHAP | Verified for one real API request | Actual Phase 04 feature row, persisted binary Random Forest event; API returned SHAP values with output semantics `attack probability`; additivity max residual `1.3826e-9` and `passed=true`. Successful output is persisted on the event row. |
| Dashboard/backend integration | Verified | Streamlit loaded against the loopback API. Browser checked all nine navigation pages and headings; no page exceptions. |
| Full automated suite | Verified | `.venv\\Scripts\\python.exe -m pytest -q`: 200 passed, 0 failed, 0 skipped; 3 warnings (one Starlette/httpx deprecation and two existing scikit-learn `penalty` deprecations). Exit code 0. |
| SQLite migration | Verified | Alembic revisions `20261104_0001` and `20261104_0002` applied to disposable SQLite DB. |
| Local Windows PostgreSQL discovery (2026-11-04) | Inspected; unavailable | PostgreSQL 18.4 binaries are installed under `C:\Program Files\PostgreSQL\18`; service `postgresql-x64-18` is Stopped (Manual). Its config specifies port 5432 and `listen_addresses='*'`; no PostgreSQL listener was found on the configured port. `psql --version`, `postgres --version`, and `pg_ctl --version` report 18.4. Starting the service was attempted through the elevated command path but Windows returned “Cannot open ... service”; no service configuration or database data was changed. Authentication, TCP, and database access could not be tested because the server is stopped. |
| Local Windows PostgreSQL recheck (2026-11-04) | Service/TCP verified; authentication blocked | Elevated service query now reports `postgresql-x64-18` Running (Manual); TCP `127.0.0.1:5432` connects. `psql` attempts with both role `postgres` and the current Windows account fail with `fe_sendauth: no password supplied`. No project `.env`, `NII_*`/`PG*` environment variables, or user `pgpass.conf` were available. Server identity/version and database access therefore remain unverified. |
| PostgreSQL current validation | Outstanding | No disposable PostgreSQL database was created and no PostgreSQL migration or API test ran. The server accepts TCP, but authentication is unavailable in the existing project/user configuration. Docker Engine remains inaccessible through its named pipe. Phase 12 PostgreSQL evidence is historical only. |

## API contract and implementation

- `GET /api/v1/events` filters/paginates persisted events by dataset, job, event status, and severity.
- `GET /api/v1/events/{event_id}` returns persisted detector evidence and safe event metadata; internal storage URIs are excluded.
- `GET /api/v1/events/{event_id}/explanation?engine=binary|multiclass|anomaly` selects the detector model recorded on the event, its Phase 10 validated explainer/preprocessor, and the documented training-only background policy. Available output includes source and transformed feature values, model-output semantics/value, SHAP contributions, reference partition, and additivity diagnostics.
- Dataset-backed rows retain a stable dataset UUID and 1-based CSV data-row number; only the requested row is read for explanation. Explanations are cached in nullable `detection_events.explanation_data`, with references in `explanation_references` (Alembic revision `20261104_0002`).
- Inline `/analyze` events without an associated registered dataset have no retained feature values; their explanation response reports `unavailable`. Unsupported model associations return `unsupported`. Neither case fabricates contributions.
- Dashboard **Explainability** retrieves event list/detail and can request the model-specific explanation. It displays explicit status/reasons.

### Route results

| Method | Endpoint | Status | Result and evidence |
|---|---|---:|---|
| GET | `/api/v1/health` | 200 | Current loopback browser session; liveness returned. |
| GET | `/api/v1/ready` | 200 | Current loopback browser session; SQLite DB and model registry readiness returned. |
| GET | `/api/v1/models` | 200 | Current loopback browser session; persisted model registry returned. |
| GET | `/api/v1/datasets` | 200 | Current loopback browser session; empty disposable DB listing returned. |
| POST | `/api/v1/datasets` | 201 | Current isolated TestClient workflow; one feature-contract row validated and registered. |
| POST | `/api/v1/analyze` | 200 | Current isolated TestClient workflow; actual binary model persisted one event. |
| GET | `/api/v1/events` | 200 | Current loopback browser and TestClient; page of persisted events returned, including expected empty collection in the separate browser DB. |
| GET | `/api/v1/events/{event_id}` | 200 | Current isolated TestClient workflow; persisted detail and source row returned. |
| GET | `/api/v1/events/{event_id}` | 404 / 422 | Automated API tests; missing event / malformed UUID. |
| GET | `/api/v1/events/{event_id}/explanation?engine=binary` | 200 | Current isolated TestClient workflow; actual RF SHAP output available and additivity passed. |
| GET | `/api/v1/events/{event_id}/explanation?engine=binary` | 200 | Automated API test; unregistered model returned `availability_status=unsupported`. |
| GET | `/api/v1/events/{event_id}/explanation?engine=invalid` | 422 | Automated API test; unsupported query value rejected. |
| GET | `/api/v1/traffic/summary` | 200 | Current loopback browser session; empty persisted summary returned. |
| GET | `/api/v1/alerts` | 200 | Current loopback browser session; empty persisted collection returned. |
| GET | `/api/v1/metrics` | 200 | Current loopback browser session; persisted counts returned. |
| POST / GET | `/api/v1/analysis-jobs` and `/api/v1/analysis-jobs/{job_id}` | 202 / 200 | Automated API test fixture; bounded synthetic job submitted and completion retrieved. |
| POST | `/api/v1/analysis-jobs/{job_id}/cancel` | 200 | Automated API test fixture; valid cancellation transition. |
| GET / PATCH | `/api/v1/alerts/{alert_id}` and `/api/v1/alerts/{alert_id}/status` | 200 / 200 | Automated API test fixture; alert detail and valid status transition. |

## Actual bounded workflow

In an isolated SQLite-backed FastAPI TestClient, one feature-only row was read from an existing Phase 04 Parquet file and uploaded as a temporary contract-valid CSV. The upload returned HTTP 201 and one validated row. `POST /api/v1/analyze` returned HTTP 200 and persisted one event. Event list and detail returned HTTP 200 and showed the source filename/row 1. The explanation route returned HTTP 200, `availability_status=available`, model `binary-random_forest-v1.0.1`, and a passed additivity check. No original CIC CSV, model artifact, or project production database was modified.

## Runtime and deployment notes

- Package manager: pip/setuptools with extras from `pyproject.toml`; the `.venv` was used for installs and commands.
- Python: 3.13.2.
- Git branch: `main`; the worktree already contained numerous user changes at task start. They remain untouched except for the Phase 14 implementation/doc updates described here; nothing was staged or committed.
- `NII_DATABASE_URL` and other `NII_*`/`PG*` environment names were absent from the inherited environment; no secrets were printed. The application requires `NII_DATABASE_URL` at runtime and has no default PostgreSQL database URL. SQLAlchemy and Alembic both use this setting. In the latest recheck, the PostgreSQL 18 service was Running and TCP 5432 connected, but authentication failed because no password source was configured.
- Disposable SQLite migration, API uploads, and integration DB were created under `.tmp-phase14/` and removed after validation. The API and Streamlit processes were stopped; ports 8179/8501 are no longer listening.
- The HTTP dashboard session used API `127.0.0.1:8179` and Streamlit `127.0.0.1:8501`.
- Docker is installed, but this session could not access Docker Engine through `dockerDesktopLinuxEngine`. Local PostgreSQL TCP works, but credentials are unavailable. No database was created, no PostgreSQL migration or API test ran, and no existing database was modified. The historical Phase 12 PostgreSQL verification remains documented, but is not presented as a current-session result.
- Models are pre-existing validated artifacts; no training or feature engineering was run. Phase 15 was not started.

## Remaining Phase 14 gate

Provide the project process with a valid existing PostgreSQL login through `NII_DATABASE_URL` or another approved secret mechanism (do not commit credentials or alter server authentication). Recheck login; then inspect whether `nii_phase14_validation` already exists, create a fresh uniquely named disposable DB if safe, and apply both migrations. Verify schema/constraints; execute PostgreSQL-backed API tests and the upload→job→event→explanation workflow; stop/restart the API and retrieve those records; verify all nine dashboard pages against the PostgreSQL-backed API. TCP connectivity passed in the current recheck, but authentication and every database-level check remain outstanding. Keep Phase 14 In Progress until the required PostgreSQL criteria and remaining dashboard-state checks pass. Other modeling evidence limitations (capture shift, overlapping duplicates, lack of external/temporal data, no authentication, and in-process job durability) remain documented and are outside this integration fix.

## Local PostgreSQL follow-up checks (2026-11-04)

- `Test-NetConnection 127.0.0.1 -Port 5432`: `TcpTestSucceeded=False`.
- `.venv\Scripts\python.exe -m pip check`: passed, no broken requirements (exit 0).
- `.venv\Scripts\python.exe -m compileall -q api dashboard src tests`: passed (exit 0).
- `git diff --check`: passed (exit 0; Git emitted existing LF-to-CRLF notices).
- `.venv\Scripts\python.exe -m pytest -vv`: collected 200 tests; first 19 tests passed, then execution stalled at `tests/test_api.py::test_app_initialization_openapi_health_readiness_and_cors`. The run was interrupted without a pytest summary or exit code; therefore it is not counted as a completed full-suite result. The previously completed 200-pass suite is recorded above as the earlier Phase 14 run, not as PostgreSQL validation.
- No PostgreSQL test database was created, no migrations or backend/dashboard processes were run for this follow-up, and no database cleanup was required. The existing Windows service remains stopped.
- **Later recheck in this resumed task:** elevated `Get-Service *postgres*` reported the service Running (Manual); a direct `TcpClient` probe connected to `127.0.0.1:5432`. Real `psql` server connections using `postgres` and the current Windows username each failed with `fe_sendauth: no password supplied` (psql exit 2). The repository `.env` is absent; inherited `NII_*`/`PG*` variables and standard user `pgpass.conf` candidates are absent. No server version/database identity could be queried and no database or migrations were touched.
- The formerly stalled API TestClient test and complete suite were rerun with loopback access enabled: the targeted test passed (1 passed, 1 warning, exit 0); full `.venv\Scripts\python.exe -m pytest -q` passed 200 tests, 0 failed, 0 skipped, with 3 warnings (Starlette/httpx deprecation and two scikit-learn `penalty` deprecations), exit 0. This is SQLite/unit/API fixture evidence, not PostgreSQL integration.
- `pip check` passed (exit 0); `compileall -q api dashboard src tests` passed (exit 0); `git diff --check` passed (exit 0, existing CRLF notices).
- Latest resumed-task rerun: `.venv\Scripts\python.exe -m pytest -q` completed with **200 passed, 0 failed, 0 skipped**, 3 warnings, exit 0. It used existing unit/API fixtures and does not establish PostgreSQL integration.
- The user reports that pgAdmin successfully authenticated to PostgreSQL 18.4 and the installation password is known. The password was not provided to chat or exposed to tools; it is not currently available to project processes through `NII_DATABASE_URL`, PostgreSQL environment variables, a project `.env`, or `pgpass.conf`. The direct `psql` attempts therefore still fail with `fe_sendauth: no password supplied`. This remains a credential handoff/configuration blocker, not evidence that the password is invalid.
