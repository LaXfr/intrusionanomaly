# Dashboard Architecture

The Streamlit dashboard is a local UI for the `/api/v1` contract, including the event retrieval and explanation routes added in Phase 14. `dashboard/app.py` owns the shared shell and nine-option radio navigation; page renderers live in `dashboard/pages/`. `.streamlit/config.toml` disables Streamlit's separate automatic multipage links because these modules are renderer modules invoked by the application shell. `dashboard/api_client.py` centralizes HTTP requests, timeout and error handling, URL validation, and endpoint paths. `dashboard/components/` contains shared response guards and layout helpers. `dashboard/services/export_service.py` serializes the current alert response locally as CSV or JSON; the backend does not expose a file-export endpoint.

The client reads `NII_DASHBOARD_API_URL` (default `http://127.0.0.1:8000/api/v1`) and `NII_DASHBOARD_TIMEOUT` (default `10` seconds). The URL must be an absolute HTTP or HTTPS base URL without embedded credentials, query parameters, or fragments. Request failures are converted to safe, readable page messages without echoing request bodies, secrets, or raw exception text. Successful responses must be JSON objects; malformed JSON and unexpected top-level shapes become visible API errors.

Pages only display information exposed by the API. Traffic visualizations use persisted aggregate summaries; they do not represent live packet capture. Dataset management uploads a Phase 05 feature-contract CSV and submits bounded jobs to existing model IDs. Alert filtering, details, and status transitions use the API's alert routes. CSV and JSON download controls serialize the filtered/listed alert records currently returned to the page. Detection event retrieval uses the paginated `/events` routes. Explainability requests use `/events/{event_id}/explanation`, displaying real SHAP contributions only when the event has a traceable registered dataset row and a supported persisted model. Empty, malformed, unavailable, and unsupported responses have explicit page states.

## Run

Install the UI extra from the repository root:

```powershell
python -m pip install -e ".[dashboard]"
```

Start the Phase 12 API and its configured PostgreSQL database using the procedure in [the backend guide](backend_architecture.md). Then start Streamlit:

```powershell
python -m streamlit run dashboard/app.py
```

Set the environment variables before launch to target another API instance. The dashboard makes requests only to the configured existing API routes. No authentication is implemented; keep both services on loopback and do not expose them to an untrusted network.

Dashboard behavior tests use Streamlit `AppTest` and mocked HTTP transports; real API integration checks are recorded in `worklog.md` and `handoff.md`.
