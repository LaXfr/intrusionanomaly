# Network Intrusion Detection & Anomaly Intelligence — Project Demo Guide

**Document Date:** 2026-11-04  
**Project:** Network Intrusion Detection & Anomaly Intelligence  
**Phase:** Phase 14 — Integration, Testing & Deployment  
**Audience:** Operators, Security Analysts, Evaluators, and Engineers  

---

## 1. Prerequisites & Environment Setup

Before starting the interactive demonstration, ensure the following local environment dependencies are present:

1. **Python Virtual Environment:**
   Ensure `.venv` is active with all project dependencies installed:
   ```powershell
   cd C:\DataScience\python(projects)\intrusionanomaly
   .\.venv\Scripts\Activate.ps1
   ```
2. **PostgreSQL Database Service:**
   Verify PostgreSQL 18 is running and listening on port 5432:
   ```powershell
   Get-Service postgresql-x64-18
   Test-NetConnection 127.0.0.1 -Port 5432
   ```
3. **Database URL Configuration:**
   Ensure `NII_DATABASE_URL` is set with the appropriate psycopg driver prefix:
   ```powershell
   $env:NII_DATABASE_URL = "postgresql+psycopg://postgres:<PASSWORD>@127.0.0.1:5432/nii_phase14_validation"
   ```

---

## 2. Starting the Application Services

The demonstration requires two concurrent local processes: the FastAPI backend and the Streamlit operator dashboard.

### Terminal 1: Launch FastAPI Backend
```powershell
cd C:\DataScience\python(projects)\intrusionanomaly
.\.venv\Scripts\uvicorn.exe api.main:app --host 127.0.0.1 --port 8000 --reload
```
*Expected log output:*
```text
INFO:     Started server process [PID]
INFO:     Waiting for application startup.
INFO:     Application startup complete.
INFO:     Uvicorn running on http://127.0.0.1:8000 (Press CTRL+C to quit)
```

### Terminal 2: Launch Streamlit Operator Dashboard
```powershell
cd C:\DataScience\python(projects)\intrusionanomaly
.\.venv\Scripts\streamlit.exe run dashboard/app.py --server.port 8501
```
*The dashboard will automatically open in your default browser at `http://localhost:8501`.*

---

## 3. Step-by-Step Operator Demonstration Walkthrough

### Step 1: Verify System Health & Connectivity
1. On the left sidebar navigation, click **System Health**.
2. **Expected View:**
   - **Backend API Status:** Displays a green indicator showing `Connected (200 OK)`.
   - **Database Dialect:** Displays `postgresql` with connection pool metrics.
   - **Model Registry:** Confirms `5` active models loaded in memory:
     - `binary-random_forest-v1.0.1`
     - `multiclass-random_forest-v1.0.0`
     - `isolation-forest-v1.0.0`
     - `binary-logistic_regression-v1.0.2`
     - `multiclass-logistic_regression-v1.0.0`

### Step 2: Ingest Network Flow Telemetry
1. Navigate to **Dataset Management** in the sidebar.
2. Under **Upload Network Traffic Dataset**, click **Browse files** and select a contract-valid CSV dataset (e.g., sample evaluation flows conforming to the 78 CIC-IDS2017 features).
3. Click **Upload & Register Dataset**.
4. **Expected View:**
   - Success alert showing `Dataset registered successfully`.
   - Displays assigned dataset UUID, total validated rows, and timestamp.
   - The registered dataset appears immediately in the **Active Datasets** table.

### Step 3: Execute Batch Intrusion Analysis
1. Navigate to **Traffic Analysis**.
2. Select the uploaded dataset from the dropdown selector.
3. Choose the target detection engine:
   - **Binary Random Forest** for high-accuracy binary classification.
   - **Multiclass Random Forest** for fine-grained attack taxonomy.
   - **Isolation Forest** for zero-day anomaly detection.
4. Click **Execute Flow Analysis**.
5. **Expected View:**
   - Real-time progress bar tracking batch inference.
   - Summary telemetry metrics: Total Flows Analyzed, Attack Detections, Anomaly Rate.
   - Temporal flow volume chart and port distribution breakdown.

### Step 4: Triage & Investigate Security Alerts
1. Navigate to **Detection Alerts**.
2. **Expected View:**
   - Interactive data grid displaying high-severity detection events.
   - Severity badges: `CRITICAL` (red), `HIGH` (orange), `MEDIUM` (yellow), `LOW` (blue).
3. Click on an alert to expand the triage drawer.
4. Update alert status from `NEW` to `INVESTIGATING` or `RESOLVED` and submit notes.
5. Notice that status transitions persist immediately to PostgreSQL.

### Step 5: Deep-Dive Model Explainability (SHAP Attributions)
1. Navigate to **Explainability**.
2. In the **Event Selector**, choose a persisted detection event (or paste an event UUID, e.g. `2d719af1-ab7f-4579-bce8-7ba2b9778757`).
3. Select the explanation engine (`binary`, `multiclass`, or `anomaly`).
4. Click **Compute / Retrieve Feature Explanation**.
5. **Expected View:**
   - **SHAP Waterfall / Bar Plot:** Displays top positive and negative contributing network features (e.g., `Bwd Packet Length Std`, `Destination Port`, `Flow Duration`).
   - **Output Space Semantics:** Confirms model output (e.g., `attack probability = 0.9412`).
   - **Additivity Verification Card:** Confirms `Additivity Passed (Max Residual: 1.38e-09)`, demonstrating mathematical fidelity to the model's true decision boundary.
   - **Persistent Caching:** If reloaded, the explanation is retrieved from PostgreSQL JSONB cache in $<5\,\text{ms}$ without re-running the explainer.

### Step 6: Review Model Performance & Latency Benchmarks
1. Navigate to **Model Performance**.
2. **Expected View:**
   - Interactive charts comparing inference throughput across batch sizes (1, 16, 64).
   - Side-by-side comparison of linear models ($>16,000\,\text{flows/s}$) vs. tree ensembles ($>3,600\,\text{flows/s}$).
   - Latency percentiles and memory footprint statistics.

---

## 4. Troubleshooting & FAQ

### Issue: "Backend Connection Error" banner in Dashboard
- **Cause:** FastAPI backend is not running or port 8000 is occupied.
- **Remedy:** Ensure Terminal 1 is active with `uvicorn api.main:app --port 8000`. Test via PowerShell: `curl http://127.0.0.1:8000/api/v1/health`.

### Issue: "NII_DATABASE_URL must use postgresql+psycopg"
- **Cause:** The database URL was configured with standard `postgresql://` without the driver qualifier.
- **Remedy:** Prepend `+psycopg` to the URL scheme: `postgresql+psycopg://...`.

### Issue: PostgreSQL Connection Refused (Port 5432)
- **Cause:** The Windows PostgreSQL service is stopped.
- **Remedy:** Start the service in an elevated PowerShell prompt:
  ```powershell
  Start-Service postgresql-x64-18
  ```
