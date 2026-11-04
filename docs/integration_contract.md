# API & Subsystem Integration Contract

**Document Date:** 2026-11-04  
**Project:** Network Intrusion Detection & Anomaly Intelligence  
**Phase:** Phase 14 — Integration, Testing & Deployment  
**Standard:** OpenAPI 3.1 / JSON Schema Draft 2020-12  

---

## 1. Architectural Interface Boundary

The Network Intrusion Detection & Anomaly Intelligence system enforces a decoupled, multi-tiered architecture:

```
+--------------------------------------------------------------+
|                   Presentation Layer                         |
|  Streamlit Multi-Page Application (dashboard/app.py)         |
|  - 9 Interactive Operator Views                              |
|  - Communication via HTTP API Client (dashboard/api_client.py)|
+------------------------------+-------------------------------+
                               |
                               | HTTP / REST (JSON & Multipart)
                               v
+--------------------------------------------------------------+
|                      REST API Layer                          |
|  FastAPI Application (api/main.py, api/routers/)             |
|  - Input Validation (Pydantic v2)                            |
|  - Rate & Size Limiting (50MB uploads, 8MB JSON)             |
|  - Security & Error Sanitization (Zero Raw Stack Traces)     |
+------------------------------+-------------------------------+
                               |
                               v
+--------------------------------------------------------------+
|               Domain & Model Service Layer                   |
|  - Feature Extraction & Schema Contract (src/features/)      |
|  - Multi-Family Model Inference (src/models/)                |
|  - On-Demand SHAP Attribution Engines (src/explainability/)  |
+------------------------------+-------------------------------+
                               |
                               v
+--------------------------------------------------------------+
|                     Persistence Layer                        |
|  SQLAlchemy 2.0 ORM & Alembic Migrations (src/db/, alembic/) |
|  - Native PostgreSQL UUID Primary Keys                       |
|  - JSONB Telemetry & Explanation Caching                     |
+------------------------------+-------------------------------+
                               |
                               v
+--------------------------------------------------------------+
|                  Relational Database Engine                  |
|  PostgreSQL 18.4 (Driver: postgresql+psycopg://)             |
|  - Connection Pooling (pool_size=5, max_overflow=10)         |
+--------------------------------------------------------------+
```

---

## 2. Global Protocol Standards

1. **Base URL:** `/api/v1`
2. **Data Encoding:** `application/json` (UTF-8) for standard request/response payloads; `multipart/form-data` for file uploads.
3. **Date/Time Standard:** ISO 8601 extended format with UTC offset (e.g., `2026-11-04T12:00:00Z`).
4. **Identifier Standard:** RFC 4122 UUID v4 strings (e.g., `2d719af1-ab7f-4579-bce8-7ba2b9778757`).
5. **Error Representation:** Uniform error envelope conforming to RFC 7807 problem details:
   ```json
   {
     "detail": "Descriptive error message explaining the failure condition."
   }
   ```
   For 422 Unprocessable Entity:
   ```json
   {
     "detail": [
       {
         "loc": ["query", "event_id"],
         "msg": "Input should be a valid UUID, invalid character: ...",
         "type": "uuid_parsing"
       }
     ]
   }
   ```

---

## 3. REST API Endpoint Specifications

### 3.1 Health & Readiness

#### `GET /api/v1/health`
- **Description:** Basic liveness probe. Indicates the ASGI server process is responding.
- **Response 200 OK:**
  ```json
  {
    "status": "healthy",
    "timestamp": "2026-11-04T12:00:00Z"
  }
  ```

#### `GET /api/v1/ready`
- **Description:** Deep readiness probe. Verifies database connectivity and model registry readiness.
- **Response 200 OK:**
  ```json
  {
    "status": "ready",
    "database": {
      "connected": true,
      "dialect": "postgresql"
    },
    "model_registry": {
      "ready": true,
      "models_loaded": 5
    }
  }
  ```
- **Response 503 Service Unavailable:** Returned if PostgreSQL or model registries are disconnected.

---

### 3.2 Model Registry

#### `GET /api/v1/models`
- **Description:** Returns all registered production models, artifact paths, and feature contracts.
- **Response 200 OK:**
  ```json
  [
    {
      "model_id": "binary-random_forest-v1.0.1",
      "model_family": "binary_random_forest",
      "version": "1.0.1",
      "output_semantics": "attack probability",
      "features_required": 78,
      "is_active": true
    },
    {
      "model_id": "multiclass-random_forest-v1.0.0",
      "model_family": "multiclass_random_forest",
      "version": "1.0.0",
      "output_semantics": "class probability",
      "features_required": 78,
      "is_active": true
    },
    {
      "model_id": "isolation-forest-v1.0.0",
      "model_family": "anomaly",
      "version": "1.0.0",
      "output_semantics": "higher-is-more-anomalous score",
      "features_required": 78,
      "is_active": true
    },
    {
      "model_id": "binary-logistic_regression-v1.0.2",
      "model_family": "binary_logistic_regression",
      "version": "1.0.2",
      "output_semantics": "ATTACK log-odds margin",
      "features_required": 78,
      "is_active": true
    },
    {
      "model_id": "multiclass-logistic_regression-v1.0.0",
      "model_family": "multiclass_logistic_regression",
      "version": "1.0.0",
      "output_semantics": "class logit",
      "features_required": 78,
      "is_active": true
    }
  ]
  ```

---

### 3.3 Dataset Management

#### `POST /api/v1/datasets`
- **Description:** Uploads and registers a network flow CSV dataset.
- **Content-Type:** `multipart/form-data`
- **Form Parameters:**
  - `file`: CSV file conforming to the 78-feature CIC-IDS2017 schema.
  - `name` (optional): Human-readable alias.
- **Validation Limits:** Max file size 50 MB; headers must match the registered feature schema.
- **Response 201 Created:**
  ```json
  {
    "dataset_id": "4a3b1d2e-8c7f-4a1b-9e2d-3c4b5a6f7e8d",
    "name": "sample_traffic_eval.csv",
    "row_count": 1000,
    "feature_count": 78,
    "created_at": "2026-11-04T12:00:00Z"
  }
  ```
- **Response 400 Bad Request:** Missing required features or non-numeric values in numeric columns.
- **Response 413 Payload Too Large:** File exceeds 50 MB limit.

#### `GET /api/v1/datasets`
- **Description:** Lists all registered datasets.
- **Query Parameters:** `limit` (default 50, max 100), `offset` (default 0).

#### `GET /api/v1/datasets/{dataset_id}`
- **Response 200 OK:** Dataset metadata and row count.
- **Response 404 Not Found:** Dataset ID does not exist.
- **Response 422 Unprocessable Entity:** Malformed UUID.

---

### 3.4 Asynchronous Analysis Jobs

#### `POST /api/v1/analysis-jobs`
- **Description:** Dispatches an asynchronous batch analysis job against a registered dataset.
- **Request Body:**
  ```json
  {
    "dataset_id": "4a3b1d2e-8c7f-4a1b-9e2d-3c4b5a6f7e8d",
    "model_id": "binary-random_forest-v1.0.1",
    "batch_size": 64
  }
  ```
- **Response 202 Accepted:**
  ```json
  {
    "job_id": "8f7e6d5c-4b3a-210f-eedd-ccbbaa998877",
    "status": "queued",
    "dataset_id": "4a3b1d2e-8c7f-4a1b-9e2d-3c4b5a6f7e8d",
    "created_at": "2026-11-04T12:00:00Z"
  }
  ```

#### `GET /api/v1/analysis-jobs/{job_id}`
- **Response 200 OK:**
  ```json
  {
    "job_id": "8f7e6d5c-4b3a-210f-eedd-ccbbaa998877",
    "status": "completed",
    "total_rows": 1000,
    "processed_rows": 1000,
    "detections_count": 14,
    "started_at": "2026-11-04T12:00:01Z",
    "completed_at": "2026-11-04T12:00:04Z"
  }
  ```

#### `POST /api/v1/analysis-jobs/{job_id}/cancel`
- **Response 200 OK:** Status updated to `cancelled`.

---

### 3.5 Real-Time Inline Flow Analysis

#### `POST /api/v1/analyze`
- **Description:** Evaluates a batch of inline network flow records synchronously.
- **Request Body (Max 8 MB):**
  ```json
  {
    "flows": [
      {
        "Destination Port": 80,
        "Flow Duration": 11262,
        "Total Fwd Packets": 3,
        "Total Backward Packets": 4,
        "...": 0.0
      }
    ],
    "model_id": "binary-random_forest-v1.0.1"
  }
  ```
- **Response 200 OK:**
  ```json
  {
    "results": [
      {
        "flow_index": 0,
        "prediction": "ATTACK",
        "score": 0.94,
        "severity": "HIGH",
        "event_id": "2d719af1-ab7f-4579-bce8-7ba2b9778757",
        "persisted": true
      }
    ],
    "count": 1
  }
  ```

---

### 3.6 Detection Events & Traceability

#### `GET /api/v1/events`
- **Query Parameters:** `limit` (int, default 50), `offset` (int, default 0), `severity` (enum: LOW, MEDIUM, HIGH, CRITICAL), `dataset_id` (UUID), `status` (enum: NEW, INVESTIGATING, RESOLVED).
- **Response 200 OK:** Paginated list of events with total count and safe metadata. Internal storage URIs are scrubbed.

#### `GET /api/v1/events/{event_id}`
- **Description:** Detailed view of an individual detection event including source dataset, row number (1-based), model predictions, and raw telemetry snapshot.
- **Response 200 OK:**
  ```json
  {
    "event_id": "2d719af1-ab7f-4579-bce8-7ba2b9778757",
    "dataset_id": "4a3b1d2e-8c7f-4a1b-9e2d-3c4b5a6f7e8d",
    "source_row_index": 1,
    "timestamp": "2026-11-04T12:00:00Z",
    "severity": "HIGH",
    "status": "NEW",
    "score": 4.185,
    "model_id": "binary-random_forest-v1.0.1",
    "evidence_data": {
      "flow_duration": 11262,
      "destination_port": 80
    }
  }
  ```
- **Response 404 Not Found:** Event ID does not exist.
- **Response 422 Unprocessable Entity:** Malformed UUID.

---

### 3.7 Explainability (SHAP Attributions)

#### `GET /api/v1/events/{event_id}/explanation?engine={binary|multiclass|anomaly}`
- **Description:** Retrieves on-demand or cached SHAP feature attributions for the specified event.
- **Response 200 OK:**
  ```json
  {
    "event_id": "2d719af1-ab7f-4579-bce8-7ba2b9778757",
    "availability_status": "available",
    "engine": "binary",
    "model_id": "binary-random_forest-v1.0.1",
    "output_semantics": "attack probability",
    "base_value": 0.1842,
    "model_output": 0.9412,
    "feature_attributions": [
      {
        "feature_name": "Bwd Packet Length Std",
        "source_value": 142.5,
        "transformed_value": 1.482,
        "shap_value": 0.312
      },
      {
        "feature_name": "Destination Port",
        "source_value": 80,
        "transformed_value": -0.215,
        "shap_value": 0.185
      }
    ],
    "additivity_diagnostics": {
      "passed": true,
      "sum_shap_plus_base": 0.9412,
      "model_output": 0.9412,
      "max_residual": 1.3826e-9
    }
  }
  ```
- **Response 200 OK (Unsupported Model):**
  ```json
  {
    "event_id": "2d719af1-ab7f-4579-bce8-7ba2b9778757",
    "availability_status": "unsupported",
    "reason": "Model architecture 'custom_mlp' does not have a registered Tree or Linear explainer.",
    "feature_attributions": []
  }
  ```
- **Response 422 Unprocessable Entity:** Invalid engine parameter.

---

## 4. Relational Database Schema Contract

The PostgreSQL 18.4 database schema conforms to Alembic revision `20261104_0002`:

1. **`datasets` Table:**
   - `id`: UUID, Primary Key
   - `name`: String(255), Not Null
   - `row_count`: Integer, Not Null
   - `created_at`: TIMESTAMP WITH TIME ZONE, Default UTC
2. **`model_registry` Table:**
   - `model_id`: String(128), Primary Key
   - `family`: String(64), Not Null
   - `version`: String(32), Not Null
   - `artifact_uri`: String(512), Not Null
3. **`analysis_jobs` Table:**
   - `id`: UUID, Primary Key
   - `dataset_id`: UUID, Foreign Key (`datasets.id`), On Delete CASCADE
   - `status`: String(32), Not Null, Indexed
4. **`detection_events` Table:**
   - `id`: UUID, Primary Key
   - `dataset_id`: UUID, Nullable, Foreign Key (`datasets.id`)
   - `job_id`: UUID, Nullable, Foreign Key (`analysis_jobs.id`)
   - `source_row_index`: Integer, Nullable
   - `severity`: String(16), Not Null, Indexed
   - `score`: Float, Not Null
   - `evidence_data`: JSONB, Not Null
   - `explanation_data`: JSONB, Nullable (Added in revision `20261104_0002`)
   - `explanation_references`: JSONB, Nullable (Added in revision `20261104_0002`)
5. **`alerts` Table:**
   - `id`: UUID, Primary Key
   - `title`: String(255), Not Null
   - `severity`: String(16), Not Null, Indexed
   - `status`: String(32), Not Null, Indexed
6. **`alert_event_links` Table:**
   - `alert_id`: UUID, Foreign Key (`alerts.id`), Primary Key
   - `event_id`: UUID, Foreign Key (`detection_events.id`), Primary Key
