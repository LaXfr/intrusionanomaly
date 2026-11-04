# System Performance, Latency, and Throughput Benchmark Report

**Document Date:** 2026-11-04  
**Project:** Network Intrusion Detection & Anomaly Intelligence  
**Phase:** Phase 14 — Integration, Testing & Deployment  
**Source Evidence:** `reports/benchmarks/20261103T223701Z/warm_inference.json`  
**Execution Environment:** Python 3.13.2 (AMD64), Windows 11 Enterprise (Build 26300), scikit-learn 1.8.0, PostgreSQL 18.4  

---

## 1. Executive Summary

This report establishes empirical performance benchmarks for the Network Intrusion Detection platform across three critical runtime layers:
1. **Model Inference Latency & Batch Throughput:** Evaluating warm inference across all five production model families at batch sizes 1, 16, and 64.
2. **Explainability Overhead:** Evaluating on-demand SHAP computation latencies for tree-based vs. linear model families and the impact of JSONB explanation caching.
3. **API & Database Persistence Overhead:** Assessing connection pooling, transaction overhead, and indexed query performance under PostgreSQL 18.4.

---

## 2. Model Inference Latency & Throughput Benchmarks

Warm inference was benchmarked across 5 repeated trials per configuration, isolating feature preprocessing from model evaluation. Cold-start initialization latencies were excluded.

### 2.1 Benchmark Summary Table

| Model ID | Family | Artifact Size | Batch Size | Median Preprocess | Median Prediction | Median Total | Latency / Row | Throughput (rows/sec) |
|---|---|---|---|---|---|---|---|---|
| `binary-random_forest-v1.0.1` | Binary RF | 1.16 MB | 1 | 3.22 ms | 12.60 ms | 15.81 ms | **15.81 ms** | **63.24** |
| `binary-random_forest-v1.0.1` | Binary RF | 1.16 MB | 16 | 3.20 ms | 12.76 ms | 15.96 ms | **1.00 ms** | **1,002.26** |
| `binary-random_forest-v1.0.1` | Binary RF | 1.16 MB | 64 | 4.24 ms | 13.20 ms | 17.44 ms | **0.27 ms** | **3,669.20** |
| `binary-logistic_regression-v1.0.2` | Binary LR | 61.5 KB | 1 | 3.75 ms | 0.087 ms | 3.84 ms | **3.84 ms** | **260.74** |
| `binary-logistic_regression-v1.0.2` | Binary LR | 61.5 KB | 16 | 3.65 ms | 0.085 ms | 3.74 ms | **0.23 ms** | **4,280.36** |
| `binary-logistic_regression-v1.0.2` | Binary LR | 61.5 KB | 64 | 3.91 ms | 0.086 ms | 3.99 ms | **0.062 ms** | **16,030.46** |
| `multiclass-random_forest-v1.0.0` | Multiclass RF | 1.26 MB | 1 | 3.93 ms | 13.11 ms | 17.04 ms | **17.04 ms** | **58.68** |
| `multiclass-random_forest-v1.0.0` | Multiclass RF | 1.26 MB | 16 | 3.83 ms | 13.13 ms | 16.96 ms | **1.06 ms** | **943.42** |
| `multiclass-random_forest-v1.0.0` | Multiclass RF | 1.26 MB | 64 | 4.26 ms | 13.42 ms | 17.68 ms | **0.28 ms** | **3,620.09** |
| `multiclass-logistic_regression-v1.0.0` | Multiclass LR | 32.6 KB | 1 | 6.87 ms | 0.082 ms | 6.96 ms | **6.96 ms** | **143.77** |
| `multiclass-logistic_regression-v1.0.0` | Multiclass LR | 32.6 KB | 16 | 3.43 ms | 0.080 ms | 3.51 ms | **0.22 ms** | **4,563.08** |
| `multiclass-logistic_regression-v1.0.0` | Multiclass LR | 32.6 KB | 64 | 3.53 ms | 0.098 ms | 3.63 ms | **0.057 ms** | **17,623.57** |
| `isolation-forest-v1.0.0` | Anomaly IF | 1.77 MB | 1 | 3.66 ms | 6.08 ms | 9.73 ms | **9.73 ms** | **102.73** |
| `isolation-forest-v1.0.0` | Anomaly IF | 1.77 MB | 16 | 3.25 ms | 6.00 ms | 9.25 ms | **0.58 ms** | **1,729.58** |
| `isolation-forest-v1.0.0` | Anomaly IF | 1.77 MB | 64 | 3.36 ms | 6.35 ms | 9.72 ms | **0.15 ms** | **6,586.80** |

---

## 3. Analysis & Key Performance Observations

### 3.1 Linear Models vs. Tree Ensembles
- **Linear Models (LR):** Demonstrate sub-millisecond prediction times ($\sim 80\text{--}90\,\mu\text{s}$) across all batch sizes. Throughput scales linearly with batch size, reaching **16,000 to 17,600 flows/second** at batch 64. Total latency is dominated by input preprocessing ($\sim 3.5\text{--}3.9\,\text{ms}$).
- **Random Forest Ensembles:** Require $\sim 12.6\text{--}13.4\,\text{ms}$ execution time for tree traversal across 100 decision trees. At batch 1, latency is $\sim 15.8\text{--}17.0\,\text{ms/row}$ ($60\text{ flows/sec}$). When batched to 64 rows, vectorized traversal amortizes tree evaluation, delivering **3,600+ flows/second** at **0.27 ms/row**.
- **Isolation Forest:** Consistently achieves intermediate performance ($\sim 6.0\text{--}6.3\,\text{ms}$ prediction time), yielding **6,586 flows/second** at batch 64.

---

## 4. Explainability & SHAP Computation Profiling

On-demand SHAP explanations compute individual feature attributions across 78 network features.

### 4.1 Computational Complexity by Explainer Type
1. **TreeExplainer (`TreeEnsemble` models):**
   - Applies tree-path traversal algorithms with training background references.
   - For 100-tree ensembles (`binary-random_forest`, `multiclass-random_forest`, `isolation-forest`), generating SHAP values for a single flow requires approximately **12 to 20 seconds**.
   - Running all 5 model families sequentially on a single detection event requires **67.1 seconds**.
2. **LinearExplainer (`LogisticRegression` models):**
   - Direct analytic computation ($\phi_i = w_i \cdot (x_i - \mathbb{E}[x_i])$).
   - Generates complete feature attributions in **10 to 25 milliseconds**.

### 4.2 Caching Strategy & Latency Elimination
Because TreeExplainer computation is CPU-intensive, Phase 14 Alembic revision `20261104_0002` introduced the `explanation_data` and `explanation_references` JSONB columns in the `detection_events` table.
- **Initial Request:** Computes SHAP attributions, validates additivity, and writes the resulting structure to `detection_events.explanation_data`.
- **Subsequent Requests:** Retrieves pre-computed JSONB payload directly from PostgreSQL via indexed event ID in **$< 5\,\text{ms}$**, eliminating duplicate CPU load and delivering instant UI rendering in the Streamlit Explainability page.

---

## 5. Database Connection & API Latency

### 5.1 Connection Pooling
FastAPI integrates with PostgreSQL via SQLAlchemy connection pooling:
- `pool_size`: 5 connections
- `max_overflow`: 10 connections
- `pool_pre_ping`: `True` (eliminates stale connection drops)
- Driver: `postgresql+psycopg://` (native Psycopg 3 C-extension / binary async-capable driver)

### 5.2 API Route Latencies
- `GET /api/v1/health`: $\sim 1\text{--}2\,\text{ms}$ (in-memory liveness check)
- `GET /api/v1/ready`: $\sim 3\text{--}5\,\text{ms}$ (SELECT 1 ping + model registry status check)
- `GET /api/v1/events`: $\sim 5\text{--}12\,\text{ms}$ (paginated indexed query with total count)
- `GET /api/v1/events/{id}`: $\sim 3\text{--}6\,\text{ms}$ (single indexed UUID lookup)
- `POST /api/v1/analyze`: $\sim 20\text{--}25\,\text{ms}$ (batch size 1 including preprocessing, inference, severity computation, and PostgreSQL transaction commit)

---

## 6. Recommendations for Production Sizing

1. **Batch Ingestion:** Configure upstream network flow collectors to batch records into groups of 32 to 64 flows prior to dispatching `/api/v1/analyze` to maximize model throughput ($>3,500\,\text{flows/sec}$).
2. **Worker Concurrency:** Run Uvicorn with 2 to 4 worker processes per CPU socket.
3. **Background Explainability:** For high-volume environments, offload TreeExplainer calculations to an asynchronous Celery/Redis worker queue, allowing the API to respond immediately while explanations are populated asynchronously.
