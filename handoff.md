# Project Handoff — Network Intrusion Detection & Anomaly Intelligence

## 1. Project Information

**Project Name:** Network Intrusion Detection & Anomaly Intelligence

**Project Category:** Data Science / Machine Learning / Cybersecurity

**Primary Language:** Python

**Primary Dataset:** CIC-IDS2017

**Project Architecture:** Modular offline network security analytics platform

**Development Environment:** Phase 10 verification used the project `.venv` on Python 3.13 with SHAP 0.54.1, scikit-learn 1.8.0 (matching saved artifact versions), and pytest. Package metadata supports Python 3.11 through 3.13. The explainability optional dependency includes SHAP and Matplotlib.

## 2. Project Objective

Develop a Python-based network security analytics platform that analyzes network flow data and identifies potentially malicious or unusual behavior.

The platform will contain two independent detection engines:

### Supervised Detection

A classification engine trained on labelled network traffic to identify known traffic categories and attack types.

### Unsupervised Detection

An anomaly detection engine trained primarily on benign traffic to identify unusual patterns that may not match known attack categories.

The outputs of both engines are processed by the Phase 09 threat intelligence layer to generate traceable structured security alerts.

The platform will also provide model explanations, performance analytics, API access, and an interactive dashboard.

## 3. Current Development State

**Overall Status:** Phases 01–13 are implemented and documented. Phase 14 is In Progress: persisted event retrieval, stable source-row links, on-demand event SHAP caching, and dashboard integration passed current SQLite/API/browser checks. Current Docker/PostgreSQL integration remains outstanding. Independent, external, temporal, and some group-complete model evidence remain unavailable.

**Current Phase:** Phase 14 Integration, Testing & Deployment

**Current Phase Status:** Installed `.[dashboard]` into `.venv`; `pip check` passed. The API and dashboard ran on loopback at ports 8179 and 8501. All nine dashboard pages rendered in browser navigation without visible exceptions. `python -m pytest -q` passed 200 tests, 0 failed, 0 skipped (3 warnings). A disposable SQLite DB was migrated through `20261104_0002`; a temporary contract-valid feature row was uploaded, passed through the real binary Random Forest, persisted as an event, and retrieved through event list/detail routes. The explanation endpoint returned actual attack-probability SHAP values with additivity max residual `1.3826e-9`; successful results are cached on the same event row. An automated API test verifies unsupported model reporting. No original source CSV or model artifact was changed. Docker Engine access was denied by the local named pipe, so current Compose/PostgreSQL verification remains outstanding. See `reports/integration/integration_readiness.md` and the Phase 14 worklog entry.

**Repository Inspection:** Completed. The project is a Git repository on `main`; the Phase 06 comparison and earlier Phase 07–09 work remain uncommitted. The repository contains the Phase 01–05 architecture and data pipelines, Phase 06 binary workflows, Phase 07 classifier, Phase 08 anomaly detector, Phase 09 intelligence layer, configurations, notebooks, reports, and tests. No commit was made.

**Implementation Progress:** Phase 02 provides CSV discovery, inspection, checksums, schema validation, standard/chunked loading, reports, metadata, and a CLI. Phase 03 adds chunked EDA and reports. Phase 04 provides audited cleaning, Parquet, labels/quarantine, provenance, and quality reports. Phase 05 adds the feature contract and leakage-safe preprocessing. Phase 06 includes capture-day-held-out binary Random Forest and Logistic Regression workflows, duplicate-feature screening, train-only preprocessing, separate checksummed artifacts, inference, and a measured comparison. Phase 07 includes Logistic Regression and Random Forest multi-class baselines. Phase 08 includes benign-only Isolation Forest, benign-only threshold calibration, held-out evaluation, and inference. Phase 09 integrates all three persisted detectors, emits provenance-rich events and research alerts, and isolates held-out labels to offline metrics. All six configured correlation rules require true timezone-aware timestamps and explicit key fields; those fields are not available in the Phase 04 export.

**Validation Note:** Phase 04 v2 retained 2,830,743 rows across eight Parquet files with 83 columns each, preserved 15 labels, quarantined zero rows, and verified raw checksums. Phase 05 validated 78 predictive features from the actual schema. Phase 07 scanned the full dataset and confirmed 15 classes; group-disjoint three-way coverage is infeasible because each attack label occurs in one source file. Its explicit stratified-row fallback split the data into 1,981,520 train, 424,611 validation, and 424,612 test rows, with all source groups overlapping; both models fit on an 80,000-row stratified sample. Random Forest achieved test macro F1 0.8549 and balanced accuracy 0.8804. These exploratory row-split metrics are not cross-capture evidence. Phase 08 used Monday–Wednesday train, Thursday validation, Friday test (1,668,530 / 458,968 / 703,245 rows). Its preprocessing and Isolation Forest were fit on 150,000 benign training rows; 456,752 benign validation rows calibrated five operating points. At the default 1% validation-FPR threshold, Friday test FPR was 4.9068%, attack recall 15.5685%, and ROC-AUC 0.6941. DDoS recall was 35.0645%, PortScan 0.0283%, and Bot 2.2380%; 12 categories had no Friday test support. Duplicate analysis found 28,644 repeated-feature groups crossing partitions (132,348 rows) and 633 cross-partition groups with differing labels. Phase 08 results are limited by these overlaps and a strong Friday DDoS-capture benign shift.

**Phase 09 Integration Results:** Latest CLI run `20261103T160444Z` loaded binary v1.0.1, multi-class, and anomaly artifacts and evaluated 3,000 Friday flows selected evenly by original label (1,500 BENIGN; 1,500 ATTACK; Bot, DDoS, PortScan). It generated 871 research alerts (552 HIGH, 319 CRITICAL), with no correlated groups. Binary attack precision/recall were 0.9969/0.2133; alert-level precision/recall were 0.9908/0.5753. All 1,407 suspicious events lacked timestamps and were skipped by each of six rules. Ground-truth labels were used only for deterministic stratified sample construction and the separate post-inference evaluation. Outputs are under `reports/intelligence/20261103T160444Z/`.

**Phase 06 Comparison:** Logistic run `20261103T163706Z`, model `binary-logistic_regression-v1.0.2`, is documented at `docs/binary_classification.md`. At threshold 0.5, Friday Logistic ROC-AUC/AP/attack precision/recall/FPR were 0.8170/0.8047/0.8413/0.4720/0.06211 versus RF 0.7385/0.7205/0.9965/0.2818/0.000681. Logistic fit took 3.976 seconds and its bundle is 61,456 bytes; RF fit was 2.459 seconds and its bundle is 1,161,628 bytes. RF inference duration was not persisted and remains unavailable. Both models use the same split, evaluation rows, binary mapping, sample, and duplicate rules. No production promotion was made.

**Dataset State:** Eight extracted CSV files are present under `data/raw/CIC-IDS2017/extracted/MachineLearningCVE/`. They were read but not modified. No ZIP archive was present under `data/raw/`, so an archive checksum could not be checked. The ingestion metadata contains per-file SHA-256 hashes, exact original headers, internal names, and source-position mappings.

**Phase 04 Data Quality Results:** The full scan found 1,358 missing tokens in `Flow Bytes/s`; 4,376 positive infinities in flow-rate fields, all associated with zero flow duration; 2,446,321 negative numeric cells across 13 source positions; and 8 full-scan constant features. Full-extract fingerprint analysis found 308,381 excess exact-row matches, 309,079 excess repeated-feature matches, and 698 feature-vector groups with differing labels. In v2, missing tokens and positive/negative infinities become nulls, while finite negative values, outliers, exact duplicates, and conflicting feature vectors remain. Numeric conversion failures were zero. All 15 labels remained valid after whitespace trimming; no rows were quarantined. See `docs/data_cleaning.md` for per-field details and limitations.

**Phase 05 Feature Contract:** The actual cleaned export has 78 numeric predictive features, no categorical predictive fields, and four present metadata fields. `destination_port` remains numeric; unavailable protocol and standalone source port are not inferred. Phases 07 and 08 use this contract. See `docs/feature_engineering.md`, `docs/multiclass_classification.md`, and `docs/anomaly_detection.md`.

**EDA Outputs:** `reports/eda/CIC-IDS2017_eda.json`, `reports/eda/CIC-IDS2017_eda.md`, and 10 PNGs under `reports/figures/eda/`. The notebook JSON and its 18 code cells were parsed/compiled; the full real-data execution was run through the EDA CLI. Jupyter was not installed, so the notebook was not interactively executed in a notebook frontend.

**Full Suite:** `python -m compileall -q src tests` passed and `python -m pytest -q` passed 161 tests in 40.85 seconds on system Python 3.13.2. Pytest reported two non-failing scikit-learn 1.8 deprecation warnings in the small Logistic artifact tests because explicit `penalty="l2"` is deprecated in a future release; it also printed an ignored `pyreadline3` destructor `OSError` after the success summary. `git diff --check` passed with only Git's LF-to-CRLF notices. The `.venv` remains incomplete for the EDA dependencies. The first two Logistic runs raised after artifact persistence during report assembly; the defects are recorded in ISSUE-016. The final run `20261103T163706Z` completed through the CLI and generated every report and artifact.

**Git Commit History:** The repository is on `main`. No commits were made or added to `gitlog.md` during Phase 07.

**Known Project Bugs:** No open implementation defects identified. Resolved issues ISSUE-001 through ISSUE-012 are recorded in `fixes.md`. The full scan found zero invalid numeric strings. Negative values, outliers, exact duplicates, and repeated feature vectors remain in the cleaned data according to policy; infinities and configured missing tokens are converted to nulls.

Do not assume the repository is empty or that no previous work exists.

## 4. Agreed Technical Direction

| Layer | Preferred Technology |
|---|---|
| Programming | Python 3.11 / 3.12 |
| Data processing | Pandas, NumPy |
| Data formats | CSV, Parquet |
| Machine learning | Scikit-learn |
| Gradient boosting | XGBoost |
| Explainable AI | SHAP |
| Network analysis | CICFlowMeter, Scapy where required |
| Backend | FastAPI |
| Database | PostgreSQL |
| ORM | SQLAlchemy |
| Dashboard | Streamlit |
| Visualization | Plotly |
| Testing | Pytest |
| Deployment | Docker |

These are preferred technologies, not permission to install every dependency immediately. Dependencies should be added only when required by the current phase.

## 5. Important Architectural Decisions

1. The platform begins with processed network flow datasets rather than requiring real-time packet capture.
2. CIC-IDS2017 is the primary benchmark dataset.
3. Large network flow datasets should be stored separately from application metadata and security alerts.
4. Parquet is the preferred format for larger processed datasets.
5. PostgreSQL is intended for alerts, model metadata, and application records.
6. Supervised classification and unsupervised anomaly detection must remain separate detection engines.
7. Threat scoring should be an explicit and documented combination of detection signals.
8. SHAP will be used where appropriate to explain model predictions.
9. The dashboard must display actual analysis results, not fabricated metrics or alerts.
10. Model evaluation must account for duplicate flows, label leakage, class imbalance, and realistic data-splitting constraints.
11. Dataset discovery is recursive under the configured dataset directory; only configured CSV extensions are considered.
12. Original source headers are preserved in the column mapping; standardized headers are used in cleaned output. Original target strings are retained in `__source_label`, and incompatible schemas are rejected rather than silently unioned.
13. Metadata-only inspection reports no row counts. Row and label summaries are recorded only after actual standard or chunked scans.

## 6. Development Sequence

The project follows the fourteen phases in `roadmap.md`:

1. Project Foundation & Architecture — Completed
2. Dataset Acquisition & Data Ingestion — Completed with real-data validation
3. Exploratory Data Analysis — Completed using all eight available CSV files
4. Data Cleaning & Leakage Prevention
5. Feature Engineering & Preprocessing
6. Supervised ML — Binary Classification
7. Supervised ML — Multi-class Classification
8. Unsupervised Anomaly Detection
9. Threat Intelligence & Alert Correlation
10. Explainable AI
11. Model Evaluation & Validation
12. Backend Development
13. Frontend & Security Analytics Dashboard
14. Integration, Testing & Deployment

## 7. Instructions for the Next Development Session

**Phase 12 implementation:** FastAPI routes are organized by capability; SQLAlchemy 2 models cover datasets, models, jobs, detection events, alerts, and event links; Alembic manages the initial schema. Dataset uploads are size/schema checked and stored under generated local names. Existing Phase 06–08 predictors and the Phase 09 pipeline are called without training. PostgreSQL persistence was verified with an actual model-backed API request. Automated API tests use synthetic model fixtures and isolated SQLite; PostgreSQL migration and real inference/persistence were separately verified against the local PostgreSQL 16 container.

**Known backend limits:** Analysis jobs use in-process FastAPI background tasks; restart marks active jobs failed. They are bounded but not a durable queue. Uploads and model artifacts remain local file storage. The backend does not provide authentication, live packet capture, or response blocking. XGBoost has no trained artifact and remains unavailable. Research model evaluation limitations from Phases 06–11 remain applicable.

**Immediate status:** Phase 14 is In Progress. Do not begin Phase 15. Latest recheck found PostgreSQL 18.4 service `postgresql-x64-18` Running (Manual) and TCP `127.0.0.1:5432` reachable. The user reports successful authentication via pgAdmin, but the credential is not exposed to Codex-launched project processes: `psql` reports `fe_sendauth: no password supplied`; there is no project `.env`, inherited PostgreSQL/database environment variable, or standard user `pgpass.conf`. No database or data was touched. Make a valid PostgreSQL URL available through an approved process environment/secret mechanism without posting it in chat, changing server auth, or committing credentials; inspect for `nii_phase14_validation` before creating it (use a unique alternative if occupied), then apply both migrations, run PostgreSQL API and restart-persistence checks, and verify PostgreSQL-backed dashboard behavior. Latest complete project suite passed 200/200 with 3 warnings when run with loopback access enabled; it is not PostgreSQL evidence.

For follow-up work, Codex must:

- Read `agent.md`, `roadmap.md`, and this `handoff.md`.
- Inspect the existing repository.
- Inspect existing files and Git status.
- Preserve existing work.
- Read `docs/data_cleaning.md`, `docs/data_leakage_policy.md`, `docs/feature_engineering.md`, `configs/feature_schema.json`, `configs/preprocessing.toml`, and the Phase 04 manifest before using the data.
- Keep raw dataset files immutable. Phase 04 outputs are numeric analytical Parquet with provenance, not encoded, scaled, or split model matrices.
- Treat finite negative values, extreme values, duplicates, and conflicting repeated-feature labels as unresolved source findings; missing tokens and infinities have been represented as nulls according to policy.
- The Phase 05 notebook's sample split is illustrative only. Fit any later data-dependent transformation only on the authorized training partition and preserve source file/row provenance for split design.

Do not claim the benchmark is entirely leakage-free, that Phase 07 row-split results generalize across captures, or that conflicting labels are adjudicated. Phase 08 capture-day groups are disjoint but duplicate-feature groups cross partitions; its 1% validation operating point did not retain a 1% false-positive rate on Friday. Do not overwrite raw files. Phase 07/08 artifacts and reports are under the paths listed in `docs/multiclass_classification.md` and `docs/anomaly_detection.md`.

## 8. Handoff Update Instructions

At the end of each completed development phase, update this document with:

- Current phase.
- Current phase status.
- Completed functionality.
- Actual repository changes.
- Important architectural decisions.
- Tests executed.
- Known issues.
- Remaining tasks.
- Exact next development action.

Do not leave outdated instructions in this document after the project advances.

## 9. Next Action

Phase 09 remains complete with bounded evaluation caveats. Actual CLI run `20261103T160444Z` integrated all three persisted detector families on 3,000 deterministic Friday rows, generated 871 research alerts, and formed no correlation groups because timestamps and endpoint identifiers are absent. Phase 10 run `20261103T182807Z` used SHAP 0.54.1 and scikit-learn 1.8.0 to explain binary Random Forest (ATTACK score), binary Logistic Regression (ATTACK log-odds), multi-class Random Forest (15 class probabilities), multi-class Logistic Regression (15 class logits), and Isolation Forest (`-score_samples`, higher is more anomalous). Training-only 100-row backgrounds were used; the anomaly background was BENIGN-only. All 33 outputs passed additivity checks. It produced 264 local explanation records, 2,574 global importance rows, and 33 SHAP plots. It enriched 3,000 event records and 871 alert sidecars; 8 selected events and alerts received references. Measured explanation/plot runtime was 67.13 seconds. No Phase 09 scoring or severity fields changed.

Phase 11 actual evaluation run `20261103T223701Z` reanalyzed saved evidence and successfully loaded all five latest model bundles. Binary Random Forest Friday metrics: ROC-AUC .738459, AP .720452, precision .996549, recall .281840, F1 .439408, FPR .000681. Binary Logistic Regression Friday metrics recalculated from saved predictions: ROC-AUC .817022, AP .804709, precision .841251, recall .471980, F1 .604698, FPR .062109. Multi-class Random Forest reused row-split metrics: accuracy .997442, balanced accuracy .880381, macro F1 .854852, weighted F1 .997414. Isolation Forest at saved 1% validation-FPR operating point: actual validation FPR .009999, Friday FPR .049068, recall .155685, precision .688720, ROC-AUC .694092, AP .549409. Every prior test score is explicitly previously inspected, not fresh independent evidence. Duplicate feature overlap, source-group limits, missing time/endpoint fields, and unavailable external data are documented.

Five model bundles underwent synthetic input stress checks and warm inference timing at batch sizes 1, 16, and 64 using 64 Friday feature rows with labels not loaded. All five rejected absent required columns and infinities; synthetic NaN, large finite, and zero-rate inputs were accepted with finite outputs. Saved Phase 10 explanation records: 264/264 additivity diagnostics passed. Real-data ablation, multi-class probability calibration, temporal/external validation, and reliable cluster confidence intervals remain unavailable. No production model artifacts were changed.

Phase 11 added 10 synthetic evaluation tests; the full suite then passed 177 tests. Phase 12 added the FastAPI routes/services, six SQLAlchemy tables, Alembic migration, PostgreSQL Compose deployment, docs, and 10 SQLite-backed API tests; its full suite passed 188 tests. PostgreSQL migration, container startup/readiness, all five artifacts, and a real model-backed request were verified during Phase 12.

Phase 13 added the Streamlit app, nine pages, configurable `ApiClient`, response guards, alert CSV/JSON serialization, project navigation config, behavior tests, and dashboard docs. Phase 13 then lacked event retrieval and API SHAP access; Phase 14 implements these capabilities as documented below.

Phase 14 added paginated event list/detail routes, dataset-backed row provenance, on-demand model-specific SHAP via the existing Phase 10 registry/backgrounds, event-row persistence/migration `20261104_0002`, and the dashboard event detail/explanation flow. The project `.venv` dashboard extra was installed. Full tests: 200 passed, 0 failed, 0 skipped, 3 warnings. A temporary real feature row went through actual binary inference; event retrieval returned the persisted result; the explanation endpoint returned SHAP with max additivity residual `1.3826e-9`, passed. Automated coverage verifies unsupported-model status. Browser navigation verified all nine page headings. The current SQLite schema migration succeeded. Docker Engine was inaccessible in this session, so PostgreSQL/Compose validation remains the outstanding Phase 14 gate. No source data or model artifacts changed.

**Exact next action:** When Docker Engine is available, validate Compose PostgreSQL migration through `20261104_0002`, API readiness, event list/detail, and an actual model-specific SHAP response. Keep Phase 14 In Progress until those results are recorded. Do not begin Phase 15.
