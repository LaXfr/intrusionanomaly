# Project Roadmap — Network Intrusion Detection & Anomaly Intelligence

## 1. Project Overview

**Project:** Network Intrusion Detection & Anomaly Intelligence  
**Primary Language:** Python  
**Primary Dataset:** CIC-IDS2017  
**Architecture:** Modular offline analytics platform

The project aims to develop a network security analytics system that combines supervised machine learning, unsupervised anomaly detection, threat scoring, explainable AI, backend APIs, and an interactive dashboard.

The roadmap defines the development sequence and expected deliverables.

## 2. Development Status

**Status Legend:**

- `Not Started` — Work has not started.
- `In Progress` — Implementation is underway.
- `Blocked` — Work cannot continue because of an unresolved dependency.
- `Completed` — Implementation and required validation are finished.
- `Needs Revision` — Implementation exists but requires correction or improvement.

All phases begin as not started. Update their status only when supported by actual implementation evidence.

## 3. Development Phases

### Phase 01 — Project Foundation & Architecture

**Status:** Completed

**Objective:** Establish a clean, maintainable, modular Python project architecture.

Tasks:

- [x] Inspect the existing repository.
- [x] Establish the project directory structure.
- [x] Define module responsibilities.
- [x] Establish configuration management.
- [x] Establish centralized logging.
- [x] Create or review dependency files.
- [x] Configure environment-variable handling.
- [x] Establish `.gitignore`.
- [x] Document the system architecture.
- [x] Add initial tests and smoke checks.
- [x] Validate the project setup.

Expected deliverables:

- Structured project repository.
- Configuration and logging infrastructure.
- Dependency management.
- Initial architecture documentation.
- Basic test infrastructure.

### Phase 02 — Dataset Acquisition & Data Ingestion

**Status:** Completed

**Objective:** Establish a reliable process for acquiring, loading, and validating CIC-IDS2017 network flow data.

Tasks:

- [x] Document the CIC-IDS2017 dataset source.
- [x] Identify the required CSV files and label structure.
- [x] Define the expected input schema.
- [x] Implement dataset loading utilities.
- [x] Implement file and schema validation.
- [x] Record dataset metadata.
- [x] Establish raw, interim, and processed data separation.
- [x] Verify ingestion using representative synthetic data.
- [x] Inspect all eight extracted CIC-IDS2017 CSV files and preserve their original contents.
- [x] Validate the real headers, label detection, duplicate-column mapping, and cross-file schemas.
- [x] Verify standard and chunked loading and complete the real-data label summary.

Expected deliverables:

- Dataset acquisition documentation.
- Reusable ingestion module.
- Dataset validation utilities.
- Data schema documentation.

The eight extracted MachineLearningCSV files have identical 79-column source headers. The repeated ` Fwd Header Length` fields occur at positions 35 and 56 and were exactly equal across all 2,830,743 rows; ingestion preserves both with position-specific internal names. Inspection and schema validation passed for all eight files; standard loading was run file-by-file, chunked loading streamed all files, and a full 15-category label summary completed. See `reports/ingestion/CIC-IDS2017_schema_audit.md`. The ZIP archive was not present under `data/raw/`, so no publisher-provided archive checksum could be verified.

### Phase 03 — Exploratory Data Analysis

**Status:** Completed

**Objective:** Understand the dataset's structure, distribution, attack categories, and potential quality issues.

Tasks:

- [x] Inspect dataset dimensions and column types.
- [x] Analyze label distribution and class imbalance, including per-file concentration.
- [x] Investigate missing values, infinities, negative values, and numeric parsing issues.
- [x] Analyze full-scan numerical moments and sample-based feature distributions.
- [x] Investigate sample-based feature correlations and redundant pairs.
- [x] Identify constant and low-information features without removing columns.
- [x] Investigate duplicates using a deterministic sample and record the scope limitation.
- [x] Generate meaningful visualizations for labels, quality, features, ports, correlations, and duplicates.
- [x] Investigate available port and per-file patterns; record absent protocol, timestamp, and identifier fields.
- [x] Document actual findings, leakage risks, benchmark limitations, and next-phase recommendations.

Expected deliverables:

- EDA notebook.
- Dataset statistics.
- Visualization reports.
- Data-quality findings.

The workflow scanned all eight available CIC-IDS2017 CSV files (2,830,743 rows, 79 source columns) in chunks and saved results under `reports/eda/` and `reports/figures/eda/`. Full-scan aggregates are separated from deterministic sample-derived correlations, quantiles, feature comparisons, and duplicate diagnostics. See `docs/eda.md`. Phase 03 remains complete.

### Phase 04 — Data Cleaning & Leakage Prevention

**Status:** Completed — the corrected v2 pipeline was run and verified against all available CIC-IDS2017 files

**Objective:** Prepare reliable data while preventing invalid experimental results caused by data leakage.

Tasks:

- [x] Normalize source headers deterministically and record exact original names/positions, resolving collisions without loss.
- [x] Assess numeric parsing, mixed representations, null tokens, conversion overflow, and precision risk.
- [x] Measure missingness, positive/negative infinity, zero-denominator associations, and negative values across all rows.
- [x] Investigate all 13 negative source positions using CICFlowMeter feature descriptions.
- [x] Fingerprint exact complete rows and feature vectors externally, including within/across-file groups and conflicting labels.
- [x] Assess full-scan constants and sampled low-cardinality/near-constant features.
- [x] Record source-file/label concentration and absent timestamp, endpoint, source-port, and protocol fields.
- [x] Define a validated versioned policy for numeric conversion, missing values, infinity, labels, duplicate handling, and leakage roles.
- [x] Implement chunked Parquet transformation, label quarantine, provenance, manifest, and feature/label policy outputs.
- [x] Run the corrected policy across all real CIC-IDS2017 files and verify Parquet, quarantine, row accounting, and unchanged raw checksums.
- [x] Add synthetic tests for schema normalization, conversion, missing/infinite handling, labels, duplicates, policy, and provenance.

Expected deliverables:

- Reusable preprocessing assessment and cleaning CLI/API.
- Versioned conservative cleaning policy.
- Full-scan JSON/Markdown quality and cleaning reports.
- Verified processed Parquet files, quarantine output, and manifest.
- Documentation of data and leakage limitations.

The historical v1 preservation-only output remains intact for audit. The completed v2 run processed 2,830,743 rows from eight files and retained all rows; 1,358 missing tokens and 4,376 positive infinities were represented as nulls, no invalid numeric conversions occurred, all 15 labels remained distinct, and no rows required quarantine. Exact duplicates and 698 conflicting feature-vector groups were preserved by the configured default. Eight Parquet files, metadata, quality reports, and a zero-row quarantine file are under the documented v2 paths. Raw checksums matched the source manifest after processing.

### Phase 05 — Feature Engineering & Preprocessing

**Status:** Completed — synthetic coverage passed and the actual Phase 04 schema/sample transform was validated; no final model split or full-dataset fit was created

**Objective:** Establish a consistent and reproducible feature preparation pipeline.

Tasks:

- [x] Define a versioned predictive feature contract from the actual cleaned schema.
- [x] Separate features, target labels, network identifiers, provenance, and investigation metadata.
- [x] Validate required/optional columns, unexpected fields, duplicate names, types, order, NaN, infinity, and leakage contamination.
- [x] Classify numerical and categorical features explicitly; preserve destination port and support categorical protocol codes when present.
- [x] Implement deterministic optional derived packet/byte totals and directional proportions with missing/zero behavior documented.
- [x] Implement training-fitted median numeric imputation, categorical missing handling, one-hot encoding, and unknown-category inference behavior.
- [x] Add independent linear, tree, and anomaly scaling profiles.
- [x] Add configurable train-fitted variance selection, disabled by default.
- [x] Add training-label-only class distribution and optional balanced-weight calculation without resampling.
- [x] Preserve training/inference feature names/order; support repeatable batch transforms and schema-versioned Joblib artifacts.
- [x] Add sparse/dense transformed matrix persistence with aligned labels and row metadata.
- [x] Create the feature-engineering notebook and document configuration, profiles, leakage rules, artifact layout, and limitations.
- [x] Run tests and verify all eight real Parquet schemas plus a bounded real-data sample transform.

Expected deliverables:

- Versioned feature contract and reusable feature engineering module.
- Train-fitted Scikit-learn preprocessing profiles.
- Artifact and transformed-matrix persistence APIs.
- Feature schema documentation and reproducible notebook.

Validation used the actual eight Phase 04 Parquet files (83 columns each) and an 8,000-row bounded sample. An illustrative 6,400-row training subset fitted the linear profile and the same object transformed 1,600 held-out sample rows. The transformed matrix had 80 named columns with two optional derived features enabled. This validates schema compatibility and a sample transformation only; it is not a final data split, full-dataset transformation, anomaly baseline, or model experiment.

### Phase 06 — Supervised ML: Binary Classification

**Status:** Completed — Random Forest and Logistic Regression were compared on the established leakage-screened capture-day partitions; research and capture-shift limitations are documented

**Objective:** Build an initial classifier that distinguishes benign traffic from malicious traffic.

Tasks:

- [x] Define binary labels with an explicit BENIGN=0, all preserved non-BENIGN labels=ATTACK mapping.
- [x] Establish a capture-day/source-file-disjoint train, validation, and test strategy.
- [x] Train a Logistic Regression baseline with training-fitted scaling and explicit L2 regularization.
- [x] Train a Random Forest model.
- [ ] Evaluate additional models where justified.
- [x] Report precision, recall, F1-score, PR-AUC, ROC-AUC, and false-positive rate.
- [x] Examine false positives and false negatives through confusion matrices and split metrics.
- [x] Investigate binary class imbalance; use class weighting and document the sampled training distribution.
- [x] Save a checksummed versioned model and fitted preprocessing artifact.
- [x] Record experiment configuration, split audit, and results.
- [x] Compare validation and Friday metrics, threshold sensitivity, runtime, and artifact sizes against the persisted Random Forest report.
- [x] Preserve evaluation labels separately and verify inference-time probability scores from the Logistic artifact.

Expected deliverables:

- Binary classification pipeline.
- Trained baseline models.
- Model comparison report.
- Saved model artifacts.
- Timestamped Logistic Regression experiment report, predictions, and checksummed artifact.

The independent Logistic Regression comparison is run `20261103T163706Z` (`binary-logistic_regression-v1.0.2`). It trained on 77,085 Monday–Wednesday rows with training-only median imputation/StandardScaler, fixed threshold 0.5, and 78 features. Friday ROC-AUC/AP/attack recall were 0.8170/0.8047/0.4720; RF v1.0.1 was 0.7385/0.7205/0.2818. Logistic Regression had lower Friday attack precision (0.8413 vs 0.9965) and higher FPR (0.0621 vs 0.000681). Its Thursday ROC-AUC was lower (0.7681 vs 0.9883), evidencing different capture sensitivity. Logistic fit took 3.976 seconds and its artifact was 61,456 bytes; RF fit took 2.459 seconds and its artifact was 1,161,628 bytes. RF inference time was not present in persisted reports and remains unavailable. See `docs/binary_classification.md` and the timestamped report. No production model selection changed.

### Phase 07 — Supervised ML: Multi-class Classification

**Status:** Completed — exploratory stratified-row evaluation; source-group holdout cannot cover every class

**Objective:** Extend known-attack classification to multiple attack categories.

Tasks:

- [x] Define supported attack categories from the validated Phase 04 labels.
- [x] Review class coverage and label quality, including source-file concentration and rare-class support.
- [x] Establish and audit the evaluation split; document why a source-group-disjoint three-way split cannot cover all classes and use the explicitly configured stratified-row fallback.
- [x] Train Logistic Regression and Random Forest multi-class baselines; record XGBoost as unavailable in the environment.
- [x] Handle class imbalance with training-only class weights and a stratified training sample that retains every rare-class training row.
- [x] Evaluate per-class performance and report multiclass aggregate metrics.
- [x] Analyze raw and normalized confusion matrices and frequent confusion pairs.
- [x] Investigate poor-performing classes and the limited support for the rarest labels.
- [x] Save versioned model artifacts and experiment metadata.

Expected deliverables:

- Multi-class classification pipeline.
- Trained multi-class models.
- Per-class evaluation report.
- Documented limitations.

The successful real-data multi-class experiment is `20261103T134128Z`. Random Forest was selected by validation macro F1 and achieved held-out row-split macro F1 0.8549. Because each attack class occurs in one source file, all source files overlap across the stratified row partitions; these metrics are exploratory and do not establish cross-capture generalization.

### Phase 08 — Unsupervised Anomaly Detection

**Status:** Completed with documented capture-day and duplicate-overlap limitations

**Objective:** Identify unusual network flows independently of the supervised attack classifier.

Tasks:

- [x] Establish a validated benign-only training population and retain original labels for evaluation.
- [x] Implement and train a configurable Isolation Forest baseline.
- [x] Investigate One-Class SVM and Local Outlier Factor; document why neither was implemented at this scale.
- [x] Calibrate multiple external thresholds using benign validation scores only.
- [x] Evaluate the frozen model on held-out capture-day data and analyze available attack categories.
- [x] Investigate false positives and false negatives with structured reports.
- [x] Keep Phase 08 inference independent and compare its decisions with Phase 06 and Phase 07 predictors in Phase 09.
- [x] Save and reload versioned model and preprocessing artifacts.
- [x] Document score interpretation, duplicate overlap, capture shift, and benchmark limits.

Expected deliverables:

- Anomaly detection pipeline.
- Trained anomaly detector.
- Threshold calibration report.
- Anomaly evaluation results.

The verified real-data experiment is `20261103T141439Z`. Monday–Wednesday benign training, Thursday benign calibration, and Friday held-out test groups are capture-day/source-file disjoint. The 150,000-row benign fit used the Phase 05 anomaly profile and Isolation Forest. At the default 1% validation-FPR point, test FPR was 4.91%, attack recall was 15.57%, and ROC-AUC was 0.6941. Three attack categories were present in Friday test data; 12 were unavailable. Duplicate-feature links cross all five days, preventing a duplicate-disjoint day-based three-way split. Full results and caveats are in `docs/anomaly_detection.md` and the run report.

### Phase 09 — Threat Intelligence & Alert Correlation

**Status:** Completed with capture-day test, bounded alert-evaluation, and missing CIC network metadata limitations documented

**Objective:** Combine detection outputs into useful security intelligence and structured alerts.

Tasks:

- [x] Define binary, multi-class, anomaly, optional network metadata, and provenance inputs.
- [x] Establish a configurable, deterministic weighted evidence score with available-signal reweighting and per-signal contribution detail.
- [x] Combine saved Phase 06, Phase 07, and Phase 08 predictions without fitting models or modifying thresholds.
- [x] Preserve raw detection outputs, score semantics, availability, validation status, and model versions.
- [x] Define versioned configurable severity bands and unscored state.
- [x] Design typed flow-event, correlation-group, and security-alert schemas.
- [x] Implement source IP, destination IP, destination service, attack-category-with-endpoints, repeated flow tuple, and endpoint-pair temporal rules with bounded time windows.
- [x] Implement evidence-based single-flow and correlated alert generation with provenance and summaries.
- [x] Implement deterministic event/alert fingerprints, repeated-alert deduplication, and severity updates.
- [x] Validate normalization, scoring, severity, event alignment, correlation, aggregation, idempotency, and reports with synthetic tests; run actual inference and separate offline alert evaluation on a label-stratified bounded CIC sample.

Expected deliverables:

- Threat intelligence module.
- Alert generation engine.
- Alert correlation utilities.
- Documented threat scoring logic.

Binary experiment `20261103T160232Z` (model v1.0.1) trained on Monday–Wednesday, validated on Thursday, and tested on Friday with test ROC-AUC 0.7385, attack precision 0.9965, and attack recall 0.2818 at a predeclared fixed 0.5 threshold. Duplicate feature vectors shared with evaluation were excluded from training; 2,915 of 80,000 training candidates were removed. Phase 09 CLI run `20261103T160444Z` loaded the binary, multi-class, and anomaly artifacts and evaluated 3,000 deterministic Friday rows (500 per source label per file) offline. Binary attack recall was 0.2133; alert-level attack precision/recall were 0.9908/0.5753. It generated 871 alerts (552 HIGH, 319 CRITICAL), with zero correlation groups and zero unscored events. These metrics are research evidence on a bounded, label-stratified sample, not deployment validation. No timestamps or endpoints exist in the Phase 04 export; all six rules skipped 1,407 suspicious events. See `docs/threat_intelligence.md` and `docs/alert_correlation.md`.

### Phase 10 — Explainable AI

**Status:** Completed (verified actual explanations for the persisted CIC-IDS2017 model artifacts)

**Objective:** Explain model predictions and identify features influencing detection decisions.

Tasks:

- [x] Inspect actual persisted artifacts, preprocessors, transformed feature order, class taxonomy, score semantics, and runtime compatibility.
- [x] Implement SHAP selection for Random Forest, Logistic Regression, and model-agnostic Isolation Forest outputs.
- [x] Select deterministic training-only backgrounds, including BENIGN-only anomaly references.
- [x] Implement transformed/original feature mapping and explicit unmapped feature handling.
- [x] Implement global per-output importance, bounded local explanations, structured summaries, and plots.
- [x] Enrich Phase 09 event and alert sidecars with explanation references without changing scores, severity, or correlation output.
- [x] Validate additive reconstruction for all 33 actual configured model outputs.
- [x] Add synthetic SHAP tests, documentation, CLI, and notebook.

Expected deliverables:

- Reusable explainability module and CLI.
- 33 actual model-output explanation targets across five persisted artifacts.
- JSONL, CSV, Markdown, JSON, and SHAP plot reports.
- Notebook and explainability documentation.

Actual run `20261103T182807Z` used 100-row deterministic training-only backgrounds, 64-row global classifier samples (16 for Isolation Forest), and 8 local records per each of the 33 outputs. All additivity checks passed. XGBoost had no persisted project artifact and remains unsupported. SHAP explains detector outputs; it does not explain Phase 09 heuristic threat scores or prove causality. See `docs/explainability.md` and `reports/explainability/20261103T182807Z/`.

### Phase 11 — Model Evaluation & Validation

**Status:** Completed with documented evidence limitations

**Objective:** Validate the complete detection system using defensible evaluation practices.

Tasks:

- [x] Finalize evaluation methodology and evidence governance.
- [x] Compare available saved model performance.
- [x] Examine saved per-class performance and confusion results.
- [x] Measure false-positive behavior and binary threshold trade-offs.
- [x] Investigate group-aware evaluation and document split constraints.
- [x] Investigate temporal evaluation feasibility; timestamps are unavailable.
- [x] Examine unseen-attack generalization limits; no independent claim made.
- [x] Document dataset, duplicate-flow, and statistical limitations.
- [x] Produce structured scorecards, visualizations, and a consolidated evaluation report.
- [x] Add reusable CLI pipeline, utilities, and synthetic tests.
- [x] Add the Phase 11 notebook and methodology documentation.

Expected deliverables:

- Model evaluation framework.
- Consolidated metrics.
- Evaluation visualizations.
- Validation and limitations report.

The framework was run against saved Phase 06–10 evidence and the five configured persisted models. Existing Thursday/Friday and Phase 07 row-split test partitions were already inspected, so the run reports reused exploratory evidence and no fresh independent final test. It adds deterministic synthetic robustness checks, actual warm inference timings over a bounded label-free feature sample, binary Logistic score reanalysis/calibration, leakage and split status, saved SHAP reconstruction audit, and explicit unavailable statuses. Real-data ablation, external transfer, temporal evaluation, multi-class probability calibration, and reliable cluster intervals remain unavailable for the reasons in `docs/model_evaluation.md` and `reports/evaluation/project_evaluation_inventory.md`. No model artifacts were modified. Phase 14 is In Progress: a current SQLite API run exercised dataset upload, real binary inference, event retrieval, and persisted SHAP with an additivity check; the full suite and nine browser pages passed. Docker Engine access failed during this session, so current Compose/PostgreSQL validation remains outstanding.

### Phase 12 — Backend Development

**Status:** Completed

**Objective:** Expose the detection and analytics functionality through a structured API.

Tasks:

- [x] Establish FastAPI application structure.
- [x] Define request and response schemas.
- [x] Implement flow analysis endpoint.
- [x] Implement alert retrieval endpoints.
- [x] Implement metrics endpoints.
- [x] Implement model information endpoints.
- [x] Establish model loading and inference services.
- [x] Integrate PostgreSQL.
- [x] Establish database models and migrations.
- [x] Implement error handling and API validation.
- [x] Test API functionality.

Expected deliverables:

- FastAPI backend.
- API schemas and endpoints.
- PostgreSQL integration.
- API documentation.
- Backend tests.

Phase 12 validation: all 188 project tests passed. The initial Alembic migration was applied to PostgreSQL 16 and recorded as head (`20261104_0001`). The Docker image built successfully; the Compose API started, reported ready, and exposed all five persisted model bundles. A real label-free CIC feature row passed through all three detector families in the Docker API with PostgreSQL storage; one NORMAL/LOW event was persisted and verified through `/metrics`, with zero alerts generated. Detailed scope, endpoint behavior, and limitations are documented in `docs/backend_architecture.md`, `docs/api_reference.md`, and `docs/database.md`.

### Phase 13 — Frontend & Security Analytics Dashboard

**Status:** Completed — dashboard behavior, all nine pages, local startup, and supported API integration were verified

**Objective:** Develop an interactive dashboard that communicates actual network detection results.

Tasks:

- [x] Establish Streamlit application structure and shared API client.
- [x] Design the dashboard layout and nine-page navigation.
- [x] Implement traffic overview and supported aggregate visualizations.
- [x] Implement attack distribution visualizations from API summaries.
- [x] Implement detection alert filtering, details, and supported lifecycle updates.
- [x] Implement anomaly analysis from available persisted aggregates.
- [x] Implement model registry/performance metadata views with unavailable states.
- [x] State the explainability API limitation without fabricating SHAP values.
- [x] Add supported dataset CSV upload and analysis-job workflows.
- [x] Add CSV and JSON alert exports from returned alert rows.
- [x] Validate dashboard responses against the backend and handle empty/malformed/error responses.
- [x] Test nine-page navigation and rendering, dashboard client behavior, exports, and API failures.
- [x] Verify local Streamlit startup and all nine pages in a browser against the running API.

Expected deliverables:

- Streamlit dashboard.
- Plotly visualizations.
- Interactive alert and traffic views.
- Dashboard usage documentation.

The dashboard is implemented in `dashboard/` and documented in `docs/dashboard_architecture.md` and `docs/dashboard_user_guide.md`. The dashboard extra installed successfully. Ten dashboard behavior tests passed; the full project suite and final check totals are recorded in the Phase 13 worklog entry. A real API run against an isolated migrated SQLite database registered a temporary 78-feature CSV and completed one record through the actual binary, multi-class, and anomaly model artifacts. The job processed one row successfully; `/traffic/summary`, `/alerts`, `/metrics`, and job status were read successfully. This benign fixture produced zero alerts; the page's current alert export produced an empty CSV and valid `[]` JSON. Docker Engine was unavailable during this Phase 13 run, so the real HTTP check used the backend's supported isolated SQLite configuration. PostgreSQL Compose validation remains recorded under Phase 12. The API does not expose SHAP records or arbitrary event/flow retrieval; the dashboard states these constraints.

### Phase 14 — Integration, Testing & Deployment

**Status:** In Progress

**Objective:** Integrate all project components into a reliable, reproducible application.

Tasks:

- [ ] Integrate data processing and ML pipelines.
- [x] Integrate supervised and anomaly detection.
- [x] Integrate threat intelligence and event-level SHAP explanations.
- [x] Integrate backend and database with event retrieval and persisted explanation cache.
- [x] Integrate dashboard and backend.
- [x] Run unit and integration tests.
- [x] Validate a dataset-to-event-to-SHAP workflow in disposable SQLite.
- [x] Verify project environment and install the dashboard extra into `.venv`.
- [ ] Create Docker configuration.
- [ ] Create Docker Compose configuration if required.
- [ ] Finalize README and architecture documentation.
- [ ] Validate setup on a clean environment.
- [x] Prepare a local demo flow and verify all nine dashboard pages in a browser.

Expected deliverables:

- Integrated application.
- Verified test suite.
- Deployment configuration.
- Complete documentation.
- Demonstration-ready project.

Current gate: SQLite migrations through `20261104_0002` and one real binary-model SHAP explanation passed. Local PostgreSQL 18.4 is Running and TCP `127.0.0.1:5432` connects. The user reports successful authentication through pgAdmin, but no approved credential source is available to project processes; `psql` reports `fe_sendauth: no password supplied`. No PostgreSQL database, migration, persistence, restart, model-family, or dashboard check was performed. The full suite passed 200 tests with loopback-enabled execution, but those tests do not establish PostgreSQL integration. Phase 14 stays In Progress until isolated PostgreSQL validation and the remaining dashboard-state criteria pass. Do not begin Phase 15.

## 4. Definition of Done

A phase can be marked Completed only when:

1. Its required functionality has been implemented.
2. Its expected deliverables exist.
3. Relevant tests have been executed.
4. Results have been checked.
5. Known limitations have been documented.
6. Relevant project documentation has been updated.
7. No unresolved blocking issue prevents the next phase.

Creating files without implementing their functionality does not count as completing a phase.

## 5. Overall Project Principles

- Follow the phase sequence unless a dependency requires adjustment.
- Prioritize correctness over speed.
- Avoid premature optimization.
- Avoid unnecessary technologies.
- Use reproducible experiments.
- Keep the system modular.
- Do not fabricate results.
- Document design decisions and limitations.
- Preserve the distinction between anomaly detection and attack classification.

**Current Project Status:** Phases 01–13 are implemented. Phase 14 Integration, Testing & Deployment is In Progress: event retrieval, stable source-row traceability, on-demand model-specific SHAP persistence, dashboard integration, migrated SQLite end-to-end validation, and nine-page browser verification are complete. The current full suite passed 200 tests, 0 failed, 0 skipped (3 warnings). Current Docker/PostgreSQL validation is outstanding because Docker Engine access failed. Do not begin Phase 15.
