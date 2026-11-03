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

**Status:** Not Started

**Objective:** Build an initial classifier that distinguishes benign traffic from malicious traffic.

Tasks:

- [ ] Define binary labels.
- [ ] Establish an appropriate data-splitting strategy.
- [ ] Train a Logistic Regression baseline.
- [ ] Train a Random Forest model.
- [ ] Evaluate additional models where justified.
- [ ] Compare precision, recall, F1-score, and PR-AUC.
- [ ] Examine false positives and false negatives.
- [ ] Investigate class imbalance.
- [ ] Save trained model artifacts.
- [ ] Record experiment configurations and results.

Expected deliverables:

- Binary classification pipeline.
- Trained baseline models.
- Model comparison report.
- Saved model artifacts.

### Phase 07 — Supervised ML: Multi-class Classification

**Status:** Not Started

**Objective:** Extend known-attack classification to multiple attack categories.

Tasks:

- [ ] Define supported attack categories.
- [ ] Review class coverage and label quality.
- [ ] Establish a valid multi-class evaluation strategy.
- [ ] Train multi-class classification models.
- [ ] Handle class imbalance appropriately.
- [ ] Evaluate per-class performance.
- [ ] Analyze confusion matrices.
- [ ] Investigate poor-performing classes.
- [ ] Save model artifacts and metadata.

Expected deliverables:

- Multi-class classification pipeline.
- Trained multi-class models.
- Per-class evaluation report.
- Documented limitations.

### Phase 08 — Unsupervised Anomaly Detection

**Status:** Not Started

**Objective:** Identify unusual network flows independently of the supervised attack classifier.

Tasks:

- [ ] Establish the benign-only training dataset.
- [ ] Implement Isolation Forest.
- [ ] Investigate other anomaly detection methods where useful.
- [ ] Calibrate thresholds using benign validation data.
- [ ] Evaluate anomaly detection behavior.
- [ ] Investigate false-positive rates.
- [ ] Compare anomaly detection against supervised predictions.
- [ ] Save anomaly model artifacts.
- [ ] Document score interpretation and limitations.

Expected deliverables:

- Anomaly detection pipeline.
- Trained anomaly detector.
- Threshold calibration report.
- Anomaly evaluation results.

### Phase 09 — Threat Intelligence & Alert Correlation

**Status:** Not Started

**Objective:** Combine detection outputs into useful security intelligence and structured alerts.

Tasks:

- [ ] Define threat scoring inputs.
- [ ] Establish an explicit threat scoring method.
- [ ] Combine supervised classification and anomaly signals.
- [ ] Preserve original detection signals.
- [ ] Define alert severity levels.
- [ ] Design alert data structures.
- [ ] Investigate repeated-flow and event correlation.
- [ ] Implement alert generation.
- [ ] Implement alert deduplication where appropriate.
- [ ] Validate scoring and correlation behavior.

Expected deliverables:

- Threat intelligence module.
- Alert generation engine.
- Alert correlation utilities.
- Documented threat scoring logic.

### Phase 10 — Explainable AI

**Status:** Not Started

**Objective:** Explain model predictions and identify features influencing detection decisions.

Tasks:

- [ ] Investigate SHAP compatibility with selected models.
- [ ] Implement global feature importance analysis.
- [ ] Implement local prediction explanations.
- [ ] Generate explanation summaries.
- [ ] Connect explanations to detection outputs.
- [ ] Document interpretation limitations.
- [ ] Validate explanation outputs.

Expected deliverables:

- Explainability module.
- Feature importance visualizations.
- Prediction explanation functionality.
- Explainability documentation.

### Phase 11 — Model Evaluation & Validation

**Status:** Not Started

**Objective:** Validate the complete detection system using defensible evaluation practices.

Tasks:

- [ ] Finalize evaluation methodology.
- [ ] Compare model performance.
- [ ] Examine per-class performance.
- [ ] Measure false-positive behavior.
- [ ] Evaluate precision-recall trade-offs.
- [ ] Investigate group-aware evaluation.
- [ ] Investigate temporal evaluation.
- [ ] Examine unseen-attack generalization where feasible.
- [ ] Document dataset limitations.
- [ ] Produce a consolidated evaluation report.

Expected deliverables:

- Model evaluation framework.
- Consolidated metrics.
- Evaluation visualizations.
- Validation and limitations report.

### Phase 12 — Backend Development

**Status:** Not Started

**Objective:** Expose the detection and analytics functionality through a structured API.

Tasks:

- [ ] Establish FastAPI application structure.
- [ ] Define request and response schemas.
- [ ] Implement flow analysis endpoint.
- [ ] Implement alert retrieval endpoints.
- [ ] Implement metrics endpoints.
- [ ] Implement model information endpoints.
- [ ] Establish model loading and inference services.
- [ ] Integrate PostgreSQL.
- [ ] Establish database models and migrations.
- [ ] Implement error handling and API validation.
- [ ] Test API functionality.

Expected deliverables:

- FastAPI backend.
- API schemas and endpoints.
- PostgreSQL integration.
- API documentation.
- Backend tests.

### Phase 13 — Frontend & Security Analytics Dashboard

**Status:** Not Started

**Objective:** Develop an interactive dashboard that communicates actual network detection results.

Tasks:

- [ ] Establish Streamlit application structure.
- [ ] Design the dashboard layout.
- [ ] Implement traffic overview.
- [ ] Implement attack distribution visualizations.
- [ ] Implement detection alert views.
- [ ] Implement anomaly analysis.
- [ ] Implement model performance visualizations.
- [ ] Integrate explainability outputs.
- [ ] Add filtering and flow-level inspection.
- [ ] Add supported CSV upload and analysis workflows.
- [ ] Add alert export functionality.
- [ ] Validate dashboard data against backend results.

Expected deliverables:

- Streamlit dashboard.
- Plotly visualizations.
- Interactive alert and traffic views.
- Dashboard usage documentation.

### Phase 14 — Integration, Testing & Deployment

**Status:** Not Started

**Objective:** Integrate all project components into a reliable, reproducible application.

Tasks:

- [ ] Integrate data processing and ML pipelines.
- [ ] Integrate supervised and anomaly detection.
- [ ] Integrate threat intelligence and explanations.
- [ ] Integrate backend and database.
- [ ] Integrate dashboard and backend.
- [ ] Run unit and integration tests.
- [ ] Validate end-to-end workflows.
- [ ] Verify configuration and environment setup.
- [ ] Create Docker configuration.
- [ ] Create Docker Compose configuration if required.
- [ ] Finalize README and architecture documentation.
- [ ] Validate setup on a clean environment.
- [ ] Prepare final project demonstration.

Expected deliverables:

- Integrated application.
- Verified test suite.
- Deployment configuration.
- Complete documentation.
- Demonstration-ready project.

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

**Current Project Status:** Phases 01–05 are complete. Phase 05 adds a versioned feature contract, leakage-safe X/y/metadata separation, optional derived features, train-fitted preprocessing profiles, feature selection support, class-weight utilities, artifact persistence, transformed-matrix storage, tests, and documentation. Real-data validation is schema-wide and sample-bounded; no final split or model was created. Phase 06 remains not started.
