# Network Intrusion Detection & Anomaly Intelligence

An offline research and analytics platform for examining network flow data, including the CIC-IDS2017 benchmark. It includes independent binary and multi-class supervised detectors, a benign-baseline anomaly detector, a threat intelligence layer that combines their outputs into traceable flow events and heuristic alerts, a FastAPI backend, and a nine-page Streamlit dashboard. Phase 09 remains limited by missing time and endpoint metadata in the processed export.

This project is not an intrusion prevention system. It does not capture traffic continuously or block network activity.

## Problem statement

Network flow datasets can contain known attacks, benign activity, duplicate records, severe class imbalance, and features that leak labels or collection details. This project is intended to provide a reproducible workflow for studying those conditions and evaluating detection approaches without presenting research results as live protective controls.

## Objectives

- Establish reproducible data ingestion, cleaning, and feature preparation.
- Evaluate supervised models for known attack categories.
- Study anomaly detection independently from labelled attack classification.
- Combine validated detection signals through a documented threat intelligence layer.
- Explain model decisions and expose real analysis results through the API and dashboard.
- Document dataset, evaluation, and model limitations.

## Planned capabilities

The project foundation, ingestion, EDA, cleaning, feature/preprocessing infrastructure, Phase 06 binary Random Forest and Logistic Regression comparison, Phase 07 multi-class classification, Phase 08 anomaly detection, Phase 09 threat intelligence and alert correlation, Phase 10 SHAP explainability, Phase 11 evaluation, Phase 12 API, Phase 13 dashboard, and Phase 14 integration work are implemented or documented in the roadmap. Phase 14 remains In Progress pending current Compose/PostgreSQL validation. Binary classification uses capture-day-held-out CIC evaluation and separate versioned predictors; its model tradeoffs and capture shift are documented in [docs/binary_classification.md](docs/binary_classification.md). Actual Phase 09 evaluation keeps labels separate from inference and reports missing correlation evidence explicitly.

## Architecture

The source package uses separate areas for ingestion, preprocessing, feature engineering, classification, anomaly detection, evaluation, intelligence, explainability, services, and persistence. The ingestion package discovers and inspects CSVs, compares schemas, loads compatible files with Pandas, streams chunks, and writes metadata and reports. Configuration and logging are shared infrastructure. The multi-class and anomaly engines remain separate; the Phase 09 intelligence layer consumes their outputs without changing their models or thresholds.

See [docs/architecture.md](docs/architecture.md) for the processing pipeline and component responsibilities. See [docs/data_ingestion.md](docs/data_ingestion.md) for acquisition and schema details, [docs/data_cleaning.md](docs/data_cleaning.md) for Phase 04 operations and outputs, and [docs/data_leakage_policy.md](docs/data_leakage_policy.md) for feature and metadata boundaries.

## Technology stack

Python 3.11 and 3.12 are the recommended development versions. The package metadata also allows Python 3.13. The default requirements install Pandas, NumPy, Matplotlib, PyArrow, Scikit-learn, Joblib, and Pytest for ingestion, EDA, Parquet cleaning, preprocessing, and the Phase 07/08 ML workflows. Later XGBoost, SHAP, API, database, dashboard, and network-analysis dependencies remain optional extras.

| Area | Planned technologies |
|---|---|
| Data processing and formats | Pandas and NumPy for ingestion; PyArrow / Parquet and optional Polars for later large-data workflows |
| Visualization | Matplotlib, Seaborn, Plotly |
| Machine learning | Scikit-learn, XGBoost, SHAP, imbalanced-learn |
| Network analysis | Scapy where packet parsing is needed; CICFlowMeter integration is a later task |
| API | FastAPI, Uvicorn, Pydantic |
| Database | PostgreSQL, SQLAlchemy, Psycopg |
| Dashboard | Streamlit |
| Testing and deployment | Pytest, Docker, Docker Compose |

## Repository structure

```text
.
├── configs/                         # Shared TOML defaults
├── data/
│   ├── raw/CIC-IDS2017/             # Expected source CSV location; data excluded
│   ├── interim/                     # Temporary transformed data; excluded
│   └── processed/                   # Analysis-ready data; excluded
├── docs/                            # Architecture and project documentation
├── models/                          # Generated model artifacts; excluded
├── notebooks/
│   ├── 01_dataset_exploration.ipynb # CIC-IDS2017 EDA workflow
│   ├── 02_data_cleaning.ipynb       # Cleaning and validation workflow
│   ├── 05_multiclass_classification.ipynb # Phase 07 classifier workflow
│   ├── 06_anomaly_detection.ipynb  # Phase 08 benign-baseline workflow
│   └── 07_threat_intelligence.ipynb # Phase 09 scoring and alert review
├── reports/
│   ├── figures/eda/                 # EDA figures
│   ├── figures/intelligence/        # Threat score, severity, and agreement figures
│   ├── eda/                         # EDA JSON and Markdown reports
│   ├── data_quality/                # Phase 04 quality and cleaning reports
│   ├── intelligence/                # Flow events, alerts, and run summaries
│   ├── evaluation/                  # Generated evaluation output; excluded
│   └── ingestion/                   # Generated ingestion reports; excluded
├── src/intrusion_intelligence/
│   ├── config.py                    # Typed TOML and environment configuration
│   ├── errors.py                    # Shared project exceptions
│   ├── logging_config.py            # Standard logging setup
│   ├── ingestion/                   # CSV discovery, inspection, loading, reports, CLI
│   ├── eda/                         # Chunked summaries, diagnostics, plots, CLI
│   ├── preprocessing/               # Quality assessment, policy, cleaning, reports, CLI
│   ├── feature_engineering/         # Versioned feature contract and preprocessing inputs
│   ├── binary/                      # Phase 06 capture-day-held-out workflow and inference
│   ├── multiclass/                  # Phase 07 supervised workflow and inference
│   ├── anomaly/                     # Phase 08 unsupervised workflow and inference
│   ├── intelligence/                # Phase 09 evidence, scoring, correlation, alerts
│   ├── evaluation/                  # Metrics and experiment evaluation
│   ├── explainability/              # Future model explanations
│   ├── services/                    # Future reusable application services
│   ├── database/                    # Future database integration
│   └── utils/                       # Shared utilities as needed
├── api/                             # FastAPI routes, schemas, services, and configuration
├── dashboard/                       # Streamlit app, nine page renderers, API client, and exports
├── tests/                           # Foundation smoke and config tests
├── alembic/                         # Versioned PostgreSQL schema migrations
├── .env.example                     # Placeholder environment variable names
├── .gitignore
├── pyproject.toml                   # Package metadata, extras, and pytest config
└── requirements.txt                 # Editable install with ingestion, EDA, and test extras
```

## Installation

Use Python 3.11 or 3.12 for the planned development environment. Python 3.13 is also supported. From the repository root, create and activate a virtual environment, then install the ingestion and test dependencies:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

If you have multiple Python versions installed, select Python 3.11 or 3.12 explicitly with the Windows launcher, for example `py -3.12 -m venv .venv`.

To install components in a later phase, request only the relevant extras. For example:

```powershell
python -m pip install -e ".[data,visualization]"
python -m pip install -e ".[ml]"
```

The optional extras are `data`, `eda` (Matplotlib), `parquet` (PyArrow), `preprocessing` (Scikit-learn and Joblib), `large-data` (Polars), `visualization`, `ml`, `api`, `database`, `dashboard`, `network`, and `dev`. The default requirements include `data`, `eda`, `parquet`, `preprocessing`, and `dev`; install `api,database` to run the backend. Installing dependencies does not start a database server.

## Backend API (Phase 12)

The FastAPI service exposes dataset validation, model registry, bounded model inference, paginated event retrieval, on-demand model-specific SHAP for dataset-backed event rows, alerts, in-process analysis-job progress, operational metrics, and traffic summaries under `/api/v1`. It uses the existing persisted models and pipeline and does not train models. PostgreSQL is the configured runtime database; local CSV contents and model artifacts remain in file storage. See [backend architecture](docs/backend_architecture.md), [API reference](docs/api_reference.md), and [database/migration guide](docs/database.md).

For a local Compose deployment, configure an ignored `.env` file from `.env.example`, then run:

```powershell
docker compose up --build
```

The service binds to loopback by default at `http://127.0.0.1:8000`; OpenAPI is at `/docs`. For local development without a containerized API, install `.[api,database]`, run `docker compose up -d db`, apply `alembic upgrade head`, then start `uvicorn api.main:app --env-file .env --host 127.0.0.1 --port 8000`. Analysis jobs run in process and are not a durable queue. The model/evaluation limitations in the Phase 06–11 documentation apply to API results.

The full test suite includes dashboard and SHAP behavior tests. After installing the project requirements, install their optional runtimes and run:

```powershell
python -m pip install -e ".[dashboard,explainability]"
python -m pytest -q
```

The saved model bundles use scikit-learn 1.8.0; the model-related extras pin that version to preserve artifact compatibility.

## Security Analytics Dashboard (Phase 13)

Install the dashboard dependencies and start the UI after the API is ready:

```powershell
python -m pip install -e ".[dashboard]"
$env:NII_DASHBOARD_API_URL = "http://127.0.0.1:8000/api/v1"
$env:NII_DASHBOARD_TIMEOUT = "10"
python -m streamlit run dashboard/app.py
```

The dashboard provides overview, traffic, attack, alerts, anomaly, model performance, event explainability, dataset management, and system health pages. Dataset upload and analysis jobs use the existing API contract; alert CSV/JSON downloads serialize rows returned by `/alerts`. Event explanation uses the source row stored in the registered dataset and persisted model, and reports unavailable cases explicitly. See [dashboard architecture](docs/dashboard_architecture.md) and the [user guide](docs/dashboard_user_guide.md) for setup and operation.

## Environment and configuration

`configs/project.toml` contains non-secret defaults. `load_config()` reads it and applies environment overrides for data/artifact paths, dataset name and directory, CSV extensions and encoding, label-header candidates, recursive discovery, loading strategy and chunk size, metadata/report destinations, random seed, logging level, database URL, application environment, and debug mode. Relative paths resolve from the repository root. The config module does not connect to PostgreSQL.

`.env.example` documents the supported variable names with placeholders. Copy values into your shell, IDE, or deployment environment as needed; `.env` files are ignored by Git and are not loaded automatically by the foundation.

```powershell
$env:NII_RANDOM_SEED = "42"
$env:NII_LOG_LEVEL = "INFO"
$env:NII_DATABASE_URL = "postgresql+psycopg://username:password@localhost:5432/network_intrusion"
```

Never commit secrets or replace the example database credentials with real credentials in tracked files.

## Dataset requirements

CIC-IDS2017 is a labelled flow benchmark published by the Canadian Institute for Cybersecurity at the University of New Brunswick. The official page lists `MachineLearningCSV.zip` for machine-learning CSVs, a separate labelled-flow archive, PCAP captures, and supporting profiles. This project targets the labelled CSVs; the pipeline supports CSV only and does not download data. The extracted CIC-IDS2017 CSVs are now present and validated. See the [official dataset page](https://www.unb.ca/cic/datasets/ids-2017.html), [dataset ingestion guide](docs/data_ingestion.md), and [real-data schema audit](reports/ingestion/CIC-IDS2017_schema_audit.md) for source, collection period, findings, caveats, and placement instructions.

The eight original extracted CSV files are under `data/raw/CIC-IDS2017/extracted/MachineLearningCVE/`; recursive discovery supports nested folders. The source files were not modified and are excluded from Git. Header validation found identical 79-column schemas across all files. The two ` Fwd Header Length` columns were retained under position-specific internal names after their values matched across all 2,830,743 rows. A complete label summary scanned 2,830,743 rows and counted 15 categories.

Inspect the configured dataset and create metadata/report outputs with:

```powershell
python -m intrusion_intelligence.ingestion inspect
```

Other supported commands include `validate`, `summary --label-counts`, `preview --file <filename>`, and `load --strategy chunked`. The requested `python -m intrusion_intelligence` command runs the full label summary. See `docs/data_ingestion.md` for exact command arguments, loading APIs, and output locations.

## Exploratory data analysis

Open [notebooks/01_dataset_exploration.ipynb](notebooks/01_dataset_exploration.ipynb) in a Jupyter-capable editor using the installed project environment. Section 3 runs the chunked scan; later sections display exact full-data aggregates and deterministic samples for correlations, feature distributions, and duplicate diagnostics. The same workflow is available without a notebook frontend:

```powershell
python -m intrusion_intelligence.eda --chunk-size 100000 --sample-size 20000 --seed 42
```

The command writes `reports/eda/CIC-IDS2017_eda.json`, `reports/eda/CIC-IDS2017_eda.md`, and PNG figures under `reports/figures/eda/`. See [docs/eda.md](docs/eda.md) for methodology, actual findings, sampling boundaries, and limitations. The workflow reads raw files only.

## Data-quality assessment and cleaning

Phase 04 performs a full chunked assessment, standardizes source headers, converts numeric features, canonicalizes missing values, replaces infinities with nulls, trims target whitespace, and quarantines missing or unexpected labels. Original labels, source files, source rows, and deterministic record IDs remain available as metadata. Negative finite values, outliers, exact duplicates, and conflicting feature vectors are preserved by the default policy. Raw files are checksummed before and after processing.

~~~powershell
python -m intrusion_intelligence.preprocessing policy validate
python -m intrusion_intelligence.preprocessing assess --chunk-size 25000 --sample-stride 100
python -m intrusion_intelligence.preprocessing clean --chunk-size 25000 --sample-stride 100
python -m intrusion_intelligence.preprocessing summary
~~~

The default outputs are under `data/processed/CIC-IDS2017-phase04-v2/cleaned/`; excluded rows are written to `data/interim/quarantine/`, and JSON/Markdown reports are under `reports/data_quality/`. The versioned policy is `configs/data_quality_policy.toml`. Existing outputs are never overwritten; use `--output-dir` to select a new run directory. See [docs/data_cleaning.md](docs/data_cleaning.md) and [docs/data_leakage_policy.md](docs/data_leakage_policy.md).

## Feature engineering and preprocessing

Phase 05 defines the predictive feature contract in `configs/feature_schema.json` and profile settings in `configs/preprocessing.toml`. The contract separates X, y, provenance, and identifiers; unknown columns and target/metadata contamination fail validation. Optional flow-derived counts and proportions are disabled by default. Numeric median imputation, categorical missing-value handling and one-hot encoding, and independent linear/tree/anomaly scaling profiles are fitted only on training X. `VarianceThreshold` feature selection is available but disabled by default.

Run the bounded real-data demonstration in [notebooks/03_feature_engineering.ipynb](notebooks/03_feature_engineering.ipynb). It reads up to 1,000 rows per Phase 04 Parquet file, creates an illustrative train/holdout partition for preprocessing checks, fits only on the illustrative training sample, and does not train a model or create the final project split. The notebook saves a versioned fitted preprocessor under `models/preprocessors/` if run; transformed matrices can be stored as sparse NPZ or dense NPY with aligned target/metadata Parquet. See [docs/feature_engineering.md](docs/feature_engineering.md) for contract, leakage safeguards, profile details, artifact layout, and limitations.

## Multi-class classification

Phase 07 preserves the observed attack labels and uses one stable versioned mapping for Logistic Regression and Random Forest. It attempts source-file group separation, checks class coverage, and records the stratified-row fallback when group-disjoint three-way coverage is infeasible. Preprocessing is fit on an 80,000-row stratified training-only sample, retaining all training rows for classes with 50 or fewer observations. Validation and selected-model test evaluation stream in batches.

Install the project requirements, then run the configured experiment from the repository root:

```powershell
python -m pip install -r requirements.txt
python -m intrusion_intelligence.multiclass --config configs/multiclass.toml
```

The notebook is [notebooks/05_multiclass_classification.ipynb](notebooks/05_multiclass_classification.ipynb). Trained bundles are stored under `models/supervised/multiclass/<model_name>/<version>/`; evaluation tables and reports are under `reports/evaluation/multiclass/<run_id>/`, figures under `reports/figures/multiclass/<run_id>/`, and experiment summaries under `reports/experiments/multiclass/<run_id>/`. Existing artifact versions are not overwritten; set a new version in `configs/multiclass.toml` before another saved run. Scikit-learn and Joblib are included by the preprocessing requirements. XGBoost was not installed or trained in the verified run.

On the actual cleaned dataset, the row-stratified experiment selected Random Forest by validation macro F1 (0.8349); its held-out row-split macro F1 was 0.8549. These are exploratory results: attack labels are concentrated in individual source files, every source group overlaps across the row partitions, and duplicate flows may cross partitions. See [docs/multiclass_classification.md](docs/multiclass_classification.md) for the complete class-level results and limitations.

## Unsupervised anomaly detection

Phase 08 implements a separate Isolation Forest baseline trained only on benign CIC-IDS2017 flows. It uses the Phase 05 feature contract and an independently fitted anomaly preprocessing profile. Whole capture days define the Monday–Wednesday training partition, Thursday benign-only threshold calibration, and Friday held-out evaluation. The notebook is [notebooks/06_anomaly_detection.ipynb](notebooks/06_anomaly_detection.ipynb); run the reusable pipeline from the repository root with:

```powershell
python -m intrusion_intelligence.anomaly --config configs/anomaly_detection.toml
```

The verified run achieved 15.57% attack recall and 4.91% test FPR at the operating point calibrated to 1% validation FPR. This is an offline benchmark result, not a probability of compromise or a guarantee of attack detection. Cross-day duplicate feature vectors and a high false-positive rate on the Friday DDoS capture are documented in [docs/anomaly_detection.md](docs/anomaly_detection.md). Versioned model and preprocessing artifacts are under `models/unsupervised/isolation_forest/` and `models/unsupervised/preprocessing/anomaly/`; reports and figures are stored by run ID. Scikit-learn and Joblib are already included in the preprocessing dependencies, so Phase 08 adds no dependencies.

## Threat intelligence and alert correlation

Phase 09 loads the persisted Phase 06 binary Random Forest, Phase 07 multi-class Random Forest, and Phase 08 Isolation Forest. It validates model and feature-schema compatibility, scores batches, preserves detector evidence, computes a configurable weighted prioritization score, assigns severity, creates traceable flow events, and applies metadata-aware correlation and alert rules. The score is a heuristic, not a probability of compromise. A separate offline evaluation pass uses held-out labels only after inference and alert generation. The cleaned CIC export still lacks timestamps and endpoints, so real-data correlation remains unavailable and is reported as such.

Run the bounded real-data sample from the repository root:

```powershell
python -m intrusion_intelligence.intelligence --config configs/intelligence.toml
```

The default run selects up to 500 evenly spaced rows per original label and Friday Parquet file, batches inference by 500, and uses the frozen anomaly model to score Thursday BENIGN validation rows for its ECDF reference. Friday labels are kept outside inference and are used only for deterministic evaluation sample construction and post-alert offline metrics. It does not train models or change thresholds. Results are written under `reports/intelligence/<run_id>/` with figures under `reports/figures/intelligence/<run_id>/`. The notebook is [notebooks/07_threat_intelligence.ipynb](notebooks/07_threat_intelligence.ipynb). The Phase 04 cleaned export lacks timestamps and endpoint identities, so its actual run can generate individual alerts but cannot form temporal correlation groups. See [docs/threat_intelligence.md](docs/threat_intelligence.md) and [docs/alert_correlation.md](docs/alert_correlation.md) for scoring semantics, alert criteria, and limitations.

## Tests

Run the project checks from the repository root:

```powershell
python -m pytest
```

The tests verify ingestion, EDA, preprocessing, binary target mapping and artifact metadata, multi-class classification, anomaly taxonomy/splitting/metrics/artifact/prediction behavior, and intelligence normalization/scoring/severity/events/correlation/alerts/idempotency/reporting using synthetic fixtures. Real CIC-IDS2017 results are recorded separately from synthetic test results.

## Roadmap

1. Project foundation and architecture (completed).
2. Dataset acquisition and data ingestion (completed with real CIC-IDS2017 validation).
3. Exploratory data analysis.
4. Data cleaning and leakage prevention.
5. Feature engineering and preprocessing (completed with synthetic tests and bounded real-data validation).
6. Supervised binary classification.
7. Supervised multi-class classification (implemented with exploratory row-stratified evaluation).
8. Unsupervised anomaly detection (completed with a capture-day holdout and documented duplicate overlap).
9. Threat intelligence and alert correlation (completed with measured held-out evaluation and CIC metadata limitations documented).
10. Explainable AI.
11. Model evaluation and validation (implemented; independent/external evidence unavailable).
12. Backend API development.
13. Security analytics dashboard.
14. Integration, testing, and deployment.

The detailed status and acceptance criteria are maintained in [roadmap.md](roadmap.md).

## Explainability

Phase 10 explains the five available persisted model bundles with the matching saved preprocessors: binary and multi-class Random Forests, binary and multi-class Logistic Regression, and Isolation Forest. Outputs are explicitly scoped to uncalibrated class scores, Logistic Regression margins/logits, or the higher-is-more-anomalous Isolation Forest score. Training-only backgrounds, transformed-to-original feature mapping, bounded global and local reports, validation diagnostics, and Phase 09 reference sidecars are documented in [docs/explainability.md](docs/explainability.md). Install the `explainability` extra with the existing model/runtime extras, then run `python -m intrusion_intelligence.explainability --config configs/explainability.toml`. Outputs are stored under `reports/explainability/<run_id>/` and `reports/figures/explainability/<run_id>/`. The guided notebook is [notebooks/08_explainability.ipynb](notebooks/08_explainability.ipynb).

## Model evaluation and validation

Phase 11 provides reusable score, threshold, leakage, calibration, uncertainty, ablation, robustness, explanation-audit, and warm inference utilities. Generate a dated report bundle with `python -m intrusion_intelligence.evaluation --config configs/evaluation.toml` or the installed `intrusion-evaluate` command. Structured scorecards and the consolidated report are written to `reports/evaluation/comprehensive/<run_id>/`; charts are written to `reports/figures/evaluation/<run_id>/`, and benchmarks to `reports/benchmarks/<run_id>/`. The notebook is [notebooks/09_model_evaluation.ipynb](notebooks/09_model_evaluation.ipynb), and the methodology is in [docs/model_evaluation.md](docs/model_evaluation.md).

All previous validation/test partitions have been inspected in earlier phases. The Phase 11 bundle labels them as reused evidence and does not claim a fresh independent test. Binary Logistic scores support reanalysis and descriptive calibration; Random Forest, multi-class, and anomaly metrics are carried forward from their saved reports where prediction rows are unavailable. Capture/day, duplicate-flow, temporal metadata, and external dataset limitations are recorded in each run's `evaluation_status.json`.

## Limitations

- Original CIC-IDS2017 source CSVs remain unchanged. Phase 04 v2 canonicalizes missing tokens and infinities to nulls in the processed copy and reported no invalid numeric conversions. Finite negatives, outliers, exact duplicates, and conflicting feature vectors remain for investigation.
- EDA has been run on the extracted CSVs; sample-based diagnostics are distinguished from exact full-scan aggregates in its report.
- Phase 06 compares capture-day-held-out binary Random Forest and Logistic Regression. Logistic Regression has higher Friday recall and ranking metrics but a higher false-positive rate; no model was promoted. Phase 07 includes Logistic Regression and Random Forest; Phase 08 has an independent Isolation Forest baseline. Phase 09 scoring and alerting are research workflows, not confirmed-incident capabilities. The Phase 12 API and Phase 13 dashboard expose persisted results, and Phase 14 adds event retrieval and dataset-backed SHAP. The system does not provide live packet capture, authentication, or response blocking.
- Multi-class metrics are from an explicitly disclosed stratified-row fallback because source-file group splits cannot cover all 15 labels. Group and duplicate overlap make these results unsuitable as evidence of cross-capture generalization.
- Logistic Regression reached its iteration limit. XGBoost was unavailable. Heartbleed, Infiltration, and SQL Injection have only 11, 36, and 21 total records, respectively, so their test metrics are unstable.
- CIC-IDS2017 is a benchmark dataset; future evaluation must document its collection context and limits.
- Future experiments must investigate duplicate and related flows, class imbalance, label leakage, temporal and group-aware splits, and generalization to unknown attacks.
- Research outputs are offline analyses and do not establish real-world blocking capability or production readiness.
