# Network Intrusion Detection & Anomaly Intelligence

An offline research and analytics platform for examining network flow data, including the CIC-IDS2017 benchmark. The planned system will combine supervised classification of known traffic categories with a separate unsupervised engine for unusual flows, then provide explainable analysis and security analytics views.

This project is not an intrusion prevention system. It does not capture traffic continuously or block network activity.

## Problem statement

Network flow datasets can contain known attacks, benign activity, duplicate records, severe class imbalance, and features that leak labels or collection details. This project is intended to provide a reproducible workflow for studying those conditions and evaluating detection approaches without presenting research results as live protective controls.

## Objectives

- Establish reproducible data ingestion, cleaning, and feature preparation.
- Evaluate supervised models for known attack categories.
- Study anomaly detection independently from labelled attack classification.
- Combine validated detection signals through a documented threat intelligence layer.
- Explain model decisions and expose real analysis results through an API and dashboard in later phases.
- Document dataset, evaluation, and model limitations.

## Planned capabilities

The project foundation, Phase 02 CSV ingestion pipeline, Phase 03 EDA workflow, Phase 04 cleaning workflow, and Phase 05 feature-contract/preprocessing infrastructure are implemented. Later capabilities include binary and multi-class classification, benign-baseline anomaly detection, threat scoring and alert correlation, model explanations, a FastAPI service, PostgreSQL-backed metadata, and a Streamlit dashboard.

## Architecture

The source package uses separate areas for ingestion, preprocessing, feature engineering, classification, anomaly detection, evaluation, intelligence, explainability, services, and persistence. The ingestion package discovers and inspects CSVs, compares schemas, loads compatible files with Pandas, streams chunks, and writes metadata and reports. Configuration and logging are shared infrastructure. The two detection engines remain separate; the intelligence layer may combine their outputs later.

See [docs/architecture.md](docs/architecture.md) for the processing pipeline and component responsibilities. See [docs/data_ingestion.md](docs/data_ingestion.md) for acquisition and schema details, [docs/data_cleaning.md](docs/data_cleaning.md) for Phase 04 operations and outputs, and [docs/data_leakage_policy.md](docs/data_leakage_policy.md) for feature and metadata boundaries.

## Technology stack

Python 3.11 and 3.12 are the recommended development versions. The package metadata also allows Python 3.13. The default requirements install Pandas, NumPy, Matplotlib, PyArrow, Scikit-learn, Joblib, and Pytest for ingestion, EDA, Parquet cleaning, and Phase 05 preprocessing. Later XGBoost, SHAP, API, database, dashboard, and network-analysis dependencies remain optional extras.

| Area | Planned technologies |
|---|---|
| Data processing and formats | Pandas and NumPy for ingestion; PyArrow / Parquet and optional Polars for later large-data workflows |
| Visualization | Matplotlib, Seaborn, Plotly |
| Machine learning | Scikit-learn, XGBoost, SHAP, imbalanced-learn |
| Network analysis | Scapy where packet parsing is needed; CICFlowMeter integration is a later task |
| API | FastAPI, Uvicorn, Pydantic |
| Database | PostgreSQL, SQLAlchemy, Psycopg |
| Dashboard | Streamlit |
| Testing and deployment | Pytest; Docker configuration is deferred until an application runtime exists |

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
│   └── 02_data_cleaning.ipynb       # Cleaning and validation workflow
├── reports/
│   ├── figures/eda/                 # EDA figures
│   ├── eda/                         # EDA JSON and Markdown reports
│   ├── data_quality/                # Phase 04 quality and cleaning reports
│   ├── evaluation/                  # Generated evaluation output; excluded
│   └── ingestion/                   # Generated ingestion reports; excluded
├── src/intrusion_intelligence/
│   ├── config.py                    # Typed TOML and environment configuration
│   ├── errors.py                    # Shared project exceptions
│   ├── logging_config.py            # Standard logging setup
│   ├── ingestion/                   # CSV discovery, inspection, loading, reports, CLI
│   ├── eda/                         # Chunked summaries, diagnostics, plots, CLI
│   ├── preprocessing/               # Quality assessment, policy, cleaning, reports, CLI
│   ├── feature_engineering/         # Future feature definitions
│   ├── models/
│   │   ├── classification/          # Supervised engine
│   │   └── anomaly_detection/       # Unsupervised engine
│   ├── evaluation/                  # Future evaluation methods
│   ├── intelligence/                # Future scoring and alert correlation
│   ├── explainability/              # Future model explanations
│   ├── services/                    # Future reusable application services
│   ├── database/                    # Future database integration
│   └── utils/                       # Shared utilities as needed
├── api/                             # Reserved for the later API phase
├── dashboard/pages/                 # Reserved for the later dashboard phase
├── tests/                           # Foundation smoke and config tests
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

The optional extras are `data`, `eda` (Matplotlib), `parquet` (PyArrow), `preprocessing` (Scikit-learn and Joblib), `large-data` (Polars), `visualization`, `ml`, `api`, `database`, `dashboard`, `network`, and `dev`. The default requirements include `data`, `eda`, `parquet`, `preprocessing`, and `dev` because Phase 04 writes Parquet and Phase 05 uses Scikit-learn/Joblib. No database server or connection is started by installing these dependencies.

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

## Tests

Run the project checks from the repository root:

```powershell
python -m pytest
```

The tests verify ingestion, EDA, and preprocessing behavior using clearly identified synthetic fixtures. Separate full scans were executed against all eight local CIC-IDS2017 CSV files; test fixtures are not presented as dataset findings.

## Roadmap

1. Project foundation and architecture (completed).
2. Dataset acquisition and data ingestion (completed with real CIC-IDS2017 validation).
3. Exploratory data analysis.
4. Data cleaning and leakage prevention.
5. Feature engineering and preprocessing (completed with synthetic tests and bounded real-data validation).
6. Supervised binary classification.
7. Supervised multi-class classification.
8. Unsupervised anomaly detection.
9. Threat intelligence and alert correlation.
10. Explainable AI.
11. Model evaluation and validation.
12. Backend API development.
13. Security analytics dashboard.
14. Integration, testing, and deployment.

The detailed status and acceptance criteria are maintained in [roadmap.md](roadmap.md).

## Limitations

- Original CIC-IDS2017 source CSVs remain unchanged. Phase 04 v2 canonicalizes missing tokens and infinities to nulls in the processed copy and reported no invalid numeric conversions. Finite negatives, outliers, exact duplicates, and conflicting feature vectors remain for investigation.
- EDA has been run on the extracted CSVs; sample-based diagnostics are distinguished from exact full-scan aggregates in its report.
- No model, model metric, alert, threat score, API endpoint, dashboard, or database connection is implemented. Phase 05 validation used an 8,000-row sample and is not an evaluation experiment.
- CIC-IDS2017 is a benchmark dataset; future evaluation must document its collection context and limits.
- Future experiments must investigate duplicate and related flows, class imbalance, label leakage, temporal and group-aware splits, and generalization to unknown attacks.
- Research outputs are offline analyses and do not establish real-world blocking capability or production readiness.
