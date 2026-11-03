# CIC-IDS2017 acquisition and ingestion

## Dataset source and purpose

CIC-IDS2017 is a labelled network-flow benchmark published by the Canadian Institute for Cybersecurity at the University of New Brunswick. Its purpose is to support research and evaluation of intrusion-detection methods using benign and attack traffic captured in a controlled network environment.

Use the [official CIC-IDS2017 page](https://www.unb.ca/cic/datasets/ids-2017.html) as the source of record. Do not use third-party mirrors for this project. No direct download URL is embedded in the code, and the ingestion CLI never downloads files.

The official page describes these relevant formats:

- Labelled CICFlowMeter flow CSVs distributed through GeneratedLabelledFlows.zip and MachineLearningCSV.zip. These contain flow-level feature columns and labels and are the initial ingestion target.
- PCAP packet captures and supporting profiles. The current loader does not parse PCAP files; they are ignored during CSV discovery.

### Official download route and selected archive

The official UNB page identifies `MachineLearningCSV.zip` as the CSV archive for machine-learning use and `GeneratedLabelledFlows.zip` as a separate labelled-flow archive. For this project's initial ingestion, use only `MachineLearningCSV.zip`; do not also download the second archive or the PCAP files.

The official "Download this dataset" link routes through [CIC's dataset request form](https://cicresearch.ca/CICDataset/CIC-IDS-2017/). During the initial Codex acquisition attempt on 2026-11-03, the form requested first name, last name, email, organization/company, job title, and country, and displayed "Server error. Please try again later." No form was submitted and no files were downloaded in that attempt. The extracted CSVs were later placed in the project by the user. For future acquisition, download only `MachineLearningCSV.zip` and place the untouched archive and extracted CSVs under `data/raw/CIC-IDS2017/`.

The official page does not publish a separate byte size or checksum for `MachineLearningCSV.zip`. Its daily size table lists 11.0, 11, 13, 7.8, and 8.3 GB (about 51.1 GB total), but does not identify that sum as the size of this specific archive. The workspace volume had 60,386,021,376 bytes free when checked on 2026-11-03; recheck space before downloading and extracting because the archive and extracted files may both need room. If CIC publishes a checksum with the download, compare it before extraction. Otherwise, `python -m zipfile -t "data/raw/CIC-IDS2017/MachineLearningCSV.zip"` checks ZIP readability, while the ingestion SHA-256 values fingerprint the files locally; without an official checksum they do not independently prove publisher authenticity. Do not substitute a third-party or modified copy if the official form is unavailable.

After placing the downloaded archive at the path above, these PowerShell commands test it and extract it without changing the ZIP:

~~~powershell
python -m zipfile -t "data/raw/CIC-IDS2017/MachineLearningCSV.zip"
Expand-Archive -LiteralPath "data/raw/CIC-IDS2017/MachineLearningCSV.zip" -DestinationPath "data/raw/CIC-IDS2017/extracted"
~~~

The flow CSV rows represent features extracted from traffic and labels associated with timestamps, endpoints, ports, protocols, and attack activity. The current phase preserves all source columns and label values. It does not remove identifiers, clean values, change labels, or concatenate incompatible schemas.

The official collection ran from 9 a.m. Monday, July 3, 2017 through 5 p.m. Friday, July 7, 2017. Monday is described as benign activity; attack activity was run Tuesday through Friday. The official page describes profiles for 25 users and more than 80 extracted flow features.

Treat CIC-IDS2017 as a controlled, five-day benchmark rather than a representative sample of current operational networks. The 2021 Engelen, Rimmer, and Joosen case study reports issues in traffic generation, flow construction, feature extraction, and labelling, and describes a corrected methodology that reconstructed or relabelled more than 20% of original traffic traces. These findings are a reason to document data provenance and defer cleaning decisions to a later phase; this ingestion code does not modify the source files. See the [IEEE paper record](https://ieeexplore.ieee.org/abstract/document/9474286/authors).

## Placement and data safety

Download the labelled flow CSV archive manually from the official dataset page and extract it under:

~~~text
data/
└── raw/
    └── CIC-IDS2017/
        ├── MachineLearningCSV.zip
        └── extracted/
            ├── Monday-WorkingHours.pcap_ISCX.csv
            ├── ...
            └── another-labelled-file.csv
~~~

The directory name and file names are conventions, not exact matching requirements. Recursive discovery searches for configured CSV extensions below the configured dataset directory. The default is data/raw/CIC-IDS2017/ and .csv. Unrelated files, including PCAPs and archives, are ignored.

Raw files are read only and excluded from Git. Do not commit downloaded data. Keep only original dataset material in this directory: the downloaded source archive and its unmodified extracted CSV files. The pipeline keeps generated metadata under data/interim/metadata/ and human-readable reports under reports/ingestion/. Both output areas are ignored by Git.

The official extracted CIC-IDS2017 MachineLearningCSV files are present under `data/raw/CIC-IDS2017/extracted/MachineLearningCVE/`. Real-data findings are recorded in the [schema audit](../reports/ingestion/CIC-IDS2017_schema_audit.md) and generated [ingestion report](../reports/ingestion/CIC-IDS2017_ingestion.md). The original CSV files remain unchanged.

Phase 04 uses the same recursive discovery and position-aware header inspection, then scans values sequentially in chunks. It writes preserved-value outputs only under `data/processed/CIC-IDS2017/`; generated quality reports are stored separately under `reports/data_quality/`. See [docs/preprocessing.md](preprocessing.md) for the versioned cleaning policy and verification steps. Ingestion itself continues to preserve raw values and does not apply the Phase 04 policy.

## Discovery and inspection

Discovery sorts matching file paths deterministically and can search recursively or only at the top level. Missing directories and directories without supported files produce clear errors. The CLI inspection command reports these conditions as unavailable results.

Inspection reads each CSV header using Python's CSV parser and retains original names. It records the relative path, byte size, extension, detected encoding, SHA-256, original and whitespace-normalized columns, duplicate names, label candidates, a source-header-sensitive schema fingerprint, warnings, and errors. SHA-256 is calculated in 1 MiB blocks. Header inspection is bounded to the first CSV record; it does not count rows.

Encoding detection checks common Unicode byte-order marks, then tries UTF-8 on a bounded sample. If that fails, CP1252 and Latin-1 are tried as fallbacks and a warning is recorded. This is a heuristic; set the configured encoding explicitly when the source encoding is known.

Leading and trailing header whitespace is reported but original headers are not changed. Every inspected column also receives an internal name. Non-colliding columns retain their exact source spelling. Exact duplicate names and distinct names that collide after surrounding whitespace is stripped receive position-specific aliases of the form `Normalized Name [source column N]`; JSON metadata records the original name, normalized comparison name, internal name, and 1-based source position. All source columns remain available; aliases do not remove values or assert semantic equivalence.

The label header defaults to `Label` and is matched case-insensitively using a trimmed comparison string. The original label header and label values remain unchanged. A missing label or multiple label candidates remains a validation error, even though candidate columns receive unique internal identifiers.

The minimum structural requirement is at least one feature column and one unambiguous label column. No fixed set of feature names is enforced because available CIC-IDS2017 CSV archives can differ.

## Schema compatibility

The first valid file in deterministic path order is the reference schema.

- Exact header names in the same order are matching, including repeated names at the same positions.
- Schemas with unique, unambiguous source names may differ in order; loading aligns them by exact source name.
- When a schema contains duplicate or whitespace-colliding names, all files must have the same exact source header sequence. Reordered collisions are incompatible because their positional identity cannot be inferred safely.
- Missing or additional raw header occurrences are incompatible; duplicate multiplicity is counted.
- Distinct headers that normalize to the same name across files are reported as conflicts and are incompatible for concatenation.
- Missing/ambiguous label headers and unreadable files remain invalid.

Schema validation reports per-file missing and additional columns, order differences, and normalized name conflicts. Multi-file loading stops if any selected file is invalid or incompatible. The pipeline does not silently create a union schema. Internal aliases preserve duplicate columns through Pandas loading; they do not assert that duplicate fields are equivalent.

## Loading strategies

Pandas is used for loading. The default installation in requirements.txt includes the data and dev extras, which provide NumPy, Pandas, and Pytest. PyArrow is separated into the parquet extra because CSV ingestion does not require it.

Standard loading reads an individual file or all selected compatible files into memory and returns a DataFrame with exact row and file counts. This is appropriate only when the selected files fit available memory.

The configured loading strategy defaults to standard in-memory loading. Set `ingestion.loading_strategy` in `configs/project.toml` or `NII_LOADING_STRATEGY` to `chunked` to make chunked loading the default. Chunked loading yields DataFrame batches sequentially, one file at a time. Its default chunk size is 100,000 rows and can be overridden in configuration or on the CLI. The loader records source names in inspection metadata and uses internal aliases only where needed to make colliding columns addressable. It keeps labels as strings, disables Pandas default NA-token conversion, raises on malformed CSV rows, and does not drop rows or columns. The real CIC-IDS2017 scan emitted a Pandas `DtypeWarning` for mixed types in `Flow Bytes/s`; ingestion leaves those values untouched for later investigation.

The Python interface is:

~~~python
from intrusion_intelligence.config import load_config
from intrusion_intelligence.ingestion import iter_dataset_chunks, load_dataset

config = load_config()
loaded = load_dataset(
    config.dataset.directory,
    supported_extensions=config.dataset.supported_extensions,
    label_candidates=config.dataset.label_candidates,
    encoding=config.ingestion.csv_encoding,
)

for chunk in iter_dataset_chunks(
    config.dataset.directory,
    chunk_size=config.ingestion.chunk_size,
):
    # Pass each DataFrame to a later pipeline component.
    print(f"Read {len(chunk.data)} rows from {chunk.source_file}")
~~~

The snippet illustrates the interface only; it does not produce detection results.

## Label summaries and scan coverage

Label-category counts are optional. They use the chunked loader and preserve observed label strings. Without a row scan, metadata records coverage as metadata_only and leaves row counts and label counts unset. A completed scan records exact rows scanned. A scan with a max-row bound is marked partial once that bound is reached, even if it may coincide with the dataset's last row.

No row total is estimated. A partial count is never presented as a complete dataset distribution.

## Metadata and reports

The JSON metadata file records dataset name and source, inspection time, dataset-relative directory, discovered file metadata, checksums, schemas, validation state, warnings, and actual scan/loading results where performed. It contains no flow records and avoids embedding absolute file paths.

The Markdown report summarizes file discovery, sizes, headers, label-column matches, checksums, schema relationships, warnings, errors, and actual row-scan or loading status. Metadata-only inspection explicitly states that rows were not scanned. Label counts appear only after a label scan.

Default output names:

- data/interim/metadata/CIC-IDS2017_ingestion.json
- reports/ingestion/CIC-IDS2017_ingestion.md

Both destinations can be changed through configs/project.toml or the environment variables NII_DATASET_METADATA_DIR and NII_INGESTION_REPORT_DIR.

## Commands

Create and activate the project environment, then install the declared ingestion and test dependencies:

~~~powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
~~~

Run commands from the repository root:

~~~powershell
$env:PYTHONPATH = "src" # when the package is not installed in the active Python environment
python -m intrusion_intelligence.ingestion inspect
python -m intrusion_intelligence.ingestion validate
python -m intrusion_intelligence.ingestion summary
python -m intrusion_intelligence.ingestion summary --label-counts
python -m intrusion_intelligence.ingestion summary --label-counts --chunk-size 50000 --max-rows 100000
python -m intrusion_intelligence.ingestion preview --file Monday-WorkingHours.pcap_ISCX.csv --rows 10
python -m intrusion_intelligence.ingestion load --file Monday-WorkingHours.pcap_ISCX.csv
python -m intrusion_intelligence.ingestion load --chunk-size 50000
python -m intrusion_intelligence.ingestion load --strategy chunked
~~~

The bare `python -m intrusion_intelligence` command is a convenience alias for `python -m intrusion_intelligence.ingestion summary --label-counts`.

Inspection and validation write fresh JSON and Markdown results based on the files actually found. Preview requires one discovered file. Load follows the configured strategy; `--strategy` overrides it, and supplying `--chunk-size` selects chunked mode. The chunked CLI command consumes every selected file and reports exact rows processed.

The same commands are available through the installed intrusion-ingest executable. The Python API can also be used directly by notebooks and future services.

## Configuration

The main settings are in configs/project.toml. Environment variables override paths and ingestion options:

| Setting | Default | Environment override |
|---|---|---|
| Raw data root | data/raw | NII_RAW_DATA_DIR |
| Dataset directory below raw root | CIC-IDS2017 | NII_DATASET_DIRECTORY |
| Dataset display name | CIC-IDS2017 | NII_DATASET_NAME |
| CSV extensions | .csv | NII_SUPPORTED_FILE_EXTENSIONS |
| Label header candidates | Label | NII_LABEL_CANDIDATES |
| Recursive discovery | true | NII_RECURSIVE_DISCOVERY |
| CSV encoding | auto | NII_CSV_ENCODING |
| Loading strategy | standard | NII_LOADING_STRATEGY |
| Chunk size | 100000 | NII_CHUNK_SIZE |
| Metadata directory | data/interim/metadata | NII_DATASET_METADATA_DIR |
| Report directory | reports/ingestion | NII_INGESTION_REPORT_DIR |

List-valued environment settings are comma-separated. Dataset source defaults to the official page and may be changed in TOML if the project adopts another authoritative source.

## Tests and phase boundary

Run python -m pytest from the project root. The ingestion tests create temporary synthetic files and do not depend on CIC-IDS2017. They cover discovery, header and checksum inspection, encoding, schema comparison, standard and chunked loading, label-summary coverage, metadata, reports, and CLI commands.

Real CIC-IDS2017 ingestion validation is complete for the eight extracted MachineLearningCSV files. Findings and the full positional header map are recorded in `reports/ingestion/CIC-IDS2017_schema_audit.md`. This phase does not perform exploratory data analysis, feature cleaning, feature engineering, model training, anomaly detection, threat scoring, API work, or dashboard work.
