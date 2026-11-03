# CIC-IDS2017 data cleaning

## Scope and output contract

Phase 04 creates a reproducible analytical copy of the locally available CIC-IDS2017 `MachineLearningCVE` CSVs. It never edits raw files. The current implementation normalizes headers, parses numeric fields, represents missing and non-finite numbers consistently, normalizes target whitespace, quarantines missing/unexpected labels, and adds provenance. It preserves finite negative values, extreme values, features, and exact duplicate records by default because the source alone does not justify changing them.

The implementation lives in `src/intrusion_intelligence/preprocessing/`. It reuses Phase 02 discovery, schema validation, source checksums, and CSV reading, and uses the Phase 04 assessment module for full-scan quality reports and duplicate fingerprints.

## Reproduce the workflow

Install the normal project dependencies, including the existing `parquet` extra for PyArrow:

```powershell
python -m pip install -r requirements.txt
python -m intrusion_intelligence.preprocessing policy validate
python -m intrusion_intelligence.preprocessing assess --chunk-size 25000 --sample-stride 100
python -m intrusion_intelligence.preprocessing clean --chunk-size 25000 --sample-stride 100
python -m intrusion_intelligence.preprocessing summary
```

The cleaner refuses to overwrite an existing versioned output. Use `--output-dir` to choose a new run directory. The policy file is copied into the output metadata, so the applied rules remain reviewable. Parquet is the explicit output format; the command does not silently fall back to CSV.

## Schema and data types

Each input file is inspected and the source files must pass the existing Phase 02 schema checks before processing. Files with the same unique columns in a different order are aligned to the first file's standardized order. Missing or additional columns, incompatible schemas, and unresolved duplicate-header order differences are rejected rather than unioned. Source column names are mapped deterministically to lower-case snake case. If multiple source headers normalize to the same name, all colliding columns receive a stable suffix containing their one-based source position. `metadata/manifest.json` keeps the exact source header, position, normalized base, and cleaned name. The available CIC-IDS2017 files have identical header order, so the shared mapping applies to all eight; the cleaner records a separate mapping for each file when an accepted order-only difference occurs.

The CIC-IDS2017 export has a numeric target-free feature matrix plus the `Label` target. The policy explicitly lists categorical, datetime, and identifier roles; remaining source features are parsed numerically with coercion failures counted and example tokens recorded. Invalid numeric strings become nulls in the analytical copy only after the original token is captured in the report. No encoding, scaling, or feature selection is performed.

## Missing and infinite values

Blank fields and common null tokens (`NA`, `N/A`, `NULL`, `None`, and `NaN`, ignoring case and surrounding whitespace) become Parquet nulls. No imputation or predictive-feature row removal occurs. Positive and negative infinity in numeric features are replaced with nulls and counted by source column. Numeric conversion failures are separately counted from missing tokens. Finite negative values and extreme finite values remain unchanged and are reported for later investigation.

Missing, blank, or unexpected target labels are excluded from the supervised-ready Parquet files and written to a separate quarantine Parquet file with their source values, source file, row number, deterministic record ID, and rejection reason. The original label for each retained record is copied to `__source_label`; the normalized target is in `label`. A machine-readable label validation report records the expected categories, raw-to-normalized mapping, and row counts.

## Duplicates

The assessment uses two independently keyed 64-bit row fingerprints combined as a 128-bit key and externally aggregated in temporary SQLite storage. It distinguishes exact complete-row duplicates, repeated feature vectors, conflicting labels, within-file groups, and cross-file groups. Fingerprint collisions are negligibly likely but nonzero, so the report identifies them as fingerprint matches.

The default policy preserves exact duplicates and all repeated feature vectors. `duplicates.action` can be changed to `drop_exact_duplicates`; that option keeps the first identical complete record in deterministic source order and sends later records to quarantine with `exact_duplicate`. Feature-vector duplicates with different labels are never removed by that rule and remain available for investigation.

## Predictive features, target, and metadata

The generated `metadata/feature_policy.json` explicitly lists candidate numeric/categorical features, target, excluded identifiers, and metadata. `label` is the target. `__source_label`, `__source_file`, `__source_row_number`, and `__record_id` are metadata and must not be passed to a model. Direct flow/IP identifiers and timestamps are excluded if they appear in a future compatible schema. Destination port and protocol remain candidate predictors when present; assess them with later feature-ablation and group-aware evaluation.

See [data_leakage_policy.md](data_leakage_policy.md) for the project-wide field policy, risks, and evaluation recommendations. The policy establishes controls; it does not prove that leakage has been eliminated.

## Provenance and artifacts

The deterministic 96-bit BLAKE2b record ID derives from the source-relative path, source file SHA-256, and one-based source row number. It does not use the target label. The manifest stores input/output checksums, file and row counts, processing timestamp and ID, software versions, policy version, schema mapping, and report links. A transformation history records the policies and operations applied.

The repository's current versioned run uses these locations:

```text
data/processed/CIC-IDS2017-phase04-v2/
  cleaned/<source-relative-path>.parquet
  metadata/manifest.json
  metadata/transformation_history.json
  metadata/feature_policy.json
  metadata/label_validation.json
  metadata/data_quality_policy.toml
data/interim/quarantine/CIC-IDS2017-phase04-v2/rejected.parquet
reports/data_quality/CIC-IDS2017_quality_report_v2_before.{json,md}
reports/data_quality/CIC-IDS2017_quality_report_v2_after.{json,md}
reports/data_quality/CIC-IDS2017_cleaning_report_v2.{json,md}
```

Parquet is used because PyArrow is present and the source is large. PyArrow is already declared in the project's `parquet` optional extra and included in `requirements.txt` for this cleaning workflow. Output validation reopens each Parquet file, checks the schema and row/label counts, checks that numeric infinities are absent, validates quarantine accounting, and recalculates raw SHA-256 checksums.

## Full-data findings and current handling

The source scan covers eight files and 2,830,743 rows. It found 1,358 `NaN` tokens in `Flow Bytes/s`, 4,376 positive infinities in flow-rate features (each paired with zero `Flow Duration`), 2,446,321 negative numeric cells across 13 source positions, and eight features constant across the full extract. Full-extract fingerprint matching found 308,381 excess exact-row matches and 698 repeated-feature groups with differing labels.

The cleaner converts those rate infinities to nulls but preserves the original text in immutable raw inputs. It preserves finite negatives, constants, duplicates, and conflicting-label feature vectors. In the available extract, labels are complete and recognized, so the quarantined output has a header and zero rows; all 2,830,743 records remain in the cleaned Parquet files. The generated reports are the authoritative run-specific results.

## Notebook and limitations

Open `notebooks/02_data_cleaning.ipynb` in a notebook-capable editor after installing the project environment. It orchestrates the reusable assessment and cleaning APIs; it does not duplicate the implementation. Choose a new output directory before re-running a completed pipeline.

The output is a clean analytical representation, not a final model matrix. Negative values and extreme values are not clipped; repeated flows and conflicting feature-vector labels are not adjudicated; timestamps, endpoint IPs, Flow ID, protocol, and source port are absent from this export. Group-aware and temporal experiment design remains future work, and this phase does not create a train/validation/test split.
