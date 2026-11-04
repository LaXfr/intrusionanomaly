# Fixes & Issue Tracking — Network Intrusion Detection & Anomaly Intelligence

## 1. Purpose

This document tracks confirmed bugs, implementation errors, data-processing issues, integration problems, and their resolutions.

It provides a structured record of technical problems encountered during development.

The objective is to prevent recurring mistakes and maintain a reliable project.

## 2. Issue Tracking Rules

1. Record actual issues encountered during implementation or testing.
2. Do not record hypothetical problems as confirmed bugs.
3. Distinguish between bugs, limitations, and future improvements.
4. Describe the conditions under which the issue occurred.
5. Record the root cause when it has been established.
6. Document the actual fix.
7. Include verification evidence.
8. Do not mark an issue resolved until the fix has been tested.
9. Keep unresolved issues visible.
10. Reference affected files and relevant development phases.

## 3. Issue Status

| Status | Meaning |
|---|---|
| Open | Confirmed issue that has not been resolved |
| In Progress | Investigation or implementation of a fix is underway |
| Resolved | Fix has been implemented and verified |
| Deferred | Issue is known but intentionally postponed |
| Cannot Reproduce | Previously reported issue could not be reproduced under documented conditions |

## 4. Severity Levels

| Severity | Meaning |
|---|---|
| Critical | Prevents the core application from functioning or creates a serious integrity/security risk |
| High | Breaks important functionality or produces materially incorrect results |
| Medium | Affects a feature but has a reasonable workaround |
| Low | Minor bug, usability problem, or non-critical inconsistency |

## 5. Issue Entry Format

Use this format for each confirmed issue.

---

### ISSUE-[NUMBER] — [SHORT ISSUE TITLE]

**Date Reported:** YYYY-MM-DD
**Development Phase:** Phase XX — [Phase Name]
**Severity:** Critical / High / Medium / Low
**Status:** Open / In Progress / Resolved / Deferred / Cannot Reproduce

#### Description

Explain the problem clearly.

#### Expected Behavior

Describe what should have happened.

#### Actual Behavior

Describe what actually happened.

#### Steps to Reproduce

1. Step 1.
2. Step 2.
3. Step 3.

#### Error Message or Evidence

Include the relevant error message, stack trace, failing test, or observed behavior.

Do not include passwords, credentials, tokens, or other secrets.

#### Root Cause

Document the confirmed cause.

Write `Under Investigation` when the cause has not yet been established.

#### Resolution

Explain the actual implementation or configuration change used to resolve the issue.

Write `Pending` when the issue remains unresolved.

#### Files Affected

- `path/to/file.py`

#### Verification

Describe the test or procedure used to verify the fix.

#### Related Changes

Reference relevant Git commits or worklog sessions where available.

---

## 6. Current Issue Register

No open project issues are recorded. ISSUE-001 through ISSUE-013 are resolved and documented below.

Phase 04's full CIC-IDS2017 scan identified source-data anomalies and duplicate/conflicting-label groups. They are evidence-backed data-quality findings, not software defects. Missing tokens and infinities are handled as documented; finite negatives, extremes, duplicates, and conflicting-label groups remain preserved for review. Current counts and limitations are recorded in the v2 quality reports and `docs/data_cleaning.md`.

---

### ISSUE-001 — Pandas deprecated concat copy argument

**Date Reported:** 2026-11-03
**Development Phase:** Phase 02 — Dataset Acquisition & Data Ingestion
**Severity:** Low
**Status:** Resolved

#### Description

The first ingestion test run emitted a Pandas deprecation warning when concatenating compatible CSV DataFrames.

#### Expected Behavior

Compatible files should concatenate without warnings on the supported Pandas version used for validation.

#### Actual Behavior

Pandas 3.0.1 reported that the `copy` keyword to `pandas.concat` is deprecated and will be removed in a future version.

#### Steps to Reproduce

1. Use Pandas 3.0.1.
2. Load multiple synthetic CSV files with identical columns in different orders.
3. Run `python -m pytest`.

#### Error Message or Evidence

Pytest reported `Pandas4Warning` from `loader.py` for the `copy` keyword during `pandas.concat`.

#### Root Cause

The loader passed `copy=False`, an argument deprecated by the installed Pandas version.

#### Resolution

Removed the `copy` argument. Concatenation still uses the required single operation for joining multiple frames.

#### Files Affected

- `src/intrusion_intelligence/ingestion/loader.py`

#### Verification

`python -m compileall -q src tests` passed. The Pandas warning did not recur in the final 32-test run on Pandas 3.0.1. That run exited 0 with no pytest warnings; Python printed an ignored `pyreadline3` console-destructor `OSError` after the summary.

#### Related Changes

Phase 02 worklog session 02, 2026-11-03.

---

### ISSUE-002 — Missing package entry point for the requested label summary

**Date Reported:** 2026-11-03
**Development Phase:** Phase 02 — Dataset Acquisition & Data Ingestion
**Severity:** Low
**Status:** Resolved

#### Description

The requested `python -m intrusion_intelligence` command failed before reaching ingestion because the package did not define a `__main__.py` module.

#### Expected Behavior

Invoking the package should run the Phase 02 full label-summary command.

#### Actual Behavior

Python reported `No module named intrusion_intelligence.__main__`.

#### Steps to Reproduce

1. Make the `src` package importable (install it or set `PYTHONPATH=src`).
2. Run `python -m intrusion_intelligence` from the project root.

#### Error Message or Evidence

Before the fix, Python reported: `No module named intrusion_intelligence.__main__; 'intrusion_intelligence' is a package and cannot be directly executed`.

#### Root Cause

The package had a focused ingestion CLI under `intrusion_intelligence.ingestion` but no package-level entry point.

#### Resolution

Added `src/intrusion_intelligence/__main__.py` as a thin alias to the existing `summary --label-counts` command. The command now reaches ingestion and reports the missing CSV input clearly when no dataset is present.

#### Files Affected

- `src/intrusion_intelligence/__main__.py`
- `tests/test_ingestion_cli.py`

#### Verification

The entry-point delegation test passed as part of `python -m pytest` (33 passed in 1.14 seconds, exit code 0). Running the package command now reports that no supported CSV files are present and exits nonzero until the dataset is acquired.

#### Related Changes

Phase 02 worklog session 03, 2026-11-03.

---

### ISSUE-003 — Real CIC-IDS2017 duplicate headers rejected

**Date Reported:** 2026-11-03
**Development Phase:** Phase 02 — Dataset Acquisition & Data Ingestion
**Severity:** High
**Status:** Resolved

#### Description

All eight official MachineLearningCSV files were rejected because the exact source header ` Fwd Header Length` occurs twice and also collides after whitespace trimming.

#### Expected Behavior

The ingestion pipeline should preserve every source field, identify ambiguous names precisely, and support compatible files without silently merging or dropping columns.

#### Actual Behavior

Inspection marked all eight files invalid, leaving schema validation with no reference schema and zero compatible files.

#### Steps to Reproduce

1. Place the eight extracted CIC-IDS2017 CSV files under `data/raw/CIC-IDS2017/`.
2. Run `python -m intrusion_intelligence.ingestion inspect`.
3. Inspect the duplicate header at positions 35 and 56.

#### Error Message or Evidence

The raw header contains ` Fwd Header Length` at positions 35 and 56 in all eight files. A chunked positional comparison of both fields covered 2,830,743 rows and found zero differing raw text values. All eight source header sequences are otherwise identical, with no missing, additional, or reordered fields.

#### Root Cause

Inspection treated every repeated or whitespace-colliding source name as an invalid schema. Pandas also cannot address duplicate DataFrame headers reliably by their original names alone.

#### Resolution

Source header strings remain unchanged in metadata. Colliding columns receive unique internal names tied to their 1-based source positions; all original columns are retained. Schema compatibility counts duplicate multiplicity and requires exact source order for schemas with collisions. Ambiguous label columns remain invalid. The repeated CIC field was not dropped despite observed equality.

#### Files Affected

- `src/intrusion_intelligence/ingestion/inspection.py`
- `src/intrusion_intelligence/ingestion/schema.py`
- `src/intrusion_intelligence/ingestion/loader.py`
- `src/intrusion_intelligence/ingestion/metadata.py`
- `src/intrusion_intelligence/ingestion/models.py`
- `tests/test_ingestion.py`

#### Verification

All 8 CSV files inspected and validated; standard loading was performed file-by-file and chunked loading across all files. The label summary covered 2,830,743 rows. `python -m pytest` passed 39 tests after the fix. The full schema and duplicate-value evidence is in `reports/ingestion/CIC-IDS2017_schema_audit.md`.

#### Related Changes

Phase 02 worklog session 04, 2026-11-03.

---

### ISSUE-004 — Label summary output failed on Windows console encoding

**Date Reported:** 2026-11-03
**Development Phase:** Phase 02 — Dataset Acquisition & Data Ingestion
**Severity:** Medium
**Status:** Resolved

#### Description

The full CIC-IDS2017 label scan completed, but printing a label containing U+FFFD raised a Windows `charmap` encoding error before the report could be written.

#### Expected Behavior

The CLI should finish and write the exact label summary even when a console cannot encode a source label character.

#### Actual Behavior

The scan counted 2,830,743 rows, then exited during label rendering with `UnicodeEncodeError`.

#### Steps to Reproduce

1. Run `python -m intrusion_intelligence` under a Windows console using a non-UTF-8 code page.
2. Include a source label with U+FFFD, as in the CIC-IDS2017 Web Attack labels.

#### Error Message or Evidence

The command reported that the `charmap` codec could not encode `\ufffd` after logging a completed 15-category scan.

#### Root Cause

The CLI used `repr()` for labels, which may still emit printable non-ASCII characters that the active console codec cannot encode.

#### Resolution

The CLI renders label keys with `ascii()`, escaping unencodable characters in console output. The in-memory labels and UTF-8 metadata/report retain the original values.

#### Files Affected

- `src/intrusion_intelligence/ingestion/cli.py`
- `tests/test_ingestion_cli.py`

#### Verification

The synthetic CLI test confirms the console output contains an escaped `\ufffd` while JSON metadata retains the original U+FFFD string. The full real-data label summary then exited 0 and wrote 15 label counts for 2,830,743 rows.

#### Related Changes

Phase 02 worklog session 04, 2026-11-03.

---

### ISSUE-005 — Matplotlib boxplot tick-label deprecation warning

**Date Reported:** 2026-11-03
**Development Phase:** Phase 03 — Exploratory Data Analysis
**Severity:** Low
**Status:** Resolved

#### Description

The EDA boxplot generator emitted a Matplotlib deprecation warning for the `labels` keyword during synthetic report-generation tests.

#### Expected Behavior

The generated boxplot should render without using an argument deprecated by the installed Matplotlib version.

#### Actual Behavior

Matplotlib reported that `labels` was renamed to `tick_labels` in version 3.9. Initial targeted tests emitted four warnings from the figure generation path.

#### Steps to Reproduce

1. Run `python -m pytest tests/test_eda.py` with Matplotlib 3.9 or later.
2. Generate EDA diagnostic figures containing the boxplot.

#### Error Message or Evidence

The test run reported `MatplotlibDeprecationWarning` identifying the renamed boxplot argument. The final full suite completed with 47 passed and no pytest warnings.

#### Root Cause

Matplotlib changed the supported name for the boxplot category tick labels while the generator used only the older keyword.

#### Resolution

Select `tick_labels` for Matplotlib versions that support it and retain `labels` for older supported versions.

#### Files Affected

- `src/intrusion_intelligence/eda/reporting.py`

#### Verification

`python -m pytest tests/test_eda.py tests/test_config.py` passed 12 tests without pytest warnings. The full `python -m pytest` run passed all 47 tests without pytest warnings.

#### Related Changes

Phase 03 worklog session 05, 2026-11-03.

This is an initial tracking state, not a guarantee that the repository contains no existing bugs.

Inspect the repository and record actual issues when they are discovered.

### ISSUE-006 — Phase 04 cleaning implementation preserved values without cleaning

**Date Reported:** 2026-11-03
**Development Phase:** Phase 04 — Data Cleaning & Leakage Prevention
**Severity:** High
**Status:** Resolved

#### Description

The initial Phase 04 implementation generated a provenance-enriched copy and quality reports but did not perform the required numeric conversion, missing-token canonicalization, infinity handling, label validation, or invalid-label quarantine.

#### Expected Behavior

The cleaned output should apply the configured conservative transformations, separate invalid target rows, and validate the resulting analytical files while preserving raw inputs.

#### Actual Behavior

The v1 output preserved all source values as strings with provenance fields. It was described as completed before verifying the cleaning operations required by the phase.

#### Root Cause

The implementation favored source-value preservation and did not distinguish an assessment copy from a cleaned analytical dataset.

#### Resolution

Implemented the versioned v2 policy and chunked Parquet cleaner with numeric conversion audits, missing/infinity handling, label validation and quarantine, provenance, feature policy, output checks, and checksum verification. The v1 output remains as historical evidence; v2 is authoritative.

#### Files Affected

- `src/intrusion_intelligence/preprocessing/cleaning.py`
- `src/intrusion_intelligence/preprocessing/service.py`
- `configs/data_quality_policy.toml`
- `docs/data_cleaning.md`

#### Verification

The full real-data v2 run retained 2,830,743 rows, quarantined zero, generated eight verified Parquet outputs, and confirmed unchanged raw checksums. `python -m pytest -q` passed 60 tests.

#### Related Changes

Phase 04 worklog Session 07, 2026-11-03.

---

### ISSUE-007 — Policy CLI could not print replacement-character labels on Windows

**Date Reported:** 2026-11-03
**Development Phase:** Phase 04 — Data Cleaning & Leakage Prevention
**Severity:** Low
**Status:** Resolved

#### Description

The policy-inspection CLI emitted the Unicode replacement character (`U+FFFD`) directly, which raised a console encoding error in the Windows PowerShell environment.

#### Expected Behavior

The CLI should print the validated policy successfully under the active Windows console encoding.

#### Actual Behavior

Printing the literal replacement character failed when the console could not encode it.

#### Root Cause

The JSON output used non-ASCII console characters without escaping.

#### Resolution

Configured JSON serialization to escape non-ASCII characters in CLI output.

#### Files Affected

- `src/intrusion_intelligence/preprocessing/cli.py`
- `tests/test_preprocessing.py`

#### Verification

`python -m pytest tests/test_preprocessing.py::test_policy_cli_reports_valid_policy -q` passed, and the complete suite passed 60 tests.

#### Related Changes

Phase 04 worklog Session 07, 2026-11-03.

---

### ISSUE-008 — Cleaner rejected compatible order-only source schemas

**Date Reported:** 2026-11-03
**Development Phase:** Phase 04 — Data Cleaning & Leakage Prevention
**Severity:** Medium
**Status:** Resolved

#### Description

Phase 02 correctly classified files with the same unique columns in a different order as compatible, but the Phase 04 cleaner compared normalized header lists positionally and rejected the later file.

#### Expected Behavior

Compatible order-only schemas should align to one deterministic cleaned schema. Metadata should retain each input file's original header positions.

#### Actual Behavior

The cleaner raised a normalized-schema error for order-only differences after ingestion had accepted those schemas.

#### Root Cause

The cleaner used strict ordered-list equality rather than mapping fields into the first file's canonical order.

#### Resolution

Align each compatible source chunk by unique normalized header names before transformation and duplicate fingerprinting. Record the exact source mapping for each file in the manifest and transformation history. Missing or additional columns remain rejected.

#### Files Affected

- `src/intrusion_intelligence/preprocessing/service.py`
- `tests/test_preprocessing.py`
- `docs/data_cleaning.md`

#### Verification

Synthetic tests verify reordered columns retain correct values and per-file positions, and missing columns fail before processed output publication. The complete suite passed 60 tests.

#### Related Changes

Phase 04 worklog Session 07, 2026-11-03.

---

### ISSUE-009 — Preprocessing wrapper did not implement Scikit-learn estimator tags

**Date Reported:** 2026-11-03
**Development Phase:** Phase 05 — Feature Engineering & Preprocessing
**Severity:** Medium
**Status:** Resolved

#### Description

The first synthetic preprocessing run failed when `check_is_fitted` inspected the custom wrapper under Scikit-learn 1.8.0. The wrapper did not implement the estimator tag interface expected by the installed version.

#### Expected Behavior

The reusable fitted preprocessor should validate fit state and expose a Scikit-learn-compatible transformer interface across the supported version range.

#### Actual Behavior

Inference transformation raised an `AttributeError` while Scikit-learn attempted to retrieve `__sklearn_tags__` from the wrapper.

#### Root Cause

The custom wrapper was not derived from `BaseEstimator` and `TransformerMixin` even though it used Scikit-learn's estimator validation utilities.

#### Resolution

Made the wrapper inherit `TransformerMixin` and `BaseEstimator`, and replaced indirect fit-state inspection with an explicit fitted-state guard that raises `PreprocessingError`.

#### Files Affected

- `src/intrusion_intelligence/preprocessing/pipeline.py`
- `tests/test_feature_engineering.py`

#### Verification

The feature-engineering tests pass with Scikit-learn 1.8.0, including inference transforms and artifact reload. The complete suite passed 74 tests.

#### Related Changes

Phase 05 worklog Session 08, 2026-11-03.

---

### ISSUE-010 — Stratified model-fit sample omitted an ultra-rare class

**Date Reported:** 2026-11-03
**Development Phase:** Phase 07 — Supervised ML: Multi-class Classification
**Severity:** Medium
**Status:** Resolved

#### Description

The first real-data Phase 07 run stopped before model fitting because the configured 80,000-row stratified training sample did not contain the Heartbleed class, despite the full training partition containing examples.

#### Expected Behavior

The model-fit sample must include all known classes when enough examples are present in the training partition, especially for the ultra-rare labels that otherwise cannot be learned.

#### Actual Behavior

The initial proportional allocation rounded Heartbleed's sample quota to zero. Taxonomy/model validation correctly rejected the sample rather than silently fitting fewer classes.

#### Root Cause

Proportional sample allocation alone does not guarantee nonzero allocation for classes with very small support.

#### Resolution

Added configurable rare-class retention: all training rows are retained for classes whose full training support is at or below 50, and the remaining sample budget is allocated among larger classes. The configured 80,000-row sample now includes all 15 labels.

#### Files Affected

- `src/intrusion_intelligence/multiclass/data.py`
- `configs/multiclass.toml`
- `tests/test_multiclass.py`

#### Verification

The synthetic rare-class retention test passed. The corrected real sample included all 8 Heartbleed, 25 Infiltration, and 15 SQL Injection training rows; the full experiment then completed both model fits and selected-model test evaluation.

#### Related Changes

Phase 07 worklog Session 09, 2026-11-03.

---

### ISSUE-011 — Anomaly inventory required absent optional metadata

**Date Reported:** 2026-11-03
**Development Phase:** Phase 08 — Unsupervised Anomaly Detection
**Severity:** Medium
**Status:** Resolved

#### Description

The first full-data Phase 08 preflight rejected the cleaned CIC-IDS2017 Parquet files because the Phase 05 contract listed optional metadata fields that are not present in this export.

#### Expected Behavior

The anomaly inventory should require the target, predictive features, and source provenance needed for validation and capture-day grouping. Optional metadata absent from the source export should be reported, not treated as a missing required feature.

#### Actual Behavior

Inventory validation treated every contract metadata field, including unavailable Flow ID, timestamp, and endpoint fields, as mandatory and stopped before model training.

#### Root Cause

The initial inventory implementation conflated the Phase 05 list of possible metadata fields with the metadata columns physically present in the Phase 04 export.

#### Resolution

Changed inventory validation to require the configured predictive fields, target, and `__source_file` provenance only. The benign preparation report now records present metadata separately from unavailable optional metadata. No absent metadata is synthesized.

#### Files Affected

- `src/intrusion_intelligence/anomaly/data.py`
- `tests/test_anomaly_detection.py`

#### Verification

The anomaly synthetic tests passed, including Parquet inventory and metadata reporting. The corrected implementation completed the full 2,830,743-row CIC-IDS2017 experiment and generated model, preprocessing, calibration, evaluation, and report artifacts.

#### Related Changes

Phase 08 worklog Session 10, 2026-11-03.

---

### ISSUE-012 — Volatile prediction timestamps changed repeat-run fingerprints

**Date Reported:** 2026-11-03
**Development Phase:** Phase 09 — Threat Intelligence & Alert Correlation
**Severity:** Medium
**Status:** Resolved

#### Description

Repeated inference for the same stable source record could produce different event and alert fingerprints because the multi-class predictor includes a prediction timestamp in its raw result.

#### Expected Behavior

Reprocessing a source row with unchanged model outputs and evidence should retain deterministic event and alert fingerprints. Prediction timestamps must remain available in the event record.

#### Actual Behavior

The fingerprint payload used the complete raw detector output, including volatile prediction-time fields, so timestamps changed the fingerprint even when model evidence was unchanged.

#### Steps to Reproduce

1. Create two predictions for the same source record with identical labels and scores.
2. Set different `prediction_timestamp_utc` values.
3. Compare generated event fingerprints and alert IDs.

#### Error Message or Evidence

The regression test now uses those two timestamps and asserts equal event fingerprints and alert IDs while checking that each raw timestamp is preserved.

#### Root Cause

Event fingerprints were calculated directly from the entire raw detector output without removing processing-time fields.

#### Resolution

Fingerprint construction now omits known prediction/processing timestamp fields. The stored raw detector results are unchanged.

#### Files Affected

- `src/intrusion_intelligence/intelligence/events.py`
- `tests/test_intelligence.py`

#### Verification

`python -m pytest tests/test_intelligence.py -q` passed 44 tests, including the repeat-run fingerprint regression case.

#### Related Changes

Phase 09 worklog Session 11, 2026-11-03.

---

### ISSUE-013 — Friday detection input selected ground-truth source labels

**Date Reported:** 2026-11-03
**Development Phase:** Phase 09 — Threat Intelligence & Alert Correlation
**Severity:** High
**Status:** Resolved

#### Description

The Friday input-column selector included `__source_label`, a ground-truth provenance field, even though the detector code did not use its values.

#### Expected Behavior

Ground-truth target and source-label columns must not be loaded into the actual detection input. They may be noted as present in the export but must remain outside prediction and alert generation.

#### Actual Behavior

`_input_columns(..., include_target=False)` selected all contract metadata fields, including `__source_label`. The first summary therefore stated labels were not used but did not accurately represent the columns read.

#### Steps to Reproduce

1. Inspect the Phase 04 Parquet schema for `label` and `__source_label`.
2. Call `_input_columns` with the Phase 05 contract and `include_target=False`.
3. Confirm whether either label column appears in the selected fields.

#### Error Message or Evidence

The regression test writes a synthetic Parquet schema containing `label`, `__source_label`, and provenance fields, then asserts both label columns are absent from the detection selection.

#### Root Cause

The input selector treated every contract metadata field as permissible detection metadata and did not reserve the source-label field as ground truth.

#### Resolution

The detection selector now excludes the target and recognized ground-truth/source-label field names. The run summary reports label fields present in the export separately from labels loaded for detection. Thursday validation still reads the target solely to select BENIGN reference rows for ECDF construction.

#### Files Affected

- `src/intrusion_intelligence/intelligence/service.py`
- `tests/test_intelligence.py`

#### Verification

`python -m pytest tests/test_intelligence.py -q` passed 44 tests. Corrected actual run `20261103T145019Z` confirms `friday_ground_truth_labels_loaded: false`, `friday_ground_truth_labels_used_for_scoring_or_alerts: false`, and `ground_truth_columns_loaded_for_detection: []`. Thursday target labels are used only to select BENIGN ECDF reference rows.

#### Related Changes

Phase 09 worklog Session 11, 2026-11-03.

---

### ISSUE-014 — Binary target mapping dropped original attack labels

**Severity:** High — binary experiment blocker

**Status:** Resolved

**Observed behavior:** The real CIC binary experiment failed while counting the selected training sample because source labels such as `DDoS` and `PortScan` became missing values.

**Root cause:** The Phase 06 sample reader correctly returns original multiclass `y` labels, but the binary experiment mapped only values already equal to `BENIGN` or `ATTACK`. It did not apply the declared mapping to original attack categories.

**Resolution:** Apply `BENIGN → BENIGN` and every other non-empty preserved source label `→ ATTACK` in a separate binary-target series. Missing/empty labels now fail closed rather than being counted as attack. Original labels remain unchanged in source data. The mapping is persisted with binary model metadata.

**Verification:** The real capture-day experiment completed across all 2,830,743 rows, retained both binary classes after duplicate screening, saved `binary-random_forest-v1.0.0`, and loaded/scored that artifact in the actual Phase 09 run. Synthetic regression tests cover multi-attack mapping and missing labels.

### ISSUE-015 — First-row Phase 09 evaluation sample had no attack labels

**Severity:** High — alert validation evidence invalid for attack recall

**Status:** Resolved

**Observed behavior:** The initial 3,000-row sample selected the first 1,000 rows from each Friday source file. Separate offline evaluation showed the entire sample was BENIGN, so attack recall and per-attack alert performance could not be measured.

**Root cause:** CIC-IDS2017 source ordering clustered labels; a prefix sample was not representative for held-out validation.

**Resolution:** Use a deterministic, evenly spaced, per-label cap of 500 rows within each Friday file. Read labels in a separate sampling/evaluation path and exclude them from detector features, events, scoring, and alert rules. Report selected and source-label counts and clearly mark metrics as label-stratified research results, not prevalence estimates.

**Verification:** Latest run `20261103T160444Z` evaluated 3,000 rows with 1,500 BENIGN and 1,500 ATTACK support, including 500 each of Bot, DDoS, and PortScan. A unit test validates deterministic selection and counts. Ground-truth isolation assertions and run metadata confirm labels were not passed to detection/scoring/alerts.

### ISSUE-016 — Logistic report assembly failed after artifact persistence

**Severity:** Medium — report completion blocked after the model and evaluation outputs were saved

**Status:** Resolved

**Observed behavior:** The first two full Logistic Regression runs trained successfully, wrote versioned classifier/preprocessor bundles and both prediction Parquets, then raised during final summary/report assembly. The first raised `KeyError: 'artifact_joblib_size_bytes'`; the second raised `KeyError: 'report_directory'` while rendering Markdown.

**Root cause:** The artifact saver records joblib sizes in its serialized metadata document but does not mutate the caller's in-memory `metadata` dictionary. The summary also lacked the report directory required by the renderer.

**Resolution:** Calculate serialized artifact size from the saved manifest and include the report directory in the summary. Earlier saved reports were recovered from persisted metadata/predictions and preserved. A final full run under v1.0.2 completed through the CLI with exit code 0; no prior artifact was overwritten.

**Verification:** The final run `20261103T163706Z` completed via `python -m intrusion_intelligence.binary.logistic_cli --config configs/binary_logistic.toml`. Loaded the actual Logistic bundle and verified both model-file sizes and SHA-256 checksums. Recomputed metrics from both prediction Parquets and matched the stored confusion matrices and metrics for 405,471 Thursday rows and 703,245 Friday rows. Verified the persisted RF report metrics agree with its checksummed model metadata. `compileall` passed, 161 tests passed, and `git diff --check` passed after documentation updates.

## 7. Important Technical Risks to Watch

The following are known areas requiring careful engineering attention. They are risk reminders, not confirmed project bugs.

### Data Quality

- Missing values.
- Infinite values.
- Inconsistent feature data types.
- Duplicate feature vectors.
- Conflicting labels.
- Incorrect column names.

### Data Leakage

- Identifiers leaking label information.
- Preprocessing fitted on the full dataset.
- Duplicate or related flows appearing across evaluation splits.
- Unrepresentative train/test splitting.
- Unrealistic performance caused by shortcuts in the dataset.

### Model Evaluation

- Severe class imbalance.
- Poor minority-class recall.
- High false-positive rates.
- Misleading accuracy scores.
- Weak performance on unseen attack categories.
- Inconsistent feature schemas between training and inference.

### System Integration

- Model loading failures.
- Inconsistent API schemas.
- Database connection failures.
- Missing or incorrect configuration.
- Dashboard values that do not match backend results.

Record an issue in the Current Issue Register only when it has actually been observed or reproduced.

### Phase 10 verified fixes

- **Anomaly background index alignment:** the BENIGN-only sample retained global row indices but supplied a candidate-length label vector, causing an out-of-bounds error. The sampler now receives the complete label vector while restricting candidates to BENIGN rows. The full actual pipeline subsequently completed with the configured 100-row benign-only training background.
- **Windows CLI Unicode output:** the first completed report write failed when PowerShell's cp1252 stdout could not encode taxonomy labels containing U+FFFD. CLI JSON now escapes non-ASCII output; a subsequent end-to-end CLI run completed successfully.
- **SHAP report metadata scope:** report assembly initially referenced a function-local SHAP import. The report writer now imports SHAP in its own scope; a subsequent end-to-end CLI run wrote the JSON and Markdown reports.

### Phase 11 verified fixes

- **Non-finite values in evaluation reports:** saved per-attack CSVs contain undefined metrics as NaN, which strict JSON serialization rejects. The evaluation writer now recursively converts non-finite numeric values to JSON `null`; the comprehensive evaluation CLI then completed and emitted strict JSON reports.
- **Anomaly threshold boundary semantics:** the reusable anomaly metric helper records explicit `>` versus `>=` comparison semantics, matching the persisted Isolation Forest operating point (`>`). Synthetic tests verify tied-score behavior.

### Phase 12 verified fixes

- **Alert detail event ordering used a missing ORM column:** the first alert-detail integration test raised `AttributeError` because `DetectionEvent` stores `generated_at`, not `created_at`. The query now orders by `generated_at`; the API suite confirmed alert details return supporting event IDs successfully.
- **Docker startup omitted migration assets:** the first application container repeatedly failed because `alembic.ini` and `alembic/` were absent from the image. The Dockerfile now copies both; rebuilding and starting the container applied/checked the migration and launched Uvicorn successfully.
- **Relocated anomaly bundle could not find its preprocessor:** the first container registry check resolved the model's project-relative preprocessor reference under Python `site-packages` instead of `/app`. The loader now searches ancestors of the configured model bundle before the source-checkout fallback; the relocated-path unit test passes, and container readiness reports all five artifacts available.

### Phase 13 verified fixes

- **Streamlit exposed renderer modules as blank multipage links:** browser inspection showed that Streamlit's automatic `pages/` links bypassed the shared dashboard shell and invoked modules that only define a `render()` function. Added project config `client.showSidebarNavigation = false`; the nine supported pages remain accessible through the app's tested radio navigation. Browser checks confirmed all nine page headings render without visible exceptions.
- **Alert-page behavior test double lacked the detail route:** the real page correctly requests `/alerts/{alert_id}` after listing an alert, but its test fake initially implemented only list retrieval. Added deterministic detail behavior to the fake and verified the page displays real fixture rows and both export controls.
- **Feature-only uploads were marked with invalid inspection metadata:** the backend intentionally accepts CSVs without a target label, but the general ingestion inspector requires a label by default. The upload service now opts into an explicit `require_label=False` inspection mode, which preserves the default labelled-dataset validation elsewhere. Added inspector and API regression checks. A live POST returned HTTP 201 with `status=VALIDATED`, `inspection_status=valid`, `label_present=false`, and an explicit optional-label warning.
- **Empty object upload/job responses produced no feedback:** the Dataset Management page treated `{}` as false and silently suppressed feedback, even though the API client correctly accepts JSON objects. The page now checks for a usable dataset ID after upload and displays an invalid-job-response message when status retrieval returns no fields. Regression tests cover successful/failed/malformed uploads, successful/failed job submission, and malformed status responses.
### ISSUE-017 — Persisted events lacked individual retrieval and exact-row SHAP in the dashboard

**Date Reported:** 2026-11-04
**Development Phase:** Phase 14 — Integration, Testing & Deployment
**Severity:** High — individual event investigation and requested explanation flow were not exposed
**Status:** Resolved for SQLite/local API; PostgreSQL migration validation outstanding

#### Description

Detection events were written to SQLAlchemy storage and included in aggregate traffic summaries, but there were no event list/detail routes. Dataset-backed analysis also did not persist a stable source row number through asynchronous jobs, so the existing Phase 10 explainer could not retrieve the exact event inputs. The dashboard Explainability page only described the missing API capability.

#### Root Cause

Phase 12 stored compact event evidence but had not added individual event retrieval or linked persisted events back to their feature row. Phase 10 explainers were designed for offline reports and were not integrated into event persistence.

#### Resolution

Added paginated `GET /events` and safe `GET /events/{event_id}` responses with 404/422 behavior. Dataset-backed synchronous and job analysis now save a stable dataset UUID reference and 1-based CSV row number in event metadata. Added an on-demand `GET /events/{event_id}/explanation?engine=...` endpoint that uses the event's persisted model ID, validated model bundle, fitted preprocessing, Phase 10 training-only background, model-specific SHAP output, and additivity validation. Successful values are cached on the same DetectionEvent row with Alembic revision `20261104_0002`; missing row data and unsupported explainers return explicit statuses without fabricated values. The dashboard retrieves the selected event detail and displays returned contributions.

#### Verification

Full project suite passed 200 tests, 0 failed, 0 skipped, with 3 warnings. An isolated SQLite workflow uploaded a one-row feature CSV derived from existing Phase 04 Parquet, persisted and retrieved an event, and returned real Random Forest SHAP output with max absolute additive residual `1.3825522948707203e-09` and `passed=true`. Automated API coverage verifies explicit unsupported-model status. Both SQLite Alembic revisions applied. All nine dashboard page headings were verified in a browser. Docker Engine access failed through its named pipe, so PostgreSQL migration/HTTP verification remains outstanding and Phase 14 remains In Progress.
