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

No open project issues are recorded. ISSUE-001 through ISSUE-009 are resolved and documented below.

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
