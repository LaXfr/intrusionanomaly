# Worklog — Network Intrusion Detection & Anomaly Intelligence

## 1. Purpose

This document maintains a chronological record of development work performed on the project.

It records actual implementation activity, engineering decisions, testing, and development progress.

The worklog is intended to make it easy to understand:

- What was implemented.
- Why it was implemented.
- Which files were affected.
- What was tested.
- What remains incomplete.
- Where development should resume.

## 2. Worklog Rules

1. Record actual work only.
2. Do not document planned tasks as completed work.
3. Do not claim tests passed unless they were executed.
4. Record important implementation decisions.
5. Record failed attempts when they reveal meaningful technical issues.
6. Keep entries chronological, with the newest entry at the bottom.
7. Reference relevant files and modules.
8. Update the handoff document when the development state changes significantly.
9. Use the phase numbers from `roadmap.md`.
10. Avoid duplicating the entire Git commit history here.

## 3. Development Progress

**Current Project Phase:** Phase 14 Integration, Testing & Deployment — In Progress

**Current Status:** Phases 01–13 remain implemented; Phase 14 added persisted event retrieval and actual dataset-backed SHAP API/dashboard flow. Current SQLite integration and nine-page browser checks passed; Docker/PostgreSQL validation remains outstanding. No commit made.

**Last Verified Development Activity:** Phase 14 event-level SHAP integration; full suite 200 passed, 0 failed, 0 skipped on 2026-11-04.

Foundation and ingestion sessions are recorded below.

## 4. Worklog Entry Format

Use the following template for every development session.

---

### Session [NUMBER] — [SHORT TITLE]

**Date:** YYYY-MM-DD
**Phase:** Phase XX — [Phase Name]
**Status:** In Progress / Completed / Blocked

#### Objective

Describe what this session was intended to accomplish.

#### Work Performed

- Describe actual implementation work.
- Mention important modifications.
- Mention configuration or architectural decisions.

#### Files Created

- `path/to/file.py` — Purpose of the file.

Write `None` when no files were created.

#### Files Modified

- `path/to/file.py` — Summary of changes.

Write `None` when no files were modified.

#### Technical Decisions

Record important decisions and their rationale.

#### Testing and Validation

- Test executed:
- Command used:
- Result:
- Issues encountered:

Clearly distinguish between tests that were run and tests that were not run.

#### Issues and Limitations

Record relevant errors, limitations, or unresolved dependencies.

Write `None` when no issues were encountered.

#### Remaining Tasks

List incomplete tasks that belong to the current phase.

#### Next Action

Describe the exact next development task.

---

## 5. Development History

### Session 01 — Establish project foundation

**Date:** 2026-11-03
**Phase:** Phase 01 — Project Foundation & Architecture
**Status:** Completed

#### Objective

Inspect the existing repository and establish a maintainable Python foundation without implementing data analysis, machine learning, API, database connectivity, or dashboard behavior.

#### Work Performed

- Confirmed the initial repository contained project instructions and tracking documents only; there was no Git metadata.
- Added a `src`-layout Python package, typed TOML/environment configuration, shared project exceptions, and reusable logging setup.
- Added optional dependency groups, environment placeholders, data/artifact Git exclusions, architecture documentation, and a project README.
- Added package import and configuration tests; left future subsystems as directory markers without pretend implementations.
- Updated the roadmap and handoff to reflect actual status.

#### Files Created

- Foundation source files under `src/intrusion_intelligence/`.
- `pyproject.toml`, `requirements.txt`, `configs/project.toml`, `.env.example`, and `.gitignore`.
- `README.md`, `docs/architecture.md`, and tests under `tests/`.
- Directory markers for future data, source, API, dashboard, model, and report areas.

#### Files Modified

- `roadmap.md` — Marked Phase 01 complete and Phase 02 not started.
- `handoff.md` — Recorded environment, repository state, validation, and next phase.

#### Technical Decisions

- Used standard-library TOML parsing and immutable dataclasses to keep foundation runtime dependencies empty.
- Grouped future libraries into optional extras so each phase can install only needed components.
- Deferred Docker and Compose files until there is an executable application runtime.
- Declared Python 3.11–3.13 support because the available interpreter is 3.13.2; 3.11 and 3.12 remain recommended.

#### Testing and Validation

- Test executed: `python -m pytest`
- Environment: Python 3.13.2, pytest 9.1.1.
- Initial result: 3 passed in 0.07 seconds.
- Repository structure and package/config imports were inspected; no dataset or ML operation was run.
- Final rerun: 3 passed in 0.04 seconds, exit code 0; an ignored `pyreadline3` console-destructor `OSError` appeared after the test summary.

#### Issues and Limitations

- No Git metadata is present in the workspace, so Git status/history could not be used and no commit was made.
- Foundation dependencies were not installed during this session; pytest was already available in the environment.
- The observed `pyreadline3` shutdown message is from the environment and did not change pytest's zero exit status; its cause was not investigated further.
- No confirmed software issue was encountered. `fixes.md` remains unchanged.

#### Remaining Tasks

- Phase 02 dataset acquisition documentation, input schema definition, and reusable ingestion/validation.
- No dataset download was performed.

#### Next Action

Start Phase 02 when requested. Document the official CIC-IDS2017 source and schema before implementing the loader; do not proceed to model or application phases.

---

### Session 02 — Dataset acquisition and CSV ingestion

**Date:** 2026-11-03
**Phase:** Phase 02 — Dataset Acquisition & Data Ingestion
**Status:** Completed with synthetic validation; real-dataset validation pending

#### Objective

Implement reusable CIC-IDS2017 CSV discovery, inspection, schema validation, loading, metadata, reporting, and CLI support without downloading the dataset or beginning EDA.

#### Work Performed

- Re-inspected all six project-control documents, the Phase 01 package/configuration, data directories, installed environment, and Git status.
- Verified CIC-IDS2017 source formats, collection period, and documented evaluation caveats from the official UNB CIC page and primary research.
- Added recursive configured CSV discovery, bounded header/encoding inspection, incremental SHA-256, whitespace/duplicate/label checks, and schema comparisons.
- Added Pandas standard and chunked loaders, bounded previews, exact label-count scans with coverage status, JSON metadata, Markdown reports, and CLI commands.
- Added configuration for dataset identity/path, CSV extensions/encoding, chunk size, label headers, and metadata/report locations.
- Updated requirements to include the Pandas data extra, added documentation, and added synthetic-fixture tests.
- Confirmed `data/raw/CIC-IDS2017/` is absent; no dataset files were downloaded or modified.

#### Files Created

- `src/intrusion_intelligence/ingestion/` — discovery, inspection, schema validation, loading, summaries, reports, service orchestration, and CLI.
- `tests/test_ingestion.py` and `tests/test_ingestion_cli.py` — synthetic CSV tests.
- `docs/data_ingestion.md` — source, placement, schema rules, loading, reporting, and usage.
- `reports/ingestion/.gitkeep` — generated-report directory marker.

#### Files Modified

- `src/intrusion_intelligence/config.py` and `errors.py` — dataset/ingestion settings and ingestion exceptions.
- `configs/project.toml`, `.env.example`, `.gitignore`, `pyproject.toml`, and `requirements.txt` — phase configuration, output exclusions, CLI entry point, and Pandas dependency group.
- `README.md` and `docs/architecture.md` — phase status and implemented ingestion architecture.
- `roadmap.md` — Phase 02 status and deliverables.
- `handoff.md` — current state and Phase 03 prerequisite.
- `fixes.md` — recorded and resolved the Pandas concat deprecation warning found during validation.

#### Technical Decisions

- Used the official CIC-IDS2017 source page as the source of record; the pipeline does not download files.
- Supported labelled flow CSVs recursively without hard-coding dataset filenames; PCAP files are ignored.
- Preserved original headers and label strings. Same-name order differences are alignable; missing, extra, duplicate, or whitespace-colliding headers block multi-file loading.
- Kept metadata-only inspection separate from row scans. Checksums read file bytes incrementally; row and label counts are recorded only after an actual full or bounded scan.
- Used synthetic CSV fixtures because the real archive is not present.

#### Testing and Validation

- Syntax check: `python -m compileall -q src tests` — passed.
- Test command: `python -m pytest`.
- Environment: Python 3.13.2, Pandas 3.0.1, pytest 9.1.1.
- Final result: 32 passed in 0.99 seconds, exit code 0. Pytest reported no warnings; Python printed an ignored `pyreadline3` console-destructor `OSError` after the summary.
- One newly added CLI error test initially failed because it asserted captured stderr instead of pytest's captured log output; the assertion was corrected and the final suite passed.
- No real CIC-IDS2017 file was inspected.

#### Issues and Limitations

- The configured dataset directory contains only `.gitkeep`, so real-archive compatibility remains unverified.
- The workspace is not a Git repository; Git status/history is unavailable and no commit was made.
- The existing `.venv` was not changed and does not contain Pandas yet; `requirements.txt` now includes the data extra for setup.
- One Pandas deprecation warning was fixed and recorded in `fixes.md`. The intermittent environment shutdown message does not change pytest's zero exit status.

#### Remaining Tasks

- Obtain and place the official labelled CSV files under `data/raw/CIC-IDS2017/` when authorized.
- Phase 03 exploratory analysis has not started.

#### Next Action

After the official CSV files are made available, run the ingestion inspection/validation commands and begin Phase 03 with the validated files. Do not automatically download data or proceed to cleaning/model phases.

---

### Session 03 — Official dataset access and real-world ingestion validation attempt

**Date:** 2026-11-03
**Phase:** Phase 02 — Dataset Acquisition & Data Ingestion
**Status:** Blocked; real-data acquisition awaits user interaction with the official download form

#### Objective

Acquire the official labelled CIC-IDS2017 CSV archive, validate it through the Phase 02 pipeline, run the existing tests, and update project tracking without starting Phase 03.

#### Work Performed

- Checked the official UNB CIC-IDS2017 page. It identifies `MachineLearningCSV.zip` as the machine-learning CSV archive and `GeneratedLabelledFlows.zip` as a separate labelled-flow archive; the official page also lists PCAP data.
- Followed the official download link to CIC's request form. The form required first name, last name, email, organization/company, job title, and country, and displayed a server error. No personal details were available for submission, so no form was submitted and no archive was downloaded.
- Confirmed `data/raw/CIC-IDS2017/` contains only `.gitkeep`. The official page does not publish an archive-specific size or checksum for `MachineLearningCSV.zip`.
- Ran inspection, schema validation, and the supported label-summary command. Inspection and validation each reported unavailable with zero discovered CSVs; the label scan could not start because no supported files exist.
- The requested bare `python -m intrusion_intelligence` command initially failed because the package did not provide `__main__.py`. Added a thin package entry point that invokes the existing full label-summary command.
- Updated dataset acquisition guidance, README status, roadmap, and handoff instructions. Kept Phase 03 not started.

#### Files Created

- `src/intrusion_intelligence/__main__.py` — Package-level alias for the full Phase 02 label summary.

#### Files Modified

- `docs/data_ingestion.md` — Documented official archive choices, form requirement/error, integrity limits, and manual placement/commands.
- `tests/test_ingestion_cli.py` — Added a delegation test for the package-level entry point.
- `README.md` — Recorded acquisition status and real-validation blocker.
- `roadmap.md` — Marked Phase 02 real-data acceptance tasks incomplete and blocked.
- `handoff.md` — Set the current phase back to Phase 02 and documented the next manual action.
- `fixes.md` — Recorded ISSUE-002 and its verified resolution.
- `worklog.md` — Recorded this session.

#### Technical Decisions

- Target only the official `MachineLearningCSV.zip` archive for this phase to avoid downloading a second, overlapping dataset archive or PCAP files.
- Do not submit guessed personal data or use a third-party/modified copy when the official form requires user interaction.
- Preserve the original archive and extracted CSV files unchanged when they become available. Keep generated metadata and reports outside `data/raw/`.
- Make the requested bare package command a convenience alias for the existing full label summary; keep the focused subcommands available under `intrusion_intelligence.ingestion`.

#### Testing and Validation

- Initial command without an import path: `python -m intrusion_intelligence.ingestion inspect` — failed with `ModuleNotFoundError` because the package is in a `src` layout and is not installed in the active system Python.
- Reran commands with PowerShell `$env:PYTHONPATH = 'src'`.
- `python -m intrusion_intelligence.ingestion inspect` — unavailable, 0 CSVs discovered, exit code 1; metadata and report were regenerated.
- `python -m intrusion_intelligence.ingestion validate` — unavailable, 0 CSVs discovered, exit code 1.
- `python -m intrusion_intelligence` — after adding the entry point, reached label scanning and reported no supported CSV files; no label counts were produced because the raw directory is empty.
- `python -m intrusion_intelligence.ingestion summary --label-counts` — no supported CSVs found, exit code 1; no label counts were produced.
- `python -m pytest` — 33 passed in 1.14 seconds, exit code 0.
- No original file checksum or real header/schema/label validation could be performed because no dataset file was available.

#### Issues and Limitations

- The official form requires user-provided identity details and reported a server error. Acquisition and real-data validation remain incomplete until the user completes the official flow and places the archive locally.
- The label-summary entry point is implemented, but cannot produce counts until the CSV files are present.
- No verified MachineLearningCSV archive size or publisher checksum was available from the official page.

#### Remaining Tasks

- Complete the official CIC download form with user-provided details and download only `MachineLearningCSV.zip`.
- Preserve the archive and extract its unchanged CSV files under `data/raw/CIC-IDS2017/`.
- Run archive integrity validation, `inspect`, `validate`, and `summary --label-counts`; investigate any genuine data/schema issues.
- Keep Phase 03 unstarted until the real-data validation is complete.

#### Next Action

Use the official [CIC-IDS2017 page](https://www.unb.ca/cic/datasets/ids-2017.html) to request and download `MachineLearningCSV.zip` with the user's own details. Once its original files are available under `data/raw/CIC-IDS2017/`, rerun the Phase 02 commands and update the report with actual results.

---

### Session 04 — Real CIC-IDS2017 schema validation

**Date:** 2026-11-03
**Phase:** Phase 02 — Dataset Acquisition & Data Ingestion
**Status:** Completed; Phase 03 remains not started

#### Objective

Inspect all eight real CIC-IDS2017 CSV headers, establish whether the duplicate `Fwd Header Length` fields are equivalent, resolve schema handling without changing source files, run all Phase 02 ingestion paths, and update project documentation.

#### Work Performed

- Confirmed 8 extracted CSV files, all UTF-8 with 79 columns. Compared every source header position across files; the exact 79-column sequences match, with no missing columns, additional columns, or order differences.
- Found the exact header ` Fwd Header Length` at 1-based positions 35 and 56 in every file. The only normalized collision group is `Fwd Header Length`. The label header is ` Label` at position 79.
- Identified 65 header strings with leading whitespace and no trailing-whitespace headers. Raw spellings remain unchanged.
- Compared duplicate field values as raw strings in 100,000-row chunks across all files: 2,830,743 pairs, 0 mismatches. Kept both columns.
- Added position-specific internal names for duplicate/normalized-colliding headers. Preserved original header arrays and added per-column source-position mappings to metadata. Schema validation counts duplicate multiplicity and requires identical source order when collisions exist; ambiguous labels remain invalid.
- Fixed CLI rendering to ASCII-escape non-ASCII labels, allowing complete summaries on Windows consoles while retaining original label strings in metadata and reports.
- Ran standard loading one file at a time, chunked loading across all files, and the complete label summary. Generated `reports/ingestion/CIC-IDS2017_schema_audit.md` with the full 79-position header map and per-file comparisons.
- Updated documentation and project tracking. Did not begin Phase 03.

#### Files Created

- `reports/ingestion/CIC-IDS2017_schema_audit.md` — Complete real-data header, schema, duplicate-value, and loading audit.

#### Files Modified

- `src/intrusion_intelligence/ingestion/models.py`, `inspection.py`, `schema.py`, `loader.py`, `service.py`, and `metadata.py` — Position-aware collision handling and source-to-internal header mapping.
- `src/intrusion_intelligence/ingestion/cli.py` — Console-safe rendering of labels containing non-ASCII characters.
- `tests/test_ingestion.py` and `tests/test_ingestion_cli.py` — Duplicate headers, whitespace collisions, different duplicate values, metadata mapping, and console encoding coverage.
- `docs/data_ingestion.md` and `docs/architecture.md` — Source-header and aliasing policy plus actual CIC-IDS2017 findings.
- `README.md`, `roadmap.md`, `handoff.md`, and `fixes.md` — Completed Phase 02 status, results, and resolved issues.
- `data/interim/metadata/CIC-IDS2017_ingestion.json` and `reports/ingestion/CIC-IDS2017_ingestion.md` — Regenerated metadata and full label-summary report.

#### Technical Decisions

- Preserve every source field, even though the two repeated CIC fields matched exactly across all rows. Do not remove, normalize, or coalesce original columns.
- Give colliding columns stable names containing their 1-based source positions; retain the exact source names in metadata.
- Require exact source order for multi-file schemas containing duplicate or whitespace-colliding names. Permit order-only alignment only when source column names are unambiguous.
- Keep multiple label candidates invalid. Use trimmed, case-insensitive comparison solely to locate the label column.
- Treat the `Flow Bytes/s` mixed-type warning as a later data-quality concern; no type coercion or cleaning was performed.

#### Testing and Validation

- `python -m pytest` with `PYTHONPATH=src` — 39 passed in 1.14 seconds, exit code 0. Python printed an ignored `pyreadline3` console-destructor `OSError` after the summary.
- `python -m intrusion_intelligence.ingestion inspect` — valid; 8 files discovered and inspected, 79 columns each.
- `python -m intrusion_intelligence.ingestion validate` — exit 0; 8 matching, 0 order-only, 0 incompatible.
- `python -m intrusion_intelligence` — complete label scan and report; 2,830,743 rows, 15 categories, exit 0.
- `python -m intrusion_intelligence.ingestion load --strategy chunked --chunk-size 100000` — 8 files, 2,830,743 rows, complete.
- Standard `load_dataset` — each of the 8 files loaded separately and released before the next; 2,830,743 rows total. A two-file standard concatenation also loaded 361,399 rows and retained both duplicate-position columns.
- Positional duplicate scan — 2,830,743 raw-string comparisons, 0 differences.
- Pandas emitted `DtypeWarning` for mixed types in `Flow Bytes/s`; ingestion completed and no values were coerced.

#### Issues and Limitations

- The ZIP archive was not present under `data/raw/`, so no publisher-provided archive checksum was available for verification. The ingestion metadata records per-file SHA-256 values.
- No original source CSV was modified. The duplicate-column test establishes exact equality for this extraction only; both fields remain preserved.
- Real-data scans reveal mixed types in `Flow Bytes/s`; investigation belongs to a later authorized data-quality phase.

#### Remaining Tasks

- Phase 02 real-data validation is complete.
- Phase 03 Exploratory Data Analysis remains not started.

#### Next Action

Keep Phase 03 unstarted for this task. Continue with that phase only when separately requested.

---

### Session 05 — Real CIC-IDS2017 exploratory data analysis (historical status)

**Date:** 2026-11-03
**Phase:** Phase 03 — Exploratory Data Analysis
**Status at the end of Session 05:** Completed; Phase 04 was then not started. Phase 04 was completed in Session 06 below.

#### Objective

Implement a reusable, read-only EDA workflow, execute it against all locally available CIC-IDS2017 data, create the requested notebook/reports/figures, and document evidence and limitations.

#### Work Performed

- Implemented `src/intrusion_intelligence/eda/` with chunked full-scan aggregates built on Phase 02 discovery, validation, and chunked loading APIs; deterministic 20,000-row uniform sampling (seed 42); and a 1,000-per-label stratified sample for selected label comparisons.
- Added exact full-scan counts and moments for file/label totals, missingness, positive and negative infinities, numeric parsing, negative and zero values, feature ranges, and destination ports. Sample-based results are separately marked for quantiles, distribution diagnostics, correlations, selected feature/label comparisons, and duplicate estimates.
- Added JSON and Markdown report generation, ten purpose-specific PNG figures, an EDA CLI, and a 20-section notebook (39 cells) that orchestrates the same API.
- Preserved original values and labels. No source CSVs were cleaned, rewritten, sampled back into the raw directory, or deduplicated.
- Ran the CLI across all eight compatible source files: 2,830,743 rows, 79 source columns, 15 original labels. Saved reports under `reports/eda/` and figures under `reports/figures/eda/`.
- Documented label/file concentration, data-quality anomalies, sample limitations, unavailable schema fields, possible scenario/port shortcuts, and recommendations in `docs/eda.md`.
- Updated README, architecture, configuration, dependency extras, test coverage, roadmap, handoff, and issue tracking. Did not update `gitlog.md` because the workspace has no Git repository and no commit was made.

#### Actual Findings

- BENIGN: 2,273,097 rows (80.30%); original attack labels: 557,646 rows across 14 classes. `Heartbleed` has 11 rows; `Web Attack � Sql Injection` has 21; `Infiltration` has 36.
- Each non-BENIGN label appears in one source file in this extract; BENIGN appears in all eight.
- Full scan: 1,358 missing values in `Flow Bytes/s`; 4,376 positive infinities across `Flow Bytes/s` and `Flow Packets/s`; 2,446,321 negative-value occurrences across 13 features; eight constant features.
- Uniform 20,000-row sample: 507 exact duplicate rows (2.535%), 576 rows in repeated feature-vector groups, and zero conflicting-label groups. These are not full-dataset duplicate counts.
- Protocol, timestamp, source port, Flow ID, and IP address columns are absent from the extracted source schema; temporal and address-level analyses could not be done.

#### Files Created

- `src/intrusion_intelligence/eda/__init__.py`, `__main__.py`, `analysis.py`, `cli.py`, `reporting.py`, `service.py`
- `notebooks/01_dataset_exploration.ipynb`
- `docs/eda.md`
- `tests/test_eda.py`
- `reports/eda/CIC-IDS2017_eda.json`, `reports/eda/CIC-IDS2017_eda.md`
- Ten PNG figures in `reports/figures/eda/`

#### Files Modified

- `src/intrusion_intelligence/config.py`, `src/intrusion_intelligence/errors.py`
- `configs/project.toml`, `.env.example`, `.gitignore`, `pyproject.toml`, `requirements.txt`
- `tests/test_config.py`, `README.md`, `docs/architecture.md`
- `roadmap.md`, `handoff.md`, `worklog.md`, `fixes.md`

#### Testing and Validation

- `python -m pytest` — 47 passed in 4.73 seconds; no pytest warnings. Python printed an ignored `pyreadline3` console-destructor `OSError` after the test summary.
- `python -m compileall -q src tests` — passed.
- Notebook JSON parsed and all 18 code cells compiled. Jupyter was unavailable, so the notebook was not interactively executed; its underlying analysis was executed end-to-end through the EDA CLI on real CIC-IDS2017 data.
- Visual inspection of the full-scan label chart confirmed the generated category/count plot; source U+FFFD in a Web Attack label renders as a replacement glyph, preserving the original label text.

#### Issues and Limitations

- Matplotlib emitted a boxplot argument deprecation warning during initial EDA tests; the rendering code now selects the supported argument based on the installed Matplotlib version. The final full test run had no pytest warnings.
- Pandas continues to emit a mixed-type `DtypeWarning` for `Flow Bytes/s`; preserving this observation without coercion is in scope for EDA. Handling it is deferred to Phase 04.
- Exact external-memory duplicate analysis was not performed. The notebook frontend was not available for interactive execution. The absence of timestamp, protocol, source-port, and endpoint identifier columns limits those analyses.

#### Remaining Tasks

- Phase 03 is complete.
- Phase 04 — Data Cleaning & Leakage Prevention remains not started.

#### Next Action at the time

The planned next action at the time was to begin Phase 04 only when requested, using the recorded evidence and preserving raw files. This plan was carried out in Session 06 below.

---

### Session 06 — Historical v1 real-data quality assessment and preservation-only preprocessing

**Date:** 2026-11-03
**Phase:** Phase 04 — Data Cleaning & Leakage Prevention
**Historical status:** Initially marked complete; a later audit found required cleaning behavior was missing. Session 07 supersedes this result. Phase 05 remains not started.

#### Objective

Investigate the full CIC-IDS2017 extract, implement an evidence-based and traceable preprocessing policy, preserve raw data, validate the processed outputs, and update project documentation.

#### Work Performed

- Implemented chunked quality assessment, a validated TOML policy, external SQLite aggregation of full-extract duplicate fingerprints, a preservation-first writer, provenance fields, manifests, transformation history, and JSON/Markdown reports in `src/intrusion_intelligence/preprocessing/`.
- Scanned all eight raw files (2,830,743 rows; 79 original columns). The assessment distinguished source tokens, numeric parseability, infinity, negatives, constants, sample-only diagnostics, full-row fingerprints, and feature-vector fingerprints.
- Kept all source features, cells, labels, row order, and rows. No imputations, clipping, infinity replacement, deduplication, or feature removal were justified. Added only `__source_file`, `__source_row_number`, and deterministic `__record_id` to each separate processed file.
- Verified per-file ordered source-cell fingerprints, output checksums, and unchanged raw SHA-256 checksums. Processed output contains 8 files totaling 1,176,640,540 bytes; the before/after assessment and cleaning reports are under `reports/data_quality/`.
- Inspected the processed dataset with Phase 02 APIs: 8 files, 82 columns each, 8 matching schemas; standard loading read one file (225,745 rows), and chunked label summary processed all 2,830,743 rows across 15 labels.
- Updated Phase 04 documentation, architecture, roadmap, handoff, worklog, README, EDA notes, and issue tracking. Phase 05 was not started.

#### Actual Findings

- 1,358 NaN tokens in `Flow Bytes/s`; no empty strings, explicit null tokens, or invalid numeric strings.
- 4,376 positive infinities in `Flow Bytes/s` and `Flow Packets/s`; every occurrence was paired with zero `Flow Duration`. No finite replacement was inferred.
- 2,446,321 negative feature-cell occurrences across 13 source positions. `-1` initial-window values remain unresolved as possible sentinels; other negatives remain flagged and unchanged.
- Eight exact constant features; 19 low-cardinality and 12 near-constant features in the deterministic diagnostic sample only.
- Full-extract fingerprints found 308,381 excess complete-row matches and 309,079 excess repeated feature-vector matches; 698 feature-vector groups had differing labels. Duplicates and conflicting labels were retained.
- Dataset concentration and missing identifiers limit causal interpretation: attack labels occur in one source file each, and the export lacks timestamps, endpoints, source ports, protocol, and Flow ID.

#### Files Created

- `src/intrusion_intelligence/preprocessing/__init__.py`, `__main__.py`, `assessment.py`, `cli.py`, `policy.py`, `reporting.py`, `service.py`
- `configs/data_quality_policy.toml`
- `docs/preprocessing.md`
- `tests/test_preprocessing.py`
- Processed CSVs under `data/processed/CIC-IDS2017/cleaned/` and manifest/history under `data/processed/CIC-IDS2017/metadata/`
- Before/after quality and cleaning reports under `reports/data_quality/`

#### Files Modified

- `pyproject.toml`, `README.md`, `docs/architecture.md`, `docs/data_ingestion.md`, `docs/eda.md`
- `roadmap.md`, `handoff.md`, `worklog.md`, `fixes.md`

#### Testing and Validation

- `python -m compileall -q src tests` — passed.
- `python -m pytest` — 54 passed in 8.09 seconds using system Python 3.13.2.
- `python -m intrusion_intelligence.preprocessing assess --chunk-size 25000 --sample-stride 100` — completed across all 8 source files.
- `python -m intrusion_intelligence.preprocessing clean --chunk-size 50000 --sample-stride 100` — completed, retained 2,830,743 rows, excluded 0, and verified raw checksums and ordered source-cell content.
- `python -m intrusion_intelligence.preprocessing summary` — reported completed outputs and unchanged raw inputs.
- Phase 02 processed-output inspection — valid, 8 matching files, 82 columns each. Standard load and complete chunked label summary succeeded.
- The project `.venv` test invocation could not collect the pre-existing EDA test module because Matplotlib is missing from that environment. The global Python environment had the dependency and passed the full suite; no package was installed.

#### Issues and Limitations

- Assessment fingerprint groups use two keyed 64-bit hashes combined into a 128-bit key; collision probability is negligible but nonzero. Duplicate counts are reported as fingerprint matches, and no rows were removed.
- Processed CSVs preserve source field values but are not model-ready numeric matrices. Missing and infinite value handling, any transformations, and evaluation split design remain future work.
- Raw CSV files are unchanged. The preservation-first result documents anomalies; it does not claim those anomalies were repaired.

#### Remaining Tasks

- At the time, the work was considered complete, but Session 07 found that numeric conversion, missing/infinity handling, and label quarantine had not been applied.
- Phase 05 — Feature Engineering & Preprocessing remains not started.

#### Next Action

Audit and correct the Phase 04 cleaning behavior as recorded in Session 07. Keep Phase 05 unstarted.

### Session 07 — Corrected data cleaning, leakage policy, and full-data validation

**Date:** 2026-11-03
**Phase:** Phase 04 — Data Cleaning & Leakage Prevention
**Status:** Completed; Phase 05 remains not started

#### Work Completed

- Audited the prior v1 implementation and found that it copied source values without performing required type, missing-value, infinity, or label cleaning. Preserved its outputs as historical artifacts and implemented v2 in the reusable preprocessing modules.
- Added deterministic lowercase snake-case header normalization with source-position suffixes for collisions; recorded the original names and positions. Added numeric conversion audits, common missing-token normalization, infinity-to-null conversion, conservative label trimming/validation, and label quarantine.
- Added alignment for compatible order-only schemas and per-file original header mappings. The available CIC-IDS2017 files share the same schema order, so the run's common mapping applies to all eight; synthetic tests cover the order-only case. Missing/additional columns remain rejected.
- Added configurable exact-duplicate removal while keeping `preserve` as the default. Full fingerprint assessment distinguishes exact rows, repeated feature vectors, cross-file groups, and conflicting labels. The v2 default retained all duplicates and conflicts.
- Wrote one typed Parquet per source file, provenance and policy metadata, a separate quarantine Parquet, before/after quality reports, and the cleaning report under the v2 paths. Raw files and the historical v1 output were left intact.
- Created the cleaning notebook and updated cleaning/leakage documentation, README, architecture, roadmap, handoff, and issue tracking. Phase 05 work was not started.

#### Actual Full-Data Results

- Processed all 8 CIC-IDS2017 CSVs: 2,830,743 input rows, 2,830,743 retained, 0 quarantined, and 8 Parquet outputs with 83 fields each.
- All 15 labels remained distinct after trimming. Numeric conversion failures: 0. Missing tokens canonicalized: 1,358. Positive infinities replaced: 4,376; negative infinities: 0. Finite negatives and extremes were preserved.
- Exact duplicate excess: 308,381; repeated feature-vector excess: 309,079; conflicting-label feature groups: 698. All remained in the output under the default duplicate policy.
- Post-clean checks found 78 numeric feature columns, valid standardized schema, no numeric infinities, valid labels, unique record IDs, consistent row/quarantine accounting, reopenable Parquet, and unchanged source SHA-256 values.

#### Testing and Validation

- `python -m pytest -q` — 60 passed in 6.29 seconds. An ignored `pyreadline3` console-destructor `OSError` printed after pytest reported success.
- `python -m compileall -q src tests` — passed.
- `python -m intrusion_intelligence.preprocessing clean --chunk-size 25000 --sample-stride 100` — completed against all eight actual files; 2,830,743 rows retained and zero excluded.
- Independently checked the manifest, output checksums, Parquet row counts and schema, labels, null/infinity behavior, unique record IDs, quarantine, and raw checksums. Notebook JSON parsed and all code cells compiled; it was not run in a notebook frontend.

#### Known Limitations and Next Action

- The available export lacks timestamp, endpoint IP, standalone source-port, protocol, and Flow ID fields. The benchmark's label/source-file concentration remains a split and evaluation risk.
- Exact duplicates and conflicting repeated-feature labels are retained for review. Hash-based duplicate assessment uses two keyed 64-bit fingerprints; a collision is very unlikely but possible.
- Missing predictive features are retained as nulls; no imputation, encoding, scaling, feature selection, train/test split, or model was introduced.
- Phase 04 is complete. Begin Phase 05 only when separately requested.

### Session 08 — Feature contract and leakage-safe preprocessing infrastructure

**Date:** 2026-11-03
**Phase:** Phase 05 — Feature Engineering & Preprocessing
**Status:** Completed; Phase 06 remains not started

#### Work Completed

- Inspected all six project-control files, the prior phase handoff, feature/leakage policies, EDA findings, actual Phase 04 Parquet outputs and metadata, package configuration, and current runtime versions.
- Generated `configs/feature_schema.json` from the actual Phase 04 manifest and feature policy. The contract contains 78 numeric predictive features, a separate target, the four present provenance fields, excluded identifiers/time fields, source-header mapping, and unavailable candidate notes for source port and protocol.
- Added `FeatureContract`, strict X/y/metadata separation and validation, optional inference columns, categorical type normalization, deterministic flow-derived packet/byte totals and proportions, and explicit missing/zero-denominator behavior.
- Added independent `linear` (StandardScaler), `tree` (no scaling), and `anomaly` (RobustScaler) preprocessing configurations. Numeric median imputation, categorical missing-value imputation, sparse one-hot encoding with unknown-category tolerance, optional missing indicators, batch transforms, and train-only variance selection are supported. Numeric all-missing training columns raise a clear error.
- Added training-label-only class distribution/weight calculation, versioned non-overwriting Joblib artifacts with JSON metadata, and sparse-NPZ/dense-NPY transformed-matrix persistence with aligned target/row metadata.
- Created the Phase 05 notebook and `docs/feature_engineering.md`; updated README, architecture, dependency extras, roadmap, handoff, and issue tracking. No classifier/anomaly model or final split was created.

#### Actual CIC-IDS2017 Validation

- Verified that all eight Phase 04 Parquet files share the same 83-column schema. The contract maps 78 numeric predictive features, `label`, `__source_label`, `__source_file`, `__source_row_number`, and `__record_id`; the current export has no categorical predictive feature.
- Read a bounded sample of 1,000 rows per source file (8,000 rows total), separated X/y/metadata, fit the linear profile on an illustrative 6,400-row training subset, and transformed 1,600 held-out sample rows. Two optional derived features yielded 80 ordered outputs. This was not a final project split and no full-dataset transform or authoritative fitted artifact was produced.

#### Testing and Validation

- `python -m pytest -q` — 74 passed in 9.17 seconds; an ignored `pyreadline3` console-destructor `OSError` printed after the success summary.
- `python -m compileall -q src tests` — passed.
- `notebooks/03_feature_engineering.ipynb` — valid JSON; all 18 code cells compiled; no outputs are embedded. The notebook was not executed in a notebook frontend.
- Synthetic tests cover schema and leakage validation, optional inference fields, numeric/categorical handling, derived formulas, zero/missing behavior, train-only medians/scaling/encoding/selection, profile independence, batch transformation, artifact round-trip, class weights, and sparse/dense storage alignment.

#### Known Limitations and Next Action

- The current export lacks protocol/source port, timestamps, endpoints, and Flow ID. It is not appropriate to fit a categorical or address/time workflow on absent fields.
- The 8,000-row sample validates schema and transformer consistency only. It does not establish a final evaluation split, full-data statistics, model performance, or a benign anomaly baseline. The `anomaly` profile must later be fitted on the Phase 08 permitted training baseline.
- Phase 05 is complete. Begin Phase 06 only when separately requested.

### Session 09 — Multi-class classification and CIC-IDS2017 evaluation

**Date:** 2026-11-03
**Phase:** Phase 07 — Supervised ML: Multi-class Classification
**Status:** Completed; Phase 06 remains not started

#### Work Completed

- Read the Phase 07 request, project instructions and handoff, and Phase 04/05 policies and artifacts. Confirmed that Phase 06 has no classifier or artifacts to reuse; Phase 07 documentation explicitly records this sequencing limitation.
- Added a versioned taxonomy that preserves the 15 validated label strings, fixes `BENIGN` at ID 0, and rejects null, blank, or unknown labels rather than mapping them to benign.
- Added group-split feasibility checks and split auditing. Since 14 attacks occur in one source Parquet file each, a group-disjoint split cannot place every class in train, validation, and test. Applied the explicitly permitted, documented stratified-row fallback (70/15/15); all eight source files overlap among partitions.
- Added a stratified, training-only 80,000-row model-fit sample and full-training-partition class weights. A first real run revealed that a proportional sample could omit Heartbleed. Updated allocation to retain all training rows for classes with support at most 50, verified that behavior, and reran successfully.
- Implemented independent Phase 05 preprocessing for Logistic Regression and Random Forest, batch validation/test prediction, multiclass aggregate and per-class metrics, confusion analysis, bounded error-feature summaries, figures, model artifacts, metadata, and an original-label batch inference wrapper.
- Created `configs/multiclass.toml`, `src/intrusion_intelligence/multiclass/`, `tests/test_multiclass.py`, the Phase 07 notebook and report. Updated README, architecture, roadmap, handoff, and issue tracking.

#### Actual CIC-IDS2017 Results

- Full inventory: 2,830,743 rows, 78 predictive numeric features, and 15 classes. `BENIGN` is 80.3004% of rows; the majority/minority ratio is approximately 206,645:1. The rarest totals are Heartbleed 11, Infiltration 36, and Web Attack Sql Injection 21.
- Stratified-row partitions: 1,981,520 train; 424,611 validation; 424,612 held-out test. This split is exploratory because source groups and potentially duplicate flows overlap; it does not demonstrate cross-capture performance.
- Both models fit on the 80,000-row stratified training sample. Logistic Regression validation macro F1 was 0.4287 and ROC-AUC OVR macro 0.9903. It reached the configured 160-iteration limit and emitted a recorded `ConvergenceWarning`.
- Random Forest validation macro F1 was 0.8349 and ROC-AUC OVR macro 0.9959. It was selected by validation macro F1 alone. Its one-time held-out row-split test macro F1 was 0.8549, balanced accuracy 0.8804, accuracy 0.9974, ROC-AUC OVR macro 0.9969, and macro average precision 0.8804.
- Minority-class recall remains weak or uncertain: Bot 0.5492 (295 test rows), Web Attack Brute Force 0.6460 (226), Web Attack XSS 0.3265 (98). The Infiltration (5), SQL Injection (3), and Heartbleed (1) test supports are too small for reliable performance conclusions.
- XGBoost was not installed and was not trained. No dependencies were installed.
- Successful experiment ID: `20261103T134128Z`. Run report, structured summary, diagnostic tables, and figures are under `reports/evaluation/multiclass/`, `reports/experiments/multiclass/`, and `reports/figures/multiclass/`. Versioned Logistic Regression and Random Forest bundles are under `models/supervised/multiclass/`.

#### Testing and Validation

- Phase 07 synthetic tests cover taxonomy validation, group and fallback splits, rare-class sample retention, metrics including absent/unseen classes, Parquet inventory/loading, full synthetic model training, artifact reload, and original-label batch prediction.
- `python -m pytest -q` — 87 passed in 17.85 seconds. Pytest printed an ignored `pyreadline3` console-destructor `OSError` after the success summary.
- `python -m compileall -q src/intrusion_intelligence/multiclass tests/test_multiclass.py` — passed.
- `notebooks/05_multiclass_classification.ipynb` — valid JSON; all 16 code cells compiled; no embedded outputs. The notebook was not executed in a notebook frontend.
- `git diff --check` — passed; Git printed only expected LF-to-CRLF working-copy warnings for pre-existing line-ending settings.
- The real-data run completed both model fits, full validation prediction, selected-model test evaluation, artifact reload smoke prediction, and output generation.
- The first real attempt stopped before fitting because its training sample omitted the 11-row Heartbleed class. The fix is documented in ISSUE-010; the corrected real run trained successfully.

#### Known Limitations and Next Action

- Phase 06 was not completed or validated first. Phase 07 uses the Phase 05 API directly and records the gap.
- Group-disjoint evaluation cannot cover every class with the present source-file label distribution. Row split results are likely optimistic due to source and duplicate overlap.
- The model fit sees only an 80,000-row training sample. Rare classes with at most 50 training examples are retained in full, but that does not create enough independent data for reliable rare-class estimates.
- Phase 07 is complete as an exploratory benchmark and reusable workflow, not as evidence of production or cross-capture performance. Continue to Phase 06 only when requested; do not describe the Phase 07 row split as leakage-free.

### Session 10 — Benign-baseline anomaly detection and CIC-IDS2017 evaluation

**Date:** 2026-11-03
**Phase:** Phase 08 — Unsupervised Anomaly Detection
**Status:** Completed with documented capture-day, duplicate-overlap, and capture-shift limitations; Phase 06 remains not started

#### Work Completed

- Read the Phase 08 prompt, project control files, architecture, Phase 02–07 modules, model artifact conventions, installed Scikit-learn version, and Git status. Preserved the pre-existing Phase 07 work and made no commit.
- Added an independent `src/intrusion_intelligence/anomaly/` workflow with validated CIC-IDS2017 preparation, exact-label handling, capture-day partitions, deterministic benign-only sampling, duplicate-feature audit, independent Phase 05 anomaly preprocessing, Isolation Forest training, score orientation, benign-only multi-point calibration, held-out evaluation, per-attack/error reporting, versioned artifacts, frozen inference, CLI, and figures.
- Added `configs/anomaly_detection.toml`, `tests/test_anomaly_detection.py`, `docs/anomaly_detection.md`, and `notebooks/06_anomaly_detection.ipynb`. Updated README, architecture, roadmap, handoff, and this worklog; recorded the optional-metadata preflight bug as resolved ISSUE-011. No dependency was added. `gitlog.md` was not changed because there was no commit.
- The first real-data preflight stopped because optional contract metadata absent from the Phase 04 export was incorrectly required. The inventory now requires only predictive fields, target, and source provenance and reports absent optional metadata; the successful corrected run is recorded in ISSUE-011.

#### Actual CIC-IDS2017 Results

- Full inventory: 2,830,743 rows, 78 predictive features, and 15 original labels. Exact benign label: `BENIGN`.
- Capture-day partitions: Monday–Wednesday train 1,668,530 rows (1,402,023 BENIGN); Thursday validation 458,968 rows (456,752 BENIGN); Friday test 703,245 rows (414,322 BENIGN, 288,923 attacks). Day and source-file groups do not overlap. Validation attack labels did not enter calibration, and test labels did not choose a model or threshold.
- Preprocessing and Isolation Forest fit only on a deterministic 150,000-row benign training sample. The preprocessing profile uses median imputation and RobustScaler. Isolation Forest uses 200 estimators, `max_samples=4096`, `max_features=1.0`, `contamination="auto"`, bootstrap false, seed 42, and four jobs.
- Calibration uses 456,752 benign Thursday scores and the empirical upper quantile with `higher`. Configured targets 0.5%, 1%, 2%, 5%, and 10% achieved validation FPRs 0.4998%, 0.9999%, 2.0000%, 4.9999%, and 10.0000%, respectively. The default 1% point threshold is 0.52820603; equality is NORMAL.
- At that frozen threshold, Friday test TN/FP/FN/TP were 393,992 / 20,330 / 243,942 / 44,981. Attack precision 0.6887, recall 0.1557, F1 0.2540, test FPR 4.9068%, FNR 84.4315%, specificity 0.9509, balanced accuracy 0.5533, ROC-AUC 0.6941, and Average Precision 0.5494.
- Friday attack-category recall: DDoS 44,892/128,027 (35.0645%); PortScan 45/158,930 (0.0283%); Bot 44/1,966 (2.2380%). Twelve categories had no Friday test support. The benign DDoS capture file had 16,306/97,718 false positives (16.69%); PortScan capture 1,398/127,537 (1.10%); Friday Morning 2,626/189,067 (1.39%).
- The duplicate-vector audit found 95,479 repeated groups overall, 32,266 spanning capture days, and 28,644 crossing the chosen partitions (132,348 rows), including 633 groups with differing original labels. Duplicate links connect all five days, so a capture-day- and duplicate-group-disjoint three-way split is impossible. The evaluation is reported with this limitation rather than described as fully leakage-free.
- One-Class SVM and Local Outlier Factor were investigated but not implemented due to their computational cost at the available benign-population scale. Only Isolation Forest was trained. The anomaly score is `-score_samples`; higher means more anomalous and does not mean malicious with certainty.
- Run ID `20261103T141439Z`. Model artifact: `models/unsupervised/isolation_forest/1.0.0/`; fitted preprocessor: `models/unsupervised/preprocessing/anomaly/1.0.0/`. Evaluation, experiment summary, and figures are stored under the matching run-ID directories. The inference artifact reload smoke check passed.

#### Testing and Validation

- `python -m pytest tests/test_anomaly_detection.py -q` — 18 passed (synthetic fixtures; no full CIC dataset required by tests).
- `python -m pytest -q` — 105 passed in 23.03 seconds.
- `python -m compileall -q src/intrusion_intelligence/anomaly tests/test_anomaly_detection.py` — passed.
- `notebooks/06_anomaly_detection.ipynb` — valid JSON; all 26 required sections present and all 7 code cells compile. Notebook cells were not executed in a Jupyter frontend; the actual run was executed through the CLI/service.
- `git diff --check` — passed after removing whitespace flagged in the new issue entry. Git may print line-ending conversion warnings for changed Windows working copies.
- The full actual-data model fit, benign validation scoring/calibration, held-out test evaluation, artifact reload prediction, and report/figure generation completed. Structured false-negative, error-analysis, and confusion-matrix outputs were added from the saved completed-run metrics and tables.

#### Known Limitations and Next Action

- The 1% validation target did not hold on Friday: test FPR was 4.91%; benign DDoS-capture traffic showed a 16.69% false-positive rate.
- Duplicate feature vectors and conflicting labels cross day partitions. The test includes only DDoS, PortScan, and Bot, so no claim is made about other attack families.
- Phase 06 binary classification remains not started. Phase 09 integration and results are recorded in Session 11 below. Phase 10 Explainable AI is the next roadmap phase; do not treat the current heuristic alert scores as probabilities or operational validation.

---

### Session 11 — Threat intelligence and alert correlation

**Date:** 2026-11-03
**Phase:** Phase 09 — Threat Intelligence & Alert Correlation
**Status:** Completed with Phase 06 and CIC metadata limitations documented

#### Objective

Integrate available detector outputs into traceable flow events, configurable heuristic scores, severity, temporal correlation, alerts, reports, and a reusable offline pipeline without training or recalibrating models.

#### Work Completed

- Inspected Phase 05 metadata separation, Phase 07 `MultiClassPredictor`, Phase 08 `AnomalyPredictor`, saved model artifacts, project configuration/reporting conventions, data fields, controls, tests, and Git status. Phase 06 binary classification has no trained artifact or prediction interface; precomputed binary results are accepted by the reusable interface and actual binary evidence is marked unavailable.
- Added `src/intrusion_intelligence/intelligence/` modules for typed schemas, detector-output normalization, ECDF reference, weighted scoring, severity bands, flow events, correlation, alert generation/deduplication, reporting, service orchestration, and CLI. Added `configs/intelligence.toml` and a console command in `pyproject.toml`. No package dependency was added.
- The actual service reuses the saved Phase 07 Random Forest (`multiclass-random_forest-v1.0.0`) and Phase 08 Isolation Forest (`isolation-forest-v1.0.0`, `target-fpr-1pct`) after checking feature-schema versions and exact feature ordering. Models are loaded once and scored in batches of 500. The Phase 08 frozen anomaly model rescored 456,752 Thursday BENIGN validation rows for an ECDF reference; no model training or threshold recalibration was performed.
- During final input-boundary review, excluded both `label` and `__source_label` from Friday detection inputs. Source file, row number, and record ID remain as provenance. Destination port is investigation context copied after prediction; row order is not used as time.
- Defaults: score weights binary 0.30, multiclass 0.25, anomaly 0.45, with available-signal weight renormalization; severity bands LOW 0–24, MEDIUM 25–49, HIGH 50–74, CRITICAL 75–100. The score is heuristic evidence prioritization, not probability of compromise. Correlation rules include source IP, destination IP, destination service, attack category, and repeated flow tuple, with configured 1/5/15-minute windows (5 minutes by default).
- Implemented evidence-based single-flow/correlated alert conditions, NEW lifecycle status, provenance references, explanations, deterministic IDs/fingerprints, repeated-alert deduplication, and severity updates. Fingerprints omit volatile processing timestamps while raw prediction timestamps remain preserved.
- Added `tests/test_intelligence.py` with 44 synthetic tests. Added `docs/threat_intelligence.md`, `docs/alert_correlation.md`, and the 21-section `notebooks/07_threat_intelligence.ipynb`; updated README, architecture, roadmap, handoff, and issue tracking. Resolved ISSUES-012 and -013 record fingerprint instability from prediction timestamps and selection of the source-label column, respectively.

#### Actual CIC-IDS2017 Integration Run

- Run `20261103T145019Z` sampled the first 1,000 rows from each of three Friday Parquet files (3,000 flows). Friday target and source-label fields were not loaded or used.
- Flow statuses: 2,923 NORMAL, 20 MALICIOUS_PREDICTION, 56 ANOMALOUS, and 1 SUSPICIOUS. There were 20 supervised-positive/anomaly-normal disagreements and 56 anomaly-positive/multi-class-BENIGN disagreements.
- Generated 76 individual flow alerts: 75 HIGH and 1 CRITICAL. Predicted-category counts in alerts were Bot 18, DoS Hulk 1, PortScan 1. These are model outputs, not ground-truth label counts.
- No correlated groups were generated. Timestamp, source/destination IP, source port, protocol, and Flow ID are absent from Phase 04 output; all five rules therefore skipped the 77 suspicious events due to missing timestamps. No source-row timing was inferred.
- Outputs are under `reports/intelligence/20261103T145019Z/` with figures under `reports/figures/intelligence/20261103T145019Z/`. They include JSONL flow events, JSON groups and alerts, CSV summaries, JSON/Markdown run summaries, configuration snapshot, and three plots.

#### Testing and Validation

- `python -m pytest tests/test_intelligence.py -q` — 44 passed.
- `python -m pytest -q` — 149 passed in 30.98 seconds. Pytest printed an ignored `pyreadline3` console-destructor `OSError` after the success summary.
- `python -m compileall -q src/intrusion_intelligence/intelligence tests/test_intelligence.py` — passed.
- Notebook JSON validated; all 21 numbered sections are present and all 18 code cells compile. The notebook was not executed in a Jupyter frontend; actual inference ran through the CLI/service.
- `git diff --check` — passed after removing whitespace flagged in new issue metadata. Expected LF-to-CRLF working-copy warnings may appear. No commit was made and `gitlog.md` was unchanged.

#### Known Limitations and Next Action

- Phase 06 remains unimplemented. The actual run cannot provide binary model evidence.
- Phase 04 lacks the fields required for temporal network correlation; the real run demonstrates skipped correlation, while synthetic tests exercise the rules.
- The actual model sample is bounded and exploratory. The Phase 07 row-split and Phase 08 Friday false-positive limitations remain; scores and alerts are not ground truth or operational validation.
- Phase 09 is complete. Phase 10 — Explainable AI is the next roadmap phase only when requested; it was not started here.

---

### Session 12 — Phase 09 remediation and evidence validation

**Date:** 2026-11-03
**Phase:** Phase 09 — Threat Intelligence & Alert Correlation (with Phase 06 binary dependency)
**Status:** Completed with capture-shift and unavailable network metadata limitations documented

#### Work completed

- Reproduced the actual-data binary training failure. The CIC reader returned original labels such as `DDoS` and `PortScan`, while the new binary training code only mapped literal `BENIGN` and `ATTACK`; other attack classes became null. Corrected the mapping to preserve source labels and map every non-empty non-BENIGN value to ATTACK. Added a fail-closed guard for missing labels. Ensured the SQLite duplicate-signature database closes on exceptions.
- Trained the versioned binary Random Forest using the Phase 05 tree preprocessing contract and capture-day/source-file split. Excluded duplicate feature vectors shared with validation/test from training, used a fixed threshold of 0.5, and persisted checksummed classifier/preprocessor/metadata files under `models/supervised/binary/random_forest/1.0.0/`.
- Integrated the persisted binary model into Phase 09. The input path now separates Friday labels from features; the labels are only used to choose an evenly spaced per-label research sample and in a distinct after-alert metric pass. Detection records, model inputs, evidence scores, and alerts contain no ground-truth label values.
- Corrected the first integration sample design after discovering the first 1,000 rows per file were all BENIGN. The final sample is deterministic and label-stratified (500 per label in each Friday source file), bounded at 3,000 rows, and clearly reported as stratified rather than prevalence representative.
- Added metadata provenance statuses, explicit event/alert missing-detector evidence, model versions, severity rationale and confidence limitations, an offline-only ground-truth status, configuration fingerprinting, six correlation rules, naive-time rejection, duplicate-event suppression, and detailed per-rule eligibility/skip/group counters. Existing default score weights and severity thresholds were retained.
- Added binary target/inference/artifact-manifest tests and Phase 09 tests for label-stratified selection, timezone-naive timestamps, duplicate events, alert metadata, and six-rule config. Updated README, architecture, threat-intelligence/correlation docs, roadmap, handoff, and this worklog. Added ISSUE-014 and ISSUE-015 below.

#### Actual results

- Final binary artifact experiment `20261103T160232Z` produced model v1.0.1 with an explicit inventory of all 14 source attack labels mapped to ATTACK; prior v1.0.0 remains preserved. The measured fit/split results remain the same as the preceding deterministic experiment: all 2,830,743 cleaned rows; train Monday–Wednesday 1,668,530 rows, validation Thursday 458,968, test Friday 703,245. Duplicate screening excluded 53,497 validation rows matching final test and 2,915 training candidates matching evaluation data. Training retained 77,085 candidates (64,506 BENIGN; 12,579 ATTACK). Friday test: accuracy .7045, balanced accuracy .6406, attack precision .9965, recall .2818, F1 .4394, ROC-AUC .7385, Average Precision .7205, FPR .00068. At the predeclared threshold, Thursday attack recall was .0055 despite ROC-AUC .9883; this shows the strong capture/distribution shift and argues against threshold tuning on the final test.
- Latest actual CLI run `20261103T160444Z`: 3,000 rows, 1,500 BENIGN and 1,500 ATTACK (Bot/DDoS/PortScan, 500 each). All three models produced evidence for 3,000 rows. It generated 871 research alerts (552 HIGH, 319 CRITICAL). Binary precision/recall were .9969/.2133; alert precision/recall were .9908/.5753 and FPR .00533 on this balanced sample. Bot, DDoS, and PortScan multiclass recalls were .588, .998, and .996. Equal weights raised recall to .7047 at precision .9991 on this sample; default weights remained because this single bounded experiment is not sufficient calibration evidence.
- The Phase 04 export provided 3,000 destination-port context values but zero timestamp, source IP, destination IP, source port, protocol, or Flow ID values. Six rules each skipped all 1,407 suspicious events for missing timestamps; 8,442 rule-event skips in total, no eligible rows, no correlation groups, and zero real-data correlation coverage. No row-order or label-based links were introduced.
- Summary fingerprint: `26e002101819b2a57d3dddff631840d48715d7bc6c2d4da485ff731a9fd0f42b`. Reports are under `reports/intelligence/20261103T160444Z/` and figures under the matching `reports/figures/intelligence/` path.

#### Verification

- `python -m compileall -q src tests` — passed.
- Final `python -m pytest -q` — 155 passed in 13.60 seconds. Pytest printed an ignored `pyreadline3` console-destructor `OSError` after the success summary.
- `python -m pytest tests/test_binary.py -q` — 3 passed; binary artifact metadata/checksum and predictor API fixtures are synthetic. Actual artifact loading and prediction were exercised by the real Phase 09 run.
- Actual binary experiment completed and actual Phase 09 CLI workflow completed. Phase 09 outputs keep labels in a separate offline evaluation report and show `ground_truth_evaluation_status: not_evaluated` on individual alerts.

#### Limitations and next action

- The binary model has strong ranking scores but poor validation threshold recall and limited Friday attack recall; the classifier is not deployment-validated. Phase 06's Logistic Regression comparison remains outstanding.
- Alert precision from a balanced stratified sample is not population alert precision. Equal-weight sensitivity is informative but not adequate to change defaults. Severity thresholds have no empirical severity calibration.
- CICFlowMeter metadata is unavailable in the processed export. Synthetic tests validate rules; the real dataset demonstrates only honest skip behavior. External official metadata was not joined to these records.
- Phase 10 Explainable AI remains not started. Do not begin it without the user's separate request.

---

### Session 13 — Phase 06 Logistic Regression comparison

**Date:** 2026-11-03
**Phase:** Phase 06 — Supervised ML: Binary Classification
**Status:** Completed; Phase 09 preserved as complete; Phase 10 not started

#### Work completed

- Inspected the existing Phase 06 Random Forest v1.0.1 experiment, its saved report/artifact, Phase 05 schema/preprocessing, CIC capture-day files, target mapping, and duplicate-vector rules. Kept Random Forest and Phase 09 logic/artifacts unchanged.
- Added a separate Logistic Regression config, runner, CLI, checksummed bundle loader/saver, and inference wrapper. The workflow repeats the RF temporal split, deterministic 80,000-candidate training sample, exact feature-vector screening, target mapping, and evaluation partitions. Median imputation and StandardScaler are fitted only on training X. The fixed threshold is 0.5; a sensitivity grid is validation-only.
- The first two full runs completed model fitting and both evaluations but failed during final report assembly (missing manifest size in caller metadata, then missing `report_directory` in the summary). Fixed both issues and preserved their v1.0.0/v1.0.1 artifacts. The final v1.0.2 full CLI run completed with exit code 0 and wrote all report files. Added ISSUE-016.
- Added focused tests for binary mapping/missing labels, original label preservation, feature/target boundary, duplicate-vector signature matching, metric and threshold validation, deterministic fit, artifact serialization/checksums, and probability inference.
- Added `docs/binary_classification.md`; updated architecture, README, roadmap, handoff, fixes, and worklog. Phase 06 is now complete as a research comparison, with no production promotion. Phase 09 completion is preserved and Phase 10 is not started.

#### Actual results

- Final experiment `20261103T163706Z`, Logistic model `binary-logistic_regression-v1.0.2`, trained on 77,085 rows (64,506 BENIGN; 12,579 ATTACK), validated on 405,471 Thursday rows, and tested on 703,245 Friday rows using all 78 predictive features. Duplicate exclusion removed 53,497 Thursday rows shared with Friday and 2,915 training candidates shared with evaluation vectors.
- Logistic validation at 0.5: ROC-AUC .768132, AP .011510, attack precision .001112, recall .011431, F1 .002027, accuracy .939276, FPR .055693; confusion matrix `[[380824,22460],[2162,25]]`.
- Logistic Friday at 0.5: ROC-AUC .817022, AP .804709, attack precision .841251, recall .471980, F1 .604698, accuracy .746475, FPR .062109; confusion matrix `[[388589,25733],[152557,136366]]`.
- RF Friday reference: ROC-AUC .738459, AP .720452, attack precision .996549, recall .281840, F1 .439408, accuracy .704548, FPR .000681. RF inference time is unavailable because the persisted report did not record it; RF was not rerun. Logistic fit took 3.976 seconds, Thursday/Friday predict-plus-transform took 1.414/2.108 seconds, and its bundle is 61,456 bytes; RF fit took 2.459 seconds and its bundle is 1,161,628 bytes.
- On Friday Logistic has better ROC-AUC, AP, recall, F1 and accuracy; RF has higher precision and much lower FPR. AP varies strongly with prevalence (Thursday .54%, Friday 41.08%). These are capture-shift observations on one benchmark, not generalization claims. Default production selection did not change.

#### Verification

- `python -m compileall -q src tests` — passed.
- `python -m pytest -q` — 161 passed in 40.85 seconds. Two non-failing scikit-learn 1.8 `penalty="l2"` deprecation warnings came from the new estimator unit test; pytest also emitted an ignored `pyreadline3` destructor `OSError` after its success summary.
- Loaded the actual Logistic bundle; classifier and preprocessor checksums matched. Recomputed metrics from both saved prediction Parquets and verified exact row counts, confusion matrices, and numeric metrics. Verified the persisted Random Forest report metrics agree with its artifact metadata/checksums without running RF inference.
- `git diff --check` — passed; Git emitted only expected LF-to-CRLF working-copy notices for tracked files.

#### Limitations and next action

- Logistic Regression trades higher Friday recall for a materially higher FPR and lower attack precision. Neither model is selected automatically for deployment.
- RF prediction duration is unavailable; no estimate was substituted.
- The model uses a deterministic bounded training sample and one held-out Friday capture. Independent temporal/capture validation remains necessary for deployment claims.
- Phase 09 is unchanged and complete. Phase 11 Model Evaluation & Validation is next.

### Session 13 — Phase 10 SHAP explainability

- Inspected the five persisted Phase 06–08 model bundles, class taxonomy, preprocessing metadata, output contracts, Phase 09 event/alert output, SHAP, scikit-learn, and XGBoost availability. Aligned the project virtual environment to scikit-learn 1.8.0 to match saved artifact versions; SHAP 0.54.1 and Matplotlib are installed in the existing `.venv`.
- Implemented a reusable `src/intrusion_intelligence/explainability/` subsystem: validated artifact registry, deterministic training-only backgrounds, transformed/original feature mapping, Tree/Linear/Permutation SHAP selection, array-shape normalization, additivity checks, local/global outputs, plot/report generation, CLI, and Phase 09 explanation-reference sidecars.
- Ran actual Phase 10 CLI run `20261103T182807Z`: five persisted models, 33 output targets, 264 local records, 2,574 global importance records, 3,000 event sidecars, 871 alert sidecars, and 33 SHAP plots including selected local waterfalls. The 100-row backgrounds are Monday–Wednesday training only; the anomaly background is BENIGN-only. All 33 output reconstruction checks passed. Eight selected events/alerts have local reference links; original score/severity/correlation fields are retained. Measured explanation/plot runtime was 67.13 seconds. Logistic Regression records label predictions correctly and record binary thresholds in the explanation output's units. Reports identify each explainer's selection reason, input representation, mapping coverage, and approximation settings.
- Added `tests/test_explainability.py` covering deterministic/benign-only synthetic background sampling, synthetic classifier/anomaly explainers, output shape normalization, feature grouping, signed contributions, report serialization, plot persistence, and Phase 09 sidecar invariants. Focused suite: 6 passed. Final full suite: 167 passed with two pre-existing scikit-learn Logistic Regression deprecation warnings.
- Added `docs/explainability.md` and `notebooks/08_explainability.ipynb`; updated README, roadmap, handoff, fixes, and this worklog. No `gitlog.md` update because no commit was made. Phase 11 remains unstarted.

### Session 14 — Phase 11 comprehensive model evaluation

- Added the reusable `src/intrusion_intelligence/evaluation/` package: classification and anomaly metrics, threshold/calibration reports, evidence classification, split/duplicate audit, uncertainty helpers, controlled train-only ablation, input stress, inference benchmark, reporting pipeline, and CLI. Added `configs/evaluation.toml` and the `intrusion-evaluate` entry point. The evaluation bundle uses existing saved results and predictions without retraining or overwriting model artifacts.
- Generated final actual run `reports/evaluation/comprehensive/20261103T223701Z/`, charts under `reports/figures/evaluation/20261103T223701Z/`, and warm timings under `reports/benchmarks/20261103T223701Z/`. It reanalyzes saved binary Logistic scores, includes saved RF/multiclass/anomaly scores with previously inspected provenance, validates five model bundles, and tests actual model interfaces with 64 label-free feature rows plus deterministic synthetic perturbations. Figures include binary ROC/PR, threshold sensitivity, capture recall, multi-class per-class recall, Logistic reliability, and anomaly FPR sensitivity.
- Friday binary Random Forest saved metrics: ROC-AUC .738459; average precision .720452; precision .996549; recall .281840; F1 .439408; FPR .000681. Binary Logistic Regression recomputed from saved predictions: ROC-AUC .817022; average precision .804709; precision .841251; recall .471980; F1 .604698; FPR .062109. Multi-class Random Forest reused row-split metrics: accuracy .997442; balanced accuracy .880381; macro F1 .854852; weighted F1 .997414. Isolation Forest at the saved target-1%-validation-FPR point: measured Thursday validation FPR .009999; Friday FPR .049068; recall .155685; precision .688720; F1 .253962; ROC-AUC .694092; AP .549409. Prior partition metrics are exploratory and previously inspected, not fresh independent test results.
- Leakage/generalization review retains binary duplicate-screening counts, 28,644 anomaly cross-partition duplicate groups, 633 conflicting-label groups, class-specific capture limitations, missing within-capture timestamps/endpoints, and absent CIC-IDS2018/UNSW-NB15. Real-data ablation and cross-group confidence intervals are unavailable. Binary Logistic calibration is descriptive; Random Forest/multiclass probabilities were not saved. Threat correlation remains synthetic-test-only; incident truth is unavailable. Saved SHAP diagnostics: 264/264 passed.
- Five saved models accepted synthetic missing/extreme/zero-rate inputs with finite outputs, and rejected a missing required feature and infinity. Warm measurements separately capture preprocessing and output calls at batches 1/16/64; they are local sample benchmarks, not production capacity evidence.
- Added 10 synthetic evaluation tests. Focused evaluation suite: 10 passed in 2.20 seconds. Full suite after the final metric helper change: 177 passed in 12.57 seconds with two scikit-learn Logistic Regression deprecation warnings. `compileall`, notebook JSON validation (24 sections), and `git diff --check` passed. Matplotlib could not write a user font-cache lock but emitted all requested figures. Added methodology and inventory docs and the 24-section notebook; README, roadmap, handoff, fixes, and worklog updated. No commit was made; `gitlog.md` is unchanged. Phase 12 Backend Development is next.
### Session 15 — Phase 12 FastAPI and PostgreSQL backend

**Date:** 2026-11-04

- Inspected Phase 02/04–11 feature, model, explainability, intelligence, evaluation, configuration, and Git state before implementation. Reused the Phase 05 78-feature contract, Phase 06 binary predictors, Phase 07 multiclass predictor, Phase 08 Isolation Forest predictor, and Phase 09 event/scoring/alert pipeline without retraining or changing thresholds.
- Implemented a modular FastAPI `/api/v1` backend with typed Pydantic request/response schemas, structured errors and request IDs, local-only defaults, explicit CORS allowlists, upload/request/analysis limits, bounded dataset validation and generated storage names, model registry metadata, actual artifact validation and cached inference, persisted analysis results, in-process dataset jobs, alert filtering/transitions, DB-backed metrics and traffic summaries, and liveness/readiness checks.
- Added SQLAlchemy 2 models for datasets, model registry, jobs, events, alerts, and alert-event links; PostgreSQL JSONB variants, foreign keys, indexes, fingerprints, and active-job uniqueness are versioned in Alembic migration `20261104_0001`. Added PostgreSQL 16 Docker Compose service, API Dockerfile, `.dockerignore`, backend config placeholders, dependency extras, README instructions, and backend architecture/API/database references.
- Added 10 endpoint integration tests using isolated SQLite and explicit synthetic detector outputs. Focused API suite: 10 passed. Final full project suite: 188 passed, with one Starlette TestClient/httpx deprecation and two existing scikit-learn Logistic Regression deprecations. The sandboxed Windows runner stalled creating an asyncio socketpair; tests passed outside the sandbox.
- Started local Docker Desktop and a loopback PostgreSQL 16 container with the `.env.example` placeholder password. `alembic upgrade head` and `alembic current` passed; current revision is `20261104_0001`. A separate PostgreSQL-backed API check analyzed one feature-only CIC-IDS2017 Parquet row (78 contract features; label excluded) with binary RF v1.0.1, multiclass RF v1.0.0, and Isolation Forest v1.0.0. API returned 200, readiness was `ready`, one NORMAL/LOW detection event persisted, no alert was generated, and `/metrics` plus `/traffic/summary` reported the actual stored event.
- A focused API test first found an incorrect `DetectionEvent.created_at` ordering reference in alert details; changed it to `generated_at` and verified alert details plus supporting event IDs through the passing suite. Job tests were also updated to provide the real `resolve_model` service contract in their synthetic test double. Added cancellation for queued/running jobs, effective at batch boundaries.
- Built and started the final Docker API image. The first startup revealed missing Alembic files and a relocated anomaly-preprocessor path; fixed both and verified Compose startup, migration check, ready status, and all five actual model bundles. Pinned scikit-learn to the 1.8.0 version used by saved artifacts. An actual label-free CIC feature row sent to the Docker API returned 200, persisted one NORMAL/LOW event to PostgreSQL, produced no alert, and was reflected in database metrics. The PostgreSQL and API containers remain running with their test database volume.
- Added `docs/backend_architecture.md`, `docs/api_reference.md`, and `docs/database.md`; updated README, roadmap, handoff, and fixes. Phase 12 is complete; Phase 13 dashboard is the exact next phase. No model artifacts were changed. No commit was made and `gitlog.md` remains unchanged.

### Session 16 — Phase 13 dashboard validation

- Installed the requested dashboard extra with `python -m pip install -e ".[dashboard]"`; Streamlit, Plotly, and HTTPX imported successfully and `python -m pip check` reported no broken requirements. The complete suite initially found two existing SHAP tests could not run because the environment lacked the project's optional `explainability` extra. Installed the already-declared extra with `python -m pip install -e ".[explainability]"`; this added SHAP 0.54.1 and its declared dependencies without changing project dependency declarations.
- Hardened the shared dashboard HTTP client against malformed URL configuration, unsafe URL credentials, timeout/connection failures, HTTP and non-JSON error responses, invalid JSON, and non-object success payloads. Errors are safe for UI display and do not echo payloads or raw exception details. Added request-shape tests for actual GET/POST/multipart contracts. Replaced export serialization's implicit DataFrame dependency with explicit CSV/JSON serialization that handles nested fields and empty results.
- Added defensive page response helpers and tested all nine page renderers for navigation, empty data, API failures, malformed summaries, honest explainability messaging, and alert list/detail/export controls. Expanded dashboard tests to verify upload success/failure and malformed responses, analysis-job submission/status/failure feedback, plus export MIME types and filenames. The final dashboard-focused suite passed **10 tests**. Added `.streamlit/config.toml` after browser testing found Streamlit's automatic multipage links opened blank renderer modules; the duplicate menu is now hidden, leaving the intended shared-shell radio navigation.
- Started the actual Streamlit app at `http://127.0.0.1:8501` against the live local API and used browser navigation to check Overview, Traffic Analysis, Attack Analysis, Detection Alerts, Anomaly Analysis, Model Performance, Explainability, Dataset Management, and System Health. Each page heading rendered with no browser-visible exception. A change in the optional dependency environment first left the prior browser connection displaying stale state; reopening/rerunning showed the updated app and custom navigation.
- Docker Engine was unavailable from this environment, so the current HTTP integration used the backend's existing SQLite configuration with a uniquely named disposable database and the current Alembic migration. The real backend reported health `alive` and readiness `ready`; `/models` listed all five real model bundles. A temporary one-row CSV containing the 78 approved predictive feature columns registered with HTTP 201 and appeared in dataset listing. A real analysis job submitted to `/analysis-jobs` returned HTTP 202 and completed with one processed/successful record and zero failures using binary RF v1.0.1, multi-class RF v1.0.0, and Isolation Forest v1.0.0. Job GET, `/traffic/summary`, `/alerts`, and `/metrics` all returned HTTP 200 and reflected the persisted result. The fixture was benign and generated no alert; local CSV export serialized to zero bytes and JSON export to `[]`. There is no backend export route, and the dashboard does not invent one.
- Ran `python -m pytest -q` after installing the existing SHAP extra and before the optional-label metadata correction: **196 passed, 0 failed** in 50.67 seconds. Two existing scikit-learn `penalty="l2"` deprecation warnings remain. The first full-suite run (before SHAP installation) had 194 pass and 2 failures due only to the missing optional SHAP package; no tests were skipped or weakened.
- Updated dashboard architecture/user docs, system architecture, README setup and test commands, Phase 13 roadmap status, handoff status, and the issue register. The docs specify dashboard installation, backend configuration/startup, all pages, dataset upload, jobs, alert exports, troubleshooting, API limits, and the SQLite integration test context. No Phase 14 work was started. No raw dataset, production database, model artifact, or detection algorithm was changed; no commit was made.
- During final log review, the successful feature-only upload was found to have `inspection_status=invalid` despite the dataset being `VALIDATED`; the inspector's default label requirement conflicted with the API's explicit optional-target contract. Added a `require_label` inspection option (default remains required) and set it false only for uploads. The regression tests confirm normal labelled inspection remains strict, while a live feature-only CSV upload returned HTTP 201 with `inspection_status=valid` and `label_present=false`. The affected suites passed **47 tests**. Final `python -m pytest -q`: **197 passed, 0 failed** in 41.09 seconds with the same two scikit-learn deprecation warnings.
- Additional dashboard regression coverage exposed silent handling of empty object responses from dataset upload and job-status endpoints. Dataset Management now verifies that uploads include a usable dataset ID and reports malformed job-status responses instead of silently showing nothing. Tests also cover backend job submission errors and assert the actual download-button filename/MIME arguments. The final dashboard suite passed **10/10**; the final full `python -m pytest -q` run passed **199 tests** with two existing scikit-learn deprecation warnings.
- Final checks: Streamlit 1.66.1, Plotly 6.9.0, and HTTPX 0.28.1 imported; `python -m pip check`, `python -m compileall -q dashboard api src/intrusion_intelligence/ingestion tests`, and `git diff --check` passed. No Ruff/Black configuration or installed Ruff command is present, so no separate linter was run. The only API base URL in dashboard code is its documented configurable loopback default. No SQLite/database/temp validation files were created in the repository, and ports 8179/8501 were no longer listening after service shutdown.
## Phase 14 Worklog — Event Retrieval, Real SHAP Integration, and Local Validation

**Date:** 2026-11-04
**Status:** In Progress; current PostgreSQL verification remains outstanding because Docker Engine was inaccessible and the installed local PostgreSQL service could not be opened or started.

### Investigation and implementation

- Audited existing routes, ORM, dataset upload/job paths, detector evidence, Phase 10 model registry/explainers, and the project `.venv`. Existing event records were persisted but lacked list/detail routes. Events from registered datasets did not carry stable row numbers into jobs. Inline analysis did not store input feature rows. The Phase 10 SHAP layer already supports Random Forest, Logistic Regression, multi-class outputs, and Isolation Forest through their correct output spaces, fitted preprocessing, and training-only backgrounds.
- Installed `.[dashboard]` into `.venv` after the sandboxed attempt could not resolve PyPI. `.venv` now has Streamlit 1.66.1, Plotly 6.9.0, and HTTPX 0.28.1. `pip check` found no broken requirements.
- Added paginated `GET /events` filters (dataset, job, status, severity), typed `GET /events/{event_id}` detail, safe detector evidence payloads, and appropriate 404/422 behavior.
- Added dataset-backed stable `dataset:<uuid>#row=<n>` references and 1-based source row provenance for synchronous and job analysis. Original upload CSVs remain unchanged; explanation reads a single row only.
- Added `GET /events/{event_id}/explanation?engine=...`. It chooses the model attached to the persisted detector evidence, transforms the exact stored source row with that artifact's fitted preprocessor, uses Phase 10 training-only background selection and SHAP session, checks additivity, returns model output semantics and raw/transformed values, and persists successful results/references on the existing event record. Inline events without a registered source file report unavailable; unsupported models are explicit. Added nullable `explanation_data` and Alembic migration `20261104_0002`.
- Updated Explainability UI to retrieve event details and request explanations using those routes. No fabricated attribution fallback is present.

### Verification performed in this session

- `.venv\\Scripts\\alembic.exe upgrade head` against a disposable SQLite DB — revisions `20261104_0001` and `20261104_0002` applied.
- End-to-end TestClient integration against an isolated SQLite DB: contract-valid one-row feature CSV upload **201**, actual binary inference **200**, event listing/detail **200**, and actual `binary-random_forest-v1.0.1` SHAP explanation **200**. Availability was `available`; output space was attack probability; additivity max absolute residual `1.3825522948707203e-09`, `passed=true`.
- API/dashboard focused tests — 20 passed after adding fake event list support.
- Full `.venv\\Scripts\\python.exe -m pytest -q` — **200 passed, 0 failed, 0 skipped**, 3 warnings (Starlette/httpx deprecation and two scikit-learn `penalty` deprecations); exit code 0.
- Started API (`127.0.0.1:8179`) and Streamlit (`127.0.0.1:8501`), opened the local dashboard in browser, and verified all nine page headings through the radio navigation with no browser-visible exceptions.
- Docker Engine access failed with permission denied to `npipe:////./pipe/dockerDesktopLinuxEngine`; no PostgreSQL/Compose validation was attempted in that session. Phase 12 PostgreSQL evidence is historical, not current.

### Changes and remaining gate

Updated `api/`, `alembic/`, `dashboard/`, API/dashboard tests, API/dashboard/system architecture docs, README, roadmap, handoff, fixes, worklog, and the integration readiness report. No original CIC-IDS2017 CSV or trained model artifact was modified; no data cleaning, feature engineering, training, Phase 15 work, or commit was performed. Phase 14 remains **In Progress** until PostgreSQL-backed migration, readiness, event retrieval, actual model explanation, restart persistence, dashboard connectivity, and remaining page-state acceptance checks pass.

## Phase 14 Follow-up — Local PostgreSQL Blocker Inspection (2026-11-04)

- Inspected Windows services and discovered `postgresql-x64-18`, PostgreSQL 18.4 installed under `C:\Program Files\PostgreSQL\18`, service status Stopped and startup type Manual. `psql`, `postgres`, and `pg_ctl` each reported version 18.4.
- Read the local server configuration without changing it: port 5432 and `listen_addresses='*'`. No PostgreSQL listener was present on the configured port.
- The project has no default database URL: `NII_DATABASE_URL` is required by SQLAlchemy runtime and Alembic. It was unset; no secrets were displayed.
- Attempted to start the existing service through the elevated command path. Windows returned “Cannot open ... service”. The service remains stopped; no configuration, cluster, database, or user data was modified.
- Result: no TCP/authentication test, disposable DB creation, PostgreSQL migration, API workflow, restart persistence, or PostgreSQL-backed dashboard verification could be performed. No test database needed cleanup. Phase 14 remains In Progress; Phase 15 was not started.
- Updated the integration-readiness report, database guide, roadmap, and handoff with the exact current blocker and safe next steps. No source code or service settings changed in this follow-up.
- Follow-up checks: `Test-NetConnection 127.0.0.1 -Port 5432` returned `TcpTestSucceeded=False`; `pip check` and `compileall` passed; `git diff --check` passed with existing line-ending notices. A fresh full `pytest -vv` collected 200 tests and passed the first 19, then stalled in `test_app_initialization_openapi_health_readiness_and_cors`; it was interrupted without an exit summary and is not a completed suite result. The prior 200-pass result remains historical to the immediately preceding Phase 14 session.

## Phase 14 Resume — PostgreSQL Service Recheck and Test Completion (2026-11-04)

- Elevated service inspection reported `postgresql-x64-18` Running (Manual); elevated TCP probe connected to `127.0.0.1:5432`.
- Actual server login was attempted with `psql` as both `postgres` and the current Windows account, with password prompting disabled. Both failed with `fe_sendauth: no password supplied` (psql exit 2). The project `.env` is absent, inherited `NII_*`/`PG*` variables are absent, and standard user `pgpass.conf` locations are absent. `NII_DATABASE_URL` is required by runtime/Alembic; there is no built-in default credential. No passwords were reset, no authentication settings changed, and no database was created or touched.
- Targeted prior stall test `.venv\Scripts\python.exe -m pytest -vv tests/test_api.py::test_app_initialization_openapi_health_readiness_and_cors` passed when executed with loopback access enabled: 1 passed, 1 warning, exit 0. Faulthandler confirmed restricted runner was blocking Windows asyncio's local socketpair; this was a runner permission issue rather than a test assertion failure.
- Full suite `.venv\Scripts\python.exe -m pytest -q`, run with loopback access enabled, completed: 200 passed, 0 failed, 0 skipped, 3 warnings, exit 0 (Starlette/httpx deprecation and two scikit-learn penalty deprecations). This suite uses existing SQLite fixtures and is not PostgreSQL verification.
- `pip check`, `compileall -q api dashboard src tests`, and `git diff --check` all passed (exit 0); Git emitted existing LF-to-CRLF notices for tracked files.
- PostgreSQL database creation, migrations, schema inspection, dataset/job/event/explanation persistence, restart checks, model-family route checks, and PostgreSQL-backed dashboard/browser checks remain blocked until an authorized PostgreSQL login is configured. Phase 14 remains In Progress; Phase 15 not started.
- In the subsequent resume task, user confirmed pgAdmin authentication for the existing PostgreSQL server. The password was not shared in chat and is not available in this process environment or standard local credential files. `psql` therefore remains blocked with “no password supplied”; this does not contradict the user-reported pgAdmin connection. The full suite was rerun with loopback access enabled: 200 passed, 0 failed, 0 skipped, 3 warnings, exit 0. `pip check`, `compileall`, and `git diff --check` passed. PostgreSQL integration remains blocked pending an approved credential source.
