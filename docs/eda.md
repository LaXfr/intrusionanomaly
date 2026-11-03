# CIC-IDS2017 exploratory data analysis

## Scope and provenance

Phase 03 uses the existing Phase 02 discovery, schema validation, and chunked CSV loader. The analysis is read-only: it does not clean, impute, remove, normalize, or rewrite source values. Dataset identity and collection context are documented at the [official CIC-IDS2017 page](https://www.unb.ca/cic/datasets/ids-2017.html). The controlled five-day weekday schedule is a benchmark limitation; the [Engelen, Rimmer, and Joosen case study](https://ieeexplore.ieee.org/abstract/document/9474286/authors) documents issues involving traffic generation, flow construction, feature extraction, and labels.

The available extract contains eight compatible `MachineLearningCVE` CSV files. The full analysis scanned all 2,830,743 rows and 79 source columns (78 flow features and one label) in 100,000-row chunks. All eight files passed schema validation and share the same source header sequence. Original headers and labels are preserved; the duplicate ` Fwd Header Length` fields remain separate position-specific columns.

## Reproducible analysis modes

Run the CLI from the repository root:

```powershell
python -m intrusion_intelligence.eda --chunk-size 100000 --sample-size 20000 --max-per-label 1000 --seed 42
```

The command discovers and validates files through the existing ingestion package. Row counts, per-file label counts, label proportions, missing values, finite numeric moments, zero/negative/infinite counts, and destination-port frequencies are computed across the full scan. Means and standard deviations are merged incrementally without retaining the full dataset in memory.

For expensive visual and pairwise statistics, the analysis uses a deterministic 20,000-row uniform priority-key sample with seed 42. Correlations, quantiles, skewness, kurtosis, sampled cardinality, feature-distribution plots, and duplicate estimates are labelled sample-derived. Feature comparisons use a second deterministic stratified sample capped at 1,000 rows per original label; it includes all 15 labels in this run and is not suitable for prevalence estimates. No sample result is reported as a complete count.

The notebook [01_dataset_exploration.ipynb](../notebooks/01_dataset_exploration.ipynb) orchestrates the same API and displays the generated outputs. It is organized into the requested 20 sections. A notebook-capable editor should use the installed project environment; the CLI runs the same full analysis without a notebook frontend.

## Actual findings from the full scan

- **Composition and labels:** 2,273,097 rows are `BENIGN` (80.30%); 557,646 rows carry one of the 14 original attack labels. The largest attack categories are `DoS Hulk` (231,073), `PortScan` (158,930), and `DDoS` (128,027). `Heartbleed` has 11 rows, `Web Attack � Sql Injection` 21, and `Infiltration` 36. The largest-to-smallest category ratio is about 206,645:1.
- **File concentration and leakage risk:** `BENIGN` occurs in all eight files; every non-benign category occurs in exactly one source file in this extract. Filenames encode collection-day/scenario groups, so file identity closely tracks labels. Keep file identity as EDA provenance and investigate group-aware or temporal evaluation later; do not use it as a predictive feature by default.
- **Missing and infinite values:** 1,358 missing cells occur in `Flow Bytes/s` (0.048% of rows). The scan counts 1,509 positive infinities in `Flow Bytes/s` and 2,867 in `Flow Packets/s`, 4,376 total. No replacements were made.
- **Negative values:** The scan found 2,446,321 negative numeric value occurrences across 13 features. Most are `-1` in `Init_Win_bytes_backward` (1,441,552) and `Init_Win_bytes_forward` (1,001,189). Other flow and IAT fields also contain negatives, including extreme values. These are observations for later investigation, not automatic error classifications.
- **Feature quality and distributions:** All 78 feature columns are numeric or numerically parseable. Eight are exactly constant across all rows: `Bwd PSH Flags`, `Bwd URG Flags`, `Fwd Avg Bytes/Bulk`, `Fwd Avg Packets/Bulk`, `Fwd Avg Bulk Rate`, `Bwd Avg Bytes/Bulk`, `Bwd Avg Packets/Bulk`, and `Bwd Avg Bulk Rate`. Sampled flow-size and packet features are strongly right-skewed with large maxima, so means and untransformed plots require context.
- **Redundancy:** The sample shows exact or near-exact correlations between pairs such as `Bwd Packet Length Mean` / `Avg Bwd Segment Size`, `Fwd Packet Length Mean` / `Avg Fwd Segment Size`, and packet/subflow counts. The two repeated `Fwd Header Length` columns also correlate at 1.0 in the sample; Phase 02 separately compared them across every source row and found no value differences. Correlation is not a feature-removal decision.
- **Duplicates:** In the 20,000-row uniform sample, 507 rows are exact duplicates (2.535%), and 576 rows belong to repeated feature-vector groups. The sample contains no conflicting-label duplicate groups and 20 feature-vector groups occurring in multiple files. These are sample estimates, not a full-dataset duplicate count.
- **Ports and unavailable fields:** `Destination Port` is present. Ports 53, 80, and 443 have the highest full-scan counts (957,971; 618,934; and 505,710). The per-label table shows scenario-specific concentrations, including port 80 for several DoS/web labels, port 21 for FTP-Patator, port 22 for SSH-Patator, and port 444 for Heartbleed and Infiltration. The CSVs have no standalone source port, protocol, timestamp, Flow ID, source IP, or destination IP fields; temporal and address-level analyses are unavailable.

These statistics describe the extracted benchmark files only. They are not estimates of operational network traffic or real-world attack prevalence.

## Outputs

The CLI creates output directories automatically:

- `reports/eda/CIC-IDS2017_eda.json` — structured full-scan and sampled results, source-file dimensions, per-file labels, quality counts, statistical summaries, correlations, duplicate estimates, field availability, and findings.
- `reports/eda/CIC-IDS2017_eda.md` — readable findings, per-file and label tables, limitations, and phase recommendations.
- `reports/figures/eda/` — label distribution, benign/malicious balance, per-file label proportions, missing values, numeric distributions, correlation heatmap, label-feature comparisons, destination ports, sampled duplicate diagnostics, and feature-quality figures.

The output includes no raw flow records. Figures and reports can be regenerated from the notebook or CLI.

## Method and limitations

- CSV loading uses Phase 02 chunking; raw data remains untouched.
- Header whitespace and duplicate source headers are retained in metadata; the duplicate fields use position-specific aliases.
- Missingness counts blank cells and common textual NA tokens for diagnostics; this interpretation does not alter records.
- Positive and negative infinity are excluded from finite numeric moments and correlation calculations, but counted separately.
- Histograms use a signed log display transform for selected high-magnitude features when needed. This changes only the plot coordinates.
- Correlations are computed over the uniform sample, while the heatmap displays the 30 highest-variance sampled features for legibility. All high-correlation pairs across numeric columns are stored in JSON.
- Duplicate diagnostics in this EDA report are sample-based. Phase 04 completed an external-memory full-extract fingerprint scan; its results supersede these sample estimates for duplicate counts. The EDA sample remains a historical diagnostic.
- Per-flow timestamps, source/destination addresses, Flow ID, protocol, and a standalone source port are absent from this CSV schema.
- The extracted files group attack categories by source file/scenario. Random row splitting alone could leak scenario-specific patterns across evaluation partitions.
- CIC-IDS2017 is a controlled, short-duration benchmark. EDA cannot establish performance or generalization on current networks.

## Recommendations for later phases

### Phase 04 — Data Cleaning & Leakage Prevention

Phase 04 is complete. Its full-scan counts, negative-value investigation, full duplicate results, policy, and processed outputs are in [docs/preprocessing.md](preprocessing.md) and the reports/data_quality artifacts. The EDA report's missing/infinity/negative/constant aggregates were reproduced. Its 20,000-row duplicate estimates were superseded by the Phase 04 full-extract fingerprint scan, which found 698 conflicting-label feature-vector groups; all records remain preserved.

### Phase 05 — Feature Engineering & Preprocessing

Phase 05 remains not started. Later feature and modeling work should evaluate heavy-tailed distributions and correlated fields, avoid automatic deletion of constant/correlated columns, and fit any learned transforms using training partitions only. Plan evaluation around class imbalance, per-class precision/recall/F1, and file/scenario concentration; do not use source-file identity as a predictive feature by default.
