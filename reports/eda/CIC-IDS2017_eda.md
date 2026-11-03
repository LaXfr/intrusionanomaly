# Exploratory data analysis: CIC-IDS2017

- **Analysis time (UTC):** 2026-11-03T07:11:22+00:00
- **Source:** https://www.unb.ca/cic/datasets/ids-2017.html
- **Coverage:** complete chunked scan (2,830,743 rows)
- **Files and columns:** 8 files; 79 source columns (78 features and one label)
- **Chunk size:** 100,000
- **Uniform sample:** 20,000 rows; seed 42

Source header whitespace and the duplicate ` Fwd Header Length` fields are preserved by the Phase 02 ingestion layer; position-specific aliases keep both columns addressable.

Full-scan counts, label proportions, missingness, numeric moments, infinities, and available destination-port counts are exact. Quantiles, correlations, feature plots, duplicate rates, and near-constant indicators use the stated deterministic samples. Raw CSV files were read only.

## Key findings

- A complete chunked scan covered 2,830,743 rows across 8 files with 79 source columns.
- BENIGN accounts for 80.30% of rows; attack labels account for the remainder.
- The largest-to-smallest category ratio is 206,645.2:1 (BENIGN versus Heartbleed).
- 14 of 14 non-benign categories occur in only one source file, so file/scenario identity closely tracks labels.
- The scan found 1,358 blank or common textual-NA cells across 1,358 rows.
- The scan found 4,376 positive or negative infinite numeric values; no replacements were made.
- The full scan found 2,446,321 negative numeric values across 13 fields; largest counts include Init_Win_bytes_backward (1,441,552), Init_Win_bytes_forward (1,001,189), Flow IAT Min (2,891). EDA flags these for investigation without assuming they are invalid.
- The deterministic sample contains strongly associated feature pairs; the largest listed Pearson pair is Bwd Packet Length Mean and Avg Bwd Segment Size (r=1.000).
- 8 numeric features are exactly constant across the full scan.
- The 20,000-row uniform sample contains 507 exact duplicate rows and 0 repeated-feature groups with conflicting labels; these duplicate results are sample-based.
- The files contain Destination Port but no standalone source port, protocol, timestamp, source/destination IP, or Flow ID columns.
- Collection-day/scenario identity remains available through the source filenames; it must be kept as analysis provenance and reviewed before any predictive use.

## Label distribution

| Original label | Rows (full scan) | Share |
|---|---:|---:|
| BENIGN | 2,273,097 | 80.3004% |
| DoS Hulk | 231,073 | 8.1630% |
| PortScan | 158,930 | 5.6144% |
| DDoS | 128,027 | 4.5227% |
| DoS GoldenEye | 10,293 | 0.3636% |
| FTP-Patator | 7,938 | 0.2804% |
| SSH-Patator | 5,897 | 0.2083% |
| DoS slowloris | 5,796 | 0.2048% |
| DoS Slowhttptest | 5,499 | 0.1943% |
| Bot | 1,966 | 0.0695% |
| Web Attack � Brute Force | 1,507 | 0.0532% |
| Web Attack � XSS | 652 | 0.0230% |
| Infiltration | 36 | 0.0013% |
| Web Attack � Sql Injection | 21 | 0.0007% |
| Heartbleed | 11 | 0.0004% |

### Label support across source files

| Original label | Files present | Dominant file share |
|---|---:|---:|
| BENIGN | 8 | 23.313% |
| DoS Hulk | 1 | 100.000% |
| PortScan | 1 | 100.000% |
| DDoS | 1 | 100.000% |
| DoS GoldenEye | 1 | 100.000% |
| FTP-Patator | 1 | 100.000% |
| SSH-Patator | 1 | 100.000% |
| DoS slowloris | 1 | 100.000% |
| DoS Slowhttptest | 1 | 100.000% |
| Bot | 1 | 100.000% |
| Web Attack � Brute Force | 1 | 100.000% |
| Web Attack � XSS | 1 | 100.000% |
| Infiltration | 1 | 100.000% |
| Web Attack � Sql Injection | 1 | 100.000% |
| Heartbleed | 1 | 100.000% |

Benign: 2,273,097 (80.300%). All other original labels: 557,646 (19.700%).

## Per-file scan

| File | Rows | Source columns | Top observed label |
|---|---:|---:|---|
| extracted/MachineLearningCVE/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv | 225,745 | 79 | DDoS |
| extracted/MachineLearningCVE/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv | 286,467 | 79 | PortScan |
| extracted/MachineLearningCVE/Friday-WorkingHours-Morning.pcap_ISCX.csv | 191,033 | 79 | BENIGN |
| extracted/MachineLearningCVE/Monday-WorkingHours.pcap_ISCX.csv | 529,918 | 79 | BENIGN |
| extracted/MachineLearningCVE/Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv | 288,602 | 79 | BENIGN |
| extracted/MachineLearningCVE/Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv | 170,366 | 79 | BENIGN |
| extracted/MachineLearningCVE/Tuesday-WorkingHours.pcap_ISCX.csv | 445,909 | 79 | BENIGN |
| extracted/MachineLearningCVE/Wednesday-workingHours.pcap_ISCX.csv | 692,703 | 79 | BENIGN |

## Data quality

- Rows with at least one blank or common textual NA token: 1,358 (0.0480%).
- Missing cells: 1,358.
- Positive/negative infinite numeric values: 4,376.
- Negative numeric values: 2,446,321; flagged for review, not treated as errors by assumption.
- Numeric columns: 78; non-numeric or mixed columns: 0.
- Schema inspection warnings: One or more headers contain leading or trailing whitespace.; Duplicate source headers are preserved with position-specific internal names: ' Fwd Header Length'; Source headers share a whitespace-normalized name and are preserved with position-specific internal names: 'Fwd Header Length'.

### Columns with missing values

| Column | Count | Share of rows |
|---|---:|---:|
| Flow Bytes/s | 1,358 | 0.0480% |

### Numeric anomalies and negative values

| Feature | +Infinity | -Infinity | Parse failures | Negative values |
|---|---:|---:|---:|---:|
| Flow Duration | 0 | 0 | 0 | 115 |
| Flow Bytes/s | 1,509 | 0 | 0 | 85 |
| Flow Packets/s | 2,867 | 0 | 0 | 115 |
| Flow IAT Mean | 0 | 0 | 0 | 115 |
| Flow IAT Max | 0 | 0 | 0 | 115 |
| Flow IAT Min | 0 | 0 | 0 | 2,891 |
| Fwd IAT Min | 0 | 0 | 0 | 17 |
| Fwd Header Length [source column 35] | 0 | 0 | 0 | 35 |
| Bwd Header Length | 0 | 0 | 0 | 22 |
| Fwd Header Length [source column 56] | 0 | 0 | 0 | 35 |
| Init_Win_bytes_forward | 0 | 0 | 0 | 1,001,189 |
| Init_Win_bytes_backward | 0 | 0 | 0 | 1,441,552 |
| min_seg_size_forward | 0 | 0 | 0 | 35 |

### Features containing negative values

| Feature | Negative values | Minimum (full scan) |
|---|---:|---:|
| Init_Win_bytes_backward | 1,441,552 | -1 |
| Init_Win_bytes_forward | 1,001,189 | -1 |
| Flow IAT Min | 2,891 | -14 |
| Flow Duration | 115 | -13 |
| Flow IAT Max | 115 | -13 |
| Flow IAT Mean | 115 | -13 |
| Flow Packets/s | 115 | -2e+06 |
| Flow Bytes/s | 85 | -2.61e+08 |
| Fwd Header Length [source column 35] | 35 | -3.221e+10 |
| Fwd Header Length [source column 56] | 35 | -3.221e+10 |
| min_seg_size_forward | 35 | -5.369e+08 |
| Bwd Header Length | 22 | -1.074e+09 |
| Fwd IAT Min | 17 | -12 |

## Numerical statistics

Full-scan mean, sample standard deviation, minimum, maximum, zero rates, and invalid-value counts are exact for numeric features. Quantiles, skewness, kurtosis, and unique-value counts below are from the uniform sample.

| Feature | Mean (full) | Median (sample) | Min (full) | Max (full) | Zero share (full) | Skew (sample) |
|---|---:|---:|---:|---:|---:|---:|
| Destination Port | 8,071 | 80 | 0 | 6.554e+04 | 0.060% | 2.078 |
| Flow Duration | 1.479e+07 | 3.131e+04 | -13 | 1.2e+08 | 0.101% | 2.189 |
| Total Fwd Packets | 9.361 | 2 | 1 | 2.198e+05 | 0.000% | 140.6 |
| Total Backward Packets | 10.39 | 2 | 0 | 2.919e+05 | 16.021% | 140.6 |
| Total Length of Fwd Packets | 549.3 | 62 | 0 | 1.29e+07 | 15.868% | 103.8 |
| Total Length of Bwd Packets | 1.616e+04 | 122 | 0 | 6.555e+08 | 25.002% | 140.7 |
| Fwd Packet Length Max | 207.6 | 37 | 0 | 2.482e+04 | 15.868% | 9.065 |
| Fwd Packet Length Min | 18.71 | 2 | 0 | 2,325 | 46.533% | 19.78 |
| Fwd Packet Length Mean | 58.2 | 34 | 0 | 5,941 | 15.868% | 9.016 |
| Fwd Packet Length Std | 68.91 | 0 | 0 | 7,126 | 65.378% | 10.56 |
| Bwd Packet Length Max | 870.8 | 79 | 0 | 1.953e+04 | 25.002% | 3.004 |
| Bwd Packet Length Min | 41.05 | 0 | 0 | 2,896 | 50.795% | 5.056 |
| Bwd Packet Length Mean | 305.9 | 72 | 0 | 5,800 | 25.002% | 2.57 |
| Bwd Packet Length Std | 335.3 | 0 | 0 | 8,195 | 71.589% | 3.485 |
| Flow Bytes/s | 1.492e+06 | 4,539 | -2.61e+08 | 2.071e+09 | 12.581% | 33.15 |
| Flow Packets/s | 7.085e+04 | 104.3 | -2e+06 | 4e+06 | 0.000% | 5.411 |
| Flow IAT Mean | 1.298e+06 | 1.175e+04 | -13 | 1.2e+08 | 0.101% | 9.427 |
| Flow IAT Std | 2.919e+06 | 133.4 | 0 | 8.48e+07 | 35.267% | 3.645 |
| Flow IAT Max | 9.182e+06 | 3.09e+04 | -13 | 1.2e+08 | 0.101% | 2.948 |
| Flow IAT Min | 1.624e+05 | 4 | -14 | 1.2e+08 | 2.673% | 19.21 |
| Fwd IAT Total | 1.448e+07 | 18 | 0 | 1.2e+08 | 25.149% | 2.212 |
| Fwd IAT Mean | 2.61e+06 | 12.5 | 0 | 1.2e+08 | 25.149% | 6.839 |
| Fwd IAT Std | 3.267e+06 | 0 | 0 | 8.46e+07 | 62.747% | 3.49 |
| Fwd IAT Max | 9.043e+06 | 14 | 0 | 1.2e+08 | 25.149% | 2.956 |
| Fwd IAT Min | 1.022e+06 | 3 | -12 | 1.2e+08 | 26.278% | 9.155 |
| Bwd IAT Total | 9.894e+06 | 3 | 0 | 1.2e+08 | 44.140% | 2.891 |
| Bwd IAT Mean | 1.806e+06 | 3 | 0 | 1.2e+08 | 44.140% | 8.067 |
| Bwd IAT Std | 1.486e+06 | 0 | 0 | 8.442e+07 | 71.332% | 5.796 |
| Bwd IAT Max | 4.685e+06 | 3 | 0 | 1.2e+08 | 44.140% | 4.435 |
| Bwd IAT Min | 9.673e+05 | 1 | 0 | 1.2e+08 | 44.505% | 9.668 |
| Fwd PSH Flags | 0.04645 | 0 | 0 | 1 | 95.355% | 4.346 |
| Bwd PSH Flags | 0 | 0 | 0 | 0 | 100.000% | 0 |
| Fwd URG Flags | 0.0001113 | 0 | 0 | 1 | 99.989% | 63.23 |
| Bwd URG Flags | 0 | 0 | 0 | 0 | 100.000% | 0 |
| Fwd Header Length [source column 35] | -2.6e+04 | 64 | -3.221e+10 | 4.645e+06 | 0.062% | 140.5 |
| Bwd Header Length | -2,273 | 40 | -1.074e+09 | 5.838e+06 | 16.026% | 140.5 |
| Fwd Packets/s | 6.387e+04 | 59.68 | 0 | 3e+06 | 0.105% | 5.586 |
| Bwd Packets/s | 6,995 | 19.64 | 0 | 2e+06 | 16.060% | 18.21 |
| Min Packet Length | 16.43 | 2 | 0 | 1,448 | 47.479% | 10.1 |
| Max Packet Length | 950.4 | 88 | 0 | 2.482e+04 | 12.616% | 2.833 |
| Packet Length Mean | 171.9 | 57.33 | 0 | 3,337 | 12.616% | 2.463 |
| Packet Length Std | 295 | 26.29 | 0 | 4,732 | 25.190% | 2.961 |
| Packet Length Variance | 4.862e+05 | 691.2 | 0 | 2.24e+07 | 25.190% | 5.41 |
| FIN Flag Count | 0.03538 | 0 | 0 | 1 | 96.462% | 4.963 |
| SYN Flag Count | 0.04645 | 0 | 0 | 1 | 95.355% | 4.346 |
| RST Flag Count | 0.0002423 | 0 | 0 | 1 | 99.976% | 53.43 |
| PSH Flag Count | 0.2981 | 0 | 0 | 1 | 70.193% | 0.8973 |
| ACK Flag Count | 0.3158 | 0 | 0 | 1 | 68.416% | 0.7847 |
| URG Flag Count | 0.09482 | 0 | 0 | 1 | 90.518% | 2.76 |
| CWE Flag Count | 0.0001113 | 0 | 0 | 1 | 99.989% | 63.23 |
| ECE Flag Count | 0.0002434 | 0 | 0 | 1 | 99.976% | 53.43 |
| Down/Up Ratio | 0.6835 | 1 | 0 | 156 | 37.028% | 32.72 |
| Average Packet Size | 192 | 72.5 | 0 | 3,893 | 12.616% | 2.55 |
| Avg Fwd Segment Size | 58.2 | 34 | 0 | 5,941 | 15.868% | 9.016 |
| Avg Bwd Segment Size | 305.9 | 72 | 0 | 5,800 | 25.002% | 2.57 |
| Fwd Header Length [source column 56] | -2.6e+04 | 64 | -3.221e+10 | 4.645e+06 | 0.062% | 140.5 |
| Fwd Avg Bytes/Bulk | 0 | 0 | 0 | 0 | 100.000% | 0 |
| Fwd Avg Packets/Bulk | 0 | 0 | 0 | 0 | 100.000% | 0 |
| Fwd Avg Bulk Rate | 0 | 0 | 0 | 0 | 100.000% | 0 |
| Bwd Avg Bytes/Bulk | 0 | 0 | 0 | 0 | 100.000% | 0 |
| Bwd Avg Packets/Bulk | 0 | 0 | 0 | 0 | 100.000% | 0 |
| Bwd Avg Bulk Rate | 0 | 0 | 0 | 0 | 100.000% | 0 |
| Subflow Fwd Packets | 9.361 | 2 | 1 | 2.198e+05 | 0.000% | 140.6 |
| Subflow Fwd Bytes | 549.3 | 62 | 0 | 1.287e+07 | 15.868% | 103.8 |
| Subflow Bwd Packets | 10.39 | 2 | 0 | 2.919e+05 | 16.021% | 140.6 |
| Subflow Bwd Bytes | 1.616e+04 | 122 | 0 | 6.555e+08 | 25.002% | 140.7 |
| Init_Win_bytes_forward | 6,990 | 251 | -1 | 6.554e+04 | 3.525% | 2.598 |
| Init_Win_bytes_backward | 1,989 | -1 | -1 | 6.554e+04 | 9.605% | 5.297 |
| act_data_pkt_fwd | 5.418 | 1 | 0 | 2.136e+05 | 34.017% | 140.8 |
| min_seg_size_forward | -2,742 | 24 | -5.369e+08 | 138 | 0.065% | 0.3707 |
| Active Mean | 8.155e+04 | 0 | 0 | 1.1e+08 | 80.259% | 12.65 |
| Active Std | 4.113e+04 | 0 | 0 | 7.42e+07 | 92.739% | 14.43 |
| Active Max | 1.532e+05 | 0 | 0 | 1.1e+08 | 80.259% | 11.07 |
| Active Min | 5.83e+04 | 0 | 0 | 1.1e+08 | 80.259% | 15.49 |
| Idle Mean | 8.316e+06 | 0 | 0 | 1.2e+08 | 79.960% | 3.131 |
| Idle Std | 5.038e+05 | 0 | 0 | 7.69e+07 | 91.902% | 10.45 |
| Idle Max | 8.696e+06 | 0 | 0 | 1.2e+08 | 79.960% | 3.012 |
| Idle Min | 7.92e+06 | 0 | 0 | 1.2e+08 | 79.960% | 3.259 |

## Correlation, duplicates, and feature quality

Pearson and Spearman correlations use 20,000 uniformly sampled rows after masking positive and negative infinity. Pairs at absolute correlation 0.95 or above are listed in the JSON output; correlation is not proof of leakage or causality.

- Pearson: Bwd Packet Length Mean / Avg Bwd Segment Size: 1.0000.
- Pearson: Fwd Packet Length Mean / Avg Fwd Segment Size: 1.0000.
- Pearson: Fwd URG Flags / CWE Flag Count: 1.0000.
- Pearson: RST Flag Count / ECE Flag Count: 1.0000.
- Pearson: Total Backward Packets / Subflow Bwd Packets: 1.0000.
- Pearson: Total Fwd Packets / Subflow Fwd Packets: 1.0000.
- Pearson: Fwd Header Length [source column 35] / Fwd Header Length [source column 56]: 1.0000.
- Pearson: Fwd PSH Flags / SYN Flag Count: 1.0000.
- Pearson: Total Length of Fwd Packets / Subflow Fwd Bytes: 1.0000.
- Pearson: Total Length of Bwd Packets / Subflow Bwd Bytes: 1.0000.
- Pearson: Bwd Header Length / Subflow Bwd Packets: 1.0000.
- Pearson: Total Backward Packets / Bwd Header Length: 1.0000.
- Pearson: Total Backward Packets / Subflow Fwd Packets: 0.9999.
- Pearson: Total Fwd Packets / Total Backward Packets: 0.9999.
- Pearson: Total Fwd Packets / Subflow Bwd Packets: 0.9999.
- Pearson: Subflow Fwd Packets / Subflow Bwd Packets: 0.9999.
- Pearson: Subflow Bwd Packets / Subflow Bwd Bytes: 0.9999.
- Pearson: Total Backward Packets / Subflow Bwd Bytes: 0.9999.
- Pearson: Bwd Header Length / Subflow Fwd Packets: 0.9999.
- Pearson: Total Fwd Packets / Bwd Header Length: 0.9999.

Duplicate checks cover a deterministic uniform sample of 20,000 rows: 507 exact duplicate rows, 576 rows in repeated feature-vector groups, 0 conflicting-label groups, and 20 groups repeated across files.

Exact constant numeric features: Bwd PSH Flags, Bwd URG Flags, Fwd Avg Bytes/Bulk, Fwd Avg Packets/Bulk, Fwd Avg Bulk Rate, Bwd Avg Bytes/Bulk, Bwd Avg Packets/Bulk, Bwd Avg Bulk Rate.
Potentially dominant or high-cardinality features are sample indicators in the JSON output; no columns were removed.

## Network fields, time, and leakage considerations

Available fields: destination_port.
Not available: no protocol field is present in these CSV files.
Not available: no standalone source-port field is present.
No timestamp column is present in the MachineLearningCVE CSV schema. Filenames identify collection-day/scenario groups, but not per-flow time.
The source filename remains available in per-file summaries and can act as a collection-scenario proxy. Keep it as provenance for EDA and assess it before any future predictive use. This phase did not split data or remove features.

## Figures

- [label_distribution.png](../figures/eda/label_distribution.png)
- [benign_malicious_distribution.png](../figures/eda/benign_malicious_distribution.png)
- [per_file_label_distribution.png](../figures/eda/per_file_label_distribution.png)
- [missing_values.png](../figures/eda/missing_values.png)
- [numeric_feature_distributions.png](../figures/eda/numeric_feature_distributions.png)
- [correlation_heatmap.png](../figures/eda/correlation_heatmap.png)
- [feature_label_comparisons.png](../figures/eda/feature_label_comparisons.png)
- [destination_port_distribution.png](../figures/eda/destination_port_distribution.png)
- [duplicate_sample_summary.png](../figures/eda/duplicate_sample_summary.png)
- [feature_quality_summary.png](../figures/eda/feature_quality_summary.png)

## Recommendations for later phases

### Phase 04 — Data Cleaning & Leakage Prevention

- Review only the full-scan missing, infinity, parse-failure, and negative-value counts; decide handling rules without changing raw source files.
- Investigate repeated feature vectors and any conflicting labels with a full external-memory workflow before deciding whether rows should be excluded.
- Keep file identity as provenance; do not assume random row splits represent independent collection scenarios.

### Phase 05 — Feature Engineering & Preprocessing

- Consider scaling and robust summaries for heavy-tailed flow measurements.
- Evaluate redundancy flagged by the sampled correlation analysis, without automatically dropping correlated features.
- Plan per-class evaluation around the observed minority counts; report recall, precision, F1, and confusion matrices rather than accuracy alone.
- Keep label-derived, file, and future identifier metadata separate from model features until leakage risks have been tested.

## Limitations and provenance

- No timestamp, protocol, source IP, destination IP, source port, or Flow ID columns are present in this extracted schema.
- File identity describes collection-day/scenario provenance and must not be added as a predictive feature without a leakage review.
- CIC-IDS2017 is a controlled, short-duration benchmark; observed proportions are not real-world attack prevalence.
- Sample-based quantiles, correlations, plots, duplicate estimates, and near-constant indicators are not full-dataset statistics.
