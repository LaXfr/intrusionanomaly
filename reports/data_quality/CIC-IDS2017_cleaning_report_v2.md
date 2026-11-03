# Cleaning run: CIC-IDS2017

- **Run status:** completed
- **Generated:** 2026-11-03T11:48:47+00:00
- **Processing ID:** dce3f5d443d9c5f6
- **Output format:** parquet
- **Policy version:** 2.0
- **Input rows:** 2,830,743
- **Output rows:** 2,830,743
- **Excluded rows:** 0
- **Raw files unchanged:** True
- **Quarantine file:** data/interim/quarantine/CIC-IDS2017-phase04-v2/rejected.parquet

## Operations applied

- Headers normalized for 79 source columns; collisions received position suffixes.
- Numeric features: 78; categorical columns: 0.
- Missing values canonicalized: 1,358.
- Positive/negative infinities replaced with missing values: 4,376.
- Failed numeric conversions recorded: 0.
- Label whitespace changes: 0.
- Exact duplicate rows removed: 0.
- Negative finite measurements and extreme values were preserved without clipping.
- Original labels remain in `__source_label`; source file, row number, and record ID are provenance metadata.

## Exclusions and label mapping

| Rejection reason | Rows |
|---|---:|
| None | 0 |

| Original label | Normalized label | Rows |
|---|---|---:|
| BENIGN | BENIGN | 2,273,097 |
| Bot | Bot | 1,966 |
| DDoS | DDoS | 128,027 |
| DoS GoldenEye | DoS GoldenEye | 10,293 |
| DoS Hulk | DoS Hulk | 231,073 |
| DoS Slowhttptest | DoS Slowhttptest | 5,499 |
| DoS slowloris | DoS slowloris | 5,796 |
| FTP-Patator | FTP-Patator | 7,938 |
| Heartbleed | Heartbleed | 11 |
| Infiltration | Infiltration | 36 |
| PortScan | PortScan | 158,930 |
| SSH-Patator | SSH-Patator | 5,897 |
| Web Attack � Brute Force | Web Attack � Brute Force | 1,507 |
| Web Attack � Sql Injection | Web Attack � Sql Injection | 21 |
| Web Attack � XSS | Web Attack � XSS | 652 |

## Transformations

Numeric feature cells were safely parsed. Common missing tokens and non-finite numerical values are represented as Parquet nulls; no values were imputed. Invalid numeric representations were coerced to null only after their counts and example strings were captured in this report. Labels were trimmed, while the decoded original label is retained separately. Exact duplicates are preserved by default; repeated feature vectors and conflicting labels are not removed.

- Candidate predictive features: 78
- Target column: `label`
- Source header mapping: `data/processed/CIC-IDS2017-phase04-v2/metadata/manifest.json`
- Feature policy: `data/processed/CIC-IDS2017-phase04-v2/metadata/feature_policy.json`
- Policy copy: `data/processed/CIC-IDS2017-phase04-v2/metadata/data_quality_policy.toml`

## Output files

| Source | Processed Parquet | Retained | Quarantined | SHA-256 |
|---|---|---:|---:|---|
| extracted/MachineLearningCVE/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv | cleaned/extracted/MachineLearningCVE/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.parquet | 225,745 | 0 | 82fdf43d56bddeb34926b7cc2796c1c85f9e93477506ac59c21d96151d777f05 |
| extracted/MachineLearningCVE/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv | cleaned/extracted/MachineLearningCVE/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.parquet | 286,467 | 0 | c4e33d585325d8df7167665530db3911fcabd7f667b2d747d7a37c871cb96875 |
| extracted/MachineLearningCVE/Friday-WorkingHours-Morning.pcap_ISCX.csv | cleaned/extracted/MachineLearningCVE/Friday-WorkingHours-Morning.pcap_ISCX.parquet | 191,033 | 0 | 9ab76b6d366d79e553ad03d6315956d56f4b5db99b174fdb60c14206979950d6 |
| extracted/MachineLearningCVE/Monday-WorkingHours.pcap_ISCX.csv | cleaned/extracted/MachineLearningCVE/Monday-WorkingHours.pcap_ISCX.parquet | 529,918 | 0 | 6a42cb447bdc92cf7ba44b9f0a56fff5581b44045948f1d4eb0be50bd135728e |
| extracted/MachineLearningCVE/Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv | cleaned/extracted/MachineLearningCVE/Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.parquet | 288,602 | 0 | b13d93a7891994c201b277bbae66983ea3d02021dc751d68a6ae813443da09d3 |
| extracted/MachineLearningCVE/Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv | cleaned/extracted/MachineLearningCVE/Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.parquet | 170,366 | 0 | 089db0f61a62f80ed89764b89f786b9d88436054a2aa7de4bca31938d21b61ac |
| extracted/MachineLearningCVE/Tuesday-WorkingHours.pcap_ISCX.csv | cleaned/extracted/MachineLearningCVE/Tuesday-WorkingHours.pcap_ISCX.parquet | 445,909 | 0 | 399cff6d5e40daa50e3d694b91e2b153020826c18d5404e7bff4a665d54496a0 |
| extracted/MachineLearningCVE/Wednesday-workingHours.pcap_ISCX.csv | cleaned/extracted/MachineLearningCVE/Wednesday-workingHours.pcap_ISCX.parquet | 692,703 | 0 | 3cf29e22b1e657142a194263e3cd3bc79025222faccf520dfad7d2e937fa0fcd |

## Validation

- **Schema Compatible:** True
- **Cleaned Headers Unique:** True
- **Parquet Files Reopened:** True
- **Parquet Row Count Matches:** True
- **Parquet Labels Match Quality Scan:** True
- **Quarantine File Reopened:** True
- **Quarantine Row Count Matches:** True
- **Infinities Absent From Cleaned Features:** True
- **Labels Valid And Nonempty:** True
- **Feature Policy Separates Target And Metadata:** True
- **Excluded Rows Accounted For:** True
- **Expected Cleaned Row Count:** True
- **Raw Files Unchanged:** True

## Quarantine

- Rows: 0
- Reasons: {}
- SHA-256: `f3f4fa50c50ee125532e7caa9a4d93473583bf6442ac771d0cf88a5f59bf115a`

## Quality reports

- Before: `reports/data_quality/CIC-IDS2017_quality_report_v2_before.md`
- After: `reports/data_quality/CIC-IDS2017_quality_report_v2_after.md`

## Limitations

- Parquet is the authoritative cleaned format; Phase 02 ingestion currently reads CSV, so downstream loading should use pandas.read_parquet or PyArrow.
- Negative measurements and extreme finite values are retained because the source alone does not establish a faithful correction.
- Exact duplicate records are preserved by default; repeated feature vectors and conflicting labels require later investigation.
- Destination port remains a candidate feature. Source file, row number, record ID, source label, timestamps, and direct endpoint identifiers are excluded from the candidate feature set.
- The CIC-IDS2017 extract lacks timestamps, source/destination IPs, protocol, a standalone source port, and Flow ID.
- No train/validation/test split or model evaluation was performed in this phase.
