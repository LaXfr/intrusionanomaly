# Data quality assessment: CIC-IDS2017

- **Generated:** 2026-11-03T11:48:47+00:00
- **Coverage:** complete (2,830,743 rows)
- **Files:** 8; source columns: 79; feature columns: 78
- **Chunk size:** 25,000
- **Input values changed:** False

## Dataset and schema

Schema compatible: **True**; distinct source header sequences: **1**.

| File | Rows | Bytes | SHA-256 |
|---|---:|---:|---|
| extracted/MachineLearningCVE/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv | 225,745 | 77,123,859 | 6ff1580f5f81c0ae28a26f7631721018577f5f7c5e0feac28b795fcfe7b411ee |
| extracted/MachineLearningCVE/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv | 286,467 | 76,906,168 | ca1824c51bfbb7b3c72290a11be04366ba8815878c6a1cc5c44cb1cee269e99b |
| extracted/MachineLearningCVE/Friday-WorkingHours-Morning.pcap_ISCX.csv | 191,033 | 58,316,725 | 53a41c24d570ea83b7ac55b2e94df94e7a8216aeb80a2af0246b6bc8bb543000 |
| extracted/MachineLearningCVE/Monday-WorkingHours.pcap_ISCX.csv | 529,918 | 176,927,918 | 852c4beb34eda186f32561fa79df7a0747e92e1a6535b01270820dd9ffe17f34 |
| extracted/MachineLearningCVE/Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv | 288,602 | 83,102,436 | 6bcda3857c2504676034e3ea57762d38393cc734cb377a726bd5cb153961b1b5 |
| extracted/MachineLearningCVE/Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv | 170,366 | 52,023,263 | d67066211fb1689c78406f1506f4c44704ecb92088353d5c96d96d6474eb819d |
| extracted/MachineLearningCVE/Tuesday-WorkingHours.pcap_ISCX.csv | 445,909 | 135,078,995 | 52b8692ae8c7d2ed04671fe2b98335693c0a92c7ab157d8c8b534d6523080851 |
| extracted/MachineLearningCVE/Wednesday-workingHours.pcap_ISCX.csv | 692,703 | 225,166,395 | 893c27dc968bf7a8adef1689f90be55ca4a4dc3088fb63d6ff247ac56856df2a |

## Label distribution

| Original label | Rows | Percent |
|---|---:|---:|
| BENIGN | 2,273,097 | 80.30037% |
| DoS Hulk | 231,073 | 8.16298% |
| PortScan | 158,930 | 5.61443% |
| DDoS | 128,027 | 4.52273% |
| DoS GoldenEye | 10,293 | 0.36361% |
| FTP-Patator | 7,938 | 0.28042% |
| SSH-Patator | 5,897 | 0.20832% |
| DoS slowloris | 5,796 | 0.20475% |
| DoS Slowhttptest | 5,499 | 0.19426% |
| Bot | 1,966 | 0.06945% |
| Web Attack � Brute Force | 1,507 | 0.05324% |
| Web Attack � XSS | 652 | 0.02303% |
| Infiltration | 36 | 0.00127% |
| Web Attack � Sql Injection | 21 | 0.00074% |
| Heartbleed | 11 | 0.00039% |

## Full-scan quality counts

| Measure | Count |
|---|---:|
| Empty String | 0 |
| Explicit Null | 0 |
| Nan Token | 1,358 |
| Missing Total | 1,358 |
| Invalid Numeric | 0 |
| Positive Infinity | 4,376 |
| Negative Infinity | 0 |
| Negative | 2,446,321 |
| Overflow Or Nonfinite Conversion | 0 |

Finding classifications are counts of affected source feature cells, not counts of unique records:

- potentially_invalid: 3,580
- unresolved_missingness: 1,358
- confirmed_invalid_nonfinite_measurement: 4,376
- unresolved_potential_sentinel: 2,442,741

## Feature-level findings

Missingness, parsing, infinity, zero, negative and finite range values are full-scan counts. Quantiles, IQR/MAD fences, sample cardinality and dominant-value rates are estimates from the deterministic systematic sample.

| Position | Source header | Missing | Invalid numeric | +Inf | -Inf | Negative | Finite min | Finite max |
|---:|---|---:|---:|---:|---:|---:|---:|---:|
| 1 |  Destination Port | 0 | 0 | 0 | 0 | 0 | 0 | 65535 |
| 2 |  Flow Duration | 0 | 0 | 0 | 0 | 115 | -13 | 1.2e+08 |
| 3 |  Total Fwd Packets | 0 | 0 | 0 | 0 | 0 | 1 | 219759 |
| 4 |  Total Backward Packets | 0 | 0 | 0 | 0 | 0 | 0 | 291922 |
| 5 | Total Length of Fwd Packets | 0 | 0 | 0 | 0 | 0 | 0 | 12900000 |
| 6 |  Total Length of Bwd Packets | 0 | 0 | 0 | 0 | 0 | 0 | 6.5545303e+08 |
| 7 |  Fwd Packet Length Max | 0 | 0 | 0 | 0 | 0 | 0 | 24820 |
| 8 |  Fwd Packet Length Min | 0 | 0 | 0 | 0 | 0 | 0 | 2325 |
| 9 |  Fwd Packet Length Mean | 0 | 0 | 0 | 0 | 0 | 0 | 5940.8571 |
| 10 |  Fwd Packet Length Std | 0 | 0 | 0 | 0 | 0 | 0 | 7125.5968 |
| 11 | Bwd Packet Length Max | 0 | 0 | 0 | 0 | 0 | 0 | 19530 |
| 12 |  Bwd Packet Length Min | 0 | 0 | 0 | 0 | 0 | 0 | 2896 |
| 13 |  Bwd Packet Length Mean | 0 | 0 | 0 | 0 | 0 | 0 | 5800.5 |
| 14 |  Bwd Packet Length Std | 0 | 0 | 0 | 0 | 0 | 0 | 8194.6605 |
| 15 | Flow Bytes/s | 1,358 | 0 | 1,509 | 0 | 85 | -2.61e+08 | 2.071e+09 |
| 16 |  Flow Packets/s | 0 | 0 | 2,867 | 0 | 115 | -2000000 | 4000000 |
| 17 |  Flow IAT Mean | 0 | 0 | 0 | 0 | 115 | -13 | 1.2e+08 |
| 18 |  Flow IAT Std | 0 | 0 | 0 | 0 | 0 | 0 | 84800262 |
| 19 |  Flow IAT Max | 0 | 0 | 0 | 0 | 115 | -13 | 1.2e+08 |
| 20 |  Flow IAT Min | 0 | 0 | 0 | 0 | 2,891 | -14 | 1.2e+08 |
| 21 | Fwd IAT Total | 0 | 0 | 0 | 0 | 0 | 0 | 1.2e+08 |
| 22 |  Fwd IAT Mean | 0 | 0 | 0 | 0 | 0 | 0 | 1.2e+08 |
| 23 |  Fwd IAT Std | 0 | 0 | 0 | 0 | 0 | 0 | 84602929 |
| 24 |  Fwd IAT Max | 0 | 0 | 0 | 0 | 0 | 0 | 1.2e+08 |
| 25 |  Fwd IAT Min | 0 | 0 | 0 | 0 | 17 | -12 | 1.2e+08 |
| 26 | Bwd IAT Total | 0 | 0 | 0 | 0 | 0 | 0 | 1.2e+08 |
| 27 |  Bwd IAT Mean | 0 | 0 | 0 | 0 | 0 | 0 | 1.2e+08 |
| 28 |  Bwd IAT Std | 0 | 0 | 0 | 0 | 0 | 0 | 84418014 |
| 29 |  Bwd IAT Max | 0 | 0 | 0 | 0 | 0 | 0 | 1.2e+08 |
| 30 |  Bwd IAT Min | 0 | 0 | 0 | 0 | 0 | 0 | 1.2e+08 |
| 31 | Fwd PSH Flags | 0 | 0 | 0 | 0 | 0 | 0 | 1 |
| 32 |  Bwd PSH Flags | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| 33 |  Fwd URG Flags | 0 | 0 | 0 | 0 | 0 | 0 | 1 |
| 34 |  Bwd URG Flags | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| 35 |  Fwd Header Length | 0 | 0 | 0 | 0 | 35 | -3.2212235e+10 | 4644908 |
| 36 |  Bwd Header Length | 0 | 0 | 0 | 0 | 22 | -1.0737413e+09 | 5838440 |
| 37 | Fwd Packets/s | 0 | 0 | 0 | 0 | 0 | 0 | 3000000 |
| 38 |  Bwd Packets/s | 0 | 0 | 0 | 0 | 0 | 0 | 2000000 |
| 39 |  Min Packet Length | 0 | 0 | 0 | 0 | 0 | 0 | 1448 |
| 40 |  Max Packet Length | 0 | 0 | 0 | 0 | 0 | 0 | 24820 |
| 41 |  Packet Length Mean | 0 | 0 | 0 | 0 | 0 | 0 | 3337.1429 |
| 42 |  Packet Length Std | 0 | 0 | 0 | 0 | 0 | 0 | 4731.5224 |
| 43 |  Packet Length Variance | 0 | 0 | 0 | 0 | 0 | 0 | 22400000 |
| 44 | FIN Flag Count | 0 | 0 | 0 | 0 | 0 | 0 | 1 |
| 45 |  SYN Flag Count | 0 | 0 | 0 | 0 | 0 | 0 | 1 |
| 46 |  RST Flag Count | 0 | 0 | 0 | 0 | 0 | 0 | 1 |
| 47 |  PSH Flag Count | 0 | 0 | 0 | 0 | 0 | 0 | 1 |
| 48 |  ACK Flag Count | 0 | 0 | 0 | 0 | 0 | 0 | 1 |
| 49 |  URG Flag Count | 0 | 0 | 0 | 0 | 0 | 0 | 1 |
| 50 |  CWE Flag Count | 0 | 0 | 0 | 0 | 0 | 0 | 1 |
| 51 |  ECE Flag Count | 0 | 0 | 0 | 0 | 0 | 0 | 1 |
| 52 |  Down/Up Ratio | 0 | 0 | 0 | 0 | 0 | 0 | 156 |
| 53 |  Average Packet Size | 0 | 0 | 0 | 0 | 0 | 0 | 3893.3333 |
| 54 |  Avg Fwd Segment Size | 0 | 0 | 0 | 0 | 0 | 0 | 5940.8571 |
| 55 |  Avg Bwd Segment Size | 0 | 0 | 0 | 0 | 0 | 0 | 5800.5 |
| 56 |  Fwd Header Length | 0 | 0 | 0 | 0 | 35 | -3.2212235e+10 | 4644908 |
| 57 | Fwd Avg Bytes/Bulk | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| 58 |  Fwd Avg Packets/Bulk | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| 59 |  Fwd Avg Bulk Rate | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| 60 |  Bwd Avg Bytes/Bulk | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| 61 |  Bwd Avg Packets/Bulk | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| 62 | Bwd Avg Bulk Rate | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| 63 | Subflow Fwd Packets | 0 | 0 | 0 | 0 | 0 | 1 | 219759 |
| 64 |  Subflow Fwd Bytes | 0 | 0 | 0 | 0 | 0 | 0 | 12870338 |
| 65 |  Subflow Bwd Packets | 0 | 0 | 0 | 0 | 0 | 0 | 291922 |
| 66 |  Subflow Bwd Bytes | 0 | 0 | 0 | 0 | 0 | 0 | 6.5545303e+08 |
| 67 | Init_Win_bytes_forward | 0 | 0 | 0 | 0 | 1,001,189 | -1 | 65535 |
| 68 |  Init_Win_bytes_backward | 0 | 0 | 0 | 0 | 1,441,552 | -1 | 65535 |
| 69 |  act_data_pkt_fwd | 0 | 0 | 0 | 0 | 0 | 0 | 213557 |
| 70 |  min_seg_size_forward | 0 | 0 | 0 | 0 | 35 | -5.3687066e+08 | 138 |
| 71 | Active Mean | 0 | 0 | 0 | 0 | 0 | 0 | 1.1e+08 |
| 72 |  Active Std | 0 | 0 | 0 | 0 | 0 | 0 | 74200000 |
| 73 |  Active Max | 0 | 0 | 0 | 0 | 0 | 0 | 1.1e+08 |
| 74 |  Active Min | 0 | 0 | 0 | 0 | 0 | 0 | 1.1e+08 |
| 75 | Idle Mean | 0 | 0 | 0 | 0 | 0 | 0 | 1.2e+08 |
| 76 |  Idle Std | 0 | 0 | 0 | 0 | 0 | 0 | 76900000 |
| 77 |  Idle Max | 0 | 0 | 0 | 0 | 0 | 0 | 1.2e+08 |
| 78 |  Idle Min | 0 | 0 | 0 | 0 | 0 | 0 | 1.2e+08 |

## Negative-value semantics

- ** Flow Duration** (115; 0.00406%): potentially_invalid_preserved. CICFlowMeter describes this field as a count, size, time interval, statistic, or ratio; negative values conflict with that definition, but row-level extraction causes are not established.
  Per file: {'extracted/MachineLearningCVE/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv': 2, 'extracted/MachineLearningCVE/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv': 36, 'extracted/MachineLearningCVE/Friday-WorkingHours-Morning.pcap_ISCX.csv': 9, 'extracted/MachineLearningCVE/Monday-WorkingHours.pcap_ISCX.csv': 15, 'extracted/MachineLearningCVE/Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv': 4, 'extracted/MachineLearningCVE/Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv': 11, 'extracted/MachineLearningCVE/Tuesday-WorkingHours.pcap_ISCX.csv': 17, 'extracted/MachineLearningCVE/Wednesday-workingHours.pcap_ISCX.csv': 21}; per label: {'BENIGN': 115}.
- **Flow Bytes/s** (85; 0.00300%): potentially_invalid_preserved. CICFlowMeter describes this field as a count, size, time interval, statistic, or ratio; negative values conflict with that definition, but row-level extraction causes are not established.
  Per file: {'extracted/MachineLearningCVE/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv': 2, 'extracted/MachineLearningCVE/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv': 36, 'extracted/MachineLearningCVE/Friday-WorkingHours-Morning.pcap_ISCX.csv': 8, 'extracted/MachineLearningCVE/Monday-WorkingHours.pcap_ISCX.csv': 9, 'extracted/MachineLearningCVE/Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv': 4, 'extracted/MachineLearningCVE/Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv': 10, 'extracted/MachineLearningCVE/Wednesday-workingHours.pcap_ISCX.csv': 16}; per label: {'BENIGN': 85}.
- ** Flow Packets/s** (115; 0.00406%): potentially_invalid_preserved. CICFlowMeter describes this field as a count, size, time interval, statistic, or ratio; negative values conflict with that definition, but row-level extraction causes are not established.
  Per file: {'extracted/MachineLearningCVE/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv': 2, 'extracted/MachineLearningCVE/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv': 36, 'extracted/MachineLearningCVE/Friday-WorkingHours-Morning.pcap_ISCX.csv': 9, 'extracted/MachineLearningCVE/Monday-WorkingHours.pcap_ISCX.csv': 15, 'extracted/MachineLearningCVE/Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv': 4, 'extracted/MachineLearningCVE/Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv': 11, 'extracted/MachineLearningCVE/Tuesday-WorkingHours.pcap_ISCX.csv': 17, 'extracted/MachineLearningCVE/Wednesday-workingHours.pcap_ISCX.csv': 21}; per label: {'BENIGN': 115}.
- ** Flow IAT Mean** (115; 0.00406%): potentially_invalid_preserved. CICFlowMeter describes this field as a count, size, time interval, statistic, or ratio; negative values conflict with that definition, but row-level extraction causes are not established.
  Per file: {'extracted/MachineLearningCVE/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv': 2, 'extracted/MachineLearningCVE/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv': 36, 'extracted/MachineLearningCVE/Friday-WorkingHours-Morning.pcap_ISCX.csv': 9, 'extracted/MachineLearningCVE/Monday-WorkingHours.pcap_ISCX.csv': 15, 'extracted/MachineLearningCVE/Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv': 4, 'extracted/MachineLearningCVE/Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv': 11, 'extracted/MachineLearningCVE/Tuesday-WorkingHours.pcap_ISCX.csv': 17, 'extracted/MachineLearningCVE/Wednesday-workingHours.pcap_ISCX.csv': 21}; per label: {'BENIGN': 115}.
- ** Flow IAT Max** (115; 0.00406%): potentially_invalid_preserved. CICFlowMeter describes this field as a count, size, time interval, statistic, or ratio; negative values conflict with that definition, but row-level extraction causes are not established.
  Per file: {'extracted/MachineLearningCVE/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv': 2, 'extracted/MachineLearningCVE/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv': 36, 'extracted/MachineLearningCVE/Friday-WorkingHours-Morning.pcap_ISCX.csv': 9, 'extracted/MachineLearningCVE/Monday-WorkingHours.pcap_ISCX.csv': 15, 'extracted/MachineLearningCVE/Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv': 4, 'extracted/MachineLearningCVE/Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv': 11, 'extracted/MachineLearningCVE/Tuesday-WorkingHours.pcap_ISCX.csv': 17, 'extracted/MachineLearningCVE/Wednesday-workingHours.pcap_ISCX.csv': 21}; per label: {'BENIGN': 115}.
- ** Flow IAT Min** (2,891; 0.10213%): potentially_invalid_preserved. CICFlowMeter describes this field as a count, size, time interval, statistic, or ratio; negative values conflict with that definition, but row-level extraction causes are not established.
  Per file: {'extracted/MachineLearningCVE/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv': 108, 'extracted/MachineLearningCVE/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv': 176, 'extracted/MachineLearningCVE/Friday-WorkingHours-Morning.pcap_ISCX.csv': 225, 'extracted/MachineLearningCVE/Monday-WorkingHours.pcap_ISCX.csv': 512, 'extracted/MachineLearningCVE/Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv': 353, 'extracted/MachineLearningCVE/Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv': 263, 'extracted/MachineLearningCVE/Tuesday-WorkingHours.pcap_ISCX.csv': 505, 'extracted/MachineLearningCVE/Wednesday-workingHours.pcap_ISCX.csv': 749}; per label: {'BENIGN': 2697, 'DDoS': 19, 'Infiltration': 1, 'FTP-Patator': 4, 'SSH-Patator': 2, 'DoS Hulk': 159, 'DoS GoldenEye': 5, 'Heartbleed': 4}.
- ** Fwd IAT Min** (17; 0.00060%): potentially_invalid_preserved. CICFlowMeter describes this field as a count, size, time interval, statistic, or ratio; negative values conflict with that definition, but row-level extraction causes are not established.
  Per file: {'extracted/MachineLearningCVE/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv': 6, 'extracted/MachineLearningCVE/Wednesday-workingHours.pcap_ISCX.csv': 11}; per label: {'DDoS': 6, 'DoS Hulk': 8, 'DoS GoldenEye': 3}.
- ** Fwd Header Length** (35; 0.00124%): potentially_invalid_preserved. CICFlowMeter describes this field as a count, size, time interval, statistic, or ratio; negative values conflict with that definition, but row-level extraction causes are not established.
  Per file: {'extracted/MachineLearningCVE/Monday-WorkingHours.pcap_ISCX.csv': 23, 'extracted/MachineLearningCVE/Tuesday-WorkingHours.pcap_ISCX.csv': 11, 'extracted/MachineLearningCVE/Wednesday-workingHours.pcap_ISCX.csv': 1}; per label: {'BENIGN': 35}.
- ** Bwd Header Length** (22; 0.00078%): potentially_invalid_preserved. CICFlowMeter describes this field as a count, size, time interval, statistic, or ratio; negative values conflict with that definition, but row-level extraction causes are not established.
  Per file: {'extracted/MachineLearningCVE/Monday-WorkingHours.pcap_ISCX.csv': 17, 'extracted/MachineLearningCVE/Tuesday-WorkingHours.pcap_ISCX.csv': 5}; per label: {'BENIGN': 22}.
- ** Fwd Header Length** (35; 0.00124%): potentially_invalid_preserved. CICFlowMeter describes this field as a count, size, time interval, statistic, or ratio; negative values conflict with that definition, but row-level extraction causes are not established.
  Per file: {'extracted/MachineLearningCVE/Monday-WorkingHours.pcap_ISCX.csv': 23, 'extracted/MachineLearningCVE/Tuesday-WorkingHours.pcap_ISCX.csv': 11, 'extracted/MachineLearningCVE/Wednesday-workingHours.pcap_ISCX.csv': 1}; per label: {'BENIGN': 35}.
- **Init_Win_bytes_forward** (1,001,189; 35.36842%): unresolved_potential_sentinel. Negative byte counts are not physically meaningful; the frequent -1 may be an unavailable-value sentinel, but the source extract does not document that encoding.
  Per file: {'extracted/MachineLearningCVE/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv': 32925, 'extracted/MachineLearningCVE/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv': 60210, 'extracted/MachineLearningCVE/Friday-WorkingHours-Morning.pcap_ISCX.csv': 95834, 'extracted/MachineLearningCVE/Monday-WorkingHours.pcap_ISCX.csv': 224495, 'extracted/MachineLearningCVE/Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv': 102433, 'extracted/MachineLearningCVE/Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv': 81911, 'extracted/MachineLearningCVE/Tuesday-WorkingHours.pcap_ISCX.csv': 200128, 'extracted/MachineLearningCVE/Wednesday-workingHours.pcap_ISCX.csv': 203253}; per label: {'BENIGN': 1001182, 'PortScan': 7}.
- ** Init_Win_bytes_backward** (1,441,552; 50.92486%): unresolved_potential_sentinel. Negative byte counts are not physically meaningful; the frequent -1 may be an unavailable-value sentinel, but the source extract does not document that encoding.
  Per file: {'extracted/MachineLearningCVE/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv': 88299, 'extracted/MachineLearningCVE/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv': 76942, 'extracted/MachineLearningCVE/Friday-WorkingHours-Morning.pcap_ISCX.csv': 118419, 'extracted/MachineLearningCVE/Monday-WorkingHours.pcap_ISCX.csv': 299094, 'extracted/MachineLearningCVE/Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv': 164351, 'extracted/MachineLearningCVE/Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv': 102373, 'extracted/MachineLearningCVE/Tuesday-WorkingHours.pcap_ISCX.csv': 256599, 'extracted/MachineLearningCVE/Wednesday-workingHours.pcap_ISCX.csv': 335475}; per label: {'BENIGN': 1318981, 'DDoS': 46528, 'PortScan': 64, 'Infiltration': 3, 'Web Attack � XSS': 17, 'FTP-Patator': 1494, 'SSH-Patator': 12, 'DoS slowloris': 1642, 'DoS Slowhttptest': 3172, 'DoS Hulk': 67060, 'DoS GoldenEye': 2579}.
- ** min_seg_size_forward** (35; 0.00124%): potentially_invalid_preserved. CICFlowMeter describes this field as a count, size, time interval, statistic, or ratio; negative values conflict with that definition, but row-level extraction causes are not established.
  Per file: {'extracted/MachineLearningCVE/Monday-WorkingHours.pcap_ISCX.csv': 23, 'extracted/MachineLearningCVE/Tuesday-WorkingHours.pcap_ISCX.csv': 11, 'extracted/MachineLearningCVE/Wednesday-workingHours.pcap_ISCX.csv': 1}; per label: {'BENIGN': 35}.

## Infinities in flow-rate fields

- **Flow Bytes/s**: +Inf=1,509, -Inf=0; with Flow Duration == 0: 1,509; with nonzero or unavailable duration: 0.
  Per file: {'extracted/MachineLearningCVE/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv': {'nan_token': 4, 'missing_total': 4, 'positive_infinity': 30, 'finite_zero': 5026, 'negative': 2}, 'extracted/MachineLearningCVE/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv': {'nan_token': 15, 'missing_total': 15, 'positive_infinity': 356, 'finite_zero': 10968, 'negative': 36}, 'extracted/MachineLearningCVE/Friday-WorkingHours-Morning.pcap_ISCX.csv': {'nan_token': 28, 'missing_total': 28, 'positive_infinity': 94, 'finite_zero': 16095, 'negative': 8}, 'extracted/MachineLearningCVE/Monday-WorkingHours.pcap_ISCX.csv': {'nan_token': 64, 'missing_total': 64, 'positive_infinity': 373, 'negative': 9, 'finite_zero': 57544}, 'extracted/MachineLearningCVE/Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv': {'nan_token': 18, 'missing_total': 18, 'positive_infinity': 189, 'negative': 4, 'finite_zero': 25058}, 'extracted/MachineLearningCVE/Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv': {'nan_token': 20, 'missing_total': 20, 'positive_infinity': 115, 'finite_zero': 18083, 'negative': 10}, 'extracted/MachineLearningCVE/Tuesday-WorkingHours.pcap_ISCX.csv': {'nan_token': 201, 'missing_total': 201, 'positive_infinity': 63, 'finite_zero': 109726}, 'extracted/MachineLearningCVE/Wednesday-workingHours.pcap_ISCX.csv': {'nan_token': 1008, 'missing_total': 1008, 'positive_infinity': 289, 'negative': 16, 'finite_zero': 113267}}; per label: {'BENIGN': {'nan_token': 409, 'missing_total': 409, 'positive_infinity': 1368, 'finite_zero': 278257, 'negative': 85}, 'DDoS': {'positive_infinity': 2}, 'PortScan': {'finite_zero': 551, 'positive_infinity': 126}, 'Bot': {'finite_zero': 2, 'positive_infinity': 10}, 'Web Attack � Brute Force': {'finite_zero': 1356}, 'Web Attack � XSS': {'finite_zero': 628}, 'Web Attack � Sql Injection': {'finite_zero': 9}, 'FTP-Patator': {'finite_zero': 18, 'positive_infinity': 3}, 'SSH-Patator': {'finite_zero': 2918}, 'DoS slowloris': {'finite_zero': 1647}, 'DoS Hulk': {'nan_token': 949, 'missing_total': 949, 'finite_zero': 64979}, 'DoS Slowhttptest': {'finite_zero': 2823}, 'DoS GoldenEye': {'finite_zero': 2579}}.
- ** Flow Packets/s**: +Inf=2,867, -Inf=0; with Flow Duration == 0: 2,867; with nonzero or unavailable duration: 0.
  Per file: {'extracted/MachineLearningCVE/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv': {'positive_infinity': 34, 'negative': 2}, 'extracted/MachineLearningCVE/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv': {'positive_infinity': 371, 'negative': 36}, 'extracted/MachineLearningCVE/Friday-WorkingHours-Morning.pcap_ISCX.csv': {'positive_infinity': 122, 'negative': 9}, 'extracted/MachineLearningCVE/Monday-WorkingHours.pcap_ISCX.csv': {'positive_infinity': 437, 'negative': 15}, 'extracted/MachineLearningCVE/Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv': {'positive_infinity': 207, 'negative': 4}, 'extracted/MachineLearningCVE/Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv': {'positive_infinity': 135, 'negative': 11}, 'extracted/MachineLearningCVE/Tuesday-WorkingHours.pcap_ISCX.csv': {'positive_infinity': 264, 'negative': 17}, 'extracted/MachineLearningCVE/Wednesday-workingHours.pcap_ISCX.csv': {'positive_infinity': 1297, 'negative': 21}}; per label: {'BENIGN': {'positive_infinity': 1777, 'negative': 115}, 'DDoS': {'positive_infinity': 2}, 'PortScan': {'positive_infinity': 126}, 'Bot': {'positive_infinity': 10}, 'FTP-Patator': {'positive_infinity': 3}, 'DoS Hulk': {'positive_infinity': 949}}.

## Duplicate investigation

Fingerprint analysis available: **True**; repeated after-output scan: **not applicable**. Method: Two independently keyed 64-bit Pandas row fingerprints are combined to 128 bits and externally aggregated in SQLite; collision probability is negligible but not mathematically zero.
- Complete-row duplicates: 308,381 excess rows in 95,169 groups; 256,479 within-file excess rows; 33,563 groups span source files.
- Feature-vector duplicates: 309,079 excess rows in 95,479 groups; 256,479 within-file excess rows; 34,208 groups span source files.
- Feature-vector groups with different labels: 698.
- Conflicting feature-vector groups containing label BENIGN: 698.
- Conflicting feature-vector groups containing label DDoS: 3.
- Conflicting feature-vector groups containing label DoS Hulk: 130.
- Conflicting feature-vector groups containing label DoS slowloris: 1.
- Conflicting feature-vector groups containing label PortScan: 564.

| Source file | Exact duplicate excess rows | Feature-vector duplicate excess rows |
|---|---:|---:|
| extracted/MachineLearningCVE/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv | 2,633 | 2,633 |
| extracted/MachineLearningCVE/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv | 72,353 | 72,353 |
| extracted/MachineLearningCVE/Friday-WorkingHours-Morning.pcap_ISCX.csv | 6,888 | 6,888 |
| extracted/MachineLearningCVE/Monday-WorkingHours.pcap_ISCX.csv | 26,935 | 26,935 |
| extracted/MachineLearningCVE/Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv | 35,630 | 35,630 |
| extracted/MachineLearningCVE/Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv | 6,066 | 6,066 |
| extracted/MachineLearningCVE/Tuesday-WorkingHours.pcap_ISCX.csv | 24,065 | 24,065 |
| extracted/MachineLearningCVE/Wednesday-workingHours.pcap_ISCX.csv | 81,909 | 81,957 |

No duplicates were removed. Fingerprint collision probability is negligible but nonzero; the scan does not claim byte-level proof for a fingerprint match.

## Constant features

 Bwd PSH Flags,  Bwd URG Flags, Fwd Avg Bytes/Bulk,  Fwd Avg Packets/Bulk,  Fwd Avg Bulk Rate,  Bwd Avg Bytes/Bulk,  Bwd Avg Packets/Bulk, Bwd Avg Bulk Rate

Sampled low-cardinality features: Fwd PSH Flags,  Bwd PSH Flags,  Fwd URG Flags,  Bwd URG Flags, FIN Flag Count,  SYN Flag Count,  RST Flag Count,  PSH Flag Count,  ACK Flag Count,  URG Flag Count,  CWE Flag Count,  ECE Flag Count,  Down/Up Ratio, Fwd Avg Bytes/Bulk,  Fwd Avg Packets/Bulk,  Fwd Avg Bulk Rate,  Bwd Avg Bytes/Bulk,  Bwd Avg Packets/Bulk, Bwd Avg Bulk Rate

Sampled near-constant features:  Bwd PSH Flags,  Fwd URG Flags,  Bwd URG Flags,  RST Flag Count,  CWE Flag Count,  ECE Flag Count, Fwd Avg Bytes/Bulk,  Fwd Avg Packets/Bulk,  Fwd Avg Bulk Rate,  Bwd Avg Bytes/Bulk,  Bwd Avg Packets/Bulk, Bwd Avg Bulk Rate

Numeric representation classifications: {'numeric': 76, 'numeric_with_missing_or_nonfinite': 2}

## Outlier diagnostics

28,313 rows were sampled. Per-feature Tukey/IQR and median absolute deviation diagnostics are in JSON; estimates are sample-based and did not trigger removals.

## Method and limitations

- CSV source text is preserved. Numeric parsing is diagnostic only.
- Outlier summaries and cardinality are systematic-sample estimates, not full-data counts.
- Duplicate counts use a dual 64-bit row fingerprint. No records are removed.
- A feature's physical semantics and CICFlowMeter implementation history do not prove why a specific row is anomalous.
