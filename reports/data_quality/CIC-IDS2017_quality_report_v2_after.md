# Data quality assessment: CIC-IDS2017

- **Generated:** 2026-11-03T11:58:00+00:00
- **Coverage:** complete (2,830,743 rows)
- **Files:** 8; source columns: 83; feature columns: 78
- **Chunk size:** 25,000
- **Input values changed:** False

## Dataset and schema

Schema compatible: **True**; distinct source header sequences: **1**.

| File | Rows | Bytes | SHA-256 |
|---|---:|---:|---|
| extracted/MachineLearningCVE/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv | 225,745 | 132,728,207 | aae030b3082e96ee252d8d59f9361ae8477ee5940cf6edce8d49e7fcd58fa5b9 |
| extracted/MachineLearningCVE/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv | 286,467 | 152,069,241 | 090e64b4568c8855806e0b895504871774add9c944beaaef86e968b12f6e2449 |
| extracted/MachineLearningCVE/Friday-WorkingHours-Morning.pcap_ISCX.csv | 191,033 | 105,160,932 | d633eaddd2418d733359610708d63e48e4ca353dbb4f51e256d216ee0bf9a133 |
| extracted/MachineLearningCVE/Monday-WorkingHours.pcap_ISCX.csv | 529,918 | 302,552,791 | 495aed46622417cd19fafade39280c9efc3a5af229ec47cfee7d5694a1b4949c |
| extracted/MachineLearningCVE/Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv | 288,602 | 159,655,585 | 984853732e05c70ccae260ba870c7351141ad70f7e55cdec2709ef9ef183eea2 |
| extracted/MachineLearningCVE/Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv | 170,366 | 96,068,418 | 2fc1b924c590399925252c215de28de923ef4d50da169eddb851402bb0df69c1 |
| extracted/MachineLearningCVE/Tuesday-WorkingHours.pcap_ISCX.csv | 445,909 | 241,659,371 | 496065d98cb04fc35d781772d417c04b49e923a1cca94800a9d3a88ffc0b6b0f |
| extracted/MachineLearningCVE/Wednesday-workingHours.pcap_ISCX.csv | 692,703 | 391,816,486 | e677f4a542dc085279e75afbe7327eea9fe3c188f65850d7406ad75ac3c85a6f |

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
| Nan Token | 5,734 |
| Missing Total | 5,734 |
| Invalid Numeric | 0 |
| Positive Infinity | 0 |
| Negative Infinity | 0 |
| Negative | 2,446,321 |
| Overflow Or Nonfinite Conversion | 0 |

Finding classifications are counts of affected source feature cells, not counts of unique records:

- potentially_invalid: 3,580
- unresolved_missingness: 5,734
- unresolved_potential_sentinel: 2,442,741

## Feature-level findings

Missingness, parsing, infinity, zero, negative and finite range values are full-scan counts. Quantiles, IQR/MAD fences, sample cardinality and dominant-value rates are estimates from the deterministic systematic sample.

| Position | Source header | Missing | Invalid numeric | +Inf | -Inf | Negative | Finite min | Finite max |
|---:|---|---:|---:|---:|---:|---:|---:|---:|
| 1 | destination_port | 0 | 0 | 0 | 0 | 0 | 0 | 65535 |
| 2 | flow_duration | 0 | 0 | 0 | 0 | 115 | -13 | 1.2e+08 |
| 3 | total_fwd_packets | 0 | 0 | 0 | 0 | 0 | 1 | 219759 |
| 4 | total_backward_packets | 0 | 0 | 0 | 0 | 0 | 0 | 291922 |
| 5 | total_length_of_fwd_packets | 0 | 0 | 0 | 0 | 0 | 0 | 12900000 |
| 6 | total_length_of_bwd_packets | 0 | 0 | 0 | 0 | 0 | 0 | 6.5545303e+08 |
| 7 | fwd_packet_length_max | 0 | 0 | 0 | 0 | 0 | 0 | 24820 |
| 8 | fwd_packet_length_min | 0 | 0 | 0 | 0 | 0 | 0 | 2325 |
| 9 | fwd_packet_length_mean | 0 | 0 | 0 | 0 | 0 | 0 | 5940.8571 |
| 10 | fwd_packet_length_std | 0 | 0 | 0 | 0 | 0 | 0 | 7125.5968 |
| 11 | bwd_packet_length_max | 0 | 0 | 0 | 0 | 0 | 0 | 19530 |
| 12 | bwd_packet_length_min | 0 | 0 | 0 | 0 | 0 | 0 | 2896 |
| 13 | bwd_packet_length_mean | 0 | 0 | 0 | 0 | 0 | 0 | 5800.5 |
| 14 | bwd_packet_length_std | 0 | 0 | 0 | 0 | 0 | 0 | 8194.6605 |
| 15 | flow_bytes_s | 2,867 | 0 | 0 | 0 | 85 | -2.61e+08 | 2.071e+09 |
| 16 | flow_packets_s | 2,867 | 0 | 0 | 0 | 115 | -2000000 | 4000000 |
| 17 | flow_iat_mean | 0 | 0 | 0 | 0 | 115 | -13 | 1.2e+08 |
| 18 | flow_iat_std | 0 | 0 | 0 | 0 | 0 | 0 | 84800262 |
| 19 | flow_iat_max | 0 | 0 | 0 | 0 | 115 | -13 | 1.2e+08 |
| 20 | flow_iat_min | 0 | 0 | 0 | 0 | 2,891 | -14 | 1.2e+08 |
| 21 | fwd_iat_total | 0 | 0 | 0 | 0 | 0 | 0 | 1.2e+08 |
| 22 | fwd_iat_mean | 0 | 0 | 0 | 0 | 0 | 0 | 1.2e+08 |
| 23 | fwd_iat_std | 0 | 0 | 0 | 0 | 0 | 0 | 84602929 |
| 24 | fwd_iat_max | 0 | 0 | 0 | 0 | 0 | 0 | 1.2e+08 |
| 25 | fwd_iat_min | 0 | 0 | 0 | 0 | 17 | -12 | 1.2e+08 |
| 26 | bwd_iat_total | 0 | 0 | 0 | 0 | 0 | 0 | 1.2e+08 |
| 27 | bwd_iat_mean | 0 | 0 | 0 | 0 | 0 | 0 | 1.2e+08 |
| 28 | bwd_iat_std | 0 | 0 | 0 | 0 | 0 | 0 | 84418014 |
| 29 | bwd_iat_max | 0 | 0 | 0 | 0 | 0 | 0 | 1.2e+08 |
| 30 | bwd_iat_min | 0 | 0 | 0 | 0 | 0 | 0 | 1.2e+08 |
| 31 | fwd_psh_flags | 0 | 0 | 0 | 0 | 0 | 0 | 1 |
| 32 | bwd_psh_flags | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| 33 | fwd_urg_flags | 0 | 0 | 0 | 0 | 0 | 0 | 1 |
| 34 | bwd_urg_flags | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| 35 | fwd_header_length__source_col_35 | 0 | 0 | 0 | 0 | 35 | -3.2212235e+10 | 4644908 |
| 36 | bwd_header_length | 0 | 0 | 0 | 0 | 22 | -1.0737413e+09 | 5838440 |
| 37 | fwd_packets_s | 0 | 0 | 0 | 0 | 0 | 0 | 3000000 |
| 38 | bwd_packets_s | 0 | 0 | 0 | 0 | 0 | 0 | 2000000 |
| 39 | min_packet_length | 0 | 0 | 0 | 0 | 0 | 0 | 1448 |
| 40 | max_packet_length | 0 | 0 | 0 | 0 | 0 | 0 | 24820 |
| 41 | packet_length_mean | 0 | 0 | 0 | 0 | 0 | 0 | 3337.1429 |
| 42 | packet_length_std | 0 | 0 | 0 | 0 | 0 | 0 | 4731.5224 |
| 43 | packet_length_variance | 0 | 0 | 0 | 0 | 0 | 0 | 22400000 |
| 44 | fin_flag_count | 0 | 0 | 0 | 0 | 0 | 0 | 1 |
| 45 | syn_flag_count | 0 | 0 | 0 | 0 | 0 | 0 | 1 |
| 46 | rst_flag_count | 0 | 0 | 0 | 0 | 0 | 0 | 1 |
| 47 | psh_flag_count | 0 | 0 | 0 | 0 | 0 | 0 | 1 |
| 48 | ack_flag_count | 0 | 0 | 0 | 0 | 0 | 0 | 1 |
| 49 | urg_flag_count | 0 | 0 | 0 | 0 | 0 | 0 | 1 |
| 50 | cwe_flag_count | 0 | 0 | 0 | 0 | 0 | 0 | 1 |
| 51 | ece_flag_count | 0 | 0 | 0 | 0 | 0 | 0 | 1 |
| 52 | down_up_ratio | 0 | 0 | 0 | 0 | 0 | 0 | 156 |
| 53 | average_packet_size | 0 | 0 | 0 | 0 | 0 | 0 | 3893.3333 |
| 54 | avg_fwd_segment_size | 0 | 0 | 0 | 0 | 0 | 0 | 5940.8571 |
| 55 | avg_bwd_segment_size | 0 | 0 | 0 | 0 | 0 | 0 | 5800.5 |
| 56 | fwd_header_length__source_col_56 | 0 | 0 | 0 | 0 | 35 | -3.2212235e+10 | 4644908 |
| 57 | fwd_avg_bytes_bulk | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| 58 | fwd_avg_packets_bulk | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| 59 | fwd_avg_bulk_rate | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| 60 | bwd_avg_bytes_bulk | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| 61 | bwd_avg_packets_bulk | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| 62 | bwd_avg_bulk_rate | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| 63 | subflow_fwd_packets | 0 | 0 | 0 | 0 | 0 | 1 | 219759 |
| 64 | subflow_fwd_bytes | 0 | 0 | 0 | 0 | 0 | 0 | 12870338 |
| 65 | subflow_bwd_packets | 0 | 0 | 0 | 0 | 0 | 0 | 291922 |
| 66 | subflow_bwd_bytes | 0 | 0 | 0 | 0 | 0 | 0 | 6.5545303e+08 |
| 67 | init_win_bytes_forward | 0 | 0 | 0 | 0 | 1,001,189 | -1 | 65535 |
| 68 | init_win_bytes_backward | 0 | 0 | 0 | 0 | 1,441,552 | -1 | 65535 |
| 69 | act_data_pkt_fwd | 0 | 0 | 0 | 0 | 0 | 0 | 213557 |
| 70 | min_seg_size_forward | 0 | 0 | 0 | 0 | 35 | -5.3687066e+08 | 138 |
| 71 | active_mean | 0 | 0 | 0 | 0 | 0 | 0 | 1.1e+08 |
| 72 | active_std | 0 | 0 | 0 | 0 | 0 | 0 | 74200000 |
| 73 | active_max | 0 | 0 | 0 | 0 | 0 | 0 | 1.1e+08 |
| 74 | active_min | 0 | 0 | 0 | 0 | 0 | 0 | 1.1e+08 |
| 75 | idle_mean | 0 | 0 | 0 | 0 | 0 | 0 | 1.2e+08 |
| 76 | idle_std | 0 | 0 | 0 | 0 | 0 | 0 | 76900000 |
| 77 | idle_max | 0 | 0 | 0 | 0 | 0 | 0 | 1.2e+08 |
| 78 | idle_min | 0 | 0 | 0 | 0 | 0 | 0 | 1.2e+08 |

## Negative-value semantics

- **flow_duration** (115; 0.00406%): potentially_invalid_preserved. CICFlowMeter describes this field as a count, size, time interval, statistic, or ratio; negative values conflict with that definition, but row-level extraction causes are not established.
  Per file: {'extracted/MachineLearningCVE/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv': 2, 'extracted/MachineLearningCVE/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv': 36, 'extracted/MachineLearningCVE/Friday-WorkingHours-Morning.pcap_ISCX.csv': 9, 'extracted/MachineLearningCVE/Monday-WorkingHours.pcap_ISCX.csv': 15, 'extracted/MachineLearningCVE/Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv': 4, 'extracted/MachineLearningCVE/Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv': 11, 'extracted/MachineLearningCVE/Tuesday-WorkingHours.pcap_ISCX.csv': 17, 'extracted/MachineLearningCVE/Wednesday-workingHours.pcap_ISCX.csv': 21}; per label: {'BENIGN': 115}.
- **flow_bytes_s** (85; 0.00300%): potentially_invalid_preserved. CICFlowMeter describes this field as a count, size, time interval, statistic, or ratio; negative values conflict with that definition, but row-level extraction causes are not established.
  Per file: {'extracted/MachineLearningCVE/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv': 2, 'extracted/MachineLearningCVE/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv': 36, 'extracted/MachineLearningCVE/Friday-WorkingHours-Morning.pcap_ISCX.csv': 8, 'extracted/MachineLearningCVE/Monday-WorkingHours.pcap_ISCX.csv': 9, 'extracted/MachineLearningCVE/Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv': 4, 'extracted/MachineLearningCVE/Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv': 10, 'extracted/MachineLearningCVE/Wednesday-workingHours.pcap_ISCX.csv': 16}; per label: {'BENIGN': 85}.
- **flow_packets_s** (115; 0.00406%): potentially_invalid_preserved. CICFlowMeter describes this field as a count, size, time interval, statistic, or ratio; negative values conflict with that definition, but row-level extraction causes are not established.
  Per file: {'extracted/MachineLearningCVE/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv': 2, 'extracted/MachineLearningCVE/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv': 36, 'extracted/MachineLearningCVE/Friday-WorkingHours-Morning.pcap_ISCX.csv': 9, 'extracted/MachineLearningCVE/Monday-WorkingHours.pcap_ISCX.csv': 15, 'extracted/MachineLearningCVE/Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv': 4, 'extracted/MachineLearningCVE/Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv': 11, 'extracted/MachineLearningCVE/Tuesday-WorkingHours.pcap_ISCX.csv': 17, 'extracted/MachineLearningCVE/Wednesday-workingHours.pcap_ISCX.csv': 21}; per label: {'BENIGN': 115}.
- **flow_iat_mean** (115; 0.00406%): potentially_invalid_preserved. CICFlowMeter describes this field as a count, size, time interval, statistic, or ratio; negative values conflict with that definition, but row-level extraction causes are not established.
  Per file: {'extracted/MachineLearningCVE/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv': 2, 'extracted/MachineLearningCVE/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv': 36, 'extracted/MachineLearningCVE/Friday-WorkingHours-Morning.pcap_ISCX.csv': 9, 'extracted/MachineLearningCVE/Monday-WorkingHours.pcap_ISCX.csv': 15, 'extracted/MachineLearningCVE/Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv': 4, 'extracted/MachineLearningCVE/Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv': 11, 'extracted/MachineLearningCVE/Tuesday-WorkingHours.pcap_ISCX.csv': 17, 'extracted/MachineLearningCVE/Wednesday-workingHours.pcap_ISCX.csv': 21}; per label: {'BENIGN': 115}.
- **flow_iat_max** (115; 0.00406%): potentially_invalid_preserved. CICFlowMeter describes this field as a count, size, time interval, statistic, or ratio; negative values conflict with that definition, but row-level extraction causes are not established.
  Per file: {'extracted/MachineLearningCVE/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv': 2, 'extracted/MachineLearningCVE/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv': 36, 'extracted/MachineLearningCVE/Friday-WorkingHours-Morning.pcap_ISCX.csv': 9, 'extracted/MachineLearningCVE/Monday-WorkingHours.pcap_ISCX.csv': 15, 'extracted/MachineLearningCVE/Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv': 4, 'extracted/MachineLearningCVE/Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv': 11, 'extracted/MachineLearningCVE/Tuesday-WorkingHours.pcap_ISCX.csv': 17, 'extracted/MachineLearningCVE/Wednesday-workingHours.pcap_ISCX.csv': 21}; per label: {'BENIGN': 115}.
- **flow_iat_min** (2,891; 0.10213%): potentially_invalid_preserved. CICFlowMeter describes this field as a count, size, time interval, statistic, or ratio; negative values conflict with that definition, but row-level extraction causes are not established.
  Per file: {'extracted/MachineLearningCVE/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv': 108, 'extracted/MachineLearningCVE/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv': 176, 'extracted/MachineLearningCVE/Friday-WorkingHours-Morning.pcap_ISCX.csv': 225, 'extracted/MachineLearningCVE/Monday-WorkingHours.pcap_ISCX.csv': 512, 'extracted/MachineLearningCVE/Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv': 353, 'extracted/MachineLearningCVE/Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv': 263, 'extracted/MachineLearningCVE/Tuesday-WorkingHours.pcap_ISCX.csv': 505, 'extracted/MachineLearningCVE/Wednesday-workingHours.pcap_ISCX.csv': 749}; per label: {'BENIGN': 2697, 'DDoS': 19, 'Infiltration': 1, 'FTP-Patator': 4, 'SSH-Patator': 2, 'DoS Hulk': 159, 'DoS GoldenEye': 5, 'Heartbleed': 4}.
- **fwd_iat_min** (17; 0.00060%): potentially_invalid_preserved. CICFlowMeter describes this field as a count, size, time interval, statistic, or ratio; negative values conflict with that definition, but row-level extraction causes are not established.
  Per file: {'extracted/MachineLearningCVE/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv': 6, 'extracted/MachineLearningCVE/Wednesday-workingHours.pcap_ISCX.csv': 11}; per label: {'DDoS': 6, 'DoS Hulk': 8, 'DoS GoldenEye': 3}.
- **fwd_header_length__source_col_35** (35; 0.00124%): potentially_invalid_preserved. CICFlowMeter describes this field as a count, size, time interval, statistic, or ratio; negative values conflict with that definition, but row-level extraction causes are not established.
  Per file: {'extracted/MachineLearningCVE/Monday-WorkingHours.pcap_ISCX.csv': 23, 'extracted/MachineLearningCVE/Tuesday-WorkingHours.pcap_ISCX.csv': 11, 'extracted/MachineLearningCVE/Wednesday-workingHours.pcap_ISCX.csv': 1}; per label: {'BENIGN': 35}.
- **bwd_header_length** (22; 0.00078%): potentially_invalid_preserved. CICFlowMeter describes this field as a count, size, time interval, statistic, or ratio; negative values conflict with that definition, but row-level extraction causes are not established.
  Per file: {'extracted/MachineLearningCVE/Monday-WorkingHours.pcap_ISCX.csv': 17, 'extracted/MachineLearningCVE/Tuesday-WorkingHours.pcap_ISCX.csv': 5}; per label: {'BENIGN': 22}.
- **fwd_header_length__source_col_56** (35; 0.00124%): potentially_invalid_preserved. CICFlowMeter describes this field as a count, size, time interval, statistic, or ratio; negative values conflict with that definition, but row-level extraction causes are not established.
  Per file: {'extracted/MachineLearningCVE/Monday-WorkingHours.pcap_ISCX.csv': 23, 'extracted/MachineLearningCVE/Tuesday-WorkingHours.pcap_ISCX.csv': 11, 'extracted/MachineLearningCVE/Wednesday-workingHours.pcap_ISCX.csv': 1}; per label: {'BENIGN': 35}.
- **init_win_bytes_forward** (1,001,189; 35.36842%): unresolved_potential_sentinel. Negative byte counts are not physically meaningful; the frequent -1 may be an unavailable-value sentinel, but the source extract does not document that encoding.
  Per file: {'extracted/MachineLearningCVE/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv': 32925, 'extracted/MachineLearningCVE/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv': 60210, 'extracted/MachineLearningCVE/Friday-WorkingHours-Morning.pcap_ISCX.csv': 95834, 'extracted/MachineLearningCVE/Monday-WorkingHours.pcap_ISCX.csv': 224495, 'extracted/MachineLearningCVE/Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv': 102433, 'extracted/MachineLearningCVE/Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv': 81911, 'extracted/MachineLearningCVE/Tuesday-WorkingHours.pcap_ISCX.csv': 200128, 'extracted/MachineLearningCVE/Wednesday-workingHours.pcap_ISCX.csv': 203253}; per label: {'BENIGN': 1001182, 'PortScan': 7}.
- **init_win_bytes_backward** (1,441,552; 50.92486%): unresolved_potential_sentinel. Negative byte counts are not physically meaningful; the frequent -1 may be an unavailable-value sentinel, but the source extract does not document that encoding.
  Per file: {'extracted/MachineLearningCVE/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv': 88299, 'extracted/MachineLearningCVE/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv': 76942, 'extracted/MachineLearningCVE/Friday-WorkingHours-Morning.pcap_ISCX.csv': 118419, 'extracted/MachineLearningCVE/Monday-WorkingHours.pcap_ISCX.csv': 299094, 'extracted/MachineLearningCVE/Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv': 164351, 'extracted/MachineLearningCVE/Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv': 102373, 'extracted/MachineLearningCVE/Tuesday-WorkingHours.pcap_ISCX.csv': 256599, 'extracted/MachineLearningCVE/Wednesday-workingHours.pcap_ISCX.csv': 335475}; per label: {'BENIGN': 1318981, 'DDoS': 46528, 'PortScan': 64, 'Infiltration': 3, 'Web Attack � XSS': 17, 'FTP-Patator': 1494, 'SSH-Patator': 12, 'DoS slowloris': 1642, 'DoS Slowhttptest': 3172, 'DoS Hulk': 67060, 'DoS GoldenEye': 2579}.
- **min_seg_size_forward** (35; 0.00124%): potentially_invalid_preserved. CICFlowMeter describes this field as a count, size, time interval, statistic, or ratio; negative values conflict with that definition, but row-level extraction causes are not established.
  Per file: {'extracted/MachineLearningCVE/Monday-WorkingHours.pcap_ISCX.csv': 23, 'extracted/MachineLearningCVE/Tuesday-WorkingHours.pcap_ISCX.csv': 11, 'extracted/MachineLearningCVE/Wednesday-workingHours.pcap_ISCX.csv': 1}; per label: {'BENIGN': 35}.

## Infinities in flow-rate fields


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

bwd_psh_flags, bwd_urg_flags, fwd_avg_bytes_bulk, fwd_avg_packets_bulk, fwd_avg_bulk_rate, bwd_avg_bytes_bulk, bwd_avg_packets_bulk, bwd_avg_bulk_rate

Sampled low-cardinality features: fwd_psh_flags, bwd_psh_flags, fwd_urg_flags, bwd_urg_flags, fin_flag_count, syn_flag_count, rst_flag_count, psh_flag_count, ack_flag_count, urg_flag_count, cwe_flag_count, ece_flag_count, down_up_ratio, fwd_avg_bytes_bulk, fwd_avg_packets_bulk, fwd_avg_bulk_rate, bwd_avg_bytes_bulk, bwd_avg_packets_bulk, bwd_avg_bulk_rate

Sampled near-constant features: bwd_psh_flags, fwd_urg_flags, bwd_urg_flags, rst_flag_count, cwe_flag_count, ece_flag_count, fwd_avg_bytes_bulk, fwd_avg_packets_bulk, fwd_avg_bulk_rate, bwd_avg_bytes_bulk, bwd_avg_packets_bulk, bwd_avg_bulk_rate

Numeric representation classifications: {'numeric': 76, 'numeric_with_missing_or_nonfinite': 2}

## Outlier diagnostics

28,313 rows were sampled. Per-feature Tukey/IQR and median absolute deviation diagnostics are in JSON; estimates are sample-based and did not trigger removals.

## Method and limitations

- CSV source text is preserved. Numeric parsing is diagnostic only.
- Outlier summaries and cardinality are systematic-sample estimates, not full-data counts.
- Duplicate counts use a dual 64-bit row fingerprint. No records are removed.
- A feature's physical semantics and CICFlowMeter implementation history do not prove why a specific row is anomalous.
