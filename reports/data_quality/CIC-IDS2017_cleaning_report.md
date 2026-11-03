# Cleaning run: CIC-IDS2017

- **Run status:** completed
- **Generated:** 2026-11-03T08:03:35+00:00
- **Policy version:** 1.0
- **Input rows:** 2,830,743
- **Output rows:** 2,830,743
- **Excluded rows:** 0
- **Labels preserved:** True
- **Source cell stream fingerprints match:** True
- **Raw files unchanged:** True

## Cleaning policy

- **structural:** header_action=preserve_source_headers_with_position_aliases; add_provenance_columns=True
- **missing:** action=preserve_source_text
- **infinity:** action=preserve_source_text
- **negative:** action=preserve
- **duplicates:** action=preserve
- **outliers:** action=preserve
- **features:** action=retain_all
- **rows:** action=exclude_none
- **labels:** action=preserve_source_text

## Transformations

Source feature and label cells were preserved as parsed text. Three provenance columns were appended: __source_file, __source_row_number, and __record_id. CSV serialization is UTF-8. No values were imputed, coerced, clipped, deduplicated, or removed.

- Rows retained: 2,830,743
- Rows excluded: 0
- Feature/label cell changes: 0
- Provenance fields appended: __source_file, __source_row_number, __record_id

## Output files

| Source | Processed CSV | Rows | SHA-256 |
|---|---|---:|---|
| extracted/MachineLearningCVE/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv | cleaned/extracted/MachineLearningCVE/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv | 225,745 | 48ff794897637bbda2af58cf127cfb2981d22c33e9dd4f1f8f8fd8c511be72a3 |
| extracted/MachineLearningCVE/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv | cleaned/extracted/MachineLearningCVE/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv | 286,467 | 829ee2c52b50a1cf908e3d906dc053f373164c6d0f5215ff879f4a21ff40f783 |
| extracted/MachineLearningCVE/Friday-WorkingHours-Morning.pcap_ISCX.csv | cleaned/extracted/MachineLearningCVE/Friday-WorkingHours-Morning.pcap_ISCX.csv | 191,033 | 8c01667e4f3866badf2695684cce33c7d126933830227508aa953fb483412059 |
| extracted/MachineLearningCVE/Monday-WorkingHours.pcap_ISCX.csv | cleaned/extracted/MachineLearningCVE/Monday-WorkingHours.pcap_ISCX.csv | 529,918 | 7ebf989ce8190c33dd3e3326be5a5514c42a965947e45a3224fc13a499db1cd1 |
| extracted/MachineLearningCVE/Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv | cleaned/extracted/MachineLearningCVE/Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv | 288,602 | 4cd226805bf08430522be67302ccae399e7290ca3fc22521425e5e7fcd88cd7b |
| extracted/MachineLearningCVE/Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv | cleaned/extracted/MachineLearningCVE/Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv | 170,366 | 3c5d8e0c02ab8e6355a852e2afd6a6eb43ecf16d67672438e3100753f3e768e3 |
| extracted/MachineLearningCVE/Tuesday-WorkingHours.pcap_ISCX.csv | cleaned/extracted/MachineLearningCVE/Tuesday-WorkingHours.pcap_ISCX.csv | 445,909 | b89ebdab0ed276276e3164ee1bc2535ce3ea3fce6f66e1f38a127ce05fde33c5 |
| extracted/MachineLearningCVE/Wednesday-workingHours.pcap_ISCX.csv | cleaned/extracted/MachineLearningCVE/Wednesday-workingHours.pcap_ISCX.csv | 692,703 | f2fbfb62614e3bea9acbbeb0cc22b6081b8b994a0932e38fc647d682ee2de64a |

## Verification

- **Labels Preserved:** True
- **Source Values Preserved:** True
- **Feature Quality Counts Preserved:** True
- **Raw Files Unchanged:** True
- **All Output Records Retained:** True
- **Record Ids Derived From Label:** False
- **Records Removed:** 0

## Limitations

- Processed CSV feature and label values are preserved as decoded source text; unresolved anomalies remain for a later, explicitly fitted modeling workflow.
- The CICFlowMeter feature documentation establishes field semantics, but the CSV alone does not establish why each invalid-looking row was produced.
- The deterministic record identifier is a 96-bit BLAKE2b digest of the source-relative path, input-file SHA-256, and 1-based source row; labels are not used.
