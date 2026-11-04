# Multi-class Classification

## Objective and scope

Phase 07 provides an offline, reproducible classifier for the original known CIC-IDS2017 traffic labels. It reuses the Phase 05 feature contract and preprocessing package. It does not implement binary classification, anomaly detection, SHAP, serving, alert correlation, or unknown-attack detection.

Phase 06 binary classification was not implemented or validated before Phase 07. The multi-class implementation was built directly on the Phase 05 API; no binary model framework or artifact existed to reuse. This limitation is recorded with the experiment.

## Taxonomy and label mapping

The supported taxonomy is discovered from the validated Phase 04 v2 Parquet files and checked against `configs/feature_schema.json`. The original normalized strings are preserved exactly, including the replacement character present in the three `Web Attack` labels in the source export. Null, blank, and contract-unknown labels fail validation. `BENIGN` must be present.

Mapping version `1.0.0` places `BENIGN` at identifier 0 and orders the observed attack labels lexicographically after it. Every model uses the same mapping; model outputs are decoded back to the original labels. Unknown labels raise an explicit error and are never remapped to `BENIGN`.

## Actual class distribution

Full-dataset counts over all eight Phase 04 outputs (2,830,743 rows):

| Label | Rows | Dataset share | Source files |
|---|---:|---:|---:|
| BENIGN | 2,273,097 | 80.3004% | 8 |
| Bot | 1,966 | 0.0695% | 1 |
| DDoS | 128,027 | 4.5227% | 1 |
| DoS GoldenEye | 10,293 | 0.3636% | 1 |
| DoS Hulk | 231,073 | 8.1630% | 1 |
| DoS Slowhttptest | 5,499 | 0.1943% | 1 |
| DoS slowloris | 5,796 | 0.2048% | 1 |
| FTP-Patator | 7,938 | 0.2804% | 1 |
| Heartbleed | 11 | 0.0004% | 1 |
| Infiltration | 36 | 0.0013% | 1 |
| PortScan | 158,930 | 5.6144% | 1 |
| SSH-Patator | 5,897 | 0.2083% | 1 |
| Web Attack � Brute Force | 1,507 | 0.0532% | 1 |
| Web Attack � Sql Injection | 21 | 0.0007% | 1 |
| Web Attack � XSS | 652 | 0.0230% | 1 |

The majority-to-minority ratio is approximately **206,645:1**. The complete per-file table is `reports/evaluation/multiclass/<run_id>/class_distribution_by_source_file.csv`; the full counts and percentages are in `class_distribution.csv`. A log-scale chart is saved under `reports/figures/multiclass/<run_id>/`.

Accuracy and weighted F1 follow the dominant `BENIGN` class. Macro F1 weights represented classes equally; balanced accuracy averages per-class recall. Per-class recall and support are needed to interpret minority performance. Small supports make precision and recall highly variable.

## Splitting and leakage limits

The configured strategy first attempts source-file-disjoint group splitting. That cannot cover all classes in three partitions: every attack class occurs in exactly one source file, while `BENIGN` occurs in all eight. The configured and reported fallback is an explicit stratified row split with 70% train, 15% validation, and 15% test:

| Partition | Rows |
|---|---:|
| Train | 1,981,520 |
| Validation | 424,611 |
| Held-out test | 424,612 |

All eight source groups overlap across the partitions. Related and duplicate flows may also overlap; Phase 04 found 308,381 excess exact-row matches and 309,079 excess repeated-feature-vector matches, with 698 conflicting-label feature groups. The row-split metrics are exploratory and do **not** establish cross-capture or real-world generalization. The split audit is in `split_audit.json`.

## Features, preprocessing, and imbalance handling

All models use the 78 approved numeric predictive inputs from the Phase 05 contract. `label` and provenance/identifiers stay outside X. Preprocessors are independent by model and are fitted only on a stratified subset of the training partition. Validation and test data are transformed without refitting.

The training partition contains 1,981,520 rows; each model used an 80,000-row reproducible sample. Every training example is retained for classes whose training support is at most 50 rows, including all 8 Heartbleed, 25 Infiltration, and 15 SQL Injection training examples. Remaining rows are allocated proportionally among larger classes. Class weights are calculated from the full training partition only. Logistic Regression and Random Forest use explicit balanced class weights; no resampling is applied.

Logistic Regression uses the `linear` StandardScaler profile. Random Forest uses the `tree` profile without scaling. The actual per-model configuration and training class counts are stored in artifact metadata and the experiment summary.

## Models and actual results

The installed Scikit-learn version is 1.8.0. XGBoost is not installed, so it was not trained; no dependency was installed for this phase.

| Model | Validation accuracy | Validation balanced accuracy | Validation macro F1 | Validation weighted F1 | Validation ROC-AUC OVR macro | Fit time |
|---|---:|---:|---:|---:|---:|---:|
| Logistic Regression | 0.8468 | 0.8732 | 0.4287 | 0.8949 | 0.9903 | 9.05 s |
| Random Forest | 0.9974 | 0.8251 | 0.8349 | 0.9974 | 0.9959 | 1.81 s |
| XGBoost | unavailable | unavailable | unavailable | unavailable | unavailable | unavailable |

Random Forest was selected using **validation macro F1 only**. It was evaluated once on the held-out test partition:

| Metric | Held-out test result |
|---|---:|
| Accuracy | 0.9974 |
| Balanced accuracy | 0.8804 |
| Macro precision | 0.8636 |
| Macro recall | 0.8804 |
| Macro F1 | 0.8549 |
| Weighted precision | 0.9974 |
| Weighted recall | 0.9974 |
| Weighted F1 | 0.9974 |
| Multiclass ROC-AUC, OVR macro | 0.9969 |
| Multiclass average precision, macro | 0.8804 |

These are actual CIC-IDS2017 results from the explicitly stratified row fallback and are likely optimistic due to group and duplicate overlap. They are not evidence of cross-capture performance.

Logistic Regression reached its configured 160-iteration limit and emitted a `ConvergenceWarning`. The warning is preserved in the model artifact and experiment metadata; its validation scores should be treated as an unconverged baseline. Random Forest had no training warning.

## Per-class and error analysis

Selected Random Forest test recall highlights:

| Label | Recall | Test support |
|---|---:|---:|
| Bot | 0.5492 | 295 |
| Web Attack � Brute Force | 0.6460 | 226 |
| Web Attack � XSS | 0.3265 | 98 |
| Infiltration | 0.8000 | 5 |
| Web Attack � Sql Injection | 1.0000 | 3 |
| Heartbleed | 1.0000 | 1 |

The last three estimates have too little support to establish reliable detection. Perfect recall for one Heartbleed record or three SQL Injection records is not a reliable claim about those attacks. Bot and Web Attack XSS remain the weakest of the larger minority classes in the held-out partition.

The most frequent selected-model test confusions were `BENIGN → DoS Hulk` (230), `BENIGN → PortScan` (145), `BENIGN → Bot` (133), and `Bot → BENIGN` (133). The normalized and raw confusion matrices, per-class metrics, and confusion-pair tables are saved with the run. A separate bounded reservoir pass compares median feature values for the top confusion pairs; those summaries are descriptive, not causal.

Random Forest's top impurity-importance features were `max_packet_length`, `total_length_of_bwd_packets`, `destination_port`, `bwd_packet_length_max`, and `avg_bwd_segment_size`. Logistic Regression importance is reported as mean absolute coefficient magnitude across classes. These scores do not show causation and were not used to remove fields. SHAP is outside Phase 07.

## Reusable training and prediction interface

The reusable workflow is in `src/intrusion_intelligence/multiclass/`; `configs/multiclass.toml` controls paths, split fractions, model parameters, sample limits, batch size, seed, and artifact version. From an installed editable project, run:

```powershell
python -m pip install -r requirements.txt
python -m intrusion_intelligence.multiclass --config configs/multiclass.toml
```

The command writes machine-readable evaluation outputs under `reports/evaluation/multiclass/<run_id>/`, figures under `reports/figures/multiclass/<run_id>/`, and experiment metadata under `reports/experiments/multiclass/<run_id>/`. Trained bundles are stored separately at `models/supervised/multiclass/<model_name>/<version>/`. Each bundle includes a classifier, matching fitted preprocessor, taxonomy, and metadata. Existing versions are not overwritten; change the configured version before a new save.

`MultiClassPredictor(artifact_path).predict(X)` validates and transforms a feature-only DataFrame, returns original label strings, and aligns per-class scores to the saved taxonomy. It does not refit. The probability scores are scores among learned known classes, not unknown-attack probabilities. Serialized Joblib files must be treated as trusted inputs.

## Run files and limitations

The actual run identifier is `20261103T134128Z`. Its readable report is `reports/evaluation/multiclass/20261103T134128Z/multiclass_classification_report.md`; the complete structured summary is `reports/experiments/multiclass/20261103T134128Z/experiment_summary.json`.

Known limitations:

- Phase 06 binary classification was not completed or validated first.
- The group-aware three-way split cannot include every class in every partition; the row fallback overlaps source files and may overlap duplicate flows.
- The classifiers use 80,000 of 1,981,520 training rows due to local memory limits, although all rare classes' training rows are retained.
- Heartbleed, Infiltration, and SQL Injection have only 11, 36, and 21 full-dataset rows, respectively.
- Logistic Regression did not converge at its configured iteration limit.
- XGBoost was unavailable; no anomaly model, unknown-attack detection, cross-dataset evaluation, or production claim is made.
