# Phase 08 — Unsupervised Anomaly Detection

## Objective and interpretation

The anomaly engine learns a baseline from validated benign CIC-IDS2017 flows and assigns higher scores to flows that differ from that baseline. It is separate from the supervised classifiers: no attack labels enter model fitting, and attack labels do not select thresholds. An anomaly is unusual relative to the observed baseline; it is not proof of malicious intent or a probability of compromise. The detector can miss attacks that resemble benign traffic and can flag legitimate but unusual traffic.

## Data and feature policy

The pipeline reads the eight Phase 04 v2 cleaned Parquet files and the Phase 05 feature contract. The actual export contains 2,830,743 rows, 78 numeric predictive features, and 15 validated original labels. The exact benign value is `BENIGN`; null, blank, or unknown labels are rejected. Features, original labels, and available metadata are kept separate. The model receives the 78 contract-approved predictive features only. Source-file provenance is used for grouping and reporting, not as a model input. The export does not contain timestamps, endpoints, Flow ID, protocol, or standalone source port; the preparation report lists unavailable optional metadata.

## Partitions and leakage audit

Partitions are explicit, chronological capture-day holdouts with no random-row fallback:

| Partition | Capture days | Rows | BENIGN | Attacks |
|---|---|---:|---:|---:|
| Train | Monday–Wednesday | 1,668,530 | 1,402,023 | 266,507 |
| Validation | Thursday | 458,968 | 456,752 | 2,216 |
| Test | Friday | 703,245 | 414,322 | 288,923 |

Only a deterministic 150,000-row sample of benign training observations fits preprocessing and Isolation Forest. Validation attacks are retained in the split audit but ignored during threshold calibration. Friday test labels are consulted only after the model and operating thresholds are frozen.

Capture-day and source-file groups are disjoint across partitions. A separate audit hashes the 78 predictive-feature vectors without labels or provenance: it found 95,479 repeated-vector groups overall, of which 32,266 cross capture days. Those links connect all five days, making a three-way split that is both capture-day-disjoint and duplicate-group-disjoint impossible for this extract. In the chosen day split, 28,644 repeated-vector groups cross partition boundaries (132,348 rows); 633 such groups have conflicting original labels. This benchmark is therefore not described as fully leakage-free, and duplicate overlap may make results optimistic.

## Preprocessing and model

The pipeline builds the independent Phase 05 `anomaly` preprocessing profile. It uses training-fitted median imputation and `RobustScaler`; the fitted transformer sees only the benign 150,000-row training sample and is reused without refitting for validation, test, and inference. Isolation Forest uses randomized tree partitions rather than distance comparisons, so scaling is not required in the way it is for One-Class SVM or LOF. The profile retains the Phase 05 training-fitted scaling interface; its affine feature transforms are not outlier treatment and should not be expected to solve capture shift. A scaled/unscaled model comparison remains a useful future sensitivity check. The current contract contains numeric features only, so no categorical encoder is needed. Transformed feature ordering and schema are versioned and checked at inference.

The implemented baseline is Scikit-learn Isolation Forest (Scikit-learn 1.8.0): 200 estimators, `max_samples=4096`, `max_features=1.0`, `contamination="auto"`, `bootstrap=False`, `random_state=42`, and `n_jobs=4`. The training subset is sampled reproducibly without replacement, and scoring streams in 20,000-row batches. On the recorded environment, preprocessing fit took about 1.51 seconds, Isolation Forest fit 1.68 seconds, and Friday transform/scoring 9.74 seconds. The saved estimator is 1,756,395 bytes and the fitted preprocessor is 6,518 bytes. These timings are environment-specific, not production throughput. `contamination` controls the estimator's internal offset; it is not an attack prevalence estimate and does not define the external decision threshold.

One-Class SVM with an RBF kernel was considered but not implemented: kernel training on a representative subset of a 1.4-million-row benign population would add substantial time and memory cost without a clear comparison benefit for this baseline. Local Outlier Factor novelty detection was also considered but not implemented because the neighbor index and full novelty-scoring workload are expensive at this scale. The model-comparison table records both statuses. No alternative was trained.

## Scores and calibration

The service obtains Isolation Forest `score_samples`, which is inlier-oriented, and negates it: `anomaly_score = -raw_model_score`. Thus higher common scores mean more anomalous. Raw values and the common score are both available in inference output. Scores are not normalized across algorithms and are not probabilities.

Thresholds use the empirical upper quantile of 456,752 benign Thursday validation scores with NumPy's `higher` quantile method. The decision rule is strictly `anomaly_score > threshold`; ties are normal. The configured operating points and measured validation false-positive rates were:

| Operating point | Threshold | Target validation FPR | Achieved validation FPR |
|---|---:|---:|---:|
| 0.5% | 0.56409132 | 0.500% | 0.4998% |
| 1% (default) | 0.52820603 | 1.000% | 0.9999% |
| 2% | 0.48703315 | 2.000% | 2.0000% |
| 5% | 0.43209545 | 5.000% | 4.9999% |
| 10% | 0.38399146 | 10.000% | 10.0000% |

These rates describe the selected validation population, not a guarantee for future traffic. The selected default was configured before inspecting test metrics; thresholds were not chosen by test F1 or attack recall.

## Held-out CIC-IDS2017 evaluation

At the default 1% validation operating point, the Friday test set produced:

| Metric | Result |
|---|---:|
| TN / FP / FN / TP | 393,992 / 20,330 / 243,942 / 44,981 |
| Attack precision | 0.6887 |
| Attack recall | 0.1557 |
| Attack F1 | 0.2540 |
| Test false-positive rate | 4.9068% |
| False-negative rate | 84.4315% |
| Specificity | 0.9509 |
| Balanced accuracy | 0.5533 |
| Accuracy | 0.6242 |
| ROC-AUC | 0.6941 |
| Average Precision | 0.5494 |

The test false-positive rate exceeded the 1% validation target, showing capture-day/source distribution shift. On Friday, BENIGN rows from the DDoS capture file had a 16.69% false-positive rate (16,306/97,718), compared with 1.10% for the PortScan capture file (1,398/127,537) and 1.39% for Friday Morning (2,626/189,067).

At the default threshold, supported attack categories were:

| Original category | Support | Detected | Recall |
|---|---:|---:|---:|
| DDoS | 128,027 | 44,892 | 35.0645% |
| PortScan | 158,930 | 45 | 0.0283% |
| Bot | 1,966 | 44 | 2.2380% |

The false negatives were 83,135 DDoS, 158,885 PortScan, and 1,922 Bot flows. The other 12 label categories have no test support under this day-based split and are marked unavailable rather than assigned fabricated recall. Error analysis also includes bounded deterministic samples of false-positive/false-negative feature medians and does not disclose raw record identifiers or endpoints.

## Artifacts, inference, and outputs

Run the experiment from the repository root:

```powershell
python -m intrusion_intelligence.anomaly --config configs/anomaly_detection.toml
```

The verified run is `20261103T141439Z`. Model version `1.0.0` is under `models/unsupervised/isolation_forest/1.0.0/`; the paired fitted preprocessor is under `models/unsupervised/preprocessing/anomaly/1.0.0/`. Model and preprocessor versions are immutable: choose unused versions in the TOML config before another saved run. `AnomalyPredictor` loads the bundle, validates feature schema, applies the saved transform and calibrated operating point, and returns raw score, anomaly score, threshold, decision, model ID, operating point, and schema/preprocessor versions. Inference does not fit or recalibrate.

The run writes structured summaries, calibration and split audits, per-attack and threshold-sensitivity tables, false-positive-by-source-file and false-negative-by-attack tables, a confusion matrix, sampled error-feature medians, a model-comparison table, and figures under `reports/evaluation/anomaly_detection/20261103T141439Z/`, `reports/experiments/anomaly_detection/20261103T141439Z/`, and `reports/figures/anomaly_detection/20261103T141439Z/`. The human-readable run report is also in the evaluation directory.

The project already includes Scikit-learn and Joblib through its preprocessing dependencies; Phase 08 added no package dependency. `notebooks/06_anomaly_detection.ipynb` uses the reusable source modules and reads the verified experiment outputs. To create a new trained bundle, update both artifact versions in the config and run the CLI; the notebook defaults to loading the existing run.

## Validation and limitations

Synthetic Pytest fixtures exercise data validation, day split integrity, duplicate auditing, benign-only fitting, score orientation, calibration, evaluation, artifacts, and inference. The complete project suite and static notebook checks are recorded in the Phase 08 worklog. The actual CIC-IDS2017 results are specific to this benchmark extraction and its capture-day groups. The duplicate overlap, conflicting labels, test distribution shift, incomplete Friday attack-family coverage, and 150,000-row training sample limit generalization claims. Phase 06 binary classification remains not started. No supervised outputs were combined; Phase 09 threat scoring and alert correlation were not begun.
