# Model Evaluation & Validation

## Architecture and commands

Phase 11 lives in `src/intrusion_intelligence/evaluation/`. Metrics, evidence governance, split audits, calibration, uncertainty, feature ablation, input stress tests, warm inference timing, and report generation are independent of notebook presentation.

From the project root, run:

```powershell
python -m intrusion_intelligence.evaluation --config configs/evaluation.toml
```

The `intrusion-evaluate` console script runs the same CLI after installation. The command reads existing Phase 06–10 reports and saved Logistic Regression score Parquets, loads the five latest configured bundles, and performs bounded model-interface checks using 64 feature-only rows. It does not retrain or overwrite model artifacts. Each run writes structured JSON and a Markdown summary to `reports/evaluation/comprehensive/<run_id>/`, figures to `reports/figures/evaluation/<run_id>/`, and warm benchmark JSON to `reports/benchmarks/<run_id>/`.

The guided notebook is `notebooks/09_model_evaluation.ipynb`; it calls the reusable pipeline and contains no fabricated execution outputs.

## Evidence categories and test-set governance

Training, validation, previously inspected test, fresh held-out, cross-group, and external evidence are different categories. Thursday/Friday results and the Phase 07 row-split test were already inspected in prior phases and reused in downstream Phase 09/10 work. The new pipeline is a reproducible reanalysis; it does not relabel those partitions as fresh. Threshold sensitivity is descriptive. It does not use test labels to select a new operating point.

No unused capture group or truly untouched final cohort exists in the local CIC-IDS2017 material. New random row splits would not repair the group structure. Keep future cohort labels reserved until model and threshold choices are frozen.

## Data and leakage audit

Split manifests are preserved in the evaluation run. Binary capture-day source files are disjoint and the Phase 06 RF report records duplicate-feature screening; 53,497 Thursday rows and 2,915 training candidates were removed for overlap with evaluation feature vectors. The anomaly audit reports 28,644 cross-partition duplicate vector groups affecting 132,348 rows and 633 conflicting-label groups. Repeated information can inflate apparent generalization but is not, by itself, proof that the target leaked into features.

All loaded artifacts match the ordered Phase 05 predictive feature contract; target and provenance fields are outside the model inputs. Prior reports document training-only fitting and benign-only anomaly calibration. Current saved artifacts do not provide full source-row lineage to reconstruct every preprocessing or sampling decision independently.

## Binary classification

ATTACK is the positive class. The framework reports precision, recall, F1, balanced accuracy, average precision, FPR, FNR, accuracy, specificity, ROC-AUC, confusion matrix, and MCC. The binary Logistic score Parquets support full validation and prior-test reanalysis, threshold grids, capture-file breakdowns, Brier/log loss, and reliability bins. Scores are labeled uncalibrated; reliability analysis is descriptive and does not fit a calibrator. Random Forest metrics come from its saved experiment report because its prediction rows were not persisted. XGBoost is unavailable and has no fabricated score.

## Multi-class classification

The saved original-to-model taxonomy is retained. The scorecard reports overall and per-class metrics and the saved Random Forest confusion matrix. Attack labels each occur in one capture file, making a class-complete group holdout infeasible. The prior stratified row split shares source groups between train, validation, and test. Very rare categories have unstable metrics. No held-out probability matrix is available for calibration or a uniform Logistic-vs-Random-Forest reanalysis.

## Anomaly detection

Isolation Forest remains a separate benign-only detector. The saved run documents benign-only training/preprocessor fitting, Thursday benign threshold calibration, and `-score_samples` orientation (higher means more anomalous). Threshold scorecards report both configured target validation FPR and measured values where present, as well as Friday test metrics and per-category recall. Anomaly scores are ranking scores, not attack probabilities. The configured 1% validation point yielded about 4.91% Friday FPR and 15.57% Friday attack recall on this previously inspected capture.

## Generalization, time, and external data

Binary and anomaly capture-day results are cross-group exploratory observations, not fresh final tests. Duplicate-vector overlap and one Friday collection day limit inference. The multi-class experiment is row-split and not group independent. Original timestamps were removed; source file/day metadata does not support within-capture chronology. CIC-IDS2018 and UNSW-NB15 are not in the workspace. Future transfer requires documented schema/taxonomy mapping and frozen CIC-trained artifacts.

## Feature ablation and robustness

The ablation utility fits temporary estimators from training partitions only and writes no production artifact. It validates consistent ordered schemas, target exclusion, and known removals. The actual contract includes destination port but not source port or protocol. A real-data comparison is not reported because no untouched cohort remains for controlled comparison.

Input stress is performed against actual persisted model interfaces using synthetic modifications to a bounded label-free feature sample: missing numeric values, large finite values, zeros for rate features, a dropped required feature, and infinity. Unknown categories are not applicable because the predictive contract is numeric-only. These checks assess interface behavior; they do not prove adversarial robustness or realistic traffic robustness.

## Calibration and uncertainty

Binary Logistic Regression has saved scores in `[0, 1]`; the framework reports Brier score, log loss, expected calibration error, and reliability bins without fitting a calibration transform. Binary Random Forest and multi-class held-out probability arrays were not saved. Isolation Forest and Phase 09 threat scores are not probabilities.

The uncertainty module supports Wilson intervals and a whole-group bootstrap with deterministic seeding and a minimum-cluster gate. No reliable project-level interval is emitted: Friday contains only three capture files, and repeated/related flows reduce the effective independent sample count. Row-level intervals would overstate evidence.

## Threat intelligence and explainability

Threat evaluation is limited to the Phase 09 offline flow sample and saved alert summary. Labels were used for stratified sample construction and post-inference metrics. There is no incident-level truth, and missing timestamps/endpoints prevent meaningful real-data correlation scoring. Threat scores remain heuristic priorities, not compromise probabilities. Correlation and deduplication are covered by synthetic Phase 09 tests.

Phase 10 saved SHAP records are checked for output semantics and additivity diagnostics; model/preprocessor compatibility and feature mappings are revalidated by loading current bundles. Additivity supports reconstruction for tested outputs and samples; SHAP is not causal evidence.

## Computational benchmarking

Warm benchmarks separately time preprocessing and model output calls over batch sizes 1, 16, and 64 with five repeats; report medians and artifact size. Model loading and cold starts are excluded. Measurements use the local Windows/Python environment and a 64-row feature-only sample. They do not establish production latency, memory capacity, real-time service performance, or integrated alerting throughput. Phase 10's saved SHAP runtime is available in its report but is not rerun here.

## Limitations and future protocol

No fresh independent final evaluation, external transfer run, temporal evaluation, multi-class held-out calibration, or reliable cluster interval is available. Real-data ablation is deferred. Reserve a new collection cohort or acquire a compatible external dataset, preserve timestamps and endpoint/event references where lawful, freeze model and thresholds before opening labels, and evaluate across enough independent capture groups before making operational claims.
