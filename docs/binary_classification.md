# Phase 06 — Binary Classification

## Reproducible CIC-IDS2017 experiment

The Phase 06 comparison uses the eight canonical Phase 04 Parquet files and the Phase 05 feature contract (78 predictive features). Training uses Monday through Wednesday, Thursday is validation, and Friday is the final held-out test. The target is `BENIGN → 0` and every non-empty original non-`BENIGN` label `→ 1`; original taxonomy labels remain in the source and a separate offline prediction output. The target and metadata never enter the model matrix.

Both models use the same 80,000-row deterministic, binary-stratified candidate sample (seed 42), the same training-only duplicate-vector exclusions, retained Thursday rows, and complete Friday partition. This yielded 77,085 training rows after removing 2,915 candidate vectors found in the held-out/evaluation signature index; 53,497 Thursday rows sharing vectors with Friday were removed. The final support counts are 403,284 benign and 2,187 attack on Thursday, and 414,322 benign and 288,923 attack on Friday. Training contains 64,506 benign and 12,579 attack rows.

Logistic Regression is configured in `configs/binary_logistic.toml`: L2 regularization (`C=1`), `lbfgs`, `max_iter=2000`, `tol=1e-4`, `class_weight="balanced"`, random seed 42, and fixed score threshold 0.5. Phase 05's linear preprocessing profile performs median imputation and StandardScaler, fitted exclusively on training features. Feature selection and feature engineering are disabled. The fit converged in 178 iterations with no `ConvergenceWarning`. The resulting `predict_proba` scores are uncalibrated ranking scores, not probabilities of compromise.

Run from the repository root with the project source on `PYTHONPATH` if the package is not installed editable:

```powershell
$env:PYTHONPATH = "src"
python -m intrusion_intelligence.binary.logistic_cli --config configs/binary_logistic.toml
```

The run creates a versioned classifier/preprocessor bundle under `models/supervised/binary/logistic_regression/` and a timestamped report under `reports/evaluation/binary_logistic/`. It saves the config, feature schema, checksums, run metadata, Thursday threshold grid, and separate evaluation-only Parquet predictions with original labels. These prediction files must never be used as detector input. Existing model versions are never overwritten.

The command/config reproduces the experiment from the same dataset and dependency versions. In this workspace, versions 1.0.0 through 1.0.2 are occupied by preserved runs; to repeat the fit here, set `artifacts.version` to a new unused patch version (for example `1.0.3`) in a copy of the config, retaining all split and training parameters. The run records that exact config and creates a fresh UTC report directory. This version bump avoids overwriting saved outputs.

## Measured comparison

The completed run `20261103T163706Z` compares Logistic Regression v1.0.2 with the persisted Random Forest v1.0.1 report and checksum-verified bundle. Random Forest inference was not rerun because the existing report has no inference timing.

| Metric at fixed threshold 0.5 | RF Thursday | Logistic Thursday | RF Friday | Logistic Friday |
|---|---:|---:|---:|---:|
| ROC-AUC | 0.988311 | 0.768132 | 0.738459 | 0.817022 |
| Average precision | 0.241645 | 0.011510 | 0.720452 | 0.804709 |
| Attack precision | 0.054795 | 0.001112 | 0.996549 | 0.841251 |
| Attack recall / TPR | 0.005487 | 0.011431 | 0.281840 | 0.471980 |
| F1 | 0.009975 | 0.002027 | 0.439408 | 0.604698 |
| Accuracy | 0.994125 | 0.939276 | 0.704548 | 0.746475 |
| False-positive rate | 0.000513 | 0.055693 | 0.000681 | 0.062109 |

Confusion matrices (true rows, predicted columns; BENIGN, ATTACK):

- Thursday RF `[[403077, 207], [2175, 12]]`; Logistic `[[380824, 22460], [2162, 25]]`.
- Friday RF `[[414040, 282], [207493, 81430]]`; Logistic `[[388589, 25733], [152557, 136366]]`.

Logistic Regression fit (preprocessing plus classifier) took 3.976 seconds; measured Thursday and Friday prediction plus transform times were 1.414 and 2.108 seconds. The v1.0.2 bundle occupies 61,456 bytes. RF fit took 2.459 seconds according to its persisted report, and its bundle occupies 1,161,628 bytes. In this run Logistic training took longer; RF inference time is unavailable, so an overall operational speed comparison cannot be made.

On Friday, Logistic Regression has higher ROC-AUC, average precision, recall, F1, and accuracy; RF has higher attack precision and substantially lower FPR. Logistic Regression therefore catches more Friday attacks but raises more benign alerts. Its artifact is much smaller, but it trained more slowly in this run and RF inference time is absent. The evidence does not establish an overall operational-efficiency winner or support changing the default model without choosing an operational false-positive/miss tradeoff and external validation.

Capture-day behavior differs by metric. RF ROC-AUC falls by 0.249853 from Thursday to Friday, while Logistic ROC-AUC rises by 0.048890. Fixed-threshold recall rises from 0.005487 to 0.281840 for RF and 0.011431 to 0.471980 for Logistic Regression; FPR rises from 0.000513 to 0.000681 for RF and 0.055693 to 0.062109 for Logistic Regression. Average precision rises for both (RF 0.241645→0.720452; Logistic 0.011510→0.804709), but Thursday attack prevalence is 0.54% and Friday prevalence is 41.08%, so the AP changes are not directly comparable as pure ranking changes. This is evidence of capture shift, not a causal attribution or generalization claim.

Threshold sensitivity is computed only on Thursday and is saved in `validation_threshold_sensitivity.json`. It does not select a threshold; Friday always uses the predeclared 0.5 threshold. The complete metrics, thresholds, exact confusion matrices, report checksums, and runtime measurements are in [the experiment report](../reports/evaluation/binary_logistic/20261103T163706Z/binary_logistic_comparison.md) and `experiment_summary.json`.

## Limitations

- CIC-IDS2017 has substantial capture-day distribution shift and an extreme change in attack prevalence; the Friday capture is one held-out day, not independent deployment evidence.
- Duplicate-vector screening uses the same two independent 64-bit row hashes as the RF workflow. Hash collision probability is negligible but nonzero.
- Scaler and imputer fit parameters are based on the deterministic 77,085-row sample, not every Monday–Wednesday row.
- `class_weight="balanced"` affects the fitted decision surface; scores are not calibrated.
- RF inference duration was absent from persisted RF results and is reported unavailable rather than estimated.
- The first two CLI attempts raised during final report assembly after the model and evaluation files had been saved: one looked for artifact size in caller metadata rather than the serialized manifest, and one omitted the report-directory field required by the renderer. Both defects are corrected. Run `20261103T163706Z` completed via the CLI with exit code 0; earlier run artifacts and reports were preserved. The final model bundle passed size and SHA-256 checks, and prediction metrics were independently recomputed. No raw dataset or existing model artifact was overwritten.

Phase 06 is complete as a reproducible, measured research comparison. Neither model is automatically selected for production; Phase 10 remains not started.
