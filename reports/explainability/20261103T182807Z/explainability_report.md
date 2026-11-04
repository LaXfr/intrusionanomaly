# Explainability report

Run: `20261103T182807Z`

Execution time: 67.13 seconds.
Explanation records: 264; global-importance rows: 2574.

SHAP values explain each configured model output in its documented units. They do not explain the Phase 09 heuristic threat score or establish causation.

## Model coverage

- **binary_random_forest** (`binary-random_forest-v1.0.1`): binary_random_forest; output space `attack_probability`; training-only background 100 rows.
  - ATTACK (attack probability), 64 rows; max additivity residual 3.27e-09.
- **binary_logistic_regression** (`binary-logistic_regression-v1.0.2`): binary_logistic_regression; output space `attack_log_odds`; training-only background 100 rows.
  - ATTACK_LOG_ODDS (ATTACK log-odds margin), 64 rows; max additivity residual 8.53e-14.
- **multiclass_random_forest** (`multiclass-random_forest-v1.0.0`): multiclass_random_forest; output space `class_probability`; training-only background 100 rows.
  - BENIGN (class probability), 64 rows; max additivity residual 2.32e-08.
  - Bot (class probability), 64 rows; max additivity residual 2.48e-10.
  - DDoS (class probability), 64 rows; max additivity residual 4.37e-08.
  - DoS GoldenEye (class probability), 64 rows; max additivity residual 1.09e-09.
  - DoS Hulk (class probability), 64 rows; max additivity residual 1.05e-09.
  - DoS Slowhttptest (class probability), 64 rows; max additivity residual 7.04e-10.
  - DoS slowloris (class probability), 64 rows; max additivity residual 7.33e-10.
  - FTP-Patator (class probability), 64 rows; max additivity residual 7.36e-10.
  - Heartbleed (class probability), 64 rows; max additivity residual 1.45e-09.
  - Infiltration (class probability), 64 rows; max additivity residual 1.11e-08.
  - PortScan (class probability), 64 rows; max additivity residual 1.44e-09.
  - SSH-Patator (class probability), 64 rows; max additivity residual 6.15e-10.
  - Web Attack � Brute Force (class probability), 64 rows; max additivity residual 1.03e-09.
  - Web Attack � Sql Injection (class probability), 64 rows; max additivity residual 4.89e-09.
  - Web Attack � XSS (class probability), 64 rows; max additivity residual 2.13e-10.
- **multiclass_logistic_regression** (`multiclass-logistic_regression-v1.0.0`): multiclass_logistic_regression; output space `class_logit`; training-only background 100 rows.
  - BENIGN (class logit), 64 rows; max additivity residual 3.55e-14.
  - Bot (class logit), 64 rows; max additivity residual 7.11e-14.
  - DDoS (class logit), 64 rows; max additivity residual 9.95e-14.
  - DoS GoldenEye (class logit), 64 rows; max additivity residual 4.26e-14.
  - DoS Hulk (class logit), 64 rows; max additivity residual 7.11e-14.
  - DoS Slowhttptest (class logit), 64 rows; max additivity residual 3.55e-14.
  - DoS slowloris (class logit), 64 rows; max additivity residual 1.6e-14.
  - FTP-Patator (class logit), 64 rows; max additivity residual 1.42e-14.
  - Heartbleed (class logit), 64 rows; max additivity residual 2.13e-14.
  - Infiltration (class logit), 64 rows; max additivity residual 1.42e-13.
  - PortScan (class logit), 64 rows; max additivity residual 3.2e-14.
  - SSH-Patator (class logit), 64 rows; max additivity residual 4.26e-14.
  - Web Attack � Brute Force (class logit), 64 rows; max additivity residual 2.49e-14.
  - Web Attack � Sql Injection (class logit), 64 rows; max additivity residual 7.11e-14.
  - Web Attack � XSS (class logit), 64 rows; max additivity residual 2.31e-14.
- **isolation_forest** (`isolation-forest-v1.0.0`): anomaly; output space `higher_is_more_anomalous_score`; training-only background 100 rows.
  - anomaly_score (higher-is-more-anomalous score), 16 rows; max additivity residual 1.22e-15.

## Limitations

- Output importance depends on the specified background and output scale.
- Isolation Forest explanations use model-agnostic permutation SHAP over the persisted transformed inputs.
- Transformed columns without a unique declared input mapping remain separately marked as unmapped.
- XGBoost was unavailable in the installed environment and has no persisted project artifact.
