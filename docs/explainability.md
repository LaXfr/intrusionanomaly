# Explainable AI with SHAP

Phase 10 uses the persisted model and fitted preprocessor artifacts under `models/`. It never fits a model or preprocessor. Run from the repository root after installing the `explainability`, `ml`, `preprocessing`, `data`, and `parquet` extras:

```powershell
python -m pip install -e ".[explainability,ml,preprocessing,data,parquet]"
python -m intrusion_intelligence.explainability --config configs/explainability.toml
```

The command writes a timestamped run under `reports/explainability/<run_id>/` and figures under `reports/figures/explainability/<run_id>/`. `notebooks/08_explainability.ipynb` provides the workflow and inspection points.

## Architecture and supported models

`model_registry.py` loads Phase 06 binary Random Forest and Logistic Regression, Phase 07 multi-class Random Forest and Logistic Regression, and the Phase 08 Isolation Forest bundle and its matching preprocessor. It validates original input order, feature schema version, fitted preprocessor status, and exact transformed feature names. Output labels for multi-class models are resolved through the artifact's saved taxonomy.

| Persisted model | SHAP approach | Output being explained |
|---|---|---|
| Binary Random Forest | TreeExplainer with interventional background | ATTACK `predict_proba` score (uncalibrated) |
| Binary Logistic Regression | LinearExplainer | ATTACK decision margin (log-odds), not probability delta |
| Multi-class Random Forest | TreeExplainer with interventional background | Per-class `predict_proba` score (uncalibrated) |
| Multi-class Logistic Regression | LinearExplainer | Per-class `decision_function` class logit |
| Isolation Forest | PermutationExplainer on an exact `-score_samples` wrapper | Higher-is-more-anomalous model score, not attack probability |

XGBoost is not configured or claimed: no XGBoost artifact was available for this phase. Forest outputs are validated against the persisted estimator's actual outputs. The permutation method is bounded and can be computationally expensive. SHAP's documented output shapes vary across explainers and versions; `normalize_shap_values` accepts legacy per-class lists and supported array layouts. See the official [TreeExplainer API](https://shap.readthedocs.io/en/latest/generated/shap.TreeExplainer.html) and [PermutationExplainer API](https://shap.readthedocs.io/en/latest/generated/shap.PermutationExplainer.html).

## Backgrounds and preprocessing

Binary and anomaly backgrounds use deterministic samples of 100 rows from Monday–Wednesday training capture files. Binary sampling is stratified by BENIGN/ATTACK; anomaly sampling contains BENIGN rows only. Multi-class backgrounds recompute the persisted Phase 07 row-stratified fallback split and sample its training indices. Labels are read only to select background indices and never become model inputs. The JSON report records dataset identity, row count, seed, policy, source files, and that target values were excluded from feature values. No test partition is used as a reference background.

The same fitted preprocessor instance used by each detector transforms both background and Phase 09 flow inputs. Schema, order, finite numeric output, and unchanged preprocessor metadata are checked before SHAP. SHAP values therefore describe transformed model inputs. `feature_mapping.py` maps actual transformed names back to declared originals, groups one-hot columns under their source field where names resolve uniquely, and retains unmapped columns explicitly. Local grouped values sum signed contributions; global grouped importance sums per-column mean absolute SHAP values. This grouping is a summary rule, not a causal decomposition.

## Global and local results

The configured global sample is bounded (64 rows for classifiers, 16 for Isolation Forest) and consists of records referenced by the configured Phase 09 run. Local outputs are limited to eight selected records per configured model output. JSONL records include transformed signed contributions, grouped original contributions, expected value, actual output, prediction metadata, threshold where present, background identity, feature names, additivity diagnostics, model/explainer identifiers, and source event reference. Global feature rankings are in `global_importance.csv`. The Markdown and JSON reports record model coverage, output semantics, sample sizes, settings, validation, and limitations.

SHAP bar and beeswarm plots are saved per configured output, alongside one local waterfall plot for a selected Phase 09 flow. Positive SHAP values increase the stated output relative to the baseline; negative values decrease it. This statement refers only to that model output: ATTACK score, log-odds, class score, class logit, or higher-is-more-anomalous Isolation Forest score. The report records measured pipeline execution time.

## Phase 09 references

The pipeline writes `phase09_events_with_explanations.jsonl` and `phase09_alerts_with_explanations.json` as sidecars. It adds explanation references and availability only. It does not change the original threat score, severity, detector evidence, alert explanation, or correlation fields. Phase 09 heuristic threat scores and correlation decisions are not model outputs explained by SHAP.

## Validation and limitations

The pipeline compares SHAP base value plus contributions to the exact output function. It uses numerical tolerances of 0.002 for forest probability outputs and 0.0001 for linear and permutation outputs, and fails the run when the maximum residual exceeds the tolerance. Permutation explanations are approximate in feature attribution but telescoping additive for the wrapper output under the explainer's evaluation path. The saved artifact's scikit-learn version is 1.8.0; explanation execution should use that version with compatible SHAP and dependencies.

SHAP values describe model output relative to a background and feature perturbation assumption. They do not establish causation, attacker intent, or universal feature importance. Network flow features are correlated, and Independent/interventional perturbations can create unrealistic combinations. CIC-IDS2017 is a controlled benchmark. Local explanations are generated only for the bounded selected set; absence of a reference means `not_selected`, not lack of model influence. A Phase 09 record's heuristic score is not an explanation target.

The optional `explainability` extra adds SHAP and Matplotlib. The complete project environment still needs the pre-existing scikit-learn, data, and Parquet dependencies. Results are research and inspection artifacts, not operational blocking recommendations.
