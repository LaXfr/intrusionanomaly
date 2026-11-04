# Threat Intelligence and Alert Generation

## Scope and architecture

Phase 09 adds an offline intelligence layer under `src/intrusion_intelligence/intelligence/`. It consumes validated binary outputs when supplied, the existing Phase 07 multi-class predictor, and the existing Phase 08 anomaly predictor. It does not train models, modify detector thresholds, claim that an alert proves a successful attack, or assign a probability of compromise.

The reusable flow is `run_intelligence_pipeline`: normalize each detector result, preserve the raw output, calculate an evidence score, create a flow event, correlate eligible suspicious events, aggregate alerts, and return summaries. `run_intelligence_experiment` is the actual CIC integration service. It loads persisted predictors once, checks the Phase 05 schema and exact feature order, predicts in batches, and writes reports. The CLI is:

```powershell
python -m intrusion_intelligence.intelligence --config configs/intelligence.toml
```

The current run selects up to 500 evenly spaced rows per original label per Friday Parquet file and batches inference by 500. Friday labels are isolated from inference and used only for deterministic offline sample construction and post-alert evaluation. The service also scores Thursday BENIGN validation features with the already-fitted Phase 08 model to construct a percentile reference; this does not retrain the model or change its calibrated threshold.

## Evidence schema and detector integration

Each flow event contains a stable event ID and fingerprint, a record reference, source file and row, optional Flow ID and UTC timestamp, investigation-only network context, raw detector results, normalized evidence for all three detector slots, model versions and artifact references, feature-schema and pipeline versions, threat score and breakdown, severity, status, disagreement flags, and validation warnings.

Normalized `SignalEvidence` records identify the source detector, raw value, normalized value when valid, interpretation, availability and validation status, model/version, and calibration status. A missing detector is `unavailable`; malformed data is `invalid`; neither state becomes a benign prediction or zero-valued evidence. Original model outputs remain recoverable from `detector_results` and `normalized_evidence`.

### Binary classifier

The common interface accepts a malicious-class score or a recognized hard prediction, along with the source threshold and model metadata when supplied. Scores must be finite and in `[0, 1]`; if a threshold and decision are both supplied they must agree. The real Phase 09 run loads `binary-random_forest-v1.0.1`; the score is explicitly uncalibrated and not a probability of compromise.

### Multi-class classifier

The service reuses `MultiClassPredictor.predict(X)`. Its actual model is `multiclass-random_forest-v1.0.0`, experiment `20261103T134128Z`. The class mapping and class-score keys are validated. With a complete normalized class distribution, attack evidence is `1 - BENIGN score`; it remains uncalibrated model evidence, not a real-world compromise probability. Hard labels, when used without class scores, become categorical indicators rather than invented probabilities.

### Anomaly detector

The service reuses `AnomalyPredictor.predict(X)` and the Phase 08 Isolation Forest artifact `isolation-forest-v1.0.0`, experiment `20261103T141439Z`, operating point `target-fpr-1pct`. The raw model score, standardized higher-is-more-anomalous score, existing threshold, decision, and operating point are retained. When a finite benign reference is available, normalized evidence is the right empirical CDF percentile:

`count(reference scores <= flow score) / number of reference scores`

That value means relative unusualness within the observed BENIGN Thursday validation scores. It is not a malicious probability. Without the reference, the existing threshold decision is represented as a categorical 0/1 indicator and identified as such.

## Threat score

Default weights in `configs/intelligence.toml` are binary 0.30, multi-class 0.25, and anomaly 0.45. They are configurable engineering assumptions, not learned or calibrated probabilities. Binary and multi-class evidence are marked as a related supervised group because they may be correlated.

For each available normalized signal, the contribution is `configured weight × normalized evidence`. Missing, invalid, or zero-weight signals are excluded. The remaining configured weights are renormalized:

`score = 100 × sum(weight × evidence) / sum(available weights)`

The result is bounded from 0 to 100. Each score includes signal values, configured/effective weights, contributions, availability reasons, configuration version, formula, and calculation status. When no valid weighted evidence is available, the score is `null` and the event is `INSUFFICIENT_EVIDENCE`. Scores are heuristic prioritization values and must not be described as probabilities of compromise.

Disagreement flags retain situations such as a supervised attack prediction with a normal anomaly decision, an anomalous result alongside a supervised BENIGN prediction, supervised engines disagreeing, and all three available families indicating suspicious activity. An unavailable engine is never counted as a negative vote.

## Phase 09 remediation validation (2026-11-03)

The independent binary model was trained with `BENIGN → 0` and every preserved non-BENIGN CIC label `→ ATTACK`. Its source files are Monday–Wednesday train, Thursday validation, and Friday final test. The Phase 05 tree preprocessor was fit on training features only. A full bounded signature scan screened shared evaluation feature vectors: 53,497 validation rows were excluded where their feature vector appeared in Friday test; 2,915 of 80,000 training candidates were excluded where they appeared in validation or test. 77,085 training rows remained (64,506 BENIGN; 12,579 ATTACK). Model `binary-random_forest-v1.0.1` (experiment `20261103T160232Z`) uses a fixed predeclared 0.5 decision threshold and a checksummed artifact bundle whose metadata lists all 14 original attack labels mapped to ATTACK. Version `1.0.0` remains preserved locally as the earlier bundle.

On all 703,245 Friday rows, binary test support was 414,322 BENIGN and 288,923 ATTACK. The fixed threshold produced accuracy 0.7045, balanced accuracy 0.6406, attack precision 0.9965, recall 0.2818, F1 0.4394, ROC-AUC 0.7385, average precision 0.7205, and FPR 0.00068. Thursday validation attack recall at that threshold was only 0.00549, despite ROC-AUC 0.9883, revealing severe capture/distribution shift and threshold ranking mismatch. No threshold was chosen using test labels.

Integrated CLI run `20261103T160444Z` reuses that binary model plus `multiclass-random_forest-v1.0.0` and `isolation-forest-v1.0.0`. It selects 500 evenly spaced rows per original label in each Friday source file for a 3,000-row, 1,500/1,500 benign/attack research sample. Labels are read separately for sample construction and offline metrics, stripped from the feature frame before prediction, and are never passed to the event, scoring, or alert pipeline. In this sample, binary precision/recall were 0.9969/0.2133; alert-level precision/recall were 0.9908/0.5753. Per-category multi-class recall was Bot 0.588, DDoS 0.998, and PortScan 0.996 (500 rows each). The run generated 871 alerts (552 HIGH, 319 CRITICAL), zero unscored events, zero duplicate suppressions, and zero correlation coverage. The bounded sample is intentionally label-stratified and must not be interpreted as a population prevalence estimate.

At a fixed score cutoff of 50, the configured weights yielded alert-level precision 0.9908 and recall 0.5753. Equal weights yielded 0.9991 precision and 0.7047 recall; supervised-heavier weights yielded 0.9988 precision and 0.5393 recall. Because this is a single bounded sample and the evidence is not calibrated, defaults remain unchanged. Severity cutoffs likewise remain policy bands without empirical severity calibration. Alerts are model/research outputs, not confirmed incidents; alert records identify supporting event IDs, model versions, missing detector evidence, score breakdown, severity rationale, confidence limitations, and a separate `not_evaluated` ground-truth status.

Metadata provenance is explicit on events. The processed export provides only source file, source row, record ID, and destination port (the latter is a predictive feature retained for investigation after inference). Timestamp, source/destination IP, source port, protocol, and Flow ID remain unavailable. Each of the six rules therefore skipped all 1,407 suspicious events for missing timestamps and emitted no correlation groups. This is an expected data limitation, not a disabled or fabricated correlation path.

## Severity and flow events

Severity bands are configurable and versioned. The defaults are LOW `[0,25)`, MEDIUM `[25,50)`, HIGH `[50,75)`, and CRITICAL `[75,100]`. A valid score maps to exactly one band; no usable score maps to `UNSCORED`.

Events are `NORMAL` when no available detector makes a positive decision, `MALICIOUS_PREDICTION` for a supervised positive alone, `ANOMALOUS` for an anomaly positive alone, `SUSPICIOUS` for two or more positive detector families, or `INSUFFICIENT_EVIDENCE` when there is no score. These statuses summarize model outputs, not ground truth.

Record identifiers, timestamps, and network metadata are investigation fields, never added to the model feature matrix by this layer. Destination port is present as a Phase 05 predictive feature; the integration retains it as context only after prediction. Friday target labels are not loaded into the detection run.

## Alert criteria, aggregation, and lifecycle

New alerts have status `NEW`; this offline workflow does not acknowledge or resolve alerts. A single-flow alert requires a score of at least 50, at least one valid signal, and (by default) a positive detector decision. A correlated alert requires at least two distinct events in a group and a maximum member score of at least 25. Events included in a correlated alert are not also emitted as single-flow alerts.

Correlated alerts preserve event and flow counts, event references, correlation rules and keys, time bounds, maximum and mean scores, highest severity, detector summaries, disagreements, and investigation context. Single-flow alerts preserve the same evidence shape with one supporting event. Explanations state the detector outputs, anomaly threshold/percentile when relevant, available score contributions, missing evidence, and correlation metadata limitations.

Event IDs are derived from pipeline version and stable source-record reference. Event fingerprints retain source identity, context, detector scores and outputs, but omit volatile prediction/processing timestamps from the fingerprint only; those timestamps remain in the raw outputs. Alert fingerprints use alert type, event fingerprints, and attack-category set. Repeated identical fingerprints are merged deterministically, preserving event references and recording severity updates when applicable.

## Correlation and output files

See [alert_correlation.md](alert_correlation.md) for keys, grouping windows, and missing-metadata behavior. Correlation requires a usable UTC timestamp for every rule and never uses row order as a time proxy.

Runs write to `reports/intelligence/<run_id>/`: flow events as JSONL and CSV, correlated groups as JSON, structured alerts as JSON, a flat alert summary CSV, a JSON summary and Markdown report, and a configuration snapshot. Figures go to `reports/figures/intelligence/<run_id>/`: threat score distribution, alert severity distribution, and detector agreement. JSON/JSONL retain nested evidence; CSV files are convenient flattened views.

Models are loaded once per run and inference is batched. Current flow events and correlation groups are held in memory for aggregation, so the service documents and defaults to a bounded sample rather than claiming full-scale streaming correlation. Cross-chunk temporal state is not implemented.

## Historical initial CIC-IDS2017 sample (superseded)

Run `20261103T145019Z` was the first integration sample and is superseded by corrected CLI run `20261103T160444Z` above. It analyzed the first 1,000 rows from each of three Friday files; this order-based sample contained only BENIGN labels and was inadequate for alert validation. The frozen anomaly model scored 456,752 BENIGN Thursday validation rows for the ECDF reference; Thursday target labels were used only to select those BENIGN reference rows. Binary evidence was unavailable then, and source labels were excluded from detection inputs.

The flow status counts were 2,923 NORMAL, 20 MALICIOUS_PREDICTION, 56 ANOMALOUS, and 1 SUSPICIOUS. The run generated 76 single-flow alerts: 75 HIGH and 1 CRITICAL. There were zero correlated groups. The alert category field reflects model predictions only (18 Bot, 1 DoS Hulk, and 1 PortScan category references in the summary), not confirmed labels. There were 20 supervised-positive/anomaly-normal disagreements and 56 anomaly-positive/multi-class-BENIGN disagreements.

The Phase 04 cleaned export lacks timestamp, source and destination IP, source port, protocol, and Flow ID. The only correlation field retained for these rows is destination port, which by itself is not an enabled correlation key. As a result, all 77 suspicious events in the sample lacked timestamps for the five configured correlation rules, so no temporal grouping was attempted. Individual alerts remain traceable to source file, row, and record ID.

The Phase 07 classifier's row-stratified evaluation has source-file overlap and is not cross-capture validation. The Phase 08 operating point produced a higher Friday false-positive rate than its Thursday calibration target. Alert counts and score thresholds are therefore research outputs, not operationally validated triage guidance. This layer is offline analytics only; it does not block traffic, prove compromise, or replace analyst review.
