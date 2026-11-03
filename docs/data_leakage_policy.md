# Data leakage and feature policy

## Purpose

This policy defines the feature/target/metadata boundary for future CIC-IDS2017 experiments. It documents controls and risks; it does not claim that leakage has been eliminated or that a model will generalize.

The generated `data/processed/CIC-IDS2017-phase04-v2/metadata/feature_policy.json` is the machine-readable run-specific field list. Consumers should select the candidate feature names from that file instead of passing the complete Parquet frame to an estimator.

## Field groups

| Group | Policy | Current CIC-IDS2017 extract |
|---|---|---|
| Target | Keep separately as `label`; never include it in predictive features. | Present; 15 original categories remain distinct after whitespace trimming. Raw text is copied to `__source_label`. |
| Direct identifiers | Exclude from primary features; retain as metadata when present. | Flow ID, source IP, and destination IP are absent. |
| Collection time | Exclude timestamps from primary features; preserve as metadata when present. | Timestamp is absent, so temporal splits cannot be constructed from these CSVs. |
| Dataset provenance | Retain for grouping, traceability, and debugging; exclude from model inputs. | `__source_file`, `__source_row_number`, and `__record_id` are appended to each cleaned row. |
| Port/protocol behavior | Keep as candidate features by default, then evaluate with ablation and group-aware validation. | `destination_port` is present and candidate; standalone source port and protocol fields are absent. |
| Flow measurements | Keep as candidate predictors after audited numeric/null handling. | 78 source flow features remain, including constants and correlated fields. |

The target, direct identifiers, timestamps, original source label, file name, row number, and internal record ID are listed outside `candidate_predictive_features`. If a future input includes a field not explicitly classified by the versioned policy, review the schema mapping and update the policy before using it.

## Risks found in EDA and Phase 04

- Every attack category in the available extract appears in exactly one source file, while BENIGN appears in all eight. Source file identity therefore tracks collection scenario and label strongly. Never use filename or row number as a predictive feature.
- Destination-port counts vary by label and include scenario-specific concentrations. Ports may reflect genuine network behavior, but they may also act as dataset-specific shortcuts. Compare later experiments with and without port fields.
- The full duplicate assessment found 308,381 excess complete-row fingerprint matches and 698 repeated feature-vector groups with different labels. Exact duplicates are retained by default, and conflicting-label feature vectors are not silently resolved. Keep related records grouped during later validation where feasible.
- The collection is a short, controlled benchmark with attack scenarios tied to source files/days. Its class frequencies do not estimate operational attack prevalence.
- The export has no timestamp, endpoint address, protocol, source port, or Flow ID. Address-aware correlation, repeated identifier analysis, and temporal evaluation cannot be performed from these files.

## Recommended evaluation controls

1. Preserve `__source_file` and `__source_row_number` through any later feature preparation as split/correlation metadata, then exclude them from model matrices.
2. Avoid random row-only splits as the sole result. Investigate source-file/day/scenario group holdouts. Since attack categories are each confined to one file in this extract, report class coverage and any classes absent from a holdout rather than implying a conventional stratified split is sufficient.
3. If timestamped or endpoint-enriched data become available, evaluate chronological holdouts and endpoint/group-based partitions without fitting transforms on held-out data.
4. Run feature ablations for destination port and any protocol field present in a later schema. Compare per-class precision, recall, F1, and confusion matrices, not accuracy alone.
5. Audit exact duplicates and conflicting feature vectors before partitioning. Do not remove repeated flows without an explicit, recorded policy and a suitable operational interpretation.
6. Treat multi-class models as closed-set classifiers. Evaluation on this benchmark does not establish detection of unseen attacks or behavior on current networks.

No final train/validation/test split or model was created in Phase 04.
