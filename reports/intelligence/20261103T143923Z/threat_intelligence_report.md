# Threat intelligence run

- Processed at: `2026-11-03T14:39:22+00:00`
- Pipeline version: `1.0.0`; scoring config: `1.0.0`; severity policy: `1.0.0`.
- Analyzed flows: 3,000; with usable detector evidence: 3,000.
- Flow events by status: `{"NORMAL": 2923, "MALICIOUS_PREDICTION": 20, "ANOMALOUS": 56, "SUSPICIOUS": 1}`.
- Alerts: 76; by severity: `{"HIGH": 75, "CRITICAL": 1}`.
- Alerts by predicted category: `{"Bot": 18, "DoS Hulk": 1, "PortScan": 1}`.
- Correlated groups: 0; correlation audit: `{"enabled_rules": ["source_ip", "destination_ip", "destination_service", "attack_category", "repeated_activity"], "window_minutes": 5, "minimum_events": 2, "suspicious_events_considered": 77, "groups_by_rule": {"source_ip": 0, "destination_ip": 0, "destination_service": 0, "attack_category": 0, "repeated_activity": 0}, "events_skipped_by_rule": {"source_ip": {"missing_timestamp": 77, "missing_key_fields": 0}, "destination_ip": {"missing_timestamp": 77, "missing_key_fields": 0}, "destination_service": {"missing_timestamp": 77, "missing_key_fields": 0}, "attack_category": {"missing_timestamp": 77, "missing_key_fields": 0}, "repeated_activity": {"missing_timestamp": 77, "missing_key_fields": 0}}, "temporal_correlation_supported": 0, "temporal_correlation_skipped": 385, "correlated_event_references": 0, "unmatched_suspicious_events": 77}`.
- Detector availability: `{"binary": {"unavailable": 3000}, "multiclass": {"available": 3000}, "anomaly": {"available": 3000}}`.
- Detector disagreements: `{"supervised_engine_predicts_attack_anomaly_is_normal": 20, "anomaly_flags_flow_supervised_engine_predicts_benign": 56}`.
- Network metadata rows present: `{"source_ip": 0, "destination_ip": 0, "source_port": 0, "destination_port": 3000, "protocol": 0}`.
- Configured signal weights: `{"binary": 0.3, "multiclass": 0.25, "anomaly": 0.45}`. Missing evidence is excluded and remaining weights are renormalized.

Threat scores are heuristic prioritization values, not probabilities of compromise. Class scores from supervised models are not necessarily calibrated. Events and alert records preserve model output and provenance; no ground-truth labels are used to generate scores, events, groups, or alerts.

## Highest-scoring alerts

| Alert ID | Severity | Score | Flows | Predicted category | Title |
|---|---|---:|---:|---|---|
| alt_a46c6440b69895c8d86f0dcf | CRITICAL | 84.98 | 1 | DoS Hulk | DoS Hulk signal on flow 43d393d0cfa56acc90317631 |
| alt_66520612bcf1763562ef6aff | HIGH | 71.87 | 1 | None | anomaly or detector disagreement signal on flow aeb7d12bb4b70f1b3095bf0d |
| alt_9c040e3375dde029762142c2 | HIGH | 68.70 | 1 | Bot | Bot signal on flow 82e23103a922f4a5639bfef1 |
| alt_e63c2699cd86135bf3fef8de | HIGH | 68.70 | 1 | Bot | Bot signal on flow c4ac1935d516382ddc3e262b |
| alt_38199506ad0b406c684f396f | HIGH | 68.57 | 1 | None | anomaly or detector disagreement signal on flow 331036a05ad778534630529a |
| alt_fd0437276e1d1360fbfa1315 | HIGH | 68.50 | 1 | None | anomaly or detector disagreement signal on flow 4e3ff021c1a6dbbbb774dea8 |
| alt_0a2384635aaa8d277a897cdb | HIGH | 67.79 | 1 | None | anomaly or detector disagreement signal on flow 7bb9da523ed2adbfa373f82c |
| alt_fb6c6f87809f9a4478e28902 | HIGH | 66.92 | 1 | Bot | Bot signal on flow cada33a0ca6fcc92cb976fce |
| alt_f80bfdc4e9535315da44e4ad | HIGH | 66.88 | 1 | None | anomaly or detector disagreement signal on flow 61d2249502e0916000a29a38 |
| alt_dfc10ebe8432e13167d1deb9 | HIGH | 66.54 | 1 | None | anomaly or detector disagreement signal on flow 4f8b0256a6f5be3bf2a6098f |

Alerts start in `NEW`. The offline workflow does not acknowledge or resolve alerts and does not take enforcement actions.
