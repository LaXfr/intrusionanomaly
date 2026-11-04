# Alert Correlation

## Purpose

The Phase 09 correlator groups suspicious flow events when an explicit configured network key and UTC timestamp are present. It preserves individual event records and does not infer relationships from file order, source-row order, destination port alone, or missing values.

## Correlation keys

| Rule | Required fields | Interpretation |
|---|---|---|
| `source_ip` | Source IP | Suspicious events from the same source. |
| `destination_ip` | Destination IP | Suspicious events aimed at the same destination. |
| `destination_service` | Destination IP, destination port, protocol | Events targeting the same explicit service tuple. |
| `attack_category` | Source IP, destination IP, predicted non-BENIGN category | Similar predicted category between the same endpoints. |
| `repeated_flow_tuple` | Source IP, destination IP, source port, destination port, protocol | Repeated events with an identical five-field flow tuple. |
| `temporal_activity` | Source IP, destination IP | Events for the same explicit endpoint pair inside the configured time window; no attack label alone is used as a key. |

Keys must be present and nonblank for an event to participate in a rule. A category is derived only from a valid multi-class prediction. Category correlation does not treat an anomaly as a known attack family.

## Temporal grouping

`configs/intelligence.toml` enables all six rules with a 5-minute default window, two-event minimum, and allowed window values of 1, 5, or 15 minutes. For each rule, events are bucketed by exact key, sorted by parsed timezone-aware timestamp converted to UTC, and grouped into non-overlapping windows anchored at the earliest event in each window. Naive timestamps are rejected rather than assumed to be UTC. Input order does not affect grouping.

## Missing metadata and audit

Correlation is skipped for a suspicious event when its timestamp is missing, invalid/naive, or a required key field is absent. Exact duplicate event fingerprints are suppressed before grouping. The audit records per-rule required fields, window and minimum size, eligible and grouped event counts, missing reasons, duplicate inputs, and unmatched suspicious events. Invalid or missing data never create a shared null key. Flow-level events still retain their provenance and can qualify as individual alerts.

The cleaned CIC-IDS2017 Phase 04 export retains source file, row number, record ID, and destination port, but lacks timestamps, endpoint addresses, source port, protocol, and Flow ID. Since every correlation rule requires a timestamp and destination service also requires destination IP and protocol, the actual Phase 09 sample produced no groups. Source row number is not substituted for time. Events include a metadata provenance record distinguishing unavailable fields from destination port observed as predictive-feature context.

In actual CLI run `20261103T160444Z`, all 1,407 suspicious events in the bounded Friday sample had a missing timestamp. Each of the six rules recorded 1,407 `missing_timestamp` skips; none had a valid event for grouping, and no correlation group or group alert was produced. This run validates missing-metadata handling on CIC data; rule formation is validated by synthetic fixtures only. Run artifacts are under `reports/intelligence/20261103T160444Z/`.

## Aggregation and duplicate handling

A correlated group contains unique event and flow counts, UTC bounds, the exact key and rule, category counts, detector decision counts, maximum and mean member score, highest severity, and destination-service count where available. A correlated alert requires at least two distinct member events and a maximum score of at least the configured group threshold. Group members are omitted from duplicate single-flow alerts within the same run.

Event fingerprints include stable source identity and detector evidence while excluding volatile inference timestamps from the fingerprint computation; raw timestamps remain available on the event. Alert fingerprints combine alert type, sorted event fingerprints, and predicted attack-category set. Repeated exact fingerprints are deduplicated and retain their supporting event IDs; a higher-severity duplicate updates the retained alert and adds a severity-history record. Similar alerts with different event evidence or category remain distinct.

## Offline limitations

The correlator works on event records supplied to one pipeline run and keeps the batch in memory. It does not maintain a streaming time-window state across batches or persist prior alerts. It cannot link events without actual endpoint and time fields. The benchmark has no complete connection metadata in its cleaned export, so synthetic tests establish rule behavior while the real run demonstrates missing-metadata handling only. Model-predicted categories are evidence, not ground-truth labels. The legacy `repeated_activity` alias remains accepted for older configs; new configurations should use `repeated_flow_tuple`.
