"""Integration runner that reuses persisted Phase 07 and Phase 08 predictors."""

from __future__ import annotations

import json
import hashlib
import logging
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

import numpy as np
import pyarrow.parquet as pq
from sklearn.metrics import accuracy_score, balanced_accuracy_score, confusion_matrix, f1_score, precision_score, recall_score

from intrusion_intelligence.anomaly.inference import AnomalyPredictor
from intrusion_intelligence.binary.inference import BinaryPredictor
from intrusion_intelligence.feature_engineering import FeatureContract, separate_features_target_metadata
from intrusion_intelligence.intelligence.config import DEFAULT_INTELLIGENCE_CONFIG, load_intelligence_config
from intrusion_intelligence.intelligence.normalization import EmpiricalScoreReference
from intrusion_intelligence.intelligence.pipeline import run_intelligence_pipeline
from intrusion_intelligence.intelligence.reporting import write_intelligence_outputs
from intrusion_intelligence.intelligence.scoring import score_evidence
from intrusion_intelligence.intelligence.schemas import json_safe
from intrusion_intelligence.multiclass.inference import MultiClassPredictor

logger = logging.getLogger(__name__)


class IntelligenceServiceError(RuntimeError):
    """Raised when detector artifacts or source rows are incompatible."""


def run_intelligence_experiment(config_path: str | Path | None = None) -> dict[str, Any]:
    """Run actual persisted detectors on a bounded CIC-IDS2017 sample.

    No model is fitted and no threshold is changed. The default run uses the
    first configured number of rows from each Friday source file and recalculates
    only the frozen anomaly model's benign-validation percentile reference.
    """
    path = config_path or DEFAULT_INTELLIGENCE_CONFIG
    config = load_intelligence_config(path)
    for name in ("binary", "multiclass", "anomaly"):
        if config["detectors"][name]["enabled"] is not True:
            raise IntelligenceServiceError(f"Actual CIC integration requires the configured {name} detector.")

    contract = FeatureContract.from_file(config["dataset"]["feature_schema"])
    binary = BinaryPredictor(config["detectors"]["binary"]["artifact_directory"])
    multiclass = MultiClassPredictor(config["detectors"]["multiclass"]["artifact_directory"])
    anomaly = AnomalyPredictor(config["detectors"]["anomaly"]["artifact_directory"])
    _validate_artifact_compatibility(contract, binary, multiclass, anomaly)
    operating_point = config["detectors"]["anomaly"]["operating_point"]
    if operating_point not in anomaly.calibration["operating_points"]:
        raise IntelligenceServiceError(f"Anomaly artifact has no calibrated operating point {operating_point!r}.")

    source_files = tuple(sorted(Path(config["dataset"]["parquet_directory"]).glob("*.parquet")))
    thursday_files = tuple(path for path in source_files if path.name.lower().startswith("thursday"))
    friday_files = tuple(path for path in source_files if path.name.lower().startswith("friday"))
    if not thursday_files or not friday_files:
        raise IntelligenceServiceError("The configured CIC-IDS2017 extract must contain Thursday validation and Friday test files.")
    present_source_columns = set(pq.ParquetFile(friday_files[0]).schema_arrow.names)
    ground_truth_columns = {contract.target_name, "__source_label", "source_label", "ground_truth", "ground_truth_label"}
    available_export_metadata = [
        name for name in (*contract.metadata_fields, *contract.excluded_fields)
        if name in present_source_columns and name not in ground_truth_columns
    ]

    reference_started = time.perf_counter()
    benign_reference, benign_validation_rows = _build_benign_reference(
        thursday_files,
        contract,
        anomaly,
        batch_size=config["sampling"]["reference_batch_size"],
        operating_point=operating_point,
    )
    reference_seconds = time.perf_counter() - reference_started
    reference = EmpiricalScoreReference(benign_reference)

    rows_per_label_per_file = int(config["sampling"]["rows_per_label_per_source_file"])
    batch_size = int(config["sampling"]["batch_size"])
    records: list[dict[str, Any]] = []
    ground_truth_labels: list[str] = []
    binary_predictions: list[dict[str, Any]] = []
    multiclass_predictions: list[dict[str, Any]] = []
    anomaly_predictions: list[dict[str, Any]] = []
    input_by_file: dict[str, int] = {}
    selection_counts: dict[str, Any] = {}
    inference_started = time.perf_counter()
    for source_path in friday_files:
        rows_read = 0
        columns = _input_columns(source_path, contract, include_target=True)
        selected_rows, source_label_counts = _select_label_stratified_rows(
            source_path, contract.target_name,
            cap_per_label=rows_per_label_per_file,
            batch_size=int(config["sampling"]["reference_batch_size"]),
        )
        selection_counts[source_path.name] = {"source_label_counts": source_label_counts, "selected_rows": len(selected_rows)}
        for frame in _read_selected_rows(source_path, columns, selected_rows, batch_size=batch_size):
            X, y_true, metadata = separate_features_target_metadata(frame, contract, require_target=True)
            if list(X.columns) != list(contract.predictive_features):
                raise IntelligenceServiceError("Phase 05 feature order changed during source-frame separation.")
            binary_batch = binary.predict(X)
            multi_batch = multiclass.predict(X)
            anomaly_frame = anomaly.predict(X, operating_point=operating_point)
            if len(multi_batch) != len(X) or len(anomaly_frame) != len(X):
                raise IntelligenceServiceError("Detector outputs are not aligned to their source feature batch.")
            for position in range(len(X)):
                meta = metadata.iloc[position].to_dict()
                record = _flow_metadata(meta, source_path, X.iloc[position].to_dict())
                records.append(record)
            ground_truth_labels.extend(y_true.astype("string").astype(str).tolist())
            binary_predictions.extend(binary_batch)
            multiclass_predictions.extend(multi_batch)
            anomaly_predictions.extend(anomaly_frame.to_dict(orient="records"))
            rows_read += len(frame)
        input_by_file[source_path.name] = rows_read
    if not records:
        raise IntelligenceServiceError("No Friday source flows were read for the configured integration sample.")
    inference_seconds = time.perf_counter() - inference_started

    model_refs = {
        "binary": str(binary.metadata.get("artifact_directory", config["detectors"]["binary"]["artifact_directory"])),
        "multiclass": str(multiclass.artifact_directory.resolve()),
        "anomaly": str(anomaly.artifact_directory.resolve()),
    }
    result = run_intelligence_pipeline(
        records,
        binary_predictions=binary_predictions,
        multiclass_predictions=multiclass_predictions,
        anomaly_predictions=anomaly_predictions,
        class_labels=multiclass.taxonomy.labels,
        benign_reference_scores=reference,
        weights=config["scoring"]["weights"],
        severity_bands=config["severity"]["bands"],
        correlation_config=config["correlation"],
        alert_config=config["alerts"],
        scoring_version=config["scoring"]["version"],
        severity_policy_version=config["severity"]["version"],
        pipeline_version=config["version"],
        feature_schema_version=contract.schema_version,
        model_artifact_references=model_refs,
    )
    now = datetime.now(timezone.utc)
    run_id = now.strftime("%Y%m%dT%H%M%SZ")
    result["summary"]["ground_truth_evaluation"] = _evaluate_alerts_against_labels(
        result, ground_truth_labels
    )
    result["summary"].update({
        "experiment_run_id": run_id,
        "input_dataset": "CIC-IDS2017 Phase 04 v2 cleaned Parquet",
        "input_sample": {
            "partition": "Friday capture-day test files",
            "selection": f"deterministic evenly spaced sample of up to {rows_per_label_per_file} rows per original label per Friday source file; labels are used only for offline evaluation sample construction and are excluded from inference inputs",
            "rows_by_source_file": input_by_file,
            "label_selection_audit": selection_counts,
            "total_rows": len(records),
            "row_order_is_not_used_as_event_time": True,
            "friday_ground_truth_labels_loaded_for_offline_evaluation_only": True,
            "ground_truth_labels_passed_to_detectors_scoring_events_or_alert_rules": False,
        },
        "detector_execution": {
            "binary": {"status": "loaded_once_and_batch_scored", "model_id": binary.model_id, "experiment_run_id": config["detectors"]["binary"]["experiment_run_id"]},
            "multiclass": {"status": "loaded_once_and_batch_scored", "model_id": multiclass.model_id, "experiment_run_id": config["detectors"]["multiclass"]["experiment_run_id"]},
            "anomaly": {"status": "loaded_once_and_batch_scored", "model_id": anomaly.metadata["model_id"], "experiment_run_id": config["detectors"]["anomaly"]["experiment_run_id"], "operating_point": operating_point},
        },
        "artifact_compatibility": "passed: both detectors match the Phase 05 feature schema and exact feature ordering",
        "anomaly_percentile_reference": {
            "source": "BENIGN Thursday validation observations scored with the frozen Phase 08 model and preprocessor",
            "target_handling": "Thursday target labels were used only to select BENIGN reference rows for the ECDF; they are not detector predictions or alert labels",
            "rows": benign_validation_rows,
            "thresholds_recalibrated": False,
            "model_retrained": False,
            "scoring_seconds": reference_seconds,
        },
        "actual_sample_inference_seconds": inference_seconds,
        "batch_size": batch_size,
        "configuration_fingerprint_sha256": hashlib.sha256(
            json.dumps(json_safe(config), sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest(),
        "correlation_metadata_limitations": {
            "available_export_metadata_columns": available_export_metadata,
            "ground_truth_columns_present_in_source_export": [
                name for name in (contract.target_name, "__source_label") if name in present_source_columns
            ],
            "ground_truth_columns_loaded_for_detection": [],
            "available_correlation_fields": [
                name for name in ("timestamp", "source_ip", "destination_ip", "source_port", "destination_port", "protocol", "flow_id")
                if name in present_source_columns
            ],
            "missing_fields_in_phase04_export": ["timestamp", "source_ip", "destination_ip", "source_port", "protocol", "Flow ID"],
            "temporal_correlation_used": False,
            "correlation_is_not_inferred_from_source_row_order": True,
        },
    })
    output_map = write_intelligence_outputs(
        result,
        intelligence_directory=config["reports"]["intelligence_directory"],
        figure_directory=config["reports"]["figure_directory"],
        run_id=run_id,
    )
    result["summary"]["outputs"] = output_map
    configuration_path = Path(config["reports"]["intelligence_directory"]) / run_id / "configuration.json"
    configuration_path.write_text(json.dumps(json_safe(config), ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    result["summary"]["outputs"]["configuration"] = str(configuration_path.resolve())
    (Path(config["reports"]["intelligence_directory"]) / run_id / "threat_intelligence_summary.json").write_text(
        json.dumps(json_safe(result["summary"]), ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    logger.info("Completed threat intelligence run %s: %s flows, %s alerts", run_id, len(records), len(result["alerts"]))
    return result


def _validate_artifact_compatibility(contract: FeatureContract, binary: BinaryPredictor, multiclass: MultiClassPredictor, anomaly: AnomalyPredictor) -> None:
    expected_features = list(contract.predictive_features)
    if binary.metadata.get("feature_schema_version") != contract.schema_version:
        raise IntelligenceServiceError("Binary artifact feature schema version is incompatible.")
    if binary.metadata.get("input_feature_names") != expected_features:
        raise IntelligenceServiceError("Binary artifact feature order is incompatible.")
    if multiclass.metadata.get("feature_schema_version") != contract.schema_version:
        raise IntelligenceServiceError("Multi-class artifact feature schema version is incompatible.")
    if multiclass.metadata.get("input_feature_names") != expected_features:
        raise IntelligenceServiceError("Multi-class artifact feature order is incompatible.")
    if anomaly.metadata.get("feature_schema_version") != contract.schema_version:
        raise IntelligenceServiceError("Anomaly artifact feature schema version is incompatible.")
    if anomaly.metadata.get("input_feature_names") != expected_features:
        raise IntelligenceServiceError("Anomaly artifact feature order is incompatible.")


def _build_benign_reference(
    validation_files: tuple[Path, ...],
    contract: FeatureContract,
    predictor: AnomalyPredictor,
    *,
    batch_size: int,
    operating_point: str,
) -> tuple[np.ndarray, int]:
    score_parts: list[np.ndarray] = []
    benign_rows = 0
    columns = list(contract.predictive_features) + [contract.target_name]
    for path in validation_files:
        for frame in _read_rows(path, columns, limit=None, batch_size=batch_size):
            X, y, _ = separate_features_target_metadata(frame, contract)
            mask = y.astype("string").eq("BENIGN")
            if not mask.any():
                continue
            result = predictor.predict(X.loc[mask], operating_point=operating_point)
            scores = result["anomaly_score"].to_numpy(dtype=np.float64)
            if not np.isfinite(scores).all():
                raise IntelligenceServiceError("Frozen anomaly model produced a non-finite validation reference score.")
            score_parts.append(scores)
            benign_rows += len(scores)
    if not score_parts:
        raise IntelligenceServiceError("No benign Thursday validation scores are available for percentile normalization.")
    return np.concatenate(score_parts), benign_rows


def _input_columns(path: Path, contract: FeatureContract, *, include_target: bool) -> list[str]:
    present = set(pq.ParquetFile(path).schema_arrow.names)
    ground_truth_columns = {contract.target_name, "__source_label", "source_label", "ground_truth", "ground_truth_label"}
    metadata = [
        name for name in (*contract.metadata_fields, *contract.excluded_fields)
        if name in present and name not in ground_truth_columns
    ]
    columns = list(contract.predictive_features) + metadata
    if include_target and contract.target_name in present:
        columns.append(contract.target_name)
    return list(dict.fromkeys(columns))


def _read_rows(path: Path, columns: list[str], *, limit: int | None, batch_size: int) -> Iterator[Any]:
    parquet_file = pq.ParquetFile(path)
    remaining = limit
    for batch in parquet_file.iter_batches(batch_size=batch_size, columns=columns):
        if remaining is not None:
            if remaining <= 0:
                break
            if batch.num_rows > remaining:
                batch = batch.slice(0, remaining)
        frame = batch.to_pandas()
        yield frame
        if remaining is not None:
            remaining -= len(frame)


def _select_label_stratified_rows(path: Path, target_column: str, *, cap_per_label: int, batch_size: int) -> tuple[list[int], dict[str, int]]:
    """Select a deterministic, label-stratified held-out evaluation sample.

    Labels are read on a separate pass and only determine which source row IDs
    enter the offline evaluation sample. The selected label column is removed
    before any detector or scoring call.
    """
    positions_by_label: dict[str, list[int]] = {}
    offset = 0
    parquet = pq.ParquetFile(path)
    for batch in parquet.iter_batches(batch_size=batch_size, columns=[target_column]):
        values = batch.column(0).to_pylist()
        for local, value in enumerate(values):
            label = str(value)
            positions_by_label.setdefault(label, []).append(offset + local)
        offset += batch.num_rows
    counts = {label: len(positions) for label, positions in sorted(positions_by_label.items())}
    selected: list[int] = []
    for label, positions in sorted(positions_by_label.items()):
        if len(positions) <= cap_per_label:
            selected.extend(positions)
        else:
            # Evenly spread picks over the file's records for this class.
            selected.extend(positions[int(i)] for i in np.linspace(0, len(positions) - 1, num=cap_per_label, dtype=np.int64))
    return sorted(selected), counts


def _read_selected_rows(path: Path, columns: list[str], selected_rows: list[int], *, batch_size: int) -> Iterator[Any]:
    selected = np.asarray(selected_rows, dtype=np.int64)
    if selected.size == 0:
        return
    parquet = pq.ParquetFile(path)
    offset = 0
    cursor = 0
    for batch in parquet.iter_batches(batch_size=batch_size, columns=columns):
        end = offset + batch.num_rows
        stop = cursor
        while stop < len(selected) and selected[stop] < end:
            stop += 1
        if stop > cursor:
            local = selected[cursor:stop] - offset
            frame = batch.to_pandas().iloc[local].reset_index(drop=True)
            yield frame
        cursor = stop
        offset = end


def _flow_metadata(metadata: dict[str, Any], path: Path, features: dict[str, Any]) -> dict[str, Any]:
    record: dict[str, Any] = {}
    source_file = _pick(metadata, "__source_file", "source_filename", "source_file") or path.name
    row_number = _pick(metadata, "__source_row_number", "source_row_number", "row_number")
    record_id = _pick(metadata, "__record_id", "record_id", "flow_id")
    record.update({
        "flow_record_reference": str(record_id) if record_id is not None else f"{source_file}#row={row_number if row_number is not None else 'unavailable'}",
        "source_filename": str(source_file),
        "source_row_number": row_number,
        "flow_id": _pick(metadata, "flow_id", "Flow ID"),
        "timestamp": _pick(metadata, "timestamp", "event_timestamp", "timestamp_utc", "Timestamp"),
        "source_ip": _pick(metadata, "source_ip", "src_ip", "Source IP"),
        "destination_ip": _pick(metadata, "destination_ip", "dst_ip", "Destination IP"),
        "source_port": _pick(metadata, "source_port", "src_port", "Source Port"),
        "destination_port": _pick(metadata, "destination_port", "dst_port", "Destination Port"),
        "protocol": _pick(metadata, "protocol", "Protocol"),
        "capture_group": path.name,
    })
    source_keys = {
        "timestamp": ("timestamp", "event_timestamp", "timestamp_utc", "Timestamp"),
        "source_ip": ("source_ip", "src_ip", "Source IP"),
        "destination_ip": ("destination_ip", "dst_ip", "Destination IP"),
        "source_port": ("source_port", "src_port", "Source Port"),
        "destination_port": ("destination_port", "dst_port", "Destination Port"),
        "protocol": ("protocol", "Protocol"),
        "flow_id": ("flow_id", "Flow ID", "flowId"),
    }
    provenance: dict[str, dict[str, Any]] = {}
    normalized_metadata = {str(key).strip().lower(): value for key, value in metadata.items()}
    for field, aliases in source_keys.items():
        present_export = any(alias.strip().lower() in normalized_metadata for alias in aliases)
        if record.get(field) is not None and present_export:
            provenance[field] = {"status": "observed", "origin": "processed_dataset_metadata", "source_field": next((alias for alias in aliases if alias.strip().lower() in normalized_metadata), None)}
        elif field == "destination_port" and record.get(field) is not None:
            provenance[field] = {"status": "observed", "origin": "predictive_feature_context", "source_field": "destination_port"}
        else:
            provenance[field] = {"status": "unavailable", "origin": None, "source_field": None}
    provenance["source_file"] = {"status": "observed", "origin": "dataset_provenance", "source_field": "__source_file" if "__source_file" in metadata else None}
    provenance["source_record_id"] = {"status": "observed" if record_id is not None else "unavailable", "origin": "dataset_provenance" if record_id is not None else None, "source_field": "__record_id" if record_id is not None else None}
    record["metadata_provenance"] = provenance
    # CIC-IDS2017 has destination_port in X, not as metadata. Retain it only
    # after inference as investigation context; it is never sent to scoring.
    if record["destination_port"] is None and "destination_port" in features:
        record["destination_port"] = features["destination_port"]
    return record


def _pick(values: dict[str, Any], *names: str) -> Any:
    normalized = {str(key).strip().lower(): value for key, value in values.items()}
    for name in names:
        value = normalized.get(name.strip().lower())
        if value is not None and str(value).strip() not in {"", "nan", "<NA>"}:
            return value
    return None


def _evaluate_alerts_against_labels(result: dict[str, Any], labels: list[str]) -> dict[str, Any]:
    """Offline-only evaluation. Labels never enter records, prediction, scoring, or alert generation."""
    events = result["events"]
    if len(events) != len(labels):
        raise IntelligenceServiceError("Ground-truth evaluation labels are misaligned with the inference sample.")
    truth_attack = np.asarray([label != "BENIGN" for label in labels], dtype=bool)
    binary_pred = np.asarray([
        event["normalized_evidence"]["binary"].get("details", {}).get("malicious_prediction") is True
        for event in events
    ], dtype=bool)
    alert_ids = {event_id for alert in result["alerts"] for event_id in alert["supporting_event_ids"]}
    alert_pred = np.asarray([event["event_id"] in alert_ids for event in events], dtype=bool)

    def metrics(prediction: np.ndarray) -> dict[str, Any]:
        tn, fp, fn, tp = confusion_matrix(truth_attack, prediction, labels=[False, True]).ravel()
        return {
            "support": {"BENIGN": int((~truth_attack).sum()), "ATTACK": int(truth_attack.sum())},
            "accuracy": float(accuracy_score(truth_attack, prediction)),
            "balanced_accuracy": float(balanced_accuracy_score(truth_attack, prediction)),
            "precision_attack": float(precision_score(truth_attack, prediction, zero_division=0)),
            "recall_attack": float(recall_score(truth_attack, prediction, zero_division=0)),
            "f1_attack": float(f1_score(truth_attack, prediction, zero_division=0)),
            "false_positive_rate": float(fp / (fp + tn)) if tn + fp else None,
            "confusion_matrix_labels": ["BENIGN", "ATTACK"],
            "confusion_matrix": [[int(tn), int(fp)], [int(fn), int(tp)]],
        }

    per_category: dict[str, Any] = {}
    observed_categories = sorted({label for label in labels if label != "BENIGN"})
    for category in observed_categories:
        actual = np.asarray([label == category for label in labels], dtype=bool)
        predicted = np.asarray([
            event["normalized_evidence"]["multiclass"].get("details", {}).get("predicted_label") == category
            for event in events
        ], dtype=bool)
        tn, fp, fn, tp = confusion_matrix(actual, predicted, labels=[False, True]).ravel()
        per_category[category] = {"support": int(actual.sum()), "predicted_support": int(predicted.sum()), "precision": float(precision_score(actual, predicted, zero_division=0)), "recall": float(recall_score(actual, predicted, zero_division=0)), "false_positive_rate": float(fp / (fp + tn)) if tn + fp else None, "confusion_matrix": [[int(tn), int(fp)], [int(fn), int(tp)]]}
    sensitivity: dict[str, Any] = {}
    alternatives = {
        "configured_default": {"binary": 0.30, "multiclass": 0.25, "anomaly": 0.45},
        "equal_weights": {"binary": 1 / 3, "multiclass": 1 / 3, "anomaly": 1 / 3},
        "supervised_heavier": {"binary": 0.40, "multiclass": 0.35, "anomaly": 0.25},
    }
    for name, candidate_weights in alternatives.items():
        candidate_pred = np.asarray([
            (score_evidence(event["normalized_evidence"], weights=candidate_weights)["threat_score"] or 0.0) >= 50.0
            and event.get("event_status") not in {"NORMAL", "INSUFFICIENT_EVIDENCE"}
            for event in events
        ], dtype=bool)
        sensitivity[name] = {"weights": candidate_weights, "fixed_score_cutoff": 50.0, "metrics": metrics(candidate_pred)}
    return {
        "status": "offline_held_out_label_evaluation",
        "labels_are_isolated_from_inference_scoring_events_and_alerts": True,
        "evaluated_rows": len(labels),
        "binary_detector": metrics(binary_pred),
        "alert_level_detection": metrics(alert_pred),
        "per_attack_category_multiclass": per_category,
        "score_weight_sensitivity_at_fixed_50_cutoff": sensitivity,
        "severity_cutoffs_empirical_status": "not calibrated; this bounded sample reports distribution and sensitivity only",
        "severity_distribution": {severity: sum(alert["severity"] == severity for alert in result["alerts"]) for severity in ("LOW", "MEDIUM", "HIGH", "CRITICAL")},
        "unscored_event_rate": sum(event.get("threat_score") is None for event in events) / len(events) if events else None,
        "correlation_coverage_rate": sum(event["event_id"] in {eid for group in result["correlated_event_groups"] for eid in group["event_ids"]} for event in events) / len(events) if events else None,
        "interpretation": "Bounded 1,000-row-per-Friday-source-file sample; research evaluation only, not deployment validation or confirmed incidents.",
    }
