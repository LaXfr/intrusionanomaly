"""Run explanations for persisted detectors and Phase 09 flow records."""

from __future__ import annotations

import json
import time
import tomllib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
import pyarrow.parquet as pq

from intrusion_intelligence.explainability.background_data import load_training_background
from intrusion_intelligence.explainability.alert_enrichment import enrich_phase09_records
from intrusion_intelligence.explainability.explainers import build_shap_session
from intrusion_intelligence.explainability.feature_mapping import aggregate_contributions, aggregate_global_importance, map_transformed_features
from intrusion_intelligence.explainability.model_registry import load_explainable_models
from intrusion_intelligence.explainability.schemas import ExplanationRecord
from intrusion_intelligence.feature_engineering import FeatureContract


def run_explainability(config_path: str | Path) -> dict[str, Any]:
    import shap

    started = time.perf_counter()
    config_path = Path(config_path).resolve()
    config = tomllib.loads(config_path.read_text(encoding="utf-8"))
    root = config_path.parent.parent
    dataset = (root / config["dataset"]["parquet_directory"]).resolve()
    contract = FeatureContract.from_file(root / config["dataset"]["feature_schema"])
    models, _ = load_explainable_models(config_path, contract=contract)
    phase09 = root / "reports" / "intelligence" / config["intelligence"]["source_run_id"]
    events_path = phase09 / "flow_detection_events.jsonl"
    events = [json.loads(line) for line in events_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    event_rows = _phase09_rows(events, dataset, contract, int(config["explanations"]["global_sample_size"]))
    if event_rows.empty:
        raise ValueError("No Phase 09 source rows could be recovered for explanation.")
    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    output_dir = root / config["reports"]["explanation_directory"] / run_id
    figure_dir = root / config["reports"]["figure_directory"] / run_id
    output_dir.mkdir(parents=True, exist_ok=False)
    figure_dir.mkdir(parents=True, exist_ok=False)
    all_records: list[dict[str, Any]] = []
    global_rows: list[dict[str, Any]] = []
    model_run_metadata: dict[str, Any] = {}
    local_limit = int(config["explanations"]["local_explanation_count"])
    for key, model in models.items():
        background = load_training_background(dataset, contract, model_family=model.family, sample_size=int(config["background"]["sample_size"]), random_seed=int(config["random_seed"]))
        bg_transformed = model.transform(background.features)
        transformed = model.transform(event_rows.loc[:, list(contract.predictive_features)])
        sample_limit = int(config["explanations"]["anomaly_global_sample_size"] if model.family == "anomaly" else config["explanations"]["global_sample_size"])
        transformed = transformed.iloc[:sample_limit]
        source_rows = event_rows.iloc[:sample_limit]
        session = build_shap_session(model, bg_transformed, random_seed=int(config["explanations"]["permutation_seed"]))
        mapping = map_transformed_features(model.feature_names, contract.predictive_features)
        selection_reason = (
            "TreeExplainer interventional probabilities are supported for this persisted Random Forest classifier."
            if model.family.endswith("random_forest") else
            "LinearExplainer decomposes the persisted Logistic Regression decision margin/logits in its model output space."
            if model.family.endswith("logistic_regression") else
            "PermutationExplainer wraps the exact persisted Isolation Forest -score_samples function because tree-path attribution is not selected for its anomaly score."
        )
        model_run_metadata[key] = {"model_id": model.model_id, "model_version": model.model_version, "model_family": model.family, "output_space": model.output_space, "background": background.metadata(), "explainer": model.explainer_type, "explainer_selection_reason": selection_reason, "input_representation": "transformed features produced by the matching persisted fitted preprocessor", "feature_mapping": {"mapped_transformed_columns": sum(source is not None for source in mapping.values()), "unmapped_transformed_columns": [name for name, source in mapping.items() if source is None], "grouping_rule": "signed local contributions sum by source; global mean absolute contributions sum by source"}, "outputs": []}
        for output in model.outputs:
            values, bases, predictions, diagnostics = session.explain(transformed, output, max_evaluations=int(config["explanations"]["permutation_max_evaluations"]))
            global_importance = aggregate_global_importance(values, model.feature_names, mapping)
            for rank, row in enumerate(global_importance, start=1):
                global_rows.append({"model_key": key, "model_id": model.model_id, "model_family": model.family, "output_name": output.name, "output_semantics": output.semantic, "rank": rank, **row})
            model_run_metadata[key]["outputs"].append({"name": output.name, "semantic": output.semantic, "explained_rows": len(transformed), "additivity": diagnostics, "top_features": global_importance[:int(config["explanations"]["top_features"])]})
            # Local rows are matched to real Phase 09 source-record references; no target values are loaded.
            count = min(local_limit, len(transformed))
            for index in range(count):
                contribution = aggregate_contributions(values[index], model.feature_names, mapping)
                source = source_rows.iloc[index]
                event = source["__event"]
                prediction_metadata = model.predict_metadata(transformed.iloc[[index]], output)
                top = contribution[:int(config["explanations"]["top_features"])]
                threshold = model.threshold
                threshold_space = "higher_is_more_anomalous_score" if model.family == "anomaly" else "attack_probability" if model.family == "binary_random_forest" else "ATTACK_log_odds_margin" if model.family == "binary_logistic_regression" else None
                if model.family == "binary_logistic_regression" and threshold is not None:
                    persisted_probability_threshold = float(threshold)
                    threshold = float(np.log(threshold / (1.0 - threshold))) if 0.0 < threshold < 1.0 else None
                else:
                    persisted_probability_threshold = None
                doc = ExplanationRecord(
                    explanation_id=f"{run_id}:{key}:{output.name}:{event['event_id']}", model_id=model.model_id, model_version=model.model_version,
                    model_family=model.family, explainer_type=model.explainer_type, output_name=output.name, output_semantics=output.semantic,
                    explanation_representation="SHAP additive feature contributions in the stated model output space",
                    predicted_label=str(prediction_metadata.get("predicted_label") or event.get("event_status")),
                    predicted_class_id=prediction_metadata.get("predicted_class_id"), model_output_value=float(predictions[index]), decision_threshold=threshold,
                    decision_threshold_space=threshold_space, persisted_decision_threshold=persisted_probability_threshold,
                    reference_dataset_id=str(background.dataset_id), feature_names=list(model.feature_names),
                    transformed_feature_contributions=[{"feature": name, "contribution": float(value)} for name, value in zip(model.feature_names, values[index])],
                    original_feature_contributions=contribution,
                    positive_contributions=[row for row in contribution if row.get("contribution", 0) > 0],
                    negative_contributions=[row for row in contribution if row.get("contribution", 0) < 0],
                    top_influential_features=top, expected_value=float(bases[index]),
                    additivity_diagnostic={**diagnostics, "row_residual": float(bases[index] + values[index].sum() - predictions[index])},
                    explanation_summary=_summary(output.semantic, top, float(predictions[index]), float(bases[index])),
                    flow_record_reference=str(event["flow_record_reference"]), source_filename=str(event.get("source_filename")),
                    source_row_number=event.get("source_row_number"), configuration={"background_rows": len(bg_transformed), "global_sample_rows": len(transformed), "random_seed": int(config["random_seed"]), "permutation_max_evaluations": int(config["explanations"]["permutation_max_evaluations"]) if model.family == "anomaly" else None, "explained_output_class_id": output.class_id},
                )
                all_records.append(doc.to_dict())
        _write_plots(session, transformed, model.outputs, figure_dir / key, key, tuple(config["explanations"].get("visualized_multiclass_labels", [])) if model.family.startswith("multiclass_") else ())
    event_refs: dict[str, list[dict[str, Any]]] = {}
    for item in all_records:
        event_refs.setdefault(item["flow_record_reference"], []).append({"explanation_id": item["explanation_id"], "model_id": item["model_id"], "output_name": item["output_name"], "path": "explanations.jsonl"})
    alerts = json.loads((phase09 / "security_alerts.json").read_text(encoding="utf-8"))
    events_out, alerts_out = enrich_phase09_records(events, alerts, event_refs)
    execution_seconds = time.perf_counter() - started
    _write_outputs(output_dir, run_id, config, model_run_metadata, all_records, global_rows, events_out, alerts_out, execution_seconds)
    return {"run_id": run_id, "execution_seconds": execution_seconds, "explanation_count": len(all_records), "global_importance_rows": len(global_rows), "events_enriched": len(events_out), "alerts_enriched": len(alerts_out), "output_directory": str(output_dir), "figure_directory": str(figure_dir), "models": model_run_metadata}


def _phase09_rows(events: list[dict[str, Any]], dataset: Path, contract: FeatureContract, limit: int) -> pd.DataFrame:
    selected = sorted(events, key=lambda row: (-float(row.get("threat_score") or -1), row["event_id"]))[:max(limit, 8)]
    wanted = {str(row["flow_record_reference"]): row for row in selected}
    features: list[dict[str, Any]] = []
    for source in sorted({str(row.get("source_filename", "")).split("/")[-1].replace(".csv", ".parquet") for row in selected}):
        path = dataset / source
        if not path.exists():
            continue
        pf = pq.ParquetFile(path)
        columns = [*contract.predictive_features, "__record_id"]
        offset = 0
        for batch in pf.iter_batches(batch_size=5000, columns=columns):
            ids = batch.column(batch.schema.get_field_index("__record_id")).to_pylist()
            positions = [i for i, record_id in enumerate(ids) if str(record_id) in wanted]
            for position in positions:
                values = batch.slice(position, 1).select(list(contract.predictive_features)).to_pydict()
                row = {name: values[name][0] for name in contract.predictive_features}
                reference = str(ids[position])
                row["__event"] = wanted[reference]
                features.append(row)
            offset += batch.num_rows
            if len(features) >= len(wanted):
                break
    if not features:
        return pd.DataFrame()
    frame = pd.DataFrame(features)
    frame["__event"] = [item["__event"] for item in features]
    return frame


def _detector_name(family: str) -> str:
    return "anomaly" if family == "anomaly" else "binary" if family.startswith("binary") else "multiclass"


def _summary(semantic: str, top: list[dict[str, Any]], prediction: float, baseline: float) -> str:
    drivers = "; ".join(f"{item['feature']} {item['contribution']:+.5g}" for item in top[:5]) or "no mapped features"
    return f"Output is {prediction:.6g} in {semantic} (baseline {baseline:.6g}); largest signed SHAP contributions: {drivers}. Positive values raise this stated output; negative values lower it."


def _write_plots(session: Any, values: pd.DataFrame, outputs: tuple[Any, ...], directory: Path, key: str, selected_labels: tuple[str, ...] = ()) -> None:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import shap
    directory.mkdir(parents=True, exist_ok=True)
    for output in outputs:
        if len(outputs) > 1 and selected_labels and output.name not in selected_labels:
            continue
        shap_values, bases, _, _ = session.explain(values.iloc[:min(32, len(values))], output)
        explanation = shap.Explanation(values=shap_values, base_values=bases, data=values.iloc[:len(shap_values)].to_numpy(), feature_names=list(values.columns))
        plt.figure()
        shap.plots.beeswarm(explanation, max_display=15, show=False)
        plt.savefig(directory / f"{output.name}_beeswarm.png", dpi=140, bbox_inches="tight")
        plt.close()
        plt.figure()
        shap.plots.bar(explanation, max_display=15, show=False)
        plt.savefig(directory / f"{output.name}_bar.png", dpi=140, bbox_inches="tight")
        plt.close()
        plt.figure()
        shap.plots.waterfall(explanation[0], max_display=15, show=False)
        plt.savefig(directory / f"{output.name}_waterfall.png", dpi=140, bbox_inches="tight")
        plt.close()


def _write_outputs(directory: Path, run_id: str, config: dict[str, Any], metadata: dict[str, Any], records: list[dict[str, Any]], global_rows: list[dict[str, Any]], events: list[dict[str, Any]], alerts: list[dict[str, Any]], execution_seconds: float) -> None:
    import shap

    def jsonl(name: str, rows: list[dict[str, Any]]) -> None:
        (directory / name).write_text("".join(json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n" for row in rows), encoding="utf-8")
    jsonl("explanations.jsonl", records)
    jsonl("phase09_events_with_explanations.jsonl", events)
    (directory / "phase09_alerts_with_explanations.json").write_text(json.dumps(alerts, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    pd.DataFrame(global_rows).to_csv(directory / "global_importance.csv", index=False)
    report = {"run_id": run_id, "created_at_utc": datetime.now(timezone.utc).isoformat(), "execution_seconds": float(execution_seconds), "shap_version": shap.__version__, "scikit_learn_version": __import__("sklearn").__version__, "models": metadata, "configuration": config, "explanation_records": len(records), "global_importance_rows": len(global_rows), "event_enrichment": "sidecar only; original Phase 09 scores, severity and correlation records preserved", "limitations": ["SHAP attribution is model-output explanation, not causal evidence.", "Unselected Phase 09 records have no local explanation.", "XGBoost artifacts were unavailable in this project snapshot."]}
    (directory / "explainability_report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    lines = ["# Explainability report", "", f"Run: `{run_id}`", "", f"Execution time: {execution_seconds:.2f} seconds.", f"Explanation records: {len(records)}; global-importance rows: {len(global_rows)}.", "", "SHAP values explain each configured model output in its documented units. They do not explain the Phase 09 heuristic threat score or establish causation.", "", "## Model coverage", ""]
    for key, model in metadata.items():
        lines.append(f"- **{key}** (`{model['model_id']}`): {model['model_family']}; output space `{model['output_space']}`; training-only background {model['background']['observations']} rows.")
        for output in model["outputs"]:
            lines.append(f"  - {output['name']} ({output['semantic']}), {output['explained_rows']} rows; max additivity residual {output['additivity']['max_absolute_residual']:.3g}.")
    lines += ["", "## Limitations", "", "- Output importance depends on the specified background and output scale.", "- Isolation Forest explanations use model-agnostic permutation SHAP over the persisted transformed inputs.", "- Transformed columns without a unique declared input mapping remain separately marked as unmapped.", "- XGBoost was unavailable in the installed environment and has no persisted project artifact.", ""]
    (directory / "explainability_report.md").write_text("\n".join(lines), encoding="utf-8")
