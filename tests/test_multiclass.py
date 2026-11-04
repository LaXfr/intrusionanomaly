from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq
import pytest

from intrusion_intelligence.feature_engineering import FeatureContract
from intrusion_intelligence.multiclass.artifacts import load_model_bundle
from intrusion_intelligence.multiclass.config import load_multiclass_config
from intrusion_intelligence.multiclass.data import collect_partition, inspect_parquet_dataset
from intrusion_intelligence.multiclass.evaluation import align_class_scores, evaluate_multiclass
from intrusion_intelligence.multiclass.inference import MultiClassPredictor
from intrusion_intelligence.multiclass.service import run_multiclass_experiment
from intrusion_intelligence.multiclass.splitting import (
    SplitError,
    make_three_way_split,
    stratified_training_sample,
)
from intrusion_intelligence.multiclass.taxonomy import ClassTaxonomy, TaxonomyError


@pytest.fixture
def small_contract() -> FeatureContract:
    return FeatureContract.from_dict(
        {
            "schema_version": "test-1.0",
            "dataset_name": "tiny-cic-fixture",
            "target": {
                "name": "label",
                "allowed_values": ["BENIGN", "Attack A", "Attack B"],
            },
            "features": [
                {"name": "flow_duration", "type": "numeric", "included": True},
                {"name": "packet_count", "type": "numeric", "included": True},
            ],
            "leakage_policy": {
                "metadata_fields": ["__source_file"],
                "excluded_fields": ["record_id"],
            },
        }
    )


def test_taxonomy_is_deterministic_preserves_labels_and_round_trips() -> None:
    observed = ["Attack B", "BENIGN", "Attack A", "BENIGN"]
    taxonomy = ClassTaxonomy.from_labels(observed, allowed_labels=["BENIGN", "Attack A", "Attack B"])

    assert taxonomy.labels == ("BENIGN", "Attack A", "Attack B")
    assert taxonomy.encode(observed) == [2, 0, 1, 0]
    assert taxonomy.decode([2, 0, 1]) == ["Attack B", "BENIGN", "Attack A"]
    assert ClassTaxonomy.from_dict(taxonomy.to_dict()).labels == taxonomy.labels
    with pytest.raises(TaxonomyError, match="Unknown labels"):
        taxonomy.encode(["unknown attack"])
    with pytest.raises(TaxonomyError, match="null"):
        ClassTaxonomy.from_labels(["BENIGN", None])
    with pytest.raises(TaxonomyError, match="blank"):
        ClassTaxonomy.from_labels(["BENIGN", "  "])
    with pytest.raises(TaxonomyError, match="BENIGN"):
        ClassTaxonomy.from_labels(["Attack A"])


def test_taxonomy_rejects_unexpected_contract_label() -> None:
    with pytest.raises(TaxonomyError, match="Unexpected target labels"):
        ClassTaxonomy.from_labels(["BENIGN", "Unreviewed"], allowed_labels=["BENIGN", "Attack A"])


def test_group_aware_split_has_disjoint_groups_and_full_class_coverage() -> None:
    labels = np.tile(np.repeat(["BENIGN", "Attack A", "Attack B"], 4), 8)
    groups = np.repeat([f"capture-{index}" for index in range(8)], 12)

    split = make_three_way_split(
        labels,
        groups,
        train_fraction=0.5,
        validation_fraction=0.25,
        test_fraction=0.25,
        strategy="group_aware",
        random_seed=11,
        group_search_attempts=8,
    )

    assert split.audit["used_strategy"] == "group_aware"
    assert split.audit["group_disjoint"] is True
    assert all(not values for values in split.audit["group_overlaps"].values())
    assert all(not values for values in split.audit["unseen_classes"].values())
    assert sum(split.audit["row_counts"].values()) == len(labels)


def test_infeasible_groups_use_explicit_stratified_fallback_and_report_overlap() -> None:
    labels = np.array(["BENIGN"] * 90 + ["Attack A"] * 30 + ["Attack B"] * 15, dtype=object)
    groups = np.array(["benign-day"] * 90 + ["attack-a-day"] * 30 + ["attack-b-day"] * 15, dtype=object)

    split = make_three_way_split(labels, groups, strategy="group_aware", random_seed=42)

    assert split.audit["used_strategy"] == "stratified_row_fallback"
    assert "fewer than three groups" in split.audit["fallback_reason"]
    assert split.audit["group_disjoint"] is False
    assert set(split.audit["unseen_classes"]["train"]) == set()
    assert set(split.audit["unseen_classes"]["validation"]) == set()
    assert set(split.audit["unseen_classes"]["test"]) == set()
    with pytest.raises(SplitError, match="fewer than three groups"):
        make_three_way_split(labels, groups, strategy="group_aware", allow_stratified_fallback=False)


def test_split_rejects_rare_class_that_cannot_cover_three_stratified_partitions() -> None:
    labels = np.array(["BENIGN"] * 10 + ["Attack A"] * 2, dtype=object)
    groups = np.array(["g1"] * 12, dtype=object)
    with pytest.raises(SplitError, match="at least three rows per class"):
        make_three_way_split(labels, groups, strategy="stratified_row")


def test_training_sample_is_reproducible_and_preserves_all_classes() -> None:
    labels = np.array(["BENIGN"] * 500 + ["Attack A"] * 30 + ["Attack B"] * 9, dtype=object)
    indices = np.arange(len(labels))
    left = stratified_training_sample(indices, labels, maximum_rows=120, random_seed=37)
    right = stratified_training_sample(indices, labels, maximum_rows=120, random_seed=37)

    assert left.tolist() == right.tolist()
    assert len(left) == 120
    assert set(labels[left]) == {"BENIGN", "Attack A", "Attack B"}


def test_training_sample_retains_every_row_of_very_rare_classes() -> None:
    labels = np.array(["BENIGN"] * 10_000 + ["Heartbleed"] * 8 + ["Infiltration"] * 25, dtype=object)
    indices = np.arange(len(labels))
    selected = stratified_training_sample(
        indices,
        labels,
        maximum_rows=5_000,
        random_seed=42,
        retain_all_if_count_at_most=50,
    )

    assert len(selected) == 5_000
    assert int(np.count_nonzero(labels[selected] == "Heartbleed")) == 8
    assert int(np.count_nonzero(labels[selected] == "Infiltration")) == 25


def test_class_scores_align_to_persisted_taxonomy_order() -> None:
    taxonomy = ClassTaxonomy(("BENIGN", "Attack A", "Attack B"))
    scores = align_class_scores(np.array([[0.7, 0.3]]), np.array([2, 0]), taxonomy)

    assert scores.shape == (1, 3)
    assert scores[0].tolist() == pytest.approx([0.3, 0.0, 0.7])


def test_evaluation_reports_overall_classwise_and_confusion_metrics() -> None:
    taxonomy = ClassTaxonomy(("BENIGN", "Attack A", "Attack B"))
    y_true = np.array([0, 0, 1, 1, 2, 2])
    y_pred = np.array([0, 1, 1, 1, 1, 2])
    scores = np.array(
        [
            [0.8, 0.1, 0.1],
            [0.3, 0.6, 0.1],
            [0.2, 0.7, 0.1],
            [0.1, 0.8, 0.1],
            [0.1, 0.6, 0.3],
            [0.1, 0.2, 0.7],
        ]
    )

    result = evaluate_multiclass(y_true, y_pred, taxonomy, scores=scores, partition="validation")

    assert result["metrics"]["partition"] == "validation"
    assert result["metrics"]["accuracy"] == pytest.approx(4 / 6)
    assert result["metrics"]["balanced_accuracy"] == pytest.approx((0.5 + 1.0 + 0.5) / 3)
    assert result["metrics"]["macro_f1"] > 0
    assert result["metrics"]["weighted_f1"] > 0
    assert result["metrics"]["multiclass_roc_auc_ovr_macro"] is not None
    assert result["metrics"]["multiclass_average_precision_macro"] is not None
    assert result["confusion_matrix"][0] == [1, 1, 0]
    assert result["per_class"][0]["false_negative_count"] == 1
    assert {pair["true_label"] for pair in result["frequent_confusion_pairs"]} == {"BENIGN", "Attack B"}


def test_evaluation_marks_unseen_training_and_undefined_metrics() -> None:
    taxonomy = ClassTaxonomy(("BENIGN", "Attack A", "Attack B"))
    result = evaluate_multiclass(
        np.array([0, 1, 2]),
        np.array([0, 1, 1]),
        taxonomy,
        scores=np.array([[0.9, 0.1, 0.0], [0.1, 0.9, 0.0], [0.1, 0.9, 0.0]]),
        learned_class_ids=np.array([0, 1]),
        partition="test",
    )

    assert result["metrics"]["observations_total"] == 3
    assert result["metrics"]["observations_scored"] == 2
    assert result["metrics"]["unseen_training_classes"] == ["Attack B"]
    assert result["per_class"][2]["status"] == "unseen_in_training"
    assert result["per_class"][2]["precision"] is None
    assert result["metrics"]["multiclass_roc_auc_ovr_macro"] is None


def test_evaluation_handles_absent_test_class_and_zero_predictions() -> None:
    taxonomy = ClassTaxonomy(("BENIGN", "Attack A", "Attack B"))
    result = evaluate_multiclass(
        np.array([0, 1, 1]),
        np.array([0, 0, 0]),
        taxonomy,
        scores=None,
        partition="validation",
    )

    assert result["per_class"][0]["precision"] == pytest.approx(1 / 3)
    assert result["per_class"][1]["precision"] is None
    assert result["per_class"][1]["recall"] == 0.0
    assert result["per_class"][2]["status"] == "not_present_in_partition"
    assert result["per_class"][2]["recall"] is None
    assert result["metrics"]["multiclass_average_precision_macro"] is None


def _write_tiny_parquets(directory: Path, contract: FeatureContract, *, groups: int = 6) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    for group_index in range(groups):
        generator = np.random.default_rng(100 + group_index)
        frames = []
        for class_name, center in (("BENIGN", 0.0), ("Attack A", 2.5), ("Attack B", 5.0)):
            values = generator.normal(center, 0.25, size=(24, 2))
            frames.append(
                pd.DataFrame(
                    {
                        "flow_duration": values[:, 0],
                        "packet_count": values[:, 1],
                        "label": class_name,
                        "__source_file": f"capture-{group_index}.csv",
                    }
                )
            )
        data = pd.concat(frames, ignore_index=True)
        data.to_parquet(directory / f"capture-{group_index}.parquet", index=False)


def test_parquet_inventory_and_partition_loader_preserve_alignment(
    tmp_path: Path,
    small_contract: FeatureContract,
) -> None:
    directory = tmp_path / "parquet"
    _write_tiny_parquets(directory, small_contract, groups=3)
    inventory = inspect_parquet_dataset(directory, small_contract)
    indices = np.array([0, 3, 9, 11, 29, 31, 58, 60])

    X, y = collect_partition(inventory.files, indices, small_contract, batch_size=8)

    assert inventory.class_counts == {"BENIGN": 72, "Attack A": 72, "Attack B": 72}
    assert len(inventory.taxonomy.labels) == 3
    assert X.columns.tolist() == list(small_contract.predictive_features)
    assert len(X) == len(y) == len(indices)
    assert set(y) <= set(inventory.taxonomy.labels)


def test_experiment_trains_saves_reloads_and_predicts_on_synthetic_parquet(
    tmp_path: Path,
    small_contract: FeatureContract,
) -> None:
    root = tmp_path / "project"
    config_dir = root / "configs"
    config_dir.mkdir(parents=True)
    schema_path = config_dir / "feature_schema.json"
    schema_path.write_text(
        json.dumps(
            {
                "schema_version": small_contract.schema_version,
                "dataset_name": small_contract.dataset_name,
                "target": {
                    "name": small_contract.target_name,
                    "allowed_values": list(small_contract.target_values),
                },
                "features": [
                    {"name": feature.name, "type": feature.feature_type, "included": feature.included}
                    for feature in small_contract.features
                ],
                "leakage_policy": {
                    "metadata_fields": list(small_contract.metadata_fields),
                    "excluded_fields": list(small_contract.excluded_fields),
                },
            }
        ),
        encoding="utf-8",
    )
    parquet_directory = root / "data" / "parquet"
    _write_tiny_parquets(parquet_directory, small_contract, groups=6)
    (config_dir / "multiclass.toml").write_text(
        """
[dataset]
parquet_directory = "data/parquet"
feature_schema = "configs/feature_schema.json"
[split]
strategy = "group_aware"
train_fraction = 0.5
validation_fraction = 0.25
test_fraction = 0.25
allow_stratified_fallback = true
group_search_attempts = 8
[training]
random_seed = 13
max_training_rows = 500
batch_size = 64
retain_all_class_rows_below = 50
mapping_version = "1.0.0"
[models.logistic_regression]
enabled = true
profile = "linear"
solver = "lbfgs"
regularization_c = 1.0
max_iterations = 100
class_weight = "balanced"
[models.random_forest]
enabled = true
profile = "tree"
estimators = 5
max_depth = 6
min_samples_split = 2
min_samples_leaf = 1
max_features = "sqrt"
class_weight = "balanced_subsample"
n_jobs = 1
[models.xgboost]
enabled = false
reason = "not installed in the test environment"
[artifacts]
directory = "models/supervised/multiclass"
version = "1.0.0"
[reports]
evaluation_directory = "reports/evaluation/multiclass"
figure_directory = "reports/figures/multiclass"
experiment_directory = "reports/experiments/multiclass"
""",
        encoding="utf-8",
    )

    summary = run_multiclass_experiment(config_dir / "multiclass.toml")

    assert summary["rows"] == 6 * 72
    assert summary["classes"] == 3
    assert summary["selected_model"] in {"logistic_regression", "random_forest"}
    assert Path(summary["report"]).is_file()
    assert Path(summary["selected_artifact"]).is_dir()
    with Path(summary["experiment_summary"]).open(encoding="utf-8") as stream:
        experiment = json.load(stream)
    assert experiment["split_audit"]["group_disjoint"] is True
    assert Path(summary["evaluation_directory"], "model_comparison.csv").is_file()
    predictor = MultiClassPredictor(summary["selected_artifact"])
    estimator, preprocessor, taxonomy, metadata = load_model_bundle(summary["selected_artifact"])
    sample = pd.DataFrame({"flow_duration": [0.0, 2.5], "packet_count": [0.0, 2.5]})
    results = predictor.predict(sample)
    assert len(results) == 2
    assert all(result["predicted_label"] in taxonomy.labels for result in results)
    assert all(result["model_id"] == metadata["model_id"] for result in results)

