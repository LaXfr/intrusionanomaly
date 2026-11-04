from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq
import pytest
from sklearn.ensemble import IsolationForest

from intrusion_intelligence.anomaly.artifacts import _resolve_preprocessor_directory, load_anomaly_bundle
from intrusion_intelligence.anomaly.calibration import CalibrationError, calibrate_operating_points
from intrusion_intelligence.anomaly.config import load_anomaly_config
from intrusion_intelligence.anomaly.data import (
    AnomalyDataError,
    capture_day_from_source,
    inspect_anomaly_dataset,
    prepare_anomaly_frame,
    validate_original_labels,
)
from intrusion_intelligence.anomaly.evaluation import (
    AnomalyEvaluationError,
    evaluate_operating_point,
    per_attack_category_summary,
)
from intrusion_intelligence.anomaly.inference import AnomalyInferenceError, AnomalyPredictor
from intrusion_intelligence.anomaly.scoring import AnomalyScoringError, higher_is_more_anomalous
from intrusion_intelligence.anomaly.service import run_anomaly_experiment
from intrusion_intelligence.anomaly.splitting import (
    AnomalySplitError,
    audit_duplicate_feature_overlap,
    make_capture_day_split,
    select_benign_training_sample,
)
from intrusion_intelligence.anomaly.training import AnomalyTrainingError, fit_isolation_forest
from intrusion_intelligence.feature_engineering import FeatureContract
from intrusion_intelligence.errors import ConfigurationError
from intrusion_intelligence.preprocessing import build_preprocessor
from intrusion_intelligence.preprocessing.config import load_preprocessing_config

PROJECT_ROOT = Path(__file__).parents[1]
PREPROCESSING_CONFIG = PROJECT_ROOT / "configs" / "preprocessing.toml"
DAYS = ("Monday", "Tuesday", "Wednesday", "Thursday", "Friday")
ALLOWED_LABELS = ("BENIGN", "Attack A", "Attack B")


@pytest.fixture
def small_contract() -> FeatureContract:
    return FeatureContract.from_dict(
        {
            "schema_version": "test-1.0",
            "dataset_name": "synthetic-anomaly-fixture",
            "target": {"name": "label", "allowed_values": list(ALLOWED_LABELS)},
            "features": [
                {"name": "flow_duration", "type": "numeric", "included": True},
                {"name": "packet_count", "type": "numeric", "included": True},
            ],
            "leakage_policy": {
                "metadata_fields": ["__source_file", "__source_row_number", "__record_id"],
                "excluded_fields": ["flow_id", "timestamp"],
            },
        }
    )


def write_synthetic_capture_files(
    root: Path,
    *,
    small_contract: FeatureContract,
    benign_rows: int = 40,
    attack_rows: int = 4,
    repeated_vector_between_days: bool = False,
) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    rng = np.random.default_rng(123)
    for day_index, day in enumerate(DAYS):
        source = f"extracted/MachineLearningCVE/{day}-synthetic-capture.csv"
        benign = rng.normal(loc=day_index * 0.05, scale=1.0, size=(benign_rows, 2))
        if repeated_vector_between_days:
            benign[0] = [0.25, 0.75]
        attacks = np.column_stack(
            [rng.normal(loc=4.0 + day_index * 0.1, scale=0.5, size=attack_rows), rng.normal(loc=3.0, scale=0.5, size=attack_rows)]
        )
        labels = ["BENIGN"] * benign_rows + (["Attack A"] * attack_rows if day in {"Monday", "Friday"} else ["Attack B"] * attack_rows)
        features = np.vstack([benign, attacks])
        frame = pd.DataFrame(
            {
                "flow_duration": features[:, 0],
                "packet_count": features[:, 1],
                "label": labels,
                "__source_file": source,
                "__source_row_number": np.arange(1, len(labels) + 1, dtype=np.int64),
                "__record_id": [f"{day}-{index}" for index in range(len(labels))],
            }
        )
        pq.write_table(pa.Table.from_pandas(frame, preserve_index=False), root / f"{day}-synthetic-capture.parquet")
    return root


def test_original_label_validation_rejects_missing_blank_unknown_and_nonexact_benign() -> None:
    assert validate_original_labels(["BENIGN", "Attack A"], ALLOWED_LABELS).tolist() == ["BENIGN", "Attack A"]
    with pytest.raises(AnomalyDataError, match="Missing"):
        validate_original_labels(["BENIGN", None], ALLOWED_LABELS)
    with pytest.raises(AnomalyDataError, match="Blank"):
        validate_original_labels(["BENIGN", "  "], ALLOWED_LABELS)
    with pytest.raises(AnomalyDataError, match="Unexpected"):
        validate_original_labels(["BENIGN", "unknown"], ALLOWED_LABELS)
    with pytest.raises(AnomalyDataError, match="Unexpected"):
        validate_original_labels([" benign"], ALLOWED_LABELS, require_benign_present=True)
    with pytest.raises(AnomalyDataError, match="exact benign label"):
        validate_original_labels(["Attack A"], ALLOWED_LABELS, require_benign_present=True)
    with pytest.raises(AnomalyDataError, match="benign label.*absent from the feature contract"):
        validate_original_labels(["Attack A"], ["Attack A"])


def test_capture_day_parser_uses_source_provenance_and_rejects_unknown_day() -> None:
    assert capture_day_from_source(r"extracted\MachineLearningCVE\Thursday-WorkingHours-WebAttacks.csv") == "Thursday"
    with pytest.raises(AnomalyDataError, match="Cannot determine"):
        capture_day_from_source("unknown-capture.csv")


def test_feature_target_metadata_separation_excludes_target_from_x(small_contract: FeatureContract) -> None:
    frame = pd.DataFrame(
        {
            "flow_duration": [1.0, 2.0],
            "packet_count": [3.0, 4.0],
            "label": ["BENIGN", "Attack A"],
            "__source_file": ["Monday.csv", "Friday.csv"],
            "__source_row_number": [1, 2],
            "__record_id": ["r1", "r2"],
        }
    )
    X, y, metadata, benign_mask = prepare_anomaly_frame(frame, small_contract)
    assert list(X.columns) == list(small_contract.predictive_features)
    assert "label" not in X
    assert y.tolist() == ["BENIGN", "Attack A"]
    assert set(metadata.columns) == set(small_contract.metadata_fields)
    assert benign_mask.tolist() == [True, False]
    with pytest.raises(AnomalyDataError, match="feature contract"):
        prepare_anomaly_frame(frame.assign(surprise=1), small_contract)


def test_inventory_validates_parquet_schema_labels_and_benign_count(tmp_path: Path, small_contract: FeatureContract) -> None:
    root = write_synthetic_capture_files(tmp_path / "data", small_contract=small_contract)
    inventory = inspect_anomaly_dataset(root, small_contract)
    assert len(inventory.labels) == 5 * 44
    assert inventory.benign_count == 200
    assert inventory.attack_count == 20
    assert inventory.feature_names == small_contract.predictive_features
    assert inventory.class_counts["Attack A"] == 8
    assert inventory.preparation_report()["labels_missing"] == 0
    assert len(inventory.capture_days) == 5


def test_inventory_rejects_missing_benign_unknown_label_and_schema_mismatch(
    tmp_path: Path, small_contract: FeatureContract
) -> None:
    root = write_synthetic_capture_files(tmp_path / "no-benign", small_contract=small_contract)
    for path in root.glob("*.parquet"):
        frame = pq.read_table(path).to_pandas()
        frame["label"] = "Attack A"
        pq.write_table(pa.Table.from_pandas(frame, preserve_index=False), path)
    with pytest.raises(AnomalyDataError, match="BENIGN"):
        inspect_anomaly_dataset(root, small_contract)

    root = write_synthetic_capture_files(tmp_path / "unknown", small_contract=small_contract)
    path = root / "Monday-synthetic-capture.parquet"
    frame = pq.read_table(path).to_pandas()
    frame.loc[0, "label"] = "UNREVIEWED"
    pq.write_table(pa.Table.from_pandas(frame, preserve_index=False), path)
    with pytest.raises(AnomalyDataError, match="Unexpected"):
        inspect_anomaly_dataset(root, small_contract)

    root = write_synthetic_capture_files(tmp_path / "schema", small_contract=small_contract)
    path = root / "Tuesday-synthetic-capture.parquet"
    frame = pq.read_table(path).to_pandas().drop(columns="packet_count")
    pq.write_table(pa.Table.from_pandas(frame, preserve_index=False), path)
    with pytest.raises(AnomalyDataError, match="schema differs"):
        inspect_anomaly_dataset(root, small_contract)


def test_capture_day_split_is_disjoint_without_row_fallback(tmp_path: Path, small_contract: FeatureContract) -> None:
    root = write_synthetic_capture_files(tmp_path / "data", small_contract=small_contract)
    inventory = inspect_anomaly_dataset(root, small_contract)
    split_config = {
        "train_days": ["Monday", "Tuesday", "Wednesday"],
        "validation_days": ["Thursday"],
        "test_days": ["Friday"],
        "random_seed": 7,
    }
    split = make_capture_day_split(inventory, split_config)
    assert split.audit["strategy"] == "capture_day_holdout"
    assert split.audit["capture_day_groups_disjoint"] is True
    assert split.audit["source_files_disjoint"] is True
    assert split.audit["row_level_fallback_used"] is False
    assert len(split.train) + len(split.validation) + len(split.test) == len(inventory.labels)
    assert split.audit["total_benign_training_rows"] == 120
    assert split.audit["total_benign_validation_rows"] == 40
    assert split.audit["malicious_test_rows"] == 4


def test_capture_day_split_rejects_overlap_missing_groups_and_benignless_partitions(
    tmp_path: Path, small_contract: FeatureContract
) -> None:
    inventory = inspect_anomaly_dataset(write_synthetic_capture_files(tmp_path / "data", small_contract=small_contract), small_contract)
    with pytest.raises(AnomalySplitError, match="multiple partitions"):
        make_capture_day_split(inventory, {"train_days": ["Monday"], "validation_days": ["Monday"], "test_days": ["Friday", "Tuesday", "Wednesday", "Thursday"]})
    with pytest.raises(AnomalySplitError, match="missing"):
        make_capture_day_split(inventory, {"train_days": ["Monday"], "validation_days": ["Thursday"], "test_days": ["Friday"]})
    root = write_synthetic_capture_files(tmp_path / "benignless-test", small_contract=small_contract)
    friday = root / "Friday-synthetic-capture.parquet"
    frame = pq.read_table(friday).to_pandas()
    frame["label"] = "Attack A"
    pq.write_table(pa.Table.from_pandas(frame, preserve_index=False), friday)
    inventory = inspect_anomaly_dataset(root, small_contract)
    with pytest.raises(AnomalySplitError, match="test partition must contain benign"):
        make_capture_day_split(
            inventory,
            {"train_days": ["Monday", "Tuesday", "Wednesday"], "validation_days": ["Thursday"], "test_days": ["Friday"]},
        )


def test_benign_training_sample_is_reproducible_and_excludes_attacks() -> None:
    labels = np.array(["BENIGN"] * 100 + ["Attack A"] * 15, dtype=object)
    indices = np.arange(len(labels))
    first = select_benign_training_sample(indices, labels, maximum_rows=35, random_seed=77)
    second = select_benign_training_sample(indices, labels, maximum_rows=35, random_seed=77)
    assert np.array_equal(first, second)
    assert len(first) == 35
    assert np.all(labels[first] == "BENIGN")
    with pytest.raises(AnomalySplitError, match="no benign"):
        select_benign_training_sample(np.arange(100, 115), labels, maximum_rows=10, random_seed=1)


def test_duplicate_feature_audit_detects_cross_partition_duplicate_groups(
    tmp_path: Path, small_contract: FeatureContract
) -> None:
    root = write_synthetic_capture_files(
        tmp_path / "data", small_contract=small_contract, repeated_vector_between_days=True
    )
    inventory = inspect_anomaly_dataset(root, small_contract)
    split = make_capture_day_split(
        inventory,
        {"train_days": ["Monday", "Tuesday", "Wednesday"], "validation_days": ["Thursday"], "test_days": ["Friday"]},
    )
    audit = audit_duplicate_feature_overlap(inventory, small_contract, split.day_to_partition, batch_size=17)
    assert audit["rows_hashed"] == len(inventory.labels)
    assert audit["repeated_feature_vector_groups_crossing_partitions"] >= 1
    assert audit["duplicate_groups_disjoint"] is False
    assert audit["joint_capture_day_and_duplicate_disjoint_three_way_split_possible"] is False


def test_preprocessing_fit_is_train_only_and_transform_does_not_refit(small_contract: FeatureContract) -> None:
    config = load_preprocessing_config(PREPROCESSING_CONFIG)
    preprocessor = build_preprocessor("anomaly", contract=small_contract, config=config)
    X_train = pd.DataFrame({"flow_duration": [0.0, 1.0, 2.0, 3.0], "packet_count": [1.0, 1.0, 2.0, 3.0]})
    before = {"numeric_imputation": preprocessor.numeric_imputation_statistics} if preprocessor.is_fitted_ else None
    preprocessor.fit(X_train)
    fitted_stats = preprocessor.preprocessing_metadata()
    transformed = preprocessor.transform(pd.DataFrame({"flow_duration": [4.0], "packet_count": [5.0]}))
    assert transformed.shape == (1, 2)
    assert preprocessor.preprocessing_metadata() == fitted_stats
    with pytest.raises(ValueError, match="Target or metadata"):
        preprocessor.transform(X_train.assign(label="BENIGN"))
    assert before is None


def test_isolation_forest_fit_accepts_only_features_and_checks_input() -> None:
    rng = np.random.default_rng(4)
    X = rng.normal(size=(40, 3))
    model, config, duration = fit_isolation_forest(
        X,
        {"n_estimators": 10, "max_samples": 50, "max_features": 1.0, "contamination": "auto", "bootstrap": False, "random_state": 5, "n_jobs": 1},
    )
    assert isinstance(model, IsolationForest)
    assert config["max_samples_effective"] == 40
    assert config["max_samples_requested"] == 50
    assert duration >= 0
    with pytest.raises(TypeError):
        fit_isolation_forest(X, {}, y=np.zeros(len(X)))  # type: ignore[call-arg]
    with pytest.raises(AnomalyTrainingError, match="at least two"):
        fit_isolation_forest(X[:1], {})
    with pytest.raises(AnomalyTrainingError, match="finite"):
        fit_isolation_forest(np.array([[np.inf], [0.0]]), {})


def test_score_orientation_inverts_inlier_oriented_raw_scores() -> None:
    class FakeEstimator:
        def score_samples(self, X: np.ndarray) -> np.ndarray:
            return np.array([0.2, -0.8])

    raw, anomaly = higher_is_more_anomalous(FakeEstimator(), np.ones((2, 1)))
    assert raw.tolist() == [0.2, -0.8]
    assert anomaly.tolist() == [-0.2, 0.8]
    with pytest.raises(AnomalyScoringError, match="NaN or infinity"):
        higher_is_more_anomalous(FakeEstimator(), np.array([[np.nan], [0.0]]))
    with pytest.raises(AnomalyScoringError, match="score_samples"):
        higher_is_more_anomalous(object(), np.ones((2, 1)))


def test_anomaly_preprocessor_reference_resolves_after_project_relocation(tmp_path: Path) -> None:
    artifact = tmp_path / "models" / "unsupervised" / "isolation_forest" / "1.0.0"
    expected = tmp_path / "models" / "unsupervised" / "preprocessing" / "anomaly" / "1.0.0"
    artifact.mkdir(parents=True)
    expected.mkdir(parents=True)
    relative = Path("models/unsupervised/preprocessing/anomaly/1.0.0")
    assert _resolve_preprocessor_directory(relative, artifact) == expected


def test_threshold_calibration_uses_upper_empirical_quantile_and_reports_ties() -> None:
    scores = np.array([0.0, 1.0, 1.0, 1.0, 2.0, 2.0, 3.0, 3.0])
    calibration = calibrate_operating_points(
        scores,
        [{"id": "fpr-25", "target_fpr": 0.25}],
    )
    point = calibration["operating_points"]["fpr-25"]
    assert point["threshold"] == 3.0
    assert point["achieved_validation_fpr"] == 0.0
    assert point["threshold_tie_observations"] == 2
    assert calibration["labels_used_for_threshold_selection"] is False
    assert point["comparison"].startswith("anomalous if anomaly_score >")
    assert point["empirical_fpr_resolution"] == pytest.approx(1 / 8)


def test_threshold_calibration_rejects_invalid_small_and_nonfinite_inputs() -> None:
    with pytest.raises(CalibrationError, match="At least"):
        calibrate_operating_points([0.1], [{"id": "x", "target_fpr": 0.1}])
    with pytest.raises(CalibrationError, match="finite"):
        calibrate_operating_points([0.1, np.inf], [{"id": "x", "target_fpr": 0.1}])
    with pytest.raises(CalibrationError, match="valid"):
        calibrate_operating_points(np.arange(20), [{"id": "x", "target_fpr": 1.0}])
    with pytest.raises(CalibrationError, match="unique"):
        calibrate_operating_points(np.arange(20), [{"id": "x", "target_fpr": 0.1}, {"id": "x2", "target_fpr": 0.1}])


def test_evaluation_metrics_and_per_attack_category_include_unseen_classes() -> None:
    labels = np.array(["BENIGN", "BENIGN", "Attack A", "Attack A", "Attack B"])
    scores = np.array([0.1, 0.8, 0.9, 0.2, 0.7])
    metric = evaluate_operating_point(labels, scores, 0.5, allowed_labels=ALLOWED_LABELS)
    assert metric["true_negative"] == 1
    assert metric["false_positive"] == 1
    assert metric["false_negative"] == 1
    assert metric["true_positive"] == 2
    assert metric["attack_recall"] == pytest.approx(2 / 3)
    assert metric["specificity"] == pytest.approx(0.5)
    assert metric["roc_auc"] is not None
    rows = per_attack_category_summary(labels, scores, 0.5, allowed_labels=ALLOWED_LABELS)
    assert [row["original_label"] for row in rows] == ["Attack A", "Attack B"]
    with pytest.raises(AnomalyEvaluationError, match="equal one-dimensional"):
        evaluate_operating_point(labels, scores[:-1], 0.5, allowed_labels=ALLOWED_LABELS)


def test_single_class_evaluation_marks_undefined_metrics() -> None:
    metric = evaluate_operating_point(["BENIGN"] * 4, [0.0, 0.1, 0.2, 0.3], 0.2, allowed_labels=ALLOWED_LABELS)
    assert metric["roc_auc"] is None
    assert metric["attack_recall"] is None
    assert metric["undefined_metric_status"]["roc_auc"].startswith("undefined")


def _write_test_configuration(tmp_path: Path, small_contract: FeatureContract) -> Path:
    project_root = tmp_path
    (project_root / "configs").mkdir(parents=True)
    schema_document = {
        "schema_version": small_contract.schema_version,
        "dataset_name": small_contract.dataset_name,
        "target": {"name": small_contract.target_name, "allowed_values": list(small_contract.target_values)},
        "features": [
            {"name": feature.name, "type": feature.feature_type, "role": "predictive", "included": True}
            for feature in small_contract.features
        ],
        "leakage_policy": {
            "metadata_fields": list(small_contract.metadata_fields),
            "excluded_fields": list(small_contract.excluded_fields),
        },
    }
    (project_root / "configs" / "feature_schema.json").write_text(json.dumps(schema_document), encoding="utf-8")
    data_root = write_synthetic_capture_files(project_root / "data", small_contract=small_contract)
    preprocessing_path = PREPROCESSING_CONFIG.as_posix()
    text = f'''version = "1.0"
random_seed = 42
[dataset]
parquet_directory = "data"
feature_schema = "configs/feature_schema.json"
preprocessing_config = "{preprocessing_path}"
benign_label = "BENIGN"
[split]
strategy = "capture_day_holdout"
train_days = ["Monday", "Tuesday", "Wednesday"]
validation_days = ["Thursday"]
test_days = ["Friday"]
random_seed = 42
[training]
max_benign_training_rows = 50
batch_size = 64
minimum_benign_training_rows = 10
minimum_benign_validation_rows = 10
[model.isolation_forest]
n_estimators = 10
max_samples = 16
max_features = 1.0
contamination = "auto"
bootstrap = false
random_state = 42
n_jobs = 1
[calibration]
quantile_method = "higher"
default_operating_point = "target-fpr-10pct"
operating_points = [
  {{ id = "target-fpr-10pct", target_fpr = 0.10 }},
  {{ id = "target-fpr-20pct", target_fpr = 0.20 }},
]
[artifacts]
model_directory = "models/unsupervised/isolation_forest"
preprocessor_directory = "models/unsupervised/preprocessing"
model_version = "1.0.0"
preprocessor_version = "1.0.0"
[reports]
evaluation_directory = "reports/evaluation/anomaly_detection"
figure_directory = "reports/figures/anomaly_detection"
experiment_directory = "reports/experiments/anomaly_detection"
error_feature_sample_rows = 50
'''
    config_path = project_root / "configs" / "anomaly_detection.toml"
    config_path.write_text(text, encoding="utf-8")
    assert data_root.exists()
    return config_path


def test_config_resolves_paths_and_rejects_row_fallback(tmp_path: Path, small_contract: FeatureContract) -> None:
    path = _write_test_configuration(tmp_path, small_contract)
    config = load_anomaly_config(path)
    assert config["split"]["strategy"] == "capture_day_holdout"
    assert config["dataset"]["benign_label"] == "BENIGN"
    text = path.read_text(encoding="utf-8").replace('strategy = "capture_day_holdout"', 'strategy = "stratified_row"')
    path.write_text(text, encoding="utf-8")
    with pytest.raises(ConfigurationError, match="row fallback is prohibited"):
        load_anomaly_config(path)


def test_real_synthetic_run_calibrates_on_benign_only_saves_and_reloads_predictor(
    tmp_path: Path, small_contract: FeatureContract
) -> None:
    config_path = _write_test_configuration(tmp_path, small_contract)
    summary = run_anomaly_experiment(config_path)
    assert summary["experiment_status"] == "completed"
    assert summary["benign_training_rows"] == 120
    assert summary["training_sample_rows"] == 50
    assert summary["benign_validation_rows"] == 40
    assert summary["test_benign_rows"] == 40
    assert summary["test_attack_rows"] == 4
    calibration = summary["calibration"]
    assert calibration["labels_used_for_threshold_selection"] is False
    assert calibration["calibration_population"] == "BENIGN validation observations only"
    assert set(calibration["operating_points"]) == {"target-fpr-10pct", "target-fpr-20pct"}
    assert summary["prediction_interface_smoke"]["status"] == "passed"
    model_path = Path(summary["artifacts"]["model"])
    estimator, preprocessor, metadata, reloaded_calibration = load_anomaly_bundle(model_path)
    assert isinstance(estimator, IsolationForest)
    assert preprocessor.profile == "anomaly"
    assert metadata["training_population"]["fit_population"] == "BENIGN only"
    assert reloaded_calibration["labels_used_for_threshold_selection"] is False
    predictor = AnomalyPredictor(model_path)
    X = pd.DataFrame({"flow_duration": [0.1, 5.0], "packet_count": [0.2, 3.0]})
    result = predictor.predict(X)
    assert set(result["decision"]) <= {"NORMAL", "ANOMALOUS"}
    assert result["model_id"].nunique() == 1
    with pytest.raises(AnomalyInferenceError, match="Unknown calibrated operating point"):
        predictor.predict(X, operating_point="attacker-picked")
    with pytest.raises(AnomalyInferenceError, match="Unable to score"):
        predictor.predict(X.assign(label="BENIGN"))
    report_path = Path(summary["outputs"]["report"])
    assert report_path.exists()
    assert "Repeated feature vectors cross the capture-day partitions" in report_path.read_text(encoding="utf-8")
