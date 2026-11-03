"""Synthetic tests for feature contracts and leakage-safe preprocessing."""

from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import pandas as pd
import pytest
from scipy import sparse

from intrusion_intelligence.feature_engineering import (
    DERIVED_FEATURES,
    FeatureContract,
    FeatureSchemaError,
    FlowFeatureEngineer,
    separate_features_target_metadata,
    validate_feature_matrix,
)
from intrusion_intelligence.preprocessing.artifacts import (
    load_preprocessor,
    save_preprocessor,
)
from intrusion_intelligence.preprocessing.class_imbalance import training_class_distribution
from intrusion_intelligence.preprocessing.config import load_preprocessing_config
from intrusion_intelligence.preprocessing.pipeline import (
    PreprocessingError,
    build_preprocessor,
)
from intrusion_intelligence.preprocessing.storage import save_transformed_matrix

PROJECT_ROOT = Path(__file__).parents[1]


@pytest.fixture
def contract() -> FeatureContract:
    return FeatureContract.from_dict(
        {
            "schema_version": "test-1.0",
            "dataset_name": "synthetic-network-flows",
            "target": {"name": "label", "allowed_values": ["BENIGN", "ATTACK"]},
            "features": [
                {"name": "flow_duration", "type": "numeric", "role": "predictive", "included": True},
                {"name": "destination_port", "type": "numeric", "role": "predictive", "included": True},
                {"name": "protocol", "type": "categorical", "role": "predictive", "included": True},
            ],
            "leakage_policy": {
                "metadata_fields": ["__source_file", "__source_row_number", "__record_id"],
                "excluded_fields": ["flow_id", "source_ip", "destination_ip", "timestamp", "__processing_id"],
            },
        }
    )


@pytest.fixture
def sample_X() -> pd.DataFrame:
    return pd.DataFrame(
        {
            "flow_duration": [0.0, 2.0, np.nan, 4.0, 8.0],
            "destination_port": [80.0, 443.0, 53.0, 80.0, 8080.0],
            "protocol": [6, 17, np.nan, 6, 17],
        },
        index=[10, 11, 12, 13, 14],
    )


def test_real_feature_schema_matches_phase04_dataset() -> None:
    contract = FeatureContract.from_file(PROJECT_ROOT / "configs" / "feature_schema.json")

    assert contract.dataset_name == "CIC-IDS2017"
    assert len(contract.predictive_features) == 78
    assert len(contract.numeric_features) == 78
    assert contract.categorical_features == ()
    assert contract.target_name == "label"
    assert "destination_port" in contract.predictive_features
    assert contract.target_name not in contract.predictive_features
    assert {"__source_file", "__source_row_number", "__record_id"}.issubset(
        contract.metadata_fields
    )
    assert all(feature.source_column for feature in contract.features)


def test_separate_features_target_and_metadata_preserves_alignment(
    contract: FeatureContract,
) -> None:
    frame = pd.DataFrame(
        {
            "flow_duration": [1.0, 2.0],
            "destination_port": [80.0, 443.0],
            "protocol": [6, 17],
            "label": ["BENIGN", "ATTACK"],
            "__source_file": ["monday.csv", "tuesday.csv"],
            "__source_row_number": [2, 8],
            "__record_id": ["r1", "r2"],
        },
        index=[20, 21],
    )

    X, y, metadata = separate_features_target_metadata(frame, contract)

    assert list(X.columns) == list(contract.predictive_features)
    assert list(y) == ["BENIGN", "ATTACK"]
    assert list(metadata["__record_id"]) == ["r1", "r2"]
    assert X.index.equals(y.index) and X.index.equals(metadata.index)
    assert "label" not in X and "__source_file" not in X


def test_feature_validation_rejects_missing_extra_duplicate_order_and_leakage(
    contract: FeatureContract,
    sample_X: pd.DataFrame,
) -> None:
    with pytest.raises(FeatureSchemaError, match="missing required"):
        validate_feature_matrix(sample_X.drop(columns="destination_port"), contract)
    with pytest.raises(FeatureSchemaError, match="Unexpected feature"):
        validate_feature_matrix(sample_X.assign(unreviewed=1), contract)
    duplicated = pd.concat([sample_X, sample_X[["protocol"]]], axis=1)
    with pytest.raises(FeatureSchemaError, match="Duplicate feature"):
        validate_feature_matrix(duplicated, contract)
    with pytest.raises(FeatureSchemaError, match="out of contract order"):
        validate_feature_matrix(sample_X[["protocol", "flow_duration", "destination_port"]], contract)
    with pytest.raises(FeatureSchemaError, match="Target or metadata"):
        validate_feature_matrix(sample_X.assign(label="BENIGN"), contract)


def test_optional_feature_may_be_missing_only_at_inference(contract: FeatureContract) -> None:
    optional_contract = FeatureContract.from_dict(
        {
            "schema_version": "optional-1.0",
            "dataset_name": "test",
            "target": {"name": "label", "allowed_values": ["BENIGN"]},
            "features": [
                {"name": "flow_duration", "type": "numeric", "included": True},
                {"name": "destination_port", "type": "numeric", "included": True, "optional": True},
            ],
            "leakage_policy": {"metadata_fields": [], "excluded_fields": []},
        }
    )
    train = pd.DataFrame({"flow_duration": [1.0, 2.0], "destination_port": [80.0, 443.0]})
    processor = build_preprocessor("tree", contract=optional_contract).fit(train)
    inference = processor.transform(pd.DataFrame({"flow_duration": [3.0]}))

    assert inference.shape[1] == len(processor.get_feature_names_out()) == 2
    with pytest.raises(PreprocessingError, match="missing required"):
        build_preprocessor("tree", contract=contract).fit(
            pd.DataFrame({"flow_duration": [1.0], "destination_port": [80.0]})
        )


def test_invalid_numeric_and_infinite_values_are_rejected(
    contract: FeatureContract,
    sample_X: pd.DataFrame,
) -> None:
    invalid = sample_X.copy()
    invalid["flow_duration"] = ["bad", "2", "3", "4", "5"]
    with pytest.raises(FeatureSchemaError, match="must have a numeric dtype"):
        validate_feature_matrix(invalid, contract)
    infinite = sample_X.copy()
    infinite.loc[10, "flow_duration"] = np.inf
    with pytest.raises(FeatureSchemaError, match="contains infinity"):
        validate_feature_matrix(infinite, contract)


def test_numeric_categorical_protocol_imputes_and_one_hot_encodes_unknown_values(
    contract: FeatureContract,
    sample_X: pd.DataFrame,
) -> None:
    processor = build_preprocessor("tree", contract=contract).fit(sample_X)
    transformed = processor.transform(
        pd.DataFrame({"flow_duration": [100.0], "destination_port": [53.0], "protocol": [99]})
    )

    assert sparse.issparse(transformed)
    assert transformed.shape[1] == len(processor.get_feature_names_out())
    assert any("protocol_6" in name for name in processor.get_feature_names_out())
    names = processor.get_feature_names_out().tolist()
    protocol_columns = [index for index, name in enumerate(names) if "protocol_" in name]
    assert transformed[:, protocol_columns].nnz == 0
    assert any("__MISSING__" in name for name in names)


def test_derived_flow_features_are_deterministic_and_handle_missing_and_zero(
    sample_X: pd.DataFrame,
) -> None:
    source = pd.DataFrame(
        {
            "total_fwd_packets": [2.0, 0.0, np.nan, 1.0],
            "total_backward_packets": [3.0, 0.0, 4.0, 1.0],
            "total_length_of_fwd_packets": [10.0, 0.0, 3.0, np.nan],
            "total_length_of_bwd_packets": [30.0, 0.0, 7.0, 1.0],
        }
    )
    selected = tuple(DERIVED_FEATURES)
    engineer = FlowFeatureEngineer(selected)
    first = engineer.fit_transform(source)
    second = engineer.transform(source)

    assert first.equals(second)
    assert first["total_packets"].tolist()[:2] == [5.0, 0.0]
    assert first["total_bytes"].iloc[0] == 40.0
    assert first["forward_packet_proportion"].iloc[0] == pytest.approx(0.4)
    assert np.isnan(first["forward_packet_proportion"].iloc[1])
    assert np.isnan(first["forward_packet_proportion"].iloc[2])
    assert np.isnan(first["total_packets"].iloc[2])
    assert np.isnan(first["forward_byte_proportion"].iloc[3])
    assert "label" not in first and not any(name.startswith("__") for name in first.columns)
    with pytest.raises(ValueError, match="missing sources"):
        FlowFeatureEngineer(("total_packets",)).fit(pd.DataFrame({"total_fwd_packets": [1]}))
    overflow = pd.DataFrame(
        {"total_fwd_packets": [np.finfo(float).max], "total_backward_packets": [np.finfo(float).max]}
    )
    assert np.isnan(FlowFeatureEngineer(("total_packets",)).fit_transform(overflow)["total_packets"].iloc[0])


def test_profiles_fit_only_on_training_and_keep_independent_statistics(
    contract: FeatureContract,
    sample_X: pd.DataFrame,
) -> None:
    linear = build_preprocessor("linear", contract=contract).fit(sample_X)
    robust = build_preprocessor("anomaly", contract=contract).fit(sample_X)
    tree = build_preprocessor("tree", contract=contract).fit(sample_X)
    medians_before = linear.numeric_imputation_statistics.copy()
    scaling_before = linear.scaling_statistics()
    categories_before = [categories.tolist() for categories in linear.pipeline_.named_steps["transform"].named_transformers_["categorical"].named_steps["encoder"].categories_]
    heldout = pd.DataFrame(
        {"flow_duration": [10000.0], "destination_port": [65000.0], "protocol": [99]},
        index=[90],
    )
    linear.transform(heldout)
    batch_outputs = list(linear.transform_batches([heldout, heldout]))

    assert medians_before["flow_duration"] == 3.0
    assert linear.numeric_imputation_statistics == medians_before
    assert linear.scaling_statistics() == scaling_before
    assert categories_before == [categories.tolist() for categories in linear.pipeline_.named_steps["transform"].named_transformers_["categorical"].named_steps["encoder"].categories_]
    assert len(batch_outputs) == 2 and all(
        output.shape == (1, len(linear.get_feature_names_out()))
        for output in batch_outputs
    )
    assert linear.preprocessing_metadata()["scaling_strategy"] == "standard"
    assert robust.preprocessing_metadata()["scaling_strategy"] == "robust"
    assert tree.preprocessing_metadata()["scaling_strategy"] == "none"
    assert linear.scaling_statistics() != robust.scaling_statistics()
    assert tree.scaling_statistics() == {}
    assert linear.pipeline_ is not robust.pipeline_
    assert linear.transform(heldout).shape[1] == robust.transform(heldout).shape[1]


def test_entirely_missing_numeric_training_column_fails_explicitly(
    contract: FeatureContract,
    sample_X: pd.DataFrame,
) -> None:
    train = pd.DataFrame(
        {
            "flow_duration": [np.nan, np.nan],
            "destination_port": [80.0, 443.0],
            "protocol": [6, 17],
        }
    )

    with pytest.raises(PreprocessingError, match="entirely missing"):
        build_preprocessor("linear", contract=contract).fit(train)

    all_missing_category = sample_X.copy()
    all_missing_category["protocol"] = np.nan
    constant_category = build_preprocessor("tree", contract=contract).fit(all_missing_category)
    assert any("__MISSING__" in name for name in constant_category.get_feature_names_out())

    mode_config = load_preprocessing_config()
    mode_config["imputation"]["categorical_strategy"] = "most_frequent"
    with pytest.raises(PreprocessingError, match="Categorical training features are entirely missing"):
        build_preprocessor("tree", contract=contract, config=mode_config).fit(all_missing_category)


def test_missing_indicators_are_configurable_and_fit_rejects_target_labels(
    contract: FeatureContract,
    sample_X: pd.DataFrame,
) -> None:
    config = load_preprocessing_config()
    config["imputation"]["add_numeric_indicators"] = True
    processor = build_preprocessor("linear", contract=contract, config=config)

    with pytest.raises(PreprocessingError, match="keep target labels separate"):
        processor.fit(sample_X, y=pd.Series(["BENIGN"] * len(sample_X)))
    processor.fit(sample_X)

    assert any("missingindicator" in name for name in processor.get_feature_names_out())
    assert config["feature_selection"]["enabled"] is False


def test_train_only_variance_selection_records_selected_and_removed_features(
    sample_X: pd.DataFrame,
) -> None:
    contract = FeatureContract.from_dict(
        {
            "schema_version": "selection-1.0",
            "dataset_name": "test",
            "target": {"name": "label"},
            "features": [
                {"name": "varying", "type": "numeric", "included": True},
                {"name": "constant", "type": "numeric", "included": True},
            ],
            "leakage_policy": {"metadata_fields": [], "excluded_fields": []},
        }
    )
    train = pd.DataFrame({"varying": [1.0, 2.0, 3.0], "constant": [7.0, 7.0, 7.0]})
    processor = build_preprocessor("tree", contract=contract, feature_selection=True).fit(train)
    metadata_before = processor.selection_metadata()
    heldout = pd.DataFrame({"varying": [100.0, 200.0], "constant": [900.0, 900.0]})
    transformed = processor.transform(heldout)

    assert transformed.shape == (2, 1)
    assert metadata_before["enabled"] is True
    assert metadata_before["selected"] == ["numeric__varying"]
    assert metadata_before["excluded"] == ["numeric__constant"]
    assert processor.selection_metadata() == metadata_before


def test_preprocessor_artifact_round_trip_and_schema_mismatch(
    contract: FeatureContract,
    sample_X: pd.DataFrame,
    tmp_path: Path,
) -> None:
    processor = build_preprocessor("linear", contract=contract).fit(sample_X)
    artifact = save_preprocessor(processor, tmp_path / "artifacts", version="1.2.0")
    metadata = json.loads((artifact / "metadata.json").read_text(encoding="utf-8"))
    loaded = load_preprocessor(artifact)
    inference = sample_X.iloc[[0, 1]].copy()

    assert artifact.name == "1.2.0"
    assert metadata["artifact_name"] == "linear-preprocessor"
    assert metadata["training_schema_fingerprint"] == contract.fingerprint(
        metadata["training_dtypes"]
    )
    assert metadata["output_feature_names"] == loaded.get_feature_names_out().tolist()
    assert np.allclose(processor.transform(inference).toarray(), loaded.transform(inference).toarray())
    assert "Do not store this row" not in json.dumps(metadata)
    with pytest.raises(FileExistsError):
        save_preprocessor(processor, tmp_path / "artifacts", version="1.2.0")
    with pytest.raises(PreprocessingError, match="missing required"):
        loaded.transform(inference.drop(columns="destination_port"))


def test_sparse_and_dense_transformed_storage_preserve_row_alignment(
    contract: FeatureContract,
    sample_X: pd.DataFrame,
    tmp_path: Path,
) -> None:
    processor = build_preprocessor("tree", contract=contract).fit(sample_X)
    transformed = processor.transform(sample_X, mode="training")
    y = pd.Series(["BENIGN", "ATTACK", "BENIGN", "ATTACK", "BENIGN"], index=sample_X.index)
    metadata = pd.DataFrame({"__record_id": [f"r{i}" for i in range(5)]}, index=sample_X.index)
    saved = save_transformed_matrix(
        transformed,
        y,
        metadata,
        processor.get_feature_names_out().tolist(),
        tmp_path / "transformed",
    )
    manifest = json.loads((saved / "manifest.json").read_text(encoding="utf-8"))
    rows = pd.read_parquet(saved / manifest["row_metadata_file"])
    loaded = sparse.load_npz(saved / manifest["matrix_file"])

    assert manifest["representation"] == "scipy_sparse_npz"
    assert loaded.shape == transformed.shape
    assert rows["label"].tolist() == y.tolist()
    assert rows["__record_id"].tolist() == metadata["__record_id"].tolist()
    with pytest.raises(FileExistsError):
        save_transformed_matrix(
            transformed,
            y,
            metadata,
            processor.get_feature_names_out().tolist(),
            saved,
        )
    dense_saved = save_transformed_matrix(
        transformed.toarray(),
        y,
        metadata,
        processor.get_feature_names_out().tolist(),
        tmp_path / "transformed-dense",
    )
    dense_manifest = json.loads((dense_saved / "manifest.json").read_text(encoding="utf-8"))
    dense = np.load(dense_saved / dense_manifest["matrix_file"], allow_pickle=False)
    assert dense_manifest["representation"] == "dense_npy"
    assert dense.shape == transformed.shape


def test_training_class_distribution_uses_supplied_training_labels_only() -> None:
    report = training_class_distribution(
        pd.Series(["BENIGN", "BENIGN", "ATTACK"]),
        class_weight="balanced",
    )

    assert report["source"] == "training_labels_only"
    assert report["row_count"] == 3
    assert report["class_counts"] == {"ATTACK": 1, "BENIGN": 2}
    assert report["class_weights"]["ATTACK"] == pytest.approx(1.5)
    assert report["class_weights"]["BENIGN"] == pytest.approx(0.75)
