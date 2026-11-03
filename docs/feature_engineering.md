# Phase 05 feature engineering and preprocessing

## Scope and architecture

Phase 05 defines an explicit feature contract, optional deterministic network-flow features, and independent Scikit-learn preprocessing profiles. It does not train classifiers or anomaly models, set a final evaluation split, or fit a production artifact on the complete CIC-IDS2017 extract.

Responsibilities are separated:

- `src/intrusion_intelligence/feature_engineering/schema.py` loads the feature contract, validates inputs, and separates X, y, and metadata.
- `src/intrusion_intelligence/feature_engineering/derived.py` implements optional network-flow feature formulas without data-fitted statistics.
- `src/intrusion_intelligence/preprocessing/pipeline.py` fits imputers, encoders, scalers, and optional selectors on training X and reuses them for transforms.
- `src/intrusion_intelligence/preprocessing/artifacts.py` versions and persists fitted profile objects plus metadata.
- `src/intrusion_intelligence/preprocessing/class_imbalance.py` reports training-label counts and optional balanced class weights.
- `src/intrusion_intelligence/preprocessing/storage.py` stores dense/sparse transformed matrices with aligned targets and row metadata.

The package API is exported from `intrusion_intelligence.feature_engineering` and `intrusion_intelligence.preprocessing`.

## Feature contract and current data

`configs/feature_schema.json` is the machine-readable schema. It was built from the Phase 04 v2 manifest, feature policy, and label-validation report. It defines the schema version, field names and original headers, numeric/categorical type, role, inclusion, optionality, transformation requirements, target categories, and metadata exclusions.

The current cleaned export has 78 numeric predictive features, one separate target (`label`), and four row-level metadata fields: `__source_label`, `__source_file`, `__source_row_number`, and `__record_id`. `destination_port` remains a numeric candidate. The export has no categorical predictive feature; protocol and standalone source port are recorded as unavailable candidates. If they appear in a future source, update and review the contract before including them. Protocol must be typed categorical even if stored as an integer.

Flow ID, source/destination IP, timestamp, target, processing ID, source label, and provenance are not predictive inputs. `separate_features_target_metadata()` returns features in contract order, y independently, and available metadata separately. It rejects unknown columns and invalid/missing target labels. Feature-only validation rejects target or metadata contamination, duplicate names, unknown fields, missing required fields, incompatible types, infinity, and changed order. Inference can omit a feature only when the contract marks it optional; the fitted imputer then preserves the transformed output width.

## Optional derived features

`FlowFeatureEngineer` preserves source columns and adds only requested outputs. All derived features are disabled by default in `configs/preprocessing.toml`.

| Derived feature | Formula | Missing and zero behavior | Purpose and caveat |
|---|---|---|---|
| `total_packets` | `total_fwd_packets + total_backward_packets` | NaN if either input is missing | Aggregate directional packet counts; related to both inputs. |
| `total_bytes` | `total_length_of_fwd_packets + total_length_of_bwd_packets` | NaN if either input is missing | Aggregate directional byte counts; related to both inputs. |
| `forward_packet_proportion` | `total_fwd_packets / (total_fwd_packets + total_backward_packets)` | NaN for missing inputs, zero/nonpositive denominator, or negative directional count | Forward traffic share; algebraically related to packet counts. |
| `forward_byte_proportion` | `total_length_of_fwd_packets / (total_length_of_fwd_packets + total_length_of_bwd_packets)` | NaN for missing inputs, zero/nonpositive denominator, or negative directional count | Forward byte share; algebraically related to byte counts. |

No label, identifier, filename, timestamp, or metadata field is used in these formulas. EDA found skewed and extreme measurements, negatives including possible `-1` sentinels, and correlated source fields. Phase 05 therefore does not enable log/power transforms, clipping, or correlation-based removal by default.

## Missing values and validation

Numeric features use train-fitted median imputation. A numeric column entirely missing in training raises an informative error; the pipeline does not choose an arbitrary constant or drop it silently. Categorical features use the explicit `__MISSING__` category by default. An alternative most-frequent strategy is supported, with an error for an entirely missing training category column.

Missing-value indicators are configurable and off by default. Numeric inputs with non-numeric dtypes or infinities are rejected before fitting/transforming; NaN is accepted for imputation. Categorical numeric codes are converted to string categories before imputation and one-hot encoding. Unknown categories use `OneHotEncoder(handle_unknown="ignore")`, preserving output width and feature order.

The current Phase 04 data contains 1,358 missing tokens in `flow_bytes_s` and 2,867 nulls in each of `flow_bytes_s` and `flow_packets_s` after infinity handling. These remain missing in X until a profile is fitted on an approved training partition.

## Independent preprocessing profiles

`build_preprocessor()` creates a new fitted object for each profile. Do not share learned preprocessing parameters between supervised and anomaly populations.

| Profile | Numeric imputation | Scaling | Intended use |
|---|---|---|---|
| `linear` | Median | `StandardScaler` | Initial linear-model workflow. |
| `tree` | Median | None | Tree-based workflow. |
| `anomaly` | Median | `RobustScaler` | Initial anomaly preprocessing; later fit only on the permitted Phase 08 baseline. |

These are configurable starting points. `RobustScaler` is included because EDA found skew and extremes; it does not remove outliers. Categorical output remains one-hot encoded and is not scaled. No log transform is enabled.

## Feature selection and class imbalance

`VarianceThreshold` is the supported initial selection method. It is disabled by default and, when enabled, learns from training rows only. Selected and removed transformed names are available through `selection_metadata()` and are saved in artifact metadata. EDA found eight features constant across the complete extract, but using the complete dataset to preselect fields would violate the train-only rule. Correlation-based, model-based, and target-supervised selection are not implemented.

`training_class_distribution(y_train, class_weight="balanced")` reports training counts/proportions and Scikit-learn balanced class weights. The API takes training labels only. No resampling or `imbalanced-learn` dependency is introduced; balancing experiments belong to later classifier work.

## Training, inference, and batch transforms

Fit only after creating an authorized training partition:

```python
preprocessor = build_preprocessor("linear", contract=contract)
X_train_transformed = preprocessor.fit_transform(X_train)
X_validation_transformed = preprocessor.transform(X_validation)
X_inference_transformed = preprocessor.transform(X_inference)
```

`fit` accepts X only and rejects a y argument. `transform` never refits. `transform_batches()` applies the same learned imputer, encoder, scaler, and selector to successive inference batches. Feature validation enforces contract order and stable transformed names. The notebook's random partition is strictly an illustrative preprocessing check, not a final project split.

## Artifacts and transformed matrices

`save_preprocessor()` writes `models/preprocessors/<profile>/<version>/preprocessor.joblib` and a JSON `metadata.json`. It refuses to overwrite an existing version. Metadata records schema and training-schema fingerprints, profile, input/output feature names and order, numeric/categorical features, imputation and encoding choices, scaling, optional derived features, feature selection, learned numeric statistics, library versions, random seed, version, and creation time. It contains no traffic rows. `load_preprocessor()` verifies profile and output feature names before returning the fitted object.

When transformed data must be materialized, `save_transformed_matrix()` writes sparse matrices as SciPy NPZ and dense matrices as NPY. It stores y and row metadata in a separate aligned Parquet file, plus feature names and checksums. It validates row counts, label/metadata index alignment, feature width, and finite output values, and refuses to overwrite an existing directory.

## Real-data validation and limits

All eight Phase 04 Parquet files were checked for matching 83-column schemas. A bounded sample of 1,000 rows per file (8,000 rows total) was extracted. An illustrative 6,400-row training subset fit the linear profile, and the same fitted object transformed 1,600 held-out sample rows, producing 80 named outputs when two optional derived features were enabled. This is a schema and sample-transform smoke check only; no transformation was fitted on the complete dataset or saved as an authoritative CIC-IDS2017 preprocessor.

The current extract has no categorical predictive column, source port, protocol, timestamps, endpoints, or Flow ID. It has strong label/source-file concentration, duplicates, and conflicting feature vectors. The sample partition is not suitable for evaluation. A real Phase 08 benign baseline and later group-aware evaluation strategy remain future work. No model, model metric, or optimal feature set is claimed.
