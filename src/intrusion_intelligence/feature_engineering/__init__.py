"""Feature contracts and optional network-flow feature engineering."""

from intrusion_intelligence.feature_engineering.derived import (
    DERIVED_FEATURES,
    FlowFeatureEngineer,
)
from intrusion_intelligence.feature_engineering.schema import (
    DEFAULT_SCHEMA_PATH,
    FeatureContract,
    FeatureSchemaError,
    FeatureSpec,
    separate_features_target_metadata,
    validate_feature_matrix,
)

__all__ = [
    "DEFAULT_SCHEMA_PATH",
    "DERIVED_FEATURES",
    "FeatureContract",
    "FeatureSchemaError",
    "FeatureSpec",
    "FlowFeatureEngineer",
    "separate_features_target_metadata",
    "validate_feature_matrix",
]
