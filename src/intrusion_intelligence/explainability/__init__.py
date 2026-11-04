"""SHAP-based explanations for persisted network-flow detectors."""

from intrusion_intelligence.explainability.pipeline import run_explainability

__all__ = ["run_explainability"]
"""Reusable Phase 10 model explainability components."""

from intrusion_intelligence.explainability.schemas import ExplainabilityError, ExplanationOutput, ExplanationRecord

__all__ = ["ExplainabilityError", "ExplanationOutput", "ExplanationRecord"]
