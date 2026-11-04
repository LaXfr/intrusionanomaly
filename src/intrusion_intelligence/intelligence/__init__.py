"""Offline threat scoring and alert correlation for detector outputs."""

from intrusion_intelligence.intelligence.pipeline import run_intelligence_pipeline
from intrusion_intelligence.intelligence.scoring import score_evidence

__all__ = ["run_intelligence_pipeline", "score_evidence"]
