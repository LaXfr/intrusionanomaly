"""Independent binary benign-versus-attack classification workflow."""

from intrusion_intelligence.binary.inference import BinaryPredictor
from intrusion_intelligence.binary.service import run_binary_experiment

__all__ = ["BinaryPredictor", "run_binary_experiment"]
