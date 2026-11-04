"""Warm inference timing and artifact-size measurements."""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any, Sequence

import numpy as np
import pandas as pd

from intrusion_intelligence.explainability.model_registry import ExplainableModel


def artifact_size_bytes(path: str | Path) -> int:
    root = Path(path)
    return sum(item.stat().st_size for item in root.rglob("*") if item.is_file()) if root.is_dir() else root.stat().st_size


def benchmark_warm_inference(model: ExplainableModel, X: pd.DataFrame, *, batch_sizes: Sequence[int], repeats: int = 5) -> dict[str, Any]:
    """Measure transform and estimator time separately on bounded warmed inputs."""
    if X.empty or repeats < 1:
        raise ValueError("Benchmark inputs and repeat count must be positive.")
    output = model.outputs[0]
    model_values = []
    for size in sorted(set(int(value) for value in batch_sizes)):
        if size < 1:
            raise ValueError("Benchmark batch sizes must be positive.")
        frame = X.iloc[:min(size, len(X))]
        model.transform(frame)
        transform_times, prediction_times = [], []
        for _ in range(repeats):
            start = time.perf_counter()
            transformed = model.transform(frame)
            transform_times.append(time.perf_counter() - start)
            start = time.perf_counter()
            predictions = model.output_values(transformed, output)
            prediction_times.append(time.perf_counter() - start)
            if not np.isfinite(predictions).all():
                raise ValueError(f"{model.model_id} returned non-finite predictions during benchmark.")
        transform_median = float(np.median(transform_times))
        prediction_median = float(np.median(prediction_times))
        total = transform_median + prediction_median
        model_values.append({"requested_batch_size": size, "actual_batch_size": len(frame), "repeats": int(repeats), "median_preprocessing_seconds": transform_median, "median_prediction_seconds": prediction_median, "median_total_seconds": total, "throughput_rows_per_second": float(len(frame) / total) if total else None, "latency_per_row_ms": float(total * 1000 / len(frame)) if len(frame) else None, "cold_start_included": False})
    return {"model_id": model.model_id, "model_family": model.family, "artifact_size_bytes": artifact_size_bytes(model.artifact_directory), "output_semantics": output.semantic, "batch_measurements": model_values}
