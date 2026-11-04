"""Environment-driven backend configuration with safe local defaults."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _path(name: str, default: str) -> Path:
    value = Path(os.getenv(name, default)).expanduser()
    return (PROJECT_ROOT / value).resolve() if not value.is_absolute() else value.resolve()


def _integer(name: str, default: int, minimum: int = 1) -> int:
    try:
        result = int(os.getenv(name, str(default)))
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer.") from exc
    if result < minimum:
        raise ValueError(f"{name} must be at least {minimum}.")
    return result


@dataclass(frozen=True, slots=True)
class Settings:
    app_name: str
    environment: str
    host: str
    port: int
    debug: bool
    database_url: str
    raw_data_dir: Path
    processed_data_dir: Path
    upload_dir: Path
    model_dir: Path
    report_dir: Path
    feature_schema_path: Path
    intelligence_config_path: Path
    explainability_config_path: Path
    max_upload_bytes: int
    max_request_bytes: int
    max_analysis_records: int
    max_batch_size: int
    max_job_rows: int
    job_batch_size: int
    cors_origins: tuple[str, ...]
    log_level: str

    @classmethod
    def from_env(cls) -> "Settings":
        origins = tuple(item.strip() for item in os.getenv("NII_API_CORS_ORIGINS", "").split(",") if item.strip())
        invalid = [origin for origin in origins if origin == "*"]
        if invalid:
            raise ValueError("Wildcard CORS origins are not allowed for the local backend.")
        host = os.getenv("NII_API_HOST", "127.0.0.1")
        if host in {"0.0.0.0", "::"} and os.getenv("NII_ALLOW_PUBLIC_BIND", "false").lower() != "true":
            raise ValueError("Public binding requires NII_ALLOW_PUBLIC_BIND=true.")
        database_url = os.getenv("NII_DATABASE_URL", "").strip()
        if database_url and not (database_url.startswith("postgresql+psycopg://") or database_url.startswith("sqlite:///")):
            raise ValueError("NII_DATABASE_URL must use postgresql+psycopg or sqlite for tests.")
        return cls(
            app_name=os.getenv("NII_APP_NAME", "Network Intrusion Detection & Anomaly Intelligence API"),
            environment=os.getenv("NII_ENVIRONMENT", "development"), host=host,
            port=_integer("NII_API_PORT", 8000), debug=os.getenv("NII_APP_DEBUG", "false").lower() == "true",
            database_url=database_url, raw_data_dir=_path("NII_RAW_DATA_DIR", "data/raw"),
            processed_data_dir=_path("NII_PROCESSED_DATA_DIR", "data/processed"),
            upload_dir=_path("NII_UPLOAD_DIR", "data/uploads"), model_dir=_path("NII_MODEL_ARTIFACT_DIR", "models"),
            report_dir=_path("NII_REPORT_DIR", "reports"), feature_schema_path=_path("NII_FEATURE_SCHEMA", "configs/feature_schema.json"),
            intelligence_config_path=_path("NII_INTELLIGENCE_CONFIG", "configs/intelligence.toml"),
            explainability_config_path=_path("NII_EXPLAINABILITY_CONFIG", "configs/explainability.toml"),
            max_upload_bytes=_integer("NII_MAX_UPLOAD_BYTES", 50 * 1024 * 1024),
            max_request_bytes=_integer("NII_MAX_REQUEST_BYTES", 8 * 1024 * 1024),
            max_analysis_records=_integer("NII_MAX_ANALYSIS_RECORDS", 100, 1),
            max_batch_size=_integer("NII_MAX_BATCH_SIZE", 500, 1),
            max_job_rows=_integer("NII_MAX_JOB_ROWS", 100_000, 1),
            job_batch_size=_integer("NII_JOB_BATCH_SIZE", 500, 1), cors_origins=origins,
            log_level=os.getenv("NII_LOG_LEVEL", "INFO").upper(),
        )


def get_settings() -> Settings:
    return Settings.from_env()
