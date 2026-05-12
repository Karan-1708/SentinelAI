from __future__ import annotations

import json

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # Database
    database_url: str = "postgresql+asyncpg://sentinel:sentinel@postgres:5432/sentinelai"

    # Elasticsearch
    elasticsearch_url: str = "https://elasticsearch:9200"
    elasticsearch_user: str = "elastic"
    elasticsearch_password: str = "changeme_elastic"
    es_ca_cert: str | None = None

    # MLflow
    mlflow_tracking_uri: str = "http://mlflow:5000"

    # Model paths (inside Docker on shared volume, or local for dev)
    model_path: str = "models/xgb_classifier.ubj"
    preprocessor_path: str = "models/preprocessor.joblib"
    isolation_forest_path: str = "models/isolation_forest.joblib"

    # API
    api_secret_key: str = "changeme_api_secret"
    cors_origins: list[str] = ["http://localhost:3000", "http://localhost:80"]

    @field_validator("cors_origins", mode="before")
    @classmethod
    def parse_cors(cls, v: object) -> list[str]:
        if isinstance(v, str):
            v = v.strip()
            if v.startswith("["):
                return json.loads(v)
            return [s.strip() for s in v.split(",") if s.strip()]
        return v

    # Anomaly thresholds for severity derivation
    anomaly_score_critical: float = -0.3
    anomaly_score_high: float = -0.15
    anomaly_score_medium: float = 0.0


settings = Settings()
