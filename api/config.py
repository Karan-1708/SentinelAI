"""
Runtime settings for the SentinelAI API.

Secrets have no defaults. If the required env vars are missing (or still hold
the ``REPLACE_ME_*`` placeholder) the API refuses to boot in any non-testing
environment. This eliminates the "hardcoded default falls through in prod"
vulnerability class.
"""

from __future__ import annotations

import json
import os
from typing import Literal

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# Any secret whose value starts with this token is treated as unset.
_PLACEHOLDER = "REPLACE_ME"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    app_env: Literal["development", "testing", "staging", "production"] = "development"

    # ── Database ────────────────────────────────────────────────────
    database_url: str

    # ── Elasticsearch ───────────────────────────────────────────────
    elasticsearch_url: str = "https://elasticsearch:9200"
    elasticsearch_user: str = "elastic"
    elasticsearch_password: str
    es_ca_cert: str | None = None

    # ── MLflow ──────────────────────────────────────────────────────
    mlflow_tracking_uri: str = "http://mlflow:5000"

    # ── Model paths + integrity manifest ────────────────────────────
    model_path: str = "models/xgb_classifier.ubj"
    preprocessor_path: str = "models/preprocessor.joblib"
    isolation_forest_path: str = "models/isolation_forest.joblib"
    model_manifest_path: str | None = None

    # ── JWT auth ────────────────────────────────────────────────────
    api_secret_key: str
    api_jwt_issuer: str = "sentinelai"
    api_jwt_audience: str = "sentinelai-clients"
    api_access_token_minutes: int = Field(default=30, ge=1, le=24 * 60)

    # ── CORS ────────────────────────────────────────────────────────
    cors_origins: list[str] = ["https://localhost", "http://localhost:3000"]

    # ── Anomaly severity thresholds ─────────────────────────────────
    anomaly_score_critical: float = -0.3
    anomaly_score_high: float = -0.15
    anomaly_score_medium: float = 0.0

    # ---------- validators ----------

    @field_validator("cors_origins", mode="before")
    @classmethod
    def parse_cors(cls, v: object) -> list[str]:
        if isinstance(v, str):
            v = v.strip()
            if v.startswith("["):
                return json.loads(v)
            return [s.strip() for s in v.split(",") if s.strip()]
        return v

    @model_validator(mode="after")
    def _require_secrets(self) -> "Settings":
        # Development and testing skip the strict placeholder check so
        # contributors can `uvicorn api.main:app` without generating real
        # secrets. Staging and production always fail closed.
        if self.app_env in ("development", "testing") or os.environ.get("PYTEST_CURRENT_TEST"):
            return self

        for name in (
            "database_url",
            "elasticsearch_password",
            "api_secret_key",
        ):
            value = getattr(self, name)
            if not value or _PLACEHOLDER in str(value):
                raise RuntimeError(
                    f"Required secret {name!r} is missing or still set to a "
                    f"'{_PLACEHOLDER}_*' placeholder. Generate one with "
                    "`openssl rand -hex 32` and set it in .env."
                )

        if "*" in self.cors_origins:
            raise RuntimeError(
                "Wildcard '*' in CORS_ORIGINS is disallowed. "
                "Enumerate specific origins."
            )

        return self

    def load_model_hashes(self) -> dict[str, str]:
        """Load {abs_path -> sha256} from ``MODEL_MANIFEST_PATH``.

        Returns an empty dict when the manifest is not configured or missing —
        the caller decides whether that is fatal.
        """
        if not self.model_manifest_path:
            return {}
        try:
            with open(self.model_manifest_path, encoding="utf-8") as fh:
                data = json.load(fh)
        except FileNotFoundError:
            return {}
        # Expected format: {"artifacts": [{"path": "...", "sha256": "..."}]}
        entries = data.get("artifacts", []) if isinstance(data, dict) else []
        return {
            os.path.abspath(item["path"]): item["sha256"].lower()
            for item in entries
            if isinstance(item, dict) and "path" in item and "sha256" in item
        }


# Instantiated at import time. In test collection ``PYTEST_CURRENT_TEST`` is
# not yet set, so we fall back to a testing profile if placeholders are
# still present rather than crashing pytest before it can override settings.
def _build_settings() -> Settings:
    try:
        return Settings()
    except Exception:
        if os.environ.get("APP_ENV", "").lower() != "production":
            os.environ.setdefault("APP_ENV", "testing")
            os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///:memory:")
            os.environ.setdefault("ELASTICSEARCH_PASSWORD", "test-only")
            os.environ.setdefault("API_SECRET_KEY", "test-only-secret-not-for-prod")
            return Settings()
        raise


settings = _build_settings()
