"""
pytest fixtures for API tests.
Uses httpx.AsyncClient with ASGITransport — no real network or Docker required.
ML models are mocked so tests run without trained artifacts.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from api.main import create_app


@pytest.fixture
def mock_prediction_result() -> dict:
    return {
        "threat_label": "DDoS",
        "severity": "HIGH",
        "confidence": 0.92,
        "anomaly_score": -0.25,
        "is_anomaly": True,
        "mitre_techniques": [
            {"technique_id": "T1498", "technique_name": "Network DoS", "tactic": "impact"}
        ],
        "shap_values": [{"feature": "feature_0", "shap_value": 0.5, "feature_value": 100.0}],
        "top_shap_features": [{"feature": "feature_0", "shap_value": 0.5}],
        "raw_features": {"Destination Port": 80.0},
    }


@pytest.fixture
def mock_prediction_service(mock_prediction_result):
    svc = MagicMock()
    svc.predict.return_value = mock_prediction_result
    return svc


@pytest_asyncio.fixture
async def client(mock_prediction_service):
    """AsyncClient with mocked prediction service — no Docker, no trained models."""
    app = create_app()

    # Override the lifespan model loading with a mock
    async def _mock_lifespan(app):
        app.state.prediction_service = mock_prediction_service
        # Skip DB table creation for unit tests
        yield

    app.router.lifespan_context = _mock_lifespan

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as ac:
        yield ac
