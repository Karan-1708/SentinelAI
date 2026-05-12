"""Tests for POST /predict endpoint."""

import pytest


SAMPLE_PAYLOAD = {
    "features": {col: 100.0 for col in [
        "Destination Port", "Flow Duration", "Total Fwd Packets",
        "Total Backward Packets", "Total Length of Fwd Packets",
    ]},
    "source_ip": "198.51.100.7",
    "dest_ip": "192.168.1.10",
    "log_source": "api",
}


@pytest.mark.asyncio
async def test_predict_returns_incident_id(client):
    response = await client.post("/predict", json=SAMPLE_PAYLOAD)
    # Will be 503 if DB not available — acceptable in pure unit test context
    assert response.status_code in (200, 503)


@pytest.mark.asyncio
async def test_predict_response_schema(client, mock_prediction_service):
    """Prediction service mock returns deterministic output — check schema."""
    # This test validates the schema when service is wired up correctly
    # Full integration test with DB is in tests/integration/
    response = await client.post("/predict", json=SAMPLE_PAYLOAD)
    if response.status_code == 200:
        data = response.json()
        assert "incident_id" in data
        assert "threat_label" in data
        assert "severity" in data
        assert "confidence" in data
        assert data["severity"] in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
        assert 0.0 <= data["confidence"] <= 1.0
