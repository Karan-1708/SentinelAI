"""
End-to-end integration test: ingest → predict → incident created → WS broadcast.
Requires: full Docker stack running + trained model artifacts.

Run with:
    pytest tests/integration/test_pipeline_e2e.py -v
"""

import asyncio
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parents[2]))

API_BASE = "http://localhost:8000"
WS_URL = "ws://localhost:8000/ws/feed"

SAMPLE_FEATURES = {col: 100.0 for col in [
    "Destination Port", "Flow Duration", "Total Fwd Packets",
    "Total Backward Packets", "Total Length of Fwd Packets",
    "Total Length of Bwd Packets", "Fwd Packet Length Max",
    "Fwd Packet Length Min", "Fwd Packet Length Mean", "Fwd Packet Length Std",
    "Bwd Packet Length Max", "Bwd Packet Length Min", "Bwd Packet Length Mean",
    "Bwd Packet Length Std", "Flow IAT Mean", "Flow IAT Std", "Flow IAT Max",
    "Flow IAT Min", "Fwd Packets/s", "Bwd Packets/s",
]}


@pytest.mark.integration
@pytest.mark.asyncio
async def test_health_endpoint():
    """API health endpoint must return 200."""
    import httpx
    async with httpx.AsyncClient() as client:
        response = await client.get(f"{API_BASE}/health", timeout=10)
    assert response.status_code == 200
    data = response.json()
    assert "status" in data


@pytest.mark.integration
@pytest.mark.asyncio
async def test_predict_creates_incident():
    """POST /predict must return 200 with incident_id."""
    import httpx
    async with httpx.AsyncClient() as client:
        response = await client.post(
            f"{API_BASE}/predict",
            json={"features": SAMPLE_FEATURES, "source_ip": "198.51.100.7"},
            timeout=30,
        )
    assert response.status_code == 200
    data = response.json()
    assert "incident_id" in data
    assert "severity" in data
    assert data["severity"] in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")


@pytest.mark.integration
@pytest.mark.asyncio
async def test_incident_retrievable_after_predict():
    """Incident created by POST /predict must be retrievable via GET /incidents/{id}."""
    import httpx
    async with httpx.AsyncClient() as client:
        # Create incident
        pred_resp = await client.post(
            f"{API_BASE}/predict",
            json={"features": SAMPLE_FEATURES},
            timeout=30,
        )
        assert pred_resp.status_code == 200
        incident_id = pred_resp.json()["incident_id"]

        # Retrieve it
        get_resp = await client.get(f"{API_BASE}/incidents/{incident_id}", timeout=10)
    assert get_resp.status_code == 200
    data = get_resp.json()
    assert data["id"] == incident_id
