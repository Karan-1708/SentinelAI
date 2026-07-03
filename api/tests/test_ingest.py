"""Tests for POST /ingest endpoint."""

import pytest


@pytest.mark.asyncio
async def test_ingest_requires_auth(client):
    response = await client.post(
        "/ingest",
        json={"features": {"Destination Port": 80.0}},
    )
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_ingest_valid_payload(client_analyst):
    response = await client_analyst.post("/ingest", json={
        "features": {"Destination Port": 80.0, "Flow Duration": 100000.0},
        "source_ip": "192.168.1.1",
        "log_source": "syslog",
    })
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "accepted"
    assert "2" in data["message"]


@pytest.mark.asyncio
async def test_ingest_empty_features(client_analyst):
    response = await client_analyst.post("/ingest", json={"features": {}})
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "error"


@pytest.mark.asyncio
async def test_ingest_missing_features_field(client_analyst):
    response = await client_analyst.post("/ingest", json={"source_ip": "10.0.0.1"})
    assert response.status_code == 422
