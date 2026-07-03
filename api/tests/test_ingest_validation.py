"""Input-validation boundary tests for /ingest and /predict."""

from __future__ import annotations

import pytest


@pytest.mark.asyncio
async def test_ingest_rejects_oversize_features(client_analyst):
    # max_length=256 in the schema; 300 must 422
    payload = {"features": {f"f_{i}": 1.0 for i in range(300)}}
    resp = await client_analyst.post("/ingest", json=payload)
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_ingest_rejects_non_finite_feature_value(client_analyst):
    # ``inf`` is not JSON-compliant, so we bypass httpx's encoder and send a
    # literal string containing it. The server must still reject the payload.
    resp = await client_analyst.post(
        "/ingest",
        content='{"features": {"Destination Port": Infinity}}',
        headers={"Content-Type": "application/json"},
    )
    assert resp.status_code in (400, 422)


@pytest.mark.asyncio
async def test_ingest_rejects_invalid_ip(client_analyst):
    payload = {
        "features": {"Destination Port": 80.0},
        "source_ip": "not-an-ip",
    }
    resp = await client_analyst.post("/ingest", json=payload)
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_ingest_rejects_boolean_value(client_analyst):
    payload = {"features": {"Destination Port": True}}
    resp = await client_analyst.post("/ingest", json=payload)
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_ingest_rejects_overflow(client_analyst):
    payload = {"features": {"Destination Port": 1e15}}
    resp = await client_analyst.post("/ingest", json=payload)
    assert resp.status_code == 422
