"""401/403 matrix per protected route."""

from __future__ import annotations

import pytest


@pytest.mark.asyncio
async def test_login_returns_jwt(client):
    resp = await client.post(
        "/auth/login",
        data={"username": "analyst@test.local", "password": "correct-horse-battery-staple"},
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["token_type"] == "bearer"
    assert isinstance(body["access_token"], str) and body["access_token"]


@pytest.mark.asyncio
async def test_login_rejects_wrong_password(client):
    resp = await client.post(
        "/auth/login",
        data={"username": "analyst@test.local", "password": "nope"},
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_login_rejects_unknown_email(client):
    resp = await client.post(
        "/auth/login",
        data={"username": "ghost@test.local", "password": "correct-horse-battery-staple"},
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_incidents_list_requires_auth(client):
    resp = await client.get("/incidents")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_incidents_list_ok_with_token(client_analyst):
    resp = await client_analyst.get("/incidents")
    assert resp.status_code == 200
    body = resp.json()
    assert "items" in body and "total" in body


@pytest.mark.asyncio
async def test_status_patch_requires_analyst(client, viewer_token):
    client.headers["Authorization"] = f"Bearer {viewer_token}"
    resp = await client.patch(
        "/incidents/00000000-0000-0000-0000-000000000000/status",
        json={"status": "IN_PROGRESS"},
    )
    # analyst-only endpoint — viewer must be 403
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_invalid_token_is_rejected(client):
    client.headers["Authorization"] = "Bearer not.a.real.jwt"
    resp = await client.get("/incidents")
    assert resp.status_code == 401
