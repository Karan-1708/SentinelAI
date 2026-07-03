"""
pytest fixtures for API tests.

Uses httpx.AsyncClient with ASGITransport — no real network or Docker required.
ML models are mocked, and the DB is replaced with an in-memory SQLite so that
authentication and CRUD paths exercise real ORM logic without needing Postgres.
"""

from __future__ import annotations

import os

# Set the testing profile before anything else imports api.config.
os.environ.setdefault("APP_ENV", "testing")
os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///:memory:")
os.environ.setdefault("ELASTICSEARCH_PASSWORD", "test-only")
os.environ.setdefault("API_SECRET_KEY", "test-only-secret-not-for-prod-32bytes!")

from unittest.mock import MagicMock  # noqa: E402

import pytest  # noqa: E402
import pytest_asyncio  # noqa: E402
from httpx import ASGITransport, AsyncClient  # noqa: E402

from api.auth.security import create_access_token, hash_password  # noqa: E402
from api.database import Base, get_engine, get_session_factory  # noqa: E402
from api.main import create_app  # noqa: E402
from api.models.user import User  # noqa: E402


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
async def _seeded_users() -> dict[str, User]:
    """Create the schema and seed one user per role. Returns {role: user}."""
    async with get_engine().begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)

    users: dict[str, User] = {}
    async with get_session_factory()() as session:
        for role in ("viewer", "analyst", "admin"):
            user = User(
                email=f"{role}@test.local",
                hashed_password=hash_password("correct-horse-battery-staple"),
                role=role,
            )
            session.add(user)
            users[role] = user
        await session.commit()
        for user in users.values():
            await session.refresh(user)
    return users


@pytest_asyncio.fixture
async def client(mock_prediction_service, _seeded_users):
    app = create_app()

    async def _mock_lifespan(app):
        app.state.prediction_service = mock_prediction_service
        yield

    app.router.lifespan_context = _mock_lifespan

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as ac:
        yield ac


@pytest.fixture
def analyst_token(_seeded_users) -> str:
    user = _seeded_users["analyst"]
    return create_access_token(subject=str(user.id), role=user.role)


@pytest.fixture
def admin_token(_seeded_users) -> str:
    user = _seeded_users["admin"]
    return create_access_token(subject=str(user.id), role=user.role)


@pytest.fixture
def viewer_token(_seeded_users) -> str:
    user = _seeded_users["viewer"]
    return create_access_token(subject=str(user.id), role=user.role)


@pytest_asyncio.fixture
async def client_analyst(client, analyst_token):
    client.headers["Authorization"] = f"Bearer {analyst_token}"
    return client


@pytest_asyncio.fixture
async def client_admin(client, admin_token):
    client.headers["Authorization"] = f"Bearer {admin_token}"
    return client
