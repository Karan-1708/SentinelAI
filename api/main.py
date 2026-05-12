"""
FastAPI application factory.

Critical: ML models are loaded ONCE in the lifespan context manager.
Loading per-request would take seconds and cause catastrophic latency.
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from api.config import settings
from api.database import Base, get_engine
from api.routers import incidents, ingest, predict, reports, ws

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # ── Startup ──────────────────────────────────────────────────────
    logger.info("Starting SentinelAI API...")

    # Create all tables (dev/test convenience; use Alembic in production)
    async with get_engine().begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    # Load ML models once — stored in app.state for dependency injection
    try:
        from api.services.prediction_service import PredictionService
        app.state.prediction_service = PredictionService()
        logger.info("Prediction service loaded successfully")
    except Exception as e:
        logger.warning("Prediction service failed to load (models not trained yet): %s", e)
        app.state.prediction_service = None

    yield

    # ── Shutdown ─────────────────────────────────────────────────────
    await get_engine().dispose()
    logger.info("SentinelAI API shutdown complete")


def create_app() -> FastAPI:
    app = FastAPI(
        title="SentinelAI",
        description="Autonomous Threat Intelligence & Incident Response API",
        version="1.0.0",
        lifespan=lifespan,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.include_router(ingest.router)
    app.include_router(predict.router)
    app.include_router(incidents.router)
    app.include_router(reports.router)
    app.include_router(ws.router)

    @app.get("/health", tags=["health"])
    async def health() -> dict:
        """Liveness + readiness check."""
        from sqlalchemy import text
        try:
            async with get_engine().connect() as conn:
                await conn.execute(text("SELECT 1"))
            db_status = "ok"
        except Exception as e:
            db_status = f"error: {e}"

        prediction_ready = app.state.prediction_service is not None
        return {
            "status": "ok" if db_status == "ok" else "degraded",
            "database": db_status,
            "prediction_service": "ready" if prediction_ready else "not_loaded",
        }

    return app


app = create_app()
