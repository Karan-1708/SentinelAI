"""
FastAPI application factory.

Highlights:
  * ML models are loaded once via the lifespan context manager.
  * All mutating and streaming endpoints require a valid JWT.
  * SlowAPI rate limits are applied globally; per-route overrides live on the
    handlers.
  * Every response carries an ``X-Request-ID`` header (also emitted with each
    log line) so client and server logs can be correlated without leaking
    stack traces to the client.
"""

from __future__ import annotations

import logging
import uuid
from contextlib import asynccontextmanager
from typing import Callable

from fastapi import FastAPI, Request, status
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware

from api.config import settings
from api.database import Base, get_engine
from api.rate_limit import limiter
from api.routers import auth as auth_router
from api.routers import incidents, ingest, predict, reports, ws

logger = logging.getLogger(__name__)


class RequestIDMiddleware(BaseHTTPMiddleware):
    """Stamp every request/response with an ``X-Request-ID`` header."""

    async def dispatch(self, request: Request, call_next: Callable):
        request_id = request.headers.get("x-request-id") or uuid.uuid4().hex
        request.state.request_id = request_id
        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        return response


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting SentinelAI API (env=%s)", settings.app_env)

    # Dev/test convenience only; production must use Alembic migrations.
    async with get_engine().begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    try:
        from api.services.prediction_service import PredictionService

        app.state.prediction_service = PredictionService()
        logger.info("Prediction service loaded successfully")
    except Exception:
        logger.exception("Prediction service failed to load (models not trained yet)")
        app.state.prediction_service = None

    yield

    await get_engine().dispose()
    logger.info("SentinelAI API shutdown complete")


def _register_exception_handlers(app: FastAPI) -> None:
    """Never leak stack traces or driver-specific messages to the client."""

    @app.exception_handler(RequestValidationError)
    async def _validation(request: Request, exc: RequestValidationError):
        # We produce a stripped-down error payload so we never leak the raw
        # input back to the client (which may include unserializable values
        # like ``inf`` from a rejected payload) or a wrapped exception.
        safe_errors = [
            {
                "loc": [str(part) for part in err.get("loc", ())],
                "msg": str(err.get("msg", "")),
                "type": str(err.get("type", "")),
            }
            for err in exc.errors()
        ]
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content=jsonable_encoder(
                {
                    "detail": safe_errors,
                    "request_id": getattr(request.state, "request_id", None),
                }
            ),
        )

    @app.exception_handler(RateLimitExceeded)
    async def _rate_limit(request: Request, exc: RateLimitExceeded):
        return JSONResponse(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            content={
                "detail": "Rate limit exceeded",
                "request_id": getattr(request.state, "request_id", None),
            },
        )

    @app.exception_handler(Exception)
    async def _fallback(request: Request, exc: Exception):
        request_id = getattr(request.state, "request_id", None)
        logger.exception(
            "Unhandled exception on %s %s (request_id=%s)",
            request.method,
            request.url.path,
            request_id,
        )
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"detail": "Internal server error", "request_id": request_id},
        )


def create_app() -> FastAPI:
    app = FastAPI(
        title="SentinelAI",
        description="Autonomous Threat Intelligence & Incident Response API",
        version="1.0.0",
        lifespan=lifespan,
    )

    # ── Middleware (order matters: outer first) ─────────────────────
    app.add_middleware(RequestIDMiddleware)
    app.add_middleware(SlowAPIMiddleware)
    app.state.limiter = limiter

    # Trusted-host enforcement is only enabled in staging/production so unit
    # tests (which use httpx's synthetic "test" host) continue to work. In
    # deployed environments it defeats Host-header injection / DNS rebinding.
    if settings.app_env in ("staging", "production"):
        allowed_hosts = [
            origin.replace("https://", "").replace("http://", "").split(":")[0]
            for origin in settings.cors_origins
        ]
        app.add_middleware(TrustedHostMiddleware, allowed_hosts=allowed_hosts)

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PATCH", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "X-Request-ID"],
        max_age=600,
    )

    _register_exception_handlers(app)

    app.include_router(auth_router.router)
    app.include_router(ingest.router)
    app.include_router(predict.router)
    app.include_router(incidents.router)
    app.include_router(reports.router)
    app.include_router(ws.router)

    @app.get("/health", tags=["health"])
    async def health(request: Request) -> dict:
        """Liveness + readiness check. Never leaks driver error strings."""
        from sqlalchemy import text

        try:
            async with get_engine().connect() as conn:
                await conn.execute(text("SELECT 1"))
            db_status = "ok"
        except Exception:
            logger.exception(
                "Health DB check failed (request_id=%s)",
                getattr(request.state, "request_id", None),
            )
            db_status = "error"

        prediction_ready = getattr(request.app.state, "prediction_service", None) is not None
        return {
            "status": "ok" if db_status == "ok" else "degraded",
            "database": db_status,
            "prediction_service": "ready" if prediction_ready else "not_loaded",
        }

    return app


app = create_app()
