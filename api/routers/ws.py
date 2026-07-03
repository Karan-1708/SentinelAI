"""
WebSocket incident feed.

Auth: JWT is passed as the ``token`` query parameter. Passing it in a query
string (rather than a header) is required because the browser WebSocket API
does not let clients set request headers. The token is not written to server
access logs — only the claim ``sub`` is logged.

CSWSH defense: the ``Origin`` header is checked against the configured CORS
origins. Any mismatch closes the socket with policy code 4403.
"""

from __future__ import annotations

import asyncio
import logging
import uuid

from fastapi import APIRouter, Query
from fastapi.websockets import WebSocket, WebSocketDisconnect
from starlette.websockets import WebSocketState

from api.auth.security import InvalidTokenError, decode_token
from api.config import settings
from api.services.broadcast_service import ConnectionRefused, manager

logger = logging.getLogger(__name__)

router = APIRouter()

_POLICY_VIOLATION = 4403
_UNAUTHORIZED = 4401
_TRY_AGAIN = 4408
_IDLE_PING_SECONDS = 25


def _origin_allowed(origin: str | None) -> bool:
    if origin is None:
        return False
    return origin in settings.cors_origins


@router.websocket("/ws/feed")
async def websocket_feed(
    websocket: WebSocket,
    token: str = Query(default=""),
) -> None:
    origin = websocket.headers.get("origin")
    if not _origin_allowed(origin):
        await websocket.close(code=_POLICY_VIOLATION, reason="Origin not allowed")
        return

    if not token:
        await websocket.close(code=_UNAUTHORIZED, reason="Missing token")
        return

    try:
        claims = decode_token(token)
        subject = uuid.UUID(str(claims["sub"]))
    except (InvalidTokenError, KeyError, ValueError):
        await websocket.close(code=_UNAUTHORIZED, reason="Invalid token")
        return

    try:
        await manager.connect(websocket)
    except ConnectionRefused:
        await websocket.close(code=_TRY_AGAIN, reason="Server at capacity")
        return

    logger.info("WebSocket subscriber connected (user=%s)", subject)

    try:
        while True:
            # Client messages are ignored; the timeout drives a server-side
            # keepalive so hung sockets are pruned instead of leaking forever.
            try:
                await asyncio.wait_for(websocket.receive_text(), timeout=_IDLE_PING_SECONDS)
            except asyncio.TimeoutError:
                if websocket.client_state == WebSocketState.CONNECTED:
                    await websocket.send_text('{"type":"ping"}')
    except WebSocketDisconnect:
        pass
    finally:
        manager.disconnect(websocket)
        logger.info("WebSocket subscriber disconnected (user=%s)", subject)
