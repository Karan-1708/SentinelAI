"""
WebSocket ConnectionManager — module-level singleton for fan-out broadcasting.

All active WebSocket connections are tracked here.
When a new incident is created, broadcast() sends it to every connected client.

For production scale: replace in-memory list with Redis pub/sub + aioredis.
The interface remains the same — the router code doesn't need to change.
"""

from __future__ import annotations

import json
import logging

from fastapi import WebSocket
from fastapi.websockets import WebSocketDisconnect

logger = logging.getLogger(__name__)


class ConnectionManager:
    def __init__(self) -> None:
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        self.active_connections.append(websocket)
        logger.info(
            "WebSocket connected. Total connections: %d",
            len(self.active_connections),
        )

    def disconnect(self, websocket: WebSocket) -> None:
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
        logger.info(
            "WebSocket disconnected. Total connections: %d",
            len(self.active_connections),
        )

    async def broadcast(self, data: dict) -> None:
        """Fan out data to all active connections. Dead connections are cleaned up."""
        if not self.active_connections:
            return

        message = json.dumps(data, default=str)
        dead: list[WebSocket] = []

        for connection in self.active_connections:
            try:
                await connection.send_text(message)
            except (WebSocketDisconnect, Exception):
                dead.append(connection)

        for conn in dead:
            self.disconnect(conn)


manager = ConnectionManager()
