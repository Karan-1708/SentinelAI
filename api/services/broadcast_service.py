"""
WebSocket ConnectionManager — module-level singleton for fan-out broadcasting.

Design:
  * Total connections are capped (`MAX_CONNECTIONS`); attempts past the cap
    raise `ConnectionRefused` so the router can respond with a policy code.
  * Each subscriber gets a bounded outbound queue (`OUTBOUND_QUEUE`). A slow
    consumer drops its own oldest messages rather than blocking the publisher
    or exhausting API memory.
  * All send errors close the socket rather than swallowing.

For horizontal scale replace the in-memory registry with Redis pub/sub; the
interface (`connect`/`disconnect`/`broadcast`) does not change.
"""

from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass, field

from fastapi import WebSocket
from fastapi.websockets import WebSocketDisconnect

logger = logging.getLogger(__name__)

MAX_CONNECTIONS = 500
OUTBOUND_QUEUE = 100


class ConnectionRefused(Exception):
    """Raised when the manager is at capacity."""


@dataclass
class _Subscriber:
    websocket: WebSocket
    queue: asyncio.Queue = field(default_factory=lambda: asyncio.Queue(maxsize=OUTBOUND_QUEUE))
    worker: asyncio.Task | None = None


class ConnectionManager:
    def __init__(self) -> None:
        self._subs: dict[WebSocket, _Subscriber] = {}
        self._lock = asyncio.Lock()

    async def connect(self, websocket: WebSocket) -> None:
        async with self._lock:
            if len(self._subs) >= MAX_CONNECTIONS:
                raise ConnectionRefused()
            await websocket.accept()
            sub = _Subscriber(websocket=websocket)
            sub.worker = asyncio.create_task(self._pump(sub))
            self._subs[websocket] = sub
        logger.info("WebSocket connected (total=%d)", len(self._subs))

    def disconnect(self, websocket: WebSocket) -> None:
        sub = self._subs.pop(websocket, None)
        if sub and sub.worker:
            sub.worker.cancel()
        logger.info("WebSocket disconnected (total=%d)", len(self._subs))

    async def broadcast(self, data: dict) -> None:
        if not self._subs:
            return
        message = json.dumps(data, default=str)
        for sub in list(self._subs.values()):
            try:
                sub.queue.put_nowait(message)
            except asyncio.QueueFull:
                # Drop-oldest: pop and retry. Ensures a slow consumer never
                # blocks the publisher or a fast one.
                try:
                    sub.queue.get_nowait()
                except asyncio.QueueEmpty:
                    pass
                try:
                    sub.queue.put_nowait(message)
                except asyncio.QueueFull:
                    logger.warning("Dropping message; subscriber queue saturated")

    async def _pump(self, sub: _Subscriber) -> None:
        try:
            while True:
                message = await sub.queue.get()
                try:
                    await sub.websocket.send_text(message)
                except (WebSocketDisconnect, RuntimeError):
                    break
                except Exception:
                    logger.exception("Broadcast send failed; closing subscriber")
                    break
        except asyncio.CancelledError:
            raise
        finally:
            self.disconnect(sub.websocket)

    # Exposed for tests / observability.
    @property
    def active_count(self) -> int:
        return len(self._subs)


manager = ConnectionManager()
