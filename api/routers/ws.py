from fastapi import APIRouter
from fastapi.websockets import WebSocket, WebSocketDisconnect

from api.services.broadcast_service import manager

router = APIRouter()


@router.websocket("/ws/feed")
async def websocket_feed(websocket: WebSocket) -> None:
    """
    Real-time incident feed via WebSocket.
    Clients connect here and receive incident summaries as JSON whenever
    a new prediction creates an incident (broadcast from POST /predict).
    """
    await manager.connect(websocket)
    try:
        while True:
            # Keep connection alive; ignore client messages (ping/pong handled by uvicorn)
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)
