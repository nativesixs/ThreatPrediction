"""
WebSocket endpoint for real-time updates.
"""
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
import asyncio
import json
import logging

router = APIRouter()
logger = logging.getLogger(__name__)

# Connected clients
connections: set[WebSocket] = set()


@router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket connection for real-time updates."""
    await websocket.accept()
    connections.add(websocket)
    logger.info(f"WebSocket client connected. Total connections: {len(connections)}")
    
    try:
        # Keep connection alive
        while True:
            # Wait for messages from client (ping/pong)
            data = await websocket.receive_text()
            
            # Echo back
            if data == "ping":
                await websocket.send_text("pong")
    
    except WebSocketDisconnect:
        connections.remove(websocket)
        logger.info(f"WebSocket client disconnected. Remaining: {len(connections)}")
    
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
        connections.discard(websocket)


async def broadcast(message: dict):
    """Broadcast message to all connected clients."""
    if not connections:
        return
    
    message_text = json.dumps(message)
    
    # Send to all connections
    disconnected = set()
    for connection in connections:
        try:
            await connection.send_text(message_text)
        except Exception as e:
            logger.warning(f"Failed to send to client: {e}")
            disconnected.add(connection)
    
    # Remove disconnected clients
    connections.difference_update(disconnected)


async def broadcast_anomaly(anomaly: dict):
    """Broadcast anomaly detection to all clients."""
    await broadcast({
        "type": "anomaly",
        "data": anomaly
    })
