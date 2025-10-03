"""
WebSocket endpoint for real-time prediction updates.
"""
import logging
import asyncio
import json
from typing import Set
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from datetime import datetime

from app.schemas.schemas import WebSocketMessage


logger = logging.getLogger(__name__)
router = APIRouter()


class ConnectionManager:
    """Manages WebSocket connections for real-time updates."""
    
    def __init__(self):
        self.active_connections: Set[WebSocket] = set()
    
    async def connect(self, websocket: WebSocket):
        """Accept and register a new WebSocket connection."""
        await websocket.accept()
        self.active_connections.add(websocket)
        logger.info(f"WebSocket connected. Total connections: {len(self.active_connections)}")
    
    def disconnect(self, websocket: WebSocket):
        """Unregister a WebSocket connection."""
        self.active_connections.discard(websocket)
        logger.info(f"WebSocket disconnected. Total connections: {len(self.active_connections)}")
    
    async def send_personal_message(self, message: dict, websocket: WebSocket):
        """Send a message to a specific WebSocket connection."""
        try:
            await websocket.send_json(message)
        except Exception as e:
            logger.error(f"Error sending message to websocket: {e}")
            self.disconnect(websocket)
    
    async def broadcast(self, message: dict):
        """Broadcast a message to all connected WebSocket clients."""
        disconnected = set()
        
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except Exception as e:
                logger.error(f"Error broadcasting to websocket: {e}")
                disconnected.add(connection)
        
        # Remove disconnected clients
        for connection in disconnected:
            self.disconnect(connection)
    
    def get_connection_count(self) -> int:
        """Get the number of active connections."""
        return len(self.active_connections)


# Global connection manager
manager = ConnectionManager()


@router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """
    WebSocket endpoint for real-time predictions.
    
    Clients connect to this endpoint to receive real-time prediction updates.
    
    Message format:
    {
        "type": "prediction" | "traffic" | "alert" | "stats",
        "data": {...},
        "timestamp": "2025-10-01T12:00:00Z"
    }
    """
    await manager.connect(websocket)
    
    try:
        # Send welcome message
        await manager.send_personal_message(
            {
                "type": "connection",
                "data": {"status": "connected", "message": "Welcome to Threat Prediction WebSocket"},
                "timestamp": datetime.utcnow().isoformat()
            },
            websocket
        )
        
        # Keep connection alive and handle incoming messages
        while True:
            # Receive messages from client (ping/pong, config updates, etc.)
            try:
                data = await asyncio.wait_for(websocket.receive_text(), timeout=30.0)
                message = json.loads(data)
                
                # Handle client messages
                msg_type = message.get("type")
                
                if msg_type == "ping":
                    await manager.send_personal_message(
                        {
                            "type": "pong",
                            "timestamp": datetime.utcnow().isoformat()
                        },
                        websocket
                    )
                
                elif msg_type == "subscribe":
                    # Client can subscribe to specific event types
                    await manager.send_personal_message(
                        {
                            "type": "subscribed",
                            "data": {"channels": message.get("channels", [])},
                            "timestamp": datetime.utcnow().isoformat()
                        },
                        websocket
                    )
                
            except asyncio.TimeoutError:
                # Send periodic heartbeat if no messages received
                await manager.send_personal_message(
                    {
                        "type": "heartbeat",
                        "timestamp": datetime.utcnow().isoformat()
                    },
                    websocket
                )
    
    except WebSocketDisconnect:
        manager.disconnect(websocket)
        logger.info("Client disconnected normally")
    
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
        manager.disconnect(websocket)


async def broadcast_prediction(prediction_data: dict):
    """
    Broadcast a prediction to all connected clients.
    
    Args:
        prediction_data: Prediction details to broadcast
    """
    message = {
        "type": "prediction",
        "data": prediction_data,
        "timestamp": datetime.utcnow().isoformat()
    }
    await manager.broadcast(message)


async def broadcast_alert(alert_data: dict):
    """
    Broadcast an alert to all connected clients.
    
    Args:
        alert_data: Alert details to broadcast
    """
    message = {
        "type": "alert",
        "data": alert_data,
        "timestamp": datetime.utcnow().isoformat()
    }
    await manager.broadcast(message)


async def broadcast_stats(stats_data: dict):
    """
    Broadcast statistics to all connected clients.
    
    Args:
        stats_data: Statistics to broadcast
    """
    message = {
        "type": "stats",
        "data": stats_data,
        "timestamp": datetime.utcnow().isoformat()
    }
    await manager.broadcast(message)


def get_connection_count() -> int:
    """Get the number of active WebSocket connections."""
    return manager.get_connection_count()
