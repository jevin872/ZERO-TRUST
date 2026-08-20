import asyncio
import json
import logging
from fastapi import WebSocket

logger = logging.getLogger(__name__)

class ConnectionManager:
    def __init__(self):
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        logger.info(f"Admin connected to WebSocket. Total active: {len(self.active_connections)}")

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
            logger.info(f"Admin disconnected. Total active: {len(self.active_connections)}")

    async def broadcast(self, message: dict):
        message_str = json.dumps(message)
        disconnected = []
        for connection in self.active_connections:
            try:
                await connection.send_text(message_str)
            except Exception:
                disconnected.append(connection)
                
        # Clean up stale connections
        for conn in disconnected:
            self.disconnect(conn)

    def broadcast_sync(self, message: dict):
        """Thread-safe synchronous wrapper to run async broadcast on the active loop."""
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                loop.create_task(self.broadcast(message))
            else:
                # If loop is not running (e.g. startup or testing), run synchronously
                asyncio.run(self.broadcast(message))
        except Exception as e:
            logger.error(f"Failed to broadcast WebSocket alert: {e}")

manager = ConnectionManager()
