import asyncio
import json
from typing import Dict, Set
from fastapi import WebSocket
from logger import logger

class ConnectionManager:
    def __init__(self):
        self.active_connections: Dict[int, Set[WebSocket]] = {}
        self.user_connections: Dict[str, WebSocket] = {}

    async def connect(self, websocket: WebSocket, chat_id: int, user_id: str):
        await websocket.accept()
        logger.info(f"WebSocket connected for user {user_id} in chat {chat_id}")

        if chat_id not in self.active_connections:
            self.active_connections[chat_id] = set()
        self.active_connections[chat_id].add(websocket)

        self.user_connections[user_id] = websocket

    async def disconnect(self, websocket: WebSocket, chat_id: int, user_id: str):
        logger.info(f"WebSocket disconnected for user {user_id} in chat {chat_id}")
        
        if chat_id in self.active_connections:
            self.active_connections[chat_id].discard(websocket)
            if not self.active_connections[chat_id]:
                del self.active_connections[chat_id]

        if user_id in self.user_connections:
            del self.user_connections[user_id]

    async def send_personal_message(self, message: str, websocket: WebSocket):
        await websocket.send_text(message)

    async def broadcast_to_chat(self, message: str, chat_id: int):
        if chat_id in self.active_connections:
            disconnected_connections = []
            for connection in self.active_connections[chat_id].copy():
                try:
                    await connection.send_text(message)
                except Exception as e:
                    logger.warning(f"Failed to send message to connection in chat {chat_id}: {e}")
                    disconnected_connections.append(connection)
            
            # Remove disconnected connections
            for connection in disconnected_connections:
                self.active_connections[chat_id].discard(connection)

    async def ping_connections(self):
        """Отправляет ping для поддержания соединений"""
        try:
            while True:
                disconnected_count = 0
                for chat_id, connections in self.active_connections.items():
                    disconnected_connections = []
                    for connection in connections.copy():
                        try:
                            await connection.send_text(json.dumps({"type": "ping"}))
                        except Exception as e:
                            logger.debug(f"Connection ping failed for chat {chat_id}: {e}")
                            disconnected_connections.append(connection)
                            disconnected_count += 1
                    
                    # Remove disconnected connections
                    for connection in disconnected_connections:
                        connections.discard(connection)
                
                if disconnected_count > 0:
                    logger.info(f"Cleaned up {disconnected_count} disconnected WebSocket connections")
                
                await asyncio.sleep(30)
        except asyncio.CancelledError:
            logger.info("Ping task cancelled during shutdown")
            raise  # Re-raise to properly handle cancellation

manager = ConnectionManager()

