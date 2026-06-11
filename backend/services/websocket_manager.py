from fastapi import WebSocket
from typing import Dict, List

class WebSocketManager:
    def __init__(self):
        # Map of job_id -> list of active WebSocket connections
        self.active_connections: Dict[str, List[WebSocket]] = {}
        
    async def connect(self, websocket: WebSocket, job_id: str):
        await websocket.accept()
        if job_id not in self.active_connections:
            self.active_connections[job_id] = []
        self.active_connections[job_id].append(websocket)
        
    def disconnect(self, websocket: WebSocket, job_id: str):
        if job_id in self.active_connections:
            if websocket in self.active_connections[job_id]:
                self.active_connections[job_id].remove(websocket)
            if not self.active_connections[job_id]:
                del self.active_connections[job_id]
                
    async def broadcast(self, job_id: str, message: dict):
        if job_id in self.active_connections:
            dead_connections = []
            for ws in self.active_connections[job_id]:
                try:
                    await ws.send_json(message)
                except Exception:
                    dead_connections.append(ws)
            # Purge any closed sockets
            for ws in dead_connections:
                self.disconnect(ws, job_id)

manager = WebSocketManager()
