import os
import asyncio
from dotenv import load_dotenv
load_dotenv()
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from typing import Dict, List

# Import Database initializers
from database import init_db

# Import Routers
from routes.jobs import router as jobs_router
from routes.campaigns import router as campaigns_router
from routes.keys import router as keys_router

app = FastAPI(
    title="SentinelAI Core API",
    description="Multi-Agent Automated Android Malware Investigation & Risk Assessment Platform Backend",
    version="2.0"
)

# CORS configuration to allow local Next.js client access
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize relational database tables on startup
@app.on_event("startup")
def startup_event():
    init_db()

# Include Routers
app.include_router(jobs_router)
app.include_router(campaigns_router)
app.include_router(keys_router)

from services.websocket_manager import manager

@app.websocket("/api/ws/{job_id}")
async def websocket_logs_endpoint(websocket: WebSocket, job_id: str):
    await manager.connect(websocket, job_id)
    try:
        # Initial greeting
        await websocket.send_json({
            "type": "SYSTEM",
            "message": f"Connected to analysis logging stream for Job {job_id}."
        })
        while True:
            # Sockets must read to stay alive
            data = await websocket.receive_text()
            await websocket.send_json({"type": "PONG", "message": "Stay-alive verified"})
    except WebSocketDisconnect:
        manager.disconnect(websocket, job_id)
    except Exception:
        manager.disconnect(websocket, job_id)

@app.get("/api/health")
def health_check():
    return {"status": "healthy", "service": "SentinelAI API", "engine": "FastAPI"}

from fastapi import BackgroundTasks, Depends, HTTPException
from sqlalchemy.orm import Session
import hashlib
from database import get_db
from schemas import JobResponse
import services.db_service as db_service
from routes.jobs import background_agent_worker, UPLOAD_DIR

@app.post("/api/upload-sample", response_model=JobResponse, status_code=202)
def upload_sample(
    sample_key: str,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
):
    if sample_key not in ["anubis", "sharkbot", "cerberus"]:
        raise HTTPException(status_code=400, detail="Invalid sample key. Choose from: anubis, sharkbot, cerberus")
        
    filename = f"simulated_{sample_key}.apk"
    sha256_hex = hashlib.sha256(filename.encode()).hexdigest()
    
    # Create the job in db
    job = db_service.create_job(db, filename, sha256_hex, 1024)
    
    # Ensure upload directory and dummy file exist
    temp_path = os.path.join(UPLOAD_DIR, filename)
    with open(temp_path, "w") as f:
        f.write("simulation")
        
    # Queue background task to run agent workflow
    background_tasks.add_task(background_agent_worker, job.id, temp_path)
    
    return job


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)

