import os
import uuid
import hashlib
import datetime
import asyncio
import subprocess
from fastapi import APIRouter, Depends, UploadFile, File, BackgroundTasks, HTTPException, WebSocket, WebSocketDisconnect
from sqlalchemy.orm import Session
from typing import List, Optional

from v2.database import get_v2_db
from v2.models import V2Job, V2Event, V2Report
from v2.schemas import (
    V2JobResponse, V2JobDetailResponse, V2JobStatusResponse,
    V2EventResponse, V2ReportResponse, V2HealthResponse
)
from v2.config import UPLOAD_DIR, ADB_PATH, EMULATOR_AVD_NAME
from services.websocket_manager import manager

router = APIRouter(prefix="/api/v2", tags=["SentinelAI v2"])

# We import the pipeline runner dynamically to avoid circular dependencies
def get_pipeline_runner():
    from v2.orchestrator import run_v2_pipeline
    return run_v2_pipeline

@router.post("/jobs", response_model=V2JobResponse, status_code=202)
def create_analysis_job(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    analysis_mode: str = "full",
    timeout_seconds: int = 180,
    db: Session = Depends(get_v2_db)
):
    """
    Upload an APK sample and start static/dynamic sandbox analysis.
    """
    if analysis_mode not in ["full", "static_only", "dynamic_only"]:
        raise HTTPException(status_code=400, detail="Invalid analysis_mode. Choose from: full, static_only, dynamic_only")

    # Enforce size restrictions (e.g. 500MB)
    MAX_SIZE = 500 * 1024 * 1024
    
    # Ensure filename has no path traversal components
    original_filename = os.path.basename(file.filename)
    
    # Generate UUID filename while preserving extension
    _, ext = os.path.splitext(original_filename)
    if ext.lower() not in [".apk", ".zip"]:
        ext = ".apk"
        
    if "simulated_" in original_filename:
        secure_filename = f"simulated_{uuid.uuid4().hex}{ext}"
    else:
        secure_filename = f"{uuid.uuid4().hex}{ext}"
    temp_path = os.path.join(UPLOAD_DIR, secure_filename)
    
    sha256_hash = hashlib.sha256()
    size = 0
    
    try:
        with open(temp_path, "wb") as buffer:
            while True:
                chunk = file.file.read(1024 * 1024)
                if not chunk:
                    break
                size += len(chunk)
                if size > MAX_SIZE:
                    os.remove(temp_path)
                    raise HTTPException(status_code=400, detail="File too large. Maximum size is 500MB.")
                buffer.write(chunk)
                sha256_hash.update(chunk)
    except Exception as e:
        if os.path.exists(temp_path):
            os.remove(temp_path)
        raise HTTPException(status_code=500, detail=f"Upload processing failed: {str(e)}")
        
    sha256_hex = sha256_hash.hexdigest()
    
    # Check cache hit (completed job in v2 with matching SHA256 and analysis mode)
    cached_job = db.query(V2Job).filter(
        V2Job.sha256 == sha256_hex,
        V2Job.analysis_mode == analysis_mode,
        V2Job.status == "COMPLETED"
    ).order_by(V2Job.completed_at.desc()).first()
    
    if cached_job:
        # Create a cloned job record to return immediately
        job = V2Job(
            filename=original_filename,
            sha256=sha256_hex,
            file_size=size,
            package_name=cached_job.package_name,
            analysis_mode=analysis_mode,
            timeout_seconds=timeout_seconds,
            status="COMPLETED",
            progress=100,
            current_stage="COMPLETED",
            static_findings=cached_job.static_findings,
            dynamic_summary=cached_job.dynamic_summary,
            iocs=cached_job.iocs,
            mitre_mappings=cached_job.mitre_mappings,
            risk_factors=cached_job.risk_factors,
            static_risk_score=cached_job.static_risk_score,
            dynamic_risk_score=cached_job.dynamic_risk_score,
            risk_score=cached_job.risk_score,
            severity=cached_job.severity,
            confidence=cached_job.confidence,
            malware_family=cached_job.malware_family,
            verdict=cached_job.verdict,
            completed_at=datetime.datetime.utcnow()
        )
        db.add(job)
        db.commit()
        db.refresh(job)
        
        # Clone events
        for ev in cached_job.events:
            db.add(V2Event(
                job_id=job.id,
                timestamp=ev.timestamp,
                elapsed_ms=ev.elapsed_ms,
                event_type=ev.event_type,
                source=ev.source,
                process_name=ev.process_name,
                payload=ev.payload,
                risk_weight=ev.risk_weight,
                is_suspicious=ev.is_suspicious
            ))
            
        # Clone report
        if cached_job.report:
            db.add(V2Report(
                job_id=job.id,
                executive_summary=cached_job.report.executive_summary,
                technical_report=cached_job.report.technical_report,
                behavioral_summary=cached_job.report.behavioral_summary,
                remediation=cached_job.report.remediation,
                mitre_mapping=cached_job.report.mitre_mapping,
                owasp_mapping=cached_job.report.owasp_mapping,
                risk_factors=cached_job.report.risk_factors,
                ai_model_used=cached_job.report.ai_model_used
            ))
            
        db.commit()
        return job

    # Create new database record for a fresh run
    job = V2Job(
        filename=original_filename,
        sha256=sha256_hex,
        file_size=size,
        analysis_mode=analysis_mode,
        timeout_seconds=timeout_seconds,
        status="QUEUED",
        progress=0,
        current_stage="QUEUED"
    )
    db.add(job)
    db.commit()
    db.refresh(job)
    
    # Queue background pipeline task
    run_v2_pipeline = get_pipeline_runner()
    background_tasks.add_task(run_v2_pipeline, job.id, temp_path)
    
    return job

@router.get("/jobs", response_model=List[V2JobResponse])
def list_analysis_jobs(db: Session = Depends(get_v2_db)):
    """
    List all v2 analysis jobs.
    """
    return db.query(V2Job).order_by(V2Job.created_at.desc()).all()

@router.get("/jobs/{job_id}", response_model=V2JobDetailResponse)
def get_analysis_job_detail(job_id: str, db: Session = Depends(get_v2_db)):
    """
    Get full job detail (job metadata, events, and report).
    """
    job = db.query(V2Job).filter(V2Job.id == job_id).first()
    if not job:
        raise HTTPException(status_code=404, detail="Analysis job not found.")
        
    events = db.query(V2Event).filter(V2Event.job_id == job_id).order_by(V2Event.timestamp.asc()).all()
    report = db.query(V2Report).filter(V2Report.job_id == job_id).first()
    
    return {
        "job": job,
        "events": events,
        "report": report
    }

@router.get("/jobs/{job_id}/status", response_model=V2JobStatusResponse)
def get_analysis_job_status(job_id: str, db: Session = Depends(get_v2_db)):
    """
    Lightweight endpoint to poll the status of a running job.
    """
    job = db.query(V2Job).filter(V2Job.id == job_id).first()
    if not job:
        raise HTTPException(status_code=404, detail="Analysis job not found.")
    return job

@router.get("/jobs/{job_id}/events", response_model=List[V2EventResponse])
def get_analysis_job_events(
    job_id: str, 
    event_type: Optional[str] = None, 
    is_suspicious: Optional[bool] = None, 
    db: Session = Depends(get_v2_db)
):
    """
    Get raw events for a job, optionally filtered by type or severity.
    """
    query = db.query(V2Event).filter(V2Event.job_id == job_id)
    if event_type:
        query = query.filter(V2Event.event_type == event_type)
    if is_suspicious is not None:
        query = query.filter(V2Event.is_suspicious == is_suspicious)
    return query.order_by(V2Event.timestamp.asc()).all()

@router.get("/jobs/{job_id}/report", response_model=V2ReportResponse)
def get_analysis_job_report(job_id: str, db: Session = Depends(get_v2_db)):
    """
    Get the AI investigation report.
    """
    report = db.query(V2Report).filter(V2Report.job_id == job_id).first()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found or not yet generated.")
    return report

@router.delete("/jobs/{job_id}")
def delete_analysis_job(job_id: str, db: Session = Depends(get_v2_db)):
    """
    Delete a v2 analysis job from database.
    """
    job = db.query(V2Job).filter(V2Job.id == job_id).first()
    if not job:
        raise HTTPException(status_code=404, detail="Job not found.")
    db.delete(job)
    db.commit()
    return {"message": "Job successfully deleted."}

@router.post("/jobs/{job_id}/cancel")
def cancel_analysis_job(job_id: str, db: Session = Depends(get_v2_db)):
    """
    Cancel an active static/dynamic analysis job, detach Frida tracing, kill emulator process, and clean up guest environment.
    """
    job = db.query(V2Job).filter(V2Job.id == job_id).first()
    if not job:
        raise HTTPException(status_code=404, detail="Analysis job not found.")
        
    if job.status in ["COMPLETED", "FAILED", "CANCELLED"]:
        return {"status": "ignored", "message": f"Job is already in {job.status} state."}
        
    job.status = "CANCELLED"
    job.current_stage = "CANCELLED"
    db.commit()
    
    # Active resource cleanup
    from v2.orchestrator import ACTIVE_SESSIONS
    session_info = ACTIVE_SESSIONS.get(job_id)
    if session_info:
        # 1. Detach Frida tracing session
        frida_session = session_info.get("frida_session")
        if frida_session:
            try:
                frida_session.detach()
            except Exception:
                pass
                
        # 2. Stop and uninstall package
        package_name = session_info.get("package_name")
        if package_name and package_name != "unknown.package":
            try:
                # Force stop package
                subprocess.run([ADB_PATH, "shell", "pm", "force-stop", package_name], capture_output=True)
                # Uninstall package
                subprocess.run([ADB_PATH, "uninstall", package_name], capture_output=True)
            except Exception:
                pass
                
        # 3. Clean up temporary uploaded file on host
        temp_path = session_info.get("temp_path")
        if temp_path and os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except Exception:
                pass
                
        # 4. Stop running emulator process
        try:
            res = subprocess.run([ADB_PATH, "devices"], capture_output=True, text=True, timeout=5)
            if "emulator-" in res.stdout:
                # Issue kill command to active emulator
                subprocess.run([ADB_PATH, "emu", "kill"], capture_output=True)
        except Exception:
            pass
            
        # Remove from ACTIVE_SESSIONS registry
        ACTIVE_SESSIONS.pop(job_id, None)
        
    return {"status": "cancelled", "message": "Job cancellation initiated successfully."}

@router.get("/health", response_model=V2HealthResponse)
def check_v2_health():
    """
    Health check endpoint for checking the status of AVD, ADB, and Frida.
    """
    adb_connected = False
    emulator_running = False
    frida_available = False

    try:
        # Check ADB connection
        result = subprocess.run([ADB_PATH, "devices"], capture_output=True, text=True, timeout=5)
        lines = result.stdout.strip().split("\n")
        # Second line usually lists devices if connected
        devices = [line for line in lines[1:] if line.strip() and "device" in line]
        if devices:
            adb_connected = True
            
            # Check if emulator is running
            for d in devices:
                if "emulator" in d:
                    emulator_running = True
                    break

            # Check if frida-server is running in the emulator
            frida_check = subprocess.run([ADB_PATH, "shell", "ps | grep frida"], capture_output=True, text=True, timeout=5)
            if "frida" in frida_check.stdout:
                frida_available = True
    except Exception:
        pass

    return {
        "status": "healthy" if adb_connected else "degraded",
        "adb_connected": adb_connected,
        "emulator_running": emulator_running,
        "frida_available": frida_available
    }

@router.websocket("/ws/{job_id}")
async def websocket_logs_v2_endpoint(websocket: WebSocket, job_id: str):
    """
    WebSocket endpoint for real-time sandbox events streaming.
    Uses the same WebSocketManager from v1.
    """
    await manager.connect(websocket, job_id)
    try:
        await websocket.send_json({
            "type": "SYSTEM",
            "message": f"Connected to SentinelAI v2 real-time telemetry stream for Job {job_id}."
        })
        while True:
            # Keep-alive loop
            data = await websocket.receive_text()
            await websocket.send_json({"type": "PONG", "message": "Keepalive verified"})
    except WebSocketDisconnect:
        manager.disconnect(websocket, job_id)
    except Exception:
        manager.disconnect(websocket, job_id)
