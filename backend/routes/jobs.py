import os
import hashlib
import datetime
import asyncio
import time
from fastapi import APIRouter, Depends, UploadFile, File, BackgroundTasks, HTTPException, Header
from sqlalchemy.orm import Session
from typing import List, Optional

from database import get_db, Job, Finding, Report, ApiKey
from schemas import JobResponse, JobDetailResponse
import services.db_service as db_service
from services.agents import execute_agent_workflow
from services.websocket_manager import manager

def verify_api_key_header(x_api_key: Optional[str] = Header(None, alias="X-API-Key"), db: Session = Depends(get_db)):
    total_keys = db.query(ApiKey).count()
    if total_keys == 0:
        return
    if not x_api_key:
        raise HTTPException(status_code=401, detail="X-API-Key header is missing. Secure access is enabled.")
    if not db_service.validate_api_key(db, x_api_key):
        raise HTTPException(status_code=401, detail="Invalid X-API-Key.")

router = APIRouter(prefix="/api/jobs", tags=["Jobs"], dependencies=[Depends(verify_api_key_header)])

UPLOAD_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)

# Helper function to run the agent graph in a background thread
def background_agent_worker(job_id: str, file_path: str):
    db = next(get_db())
    job = db.query(Job).filter(Job.id == job_id).first()
    if not job:
        db.close()
        return
        
    try:
        job.status = "ANALYZING"
        db.commit()
        
        # Broadcast initial state transition
        asyncio.run(manager.broadcast(job_id, {"type": "STATUS_CHANGE", "status": "ANALYZING"}))
        asyncio.run(manager.broadcast(job_id, {"type": "LOG", "message": "[System] Initializing analysis environment."}))
        
        # Run agent state pipeline
        results = execute_agent_workflow(file_path)
        
        # Stream logs sequentially with a small simulated delay for UX animation
        for log in results["logs"]:
            time.sleep(0.8)
            asyncio.run(manager.broadcast(job_id, {"type": "LOG", "message": log}))
            
        # Save extracted findings
        db_service.add_job_findings(db, job_id, results["code_findings"])
        
        # Save generated report
        report_data = {
            "executive_summary": results["report"]["executive_summary"],
            "technical_report": results["report"]["technical_report"],
            "remediation_guidance": results["report"]["remediation_guidance"],
            "mitre_mapping": results["threat_intel"]["mitre_mapping"],
            "owasp_mapping": results["threat_intel"]["owasp_mapping"]
        }
        db_service.save_job_report(db, job_id, report_data)
        
        # Update final job state
        job.status = "COMPLETED"
        job.risk_score = results["risk_assessment"]["risk_score"]
        job.severity = results["risk_assessment"]["severity"]
        job.confidence = results["risk_assessment"]["confidence_score"]
        job.malware_family = results["threat_intel"]["malware_family"]
        job.completed_at = datetime.datetime.utcnow()
        db.commit()
        
        # Broadcast completion status and metrics
        asyncio.run(manager.broadcast(job_id, {
            "type": "STATUS_CHANGE",
            "status": "COMPLETED",
            "risk_score": job.risk_score,
            "severity": job.severity
        }))
        asyncio.run(manager.broadcast(job_id, {"type": "LOG", "message": "[System] Analysis completed. Reports generated."}))
        
    except Exception as e:
        db.rollback()
        job.status = "FAILED"
        db.commit()
        print(f"Background worker failed for job {job_id}: {str(e)}")
        asyncio.run(manager.broadcast(job_id, {"type": "STATUS_CHANGE", "status": "FAILED"}))
        asyncio.run(manager.broadcast(job_id, {"type": "LOG", "message": f"[System Error] Pipeline crashed: {str(e)}"}))
    finally:
        db.close()

@router.post("/upload", response_model=JobResponse, status_code=202)
def upload_apk(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    db: Session = Depends(get_db)
):
    # Enforce size restrictions (e.g. 500MB)
    MAX_SIZE = 500 * 1024 * 1024
    temp_path = os.path.join(UPLOAD_DIR, file.filename)
    
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
    
    # Check cache hit (completed job with matching SHA256)
    cached_job = db.query(Job).filter(Job.sha256 == sha256_hex, Job.status == "COMPLETED").order_by(Job.completed_at.desc()).first()
    
    # Create new database record
    job = db_service.create_job(db, file.filename, sha256_hex, size)
    
    if cached_job:
        # Accelerated duplicate return path: clone findings and report to avoid re-run
        job.status = "COMPLETED"
        job.risk_score = cached_job.risk_score
        job.severity = cached_job.severity
        job.confidence = cached_job.confidence
        job.malware_family = cached_job.malware_family
        job.completed_at = datetime.datetime.utcnow()
        
        # Clone findings
        cached_findings = db.query(Finding).filter(Finding.job_id == cached_job.id).all()
        for f in cached_findings:
            db.add(Finding(
                job_id=job.id,
                type=f.type,
                title=f.title,
                description=f.description,
                severity=f.severity,
                location=f.location,
                evidence_snippet=f.evidence_snippet
            ))
            
        # Clone report
        cached_report = db.query(Report).filter(Report.job_id == cached_job.id).first()
        if cached_report:
            db.add(Report(
                job_id=job.id,
                executive_summary=cached_report.executive_summary,
                technical_report=cached_report.technical_report,
                remediation_guidance=cached_report.remediation_guidance,
                mitre_mapping=cached_report.mitre_mapping,
                owasp_mapping=cached_report.owasp_mapping
            ))
            
        db.commit()
    else:
        # Queue background task
        background_tasks.add_task(background_agent_worker, job.id, temp_path)
        
    return job

@router.get("", response_model=List[JobResponse])
def list_jobs(db: Session = Depends(get_db)):
    return db_service.get_jobs(db)

@router.get("/{job_id}", response_model=JobDetailResponse)
def get_job(job_id: str, db: Session = Depends(get_db)):
    job = db_service.get_job_by_id(db, job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found.")
        
    findings = db.query(Finding).filter(Finding.job_id == job_id).all()
    report = db.query(Report).filter(Report.job_id == job_id).first()
    
    return {
        "job": job,
        "findings": findings,
        "report": report
    }

@router.delete("/{job_id}")
def delete_job(job_id: str, db: Session = Depends(get_db)):
    success = db_service.delete_job_by_id(db, job_id)
    if not success:
        raise HTTPException(status_code=404, detail="Job not found.")
    return {"message": "Job successfully deleted."}
