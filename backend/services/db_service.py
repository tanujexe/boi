import datetime
import hashlib
import uuid
from sqlalchemy.orm import Session
from database import Job, Finding, Report, ApiKey

def create_job(db: Session, filename: str, sha256: str, size_bytes: int) -> Job:
    job = Job(
        id=str(uuid.uuid4()),
        filename=filename,
        sha256=sha256,
        size_bytes=size_bytes,
        status="QUEUED"
    )
    db.add(job)
    db.commit()
    db.refresh(job)
    return job

def get_job_by_id(db: Session, job_id: str) -> Job:
    return db.query(Job).filter(Job.id == job_id).first()

def get_jobs(db: Session, limit: int = 100) -> list[Job]:
    return db.query(Job).order_by(Job.created_at.desc()).limit(limit).all()

def delete_job_by_id(db: Session, job_id: str) -> bool:
    job = get_job_by_id(db, job_id)
    if job:
        db.delete(job)
        db.commit()
        return True
    return False

def add_job_findings(db: Session, job_id: str, findings: list[dict]):
    for f in findings:
        finding = Finding(
            id=str(uuid.uuid4()),
            job_id=job_id,
            type=f["type"],
            title=f["title"],
            description=f["description"],
            severity=f["severity"],
            location=f.get("location"),
            evidence_snippet=f.get("evidence_snippet"),
            extra_data=f.get("extra_data", {})
        )
        db.add(finding)
    db.commit()

def save_job_report(db: Session, job_id: str, report_data: dict) -> Report:
    report = Report(
        job_id=job_id,
        executive_summary=report_data["executive_summary"],
        technical_report=report_data["technical_report"],
        remediation_guidance=report_data["remediation_guidance"],
        mitre_mapping=report_data.get("mitre_mapping", []),
        owasp_mapping=report_data.get("owasp_mapping", [])
    )
    db.add(report)
    db.commit()
    return report

def generate_new_api_key(db: Session, name: str) -> dict:
    raw_key = "sentinel_" + hashlib.sha256(str(uuid.uuid4()).encode()).hexdigest()[:32]
    key_prefix = raw_key[:14]  # "sentinel_xxxx"
    hashed_key = hashlib.sha256(raw_key.encode()).hexdigest()
    
    api_key = ApiKey(
        id=str(uuid.uuid4()),
        name=name,
        key_prefix=key_prefix,
        hashed_key=hashed_key
    )
    db.add(api_key)
    db.commit()
    db.refresh(api_key)
    
    return {
        "id": api_key.id,
        "name": api_key.name,
        "key_prefix": api_key.key_prefix,
        "full_key": raw_key,
        "created_at": api_key.created_at
    }

def get_api_keys(db: Session) -> list[ApiKey]:
    return db.query(ApiKey).order_by(ApiKey.created_at.desc()).all()

def revoke_api_key(db: Session, key_id: str) -> bool:
    key = db.query(ApiKey).filter(ApiKey.id == key_id).first()
    if key:
        db.delete(key)
        db.commit()
        return True
    return False

def validate_api_key(db: Session, raw_key: str) -> bool:
    import hashlib
    hashed_key = hashlib.sha256(raw_key.encode()).hexdigest()
    key_record = db.query(ApiKey).filter(ApiKey.hashed_key == hashed_key).first()
    return key_record is not None
