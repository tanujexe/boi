from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from datetime import datetime

class V2JobCreate(BaseModel):
    analysis_mode: Optional[str] = "full"  # static_only | dynamic_only | full
    timeout_seconds: Optional[int] = 180

class V2JobResponse(BaseModel):
    id: str
    filename: str
    sha256: str
    file_size: int
    package_name: Optional[str] = None
    analysis_mode: str
    timeout_seconds: int
    status: str
    progress: int
    current_stage: Optional[str] = None
    error_message: Optional[str] = None
    
    # Results metadata
    dynamic_summary: Optional[Dict[str, Any]] = None
    static_findings: Optional[Dict[str, Any]] = None
    iocs: Optional[List[Any]] = None
    mitre_mappings: Optional[List[Any]] = None
    risk_factors: Optional[List[Any]] = None
    
    static_risk_score: Optional[int] = None
    dynamic_risk_score: Optional[int] = None
    risk_score: Optional[int] = None
    severity: Optional[str] = None
    confidence: Optional[int] = None
    malware_family: Optional[str] = None
    verdict: Optional[str] = None
    
    created_at: datetime
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None

    class Config:
        from_attributes = True

class V2JobStatusResponse(BaseModel):
    id: str
    status: str
    progress: int
    current_stage: Optional[str] = None
    error_message: Optional[str] = None

    class Config:
        from_attributes = True

class V2EventResponse(BaseModel):
    id: str
    job_id: str
    timestamp: datetime
    elapsed_ms: Optional[int] = None
    event_type: str
    source: str
    process_name: Optional[str] = None
    payload: Dict[str, Any]
    risk_weight: float
    is_suspicious: bool

    class Config:
        from_attributes = True

class V2ReportResponse(BaseModel):
    job_id: str
    executive_summary: str
    technical_report: str
    behavioral_summary: str
    remediation: str
    mitre_mapping: Optional[List[Any]] = None
    owasp_mapping: Optional[List[Any]] = None
    risk_factors: Optional[List[Any]] = None
    ai_model_used: Optional[str] = None
    generated_at: datetime

    class Config:
        from_attributes = True

class V2JobDetailResponse(BaseModel):
    job: V2JobResponse
    events: List[V2EventResponse]
    report: Optional[V2ReportResponse] = None

class V2HealthResponse(BaseModel):
    status: str
    adb_connected: bool
    emulator_running: bool
    frida_available: bool
