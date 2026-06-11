from pydantic import BaseModel, Field
from typing import List, Optional, Any
from datetime import datetime

# API Key schemas
class ApiKeyBase(BaseModel):
    name: str

class ApiKeyCreate(ApiKeyBase):
    pass

class ApiKeyResponse(ApiKeyBase):
    id: str
    key_prefix: str
    created_at: datetime

    class Config:
        from_attributes = True

class ApiKeyGeneratedResponse(ApiKeyResponse):
    full_key: str

# Finding schemas
class FindingBase(BaseModel):
    type: str
    title: str
    description: str
    severity: str
    location: Optional[str] = None
    evidence_snippet: Optional[str] = None

class FindingResponse(FindingBase):
    id: str
    job_id: str

    class Config:
        from_attributes = True

# Report schemas
class ReportBase(BaseModel):
    executive_summary: str
    technical_report: str
    remediation_guidance: str
    mitre_mapping: Optional[List[Any]] = None
    owasp_mapping: Optional[List[Any]] = None

class ReportResponse(ReportBase):
    job_id: str

    class Config:
        from_attributes = True

# Job schemas
class JobBase(BaseModel):
    filename: str
    sha256: str
    size_bytes: int

class JobResponse(JobBase):
    id: str
    status: str
    risk_score: Optional[int] = None
    severity: Optional[str] = None
    confidence: Optional[int] = None
    malware_family: Optional[str] = None
    created_at: datetime
    completed_at: Optional[datetime] = None

    class Config:
        from_attributes = True

class JobDetailResponse(BaseModel):
    job: JobResponse
    findings: List[FindingResponse]
    report: Optional[ReportResponse] = None

# Campaign schemas
class CampaignAppResponse(BaseModel):
    job_id: str
    filename: str
    risk_score: int
    malware_family: str

class CampaignResponse(BaseModel):
    campaign_id: str
    correlated_value: str
    type: str
    malware_family: str
    threat_level: str
    affected_apps: List[CampaignAppResponse]
