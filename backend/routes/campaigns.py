from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from typing import List
import hashlib

from database import get_db, Job, Finding
from schemas import CampaignResponse
from routes.jobs import verify_api_key_header

router = APIRouter(prefix="/api/campaigns", tags=["Campaigns"], dependencies=[Depends(verify_api_key_header)])

@router.get("", response_model=List[CampaignResponse])
def get_campaigns(db: Session = Depends(get_db)):
    completed_jobs = db.query(Job).filter(Job.status == "COMPLETED").all()
    
    domain_map = {}
    for job in completed_jobs:
        findings = db.query(Finding).filter(Finding.job_id == job.id, Finding.type == "url").all()
        for f in findings:
            domain = f.evidence_snippet
            if domain:
                if domain not in domain_map:
                    domain_map[domain] = []
                domain_map[domain].append({
                    "job_id": job.id,
                    "filename": job.filename,
                    "risk_score": job.risk_score or 0,
                    "malware_family": job.malware_family or "Unknown"
                })
                
    campaigns = []
    # If jobs share the same external indicator, package them into a campaign group
    for domain, linked_apps in domain_map.items():
        if len(linked_apps) > 1:
            campaigns.append({
                "campaign_id": hashlib.md5(domain.encode()).hexdigest()[:12],
                "correlated_value": domain,
                "type": "C2 Server Infrastructure",
                "malware_family": linked_apps[0]["malware_family"],
                "threat_level": "High" if len(linked_apps) > 2 else "Medium",
                "affected_apps": linked_apps
            })
            
    # Default campaigns to seed the visual interface for high-fidelity demonstration
    if not campaigns:
        campaigns = [
            {
                "campaign_id": "c_anubis_01",
                "correlated_value": "http://194.26.135.84/api/v2",
                "type": "C2 Server IP Infrastructure",
                "malware_family": "Anubis Banking Trojan (Simulated)",
                "threat_level": "High",
                "affected_apps": [
                    {"job_id": "anubis_job_1", "filename": "Anubis_Update_v2.apk", "risk_score": 85, "malware_family": "Anubis Banking Trojan"},
                    {"job_id": "anubis_job_2", "filename": "FlashPlayer_Utility.apk", "risk_score": 90, "malware_family": "Anubis Banking Trojan"}
                ]
            },
            {
                "campaign_id": "c_shark_02",
                "correlated_value": "fast-update-bank.online",
                "type": "Phishing Gate Domain",
                "malware_family": "SharkBot Financial Trojan (Simulated)",
                "threat_level": "Critical",
                "affected_apps": [
                    {"job_id": "shark_job_1", "filename": "HDFC_MobileBank_Sec.apk", "risk_score": 95, "malware_family": "SharkBot Financial Trojan"},
                    {"job_id": "shark_job_2", "filename": "SBI_Yono_Update.apk", "risk_score": 95, "malware_family": "SharkBot Financial Trojan"}
                ]
            }
        ]
        
    return campaigns
