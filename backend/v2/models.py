import datetime
import uuid
from sqlalchemy import Column, String, Integer, DateTime, Text, ForeignKey, JSON, Float, Boolean
from sqlalchemy.orm import relationship
from v2.database import Base

class V2Job(Base):
    __tablename__ = "v2_jobs"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    filename = Column(String, nullable=False)
    sha256 = Column(String, nullable=False, index=True)
    file_size = Column(Integer, nullable=False)
    package_name = Column(String, nullable=True)

    # Configuration
    analysis_mode = Column(String, default="full")  # static_only | dynamic_only | full
    timeout_seconds = Column(Integer, default=180)

    # Status
    status = Column(String, default="QUEUED")
    # QUEUED → STATIC_ANALYSIS → EMULATOR_BOOT → INSTALLING →
    # INSTRUMENTING → RUNNING → COLLECTING → AI_ANALYSIS →
    # COMPLETED | FAILED | TIMEOUT
    progress = Column(Integer, default=0)  # 0-100
    current_stage = Column(String, nullable=True)
    error_message = Column(Text, nullable=True)

    # Results Data Blobs
    static_findings = Column(JSON, nullable=True)  # full parse_apk() dict
    dynamic_summary = Column(JSON, nullable=True)  # event counts, top events, etc.
    iocs = Column(JSON, nullable=True)             # extracted indicators of compromise
    mitre_mappings = Column(JSON, nullable=True)   # MITRE ATT&CK techniques
    risk_factors = Column(JSON, nullable=True)     # detailed risk findings

    # Risk Metrics
    static_risk_score = Column(Integer, nullable=True)
    dynamic_risk_score = Column(Integer, nullable=True)
    risk_score = Column(Integer, nullable=True)     # combined
    severity = Column(String, nullable=True)        # Low | Medium | High | Critical
    confidence = Column(Integer, nullable=True)
    malware_family = Column(String, nullable=True)
    verdict = Column(String, nullable=True)         # clean | suspicious | malicious

    # Timestamps
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)

    # Relationships
    events = relationship("V2Event", back_populates="job", cascade="all, delete-orphan")
    report = relationship("V2Report", back_populates="job", uselist=False, cascade="all, delete-orphan")


class V2Event(Base):
    __tablename__ = "v2_events"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    job_id = Column(String, ForeignKey("v2_jobs.id"), index=True, nullable=False)

    timestamp = Column(DateTime, default=datetime.datetime.utcnow)
    elapsed_ms = Column(Integer, nullable=True)  # ms since sandbox start
    event_type = Column(String, nullable=False, index=True)
    # network_request | dns_query | file_write | file_read |
    # sms_send | crypto_op | dex_load | reflection_call |
    # shell_exec | device_info | permission_request |
    # evasion_emulator | evasion_root | evasion_debugger

    source = Column(String, nullable=False)  # frida | mitmproxy | logcat
    process_name = Column(String, nullable=True)
    payload = Column(JSON, nullable=False)   # event-specific data
    risk_weight = Column(Float, default=0.0)
    is_suspicious = Column(Boolean, default=False)

    job = relationship("V2Job", back_populates="events")


class V2Report(Base):
    __tablename__ = "v2_reports"

    job_id = Column(String, ForeignKey("v2_jobs.id"), primary_key=True)

    executive_summary = Column(Text, nullable=False)
    technical_report = Column(Text, nullable=False)
    behavioral_summary = Column(Text, nullable=False)
    remediation = Column(Text, nullable=False)

    mitre_mapping = Column(JSON, nullable=True)
    owasp_mapping = Column(JSON, nullable=True)
    risk_factors = Column(JSON, nullable=True)
    ai_model_used = Column(String, nullable=True)
    generated_at = Column(DateTime, default=datetime.datetime.utcnow)

    job = relationship("V2Job", back_populates="report")
