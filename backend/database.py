import os
import datetime
import uuid
from sqlalchemy import create_engine, Column, String, Integer, DateTime, Text, ForeignKey, JSON
from sqlalchemy.orm import declarative_base, sessionmaker, relationship

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sentinel_ai.db")
DATABASE_URL = f"sqlite:///{DB_PATH}"

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class Job(Base):
    __tablename__ = "jobs"
    
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    filename = Column(String, nullable=False)
    sha256 = Column(String, nullable=False, index=True)
    size_bytes = Column(Integer, nullable=False)
    status = Column(String, nullable=False, default="QUEUED")  # QUEUED, ANALYZING, COMPLETED, FAILED
    risk_score = Column(Integer, nullable=True)
    severity = Column(String, nullable=True)                  # Low, Medium, High, Critical
    confidence = Column(Integer, nullable=True)
    malware_family = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)
    
    findings = relationship("Finding", back_populates="job", cascade="all, delete-orphan")
    report = relationship("Report", back_populates="job", uselist=False, cascade="all, delete-orphan")

class Finding(Base):
    __tablename__ = "findings"
    
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    job_id = Column(String, ForeignKey("jobs.id"), nullable=False)
    type = Column(String, nullable=False)                      # permission, api, url, obfuscation, threat
    title = Column(String, nullable=False)
    description = Column(Text, nullable=False)
    severity = Column(String, nullable=False)                  # Low, Medium, High, Critical
    location = Column(String, nullable=True)
    evidence_snippet = Column(Text, nullable=True)
    extra_data = Column(JSON, nullable=True)
    
    job = relationship("Job", back_populates="findings")

class Report(Base):
    __tablename__ = "reports"
    
    job_id = Column(String, ForeignKey("jobs.id"), primary_key=True)
    executive_summary = Column(Text, nullable=False)
    technical_report = Column(Text, nullable=False)
    remediation_guidance = Column(Text, nullable=False)
    mitre_mapping = Column(JSON, nullable=True)                # List of mapped TTPs
    owasp_mapping = Column(JSON, nullable=True)                # List of mapped OWASP items
    
    job = relationship("Job", back_populates="report")

class ApiKey(Base):
    __tablename__ = "api_keys"
    
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String, nullable=False)
    key_prefix = Column(String, nullable=False)
    hashed_key = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

def init_db():
    Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
