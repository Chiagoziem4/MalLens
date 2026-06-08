"""
Database models for MalLens analysis system.
"""
import uuid
from datetime import datetime
from enum import Enum as PyEnum

from sqlalchemy import (
    Column, String, Integer, Float, DateTime, Text, JSON, ForeignKey, Enum
)
from sqlalchemy.orm import relationship

from app.core.database import Base


class AnalysisStatus(str, PyEnum):
    PENDING = "pending"
    PROCESSING = "processing"
    STATIC_COMPLETE = "static_complete"
    DYNAMIC_COMPLETE = "dynamic_complete"
    COMPLETED = "completed"
    ERROR = "error"


class ThreatLevel(str, PyEnum):
    CLEAN = "clean"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


def generate_uuid():
    return str(uuid.uuid4())


class Analysis(Base):
    __tablename__ = "analyses"

    id = Column(String, primary_key=True, default=generate_uuid)
    file_name = Column(String, nullable=False)
    file_hash_md5 = Column(String(32))
    file_hash_sha1 = Column(String(40))
    file_hash_sha256 = Column(String(64))
    file_size = Column(Integer)
    file_type = Column(String)
    mime_type = Column(String)
    status = Column(Enum(AnalysisStatus), default=AnalysisStatus.PENDING)
    threat_level = Column(Enum(ThreatLevel), default=ThreatLevel.CLEAN)
    threat_score = Column(Float, default=0.0)
    created_at = Column(DateTime, default=datetime.utcnow)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    error_message = Column(Text, nullable=True)

    # Relationships
    static_result = relationship("StaticResult", back_populates="analysis", uselist=False, cascade="all, delete-orphan")
    dynamic_result = relationship("DynamicResult", back_populates="analysis", uselist=False, cascade="all, delete-orphan")
    iocs = relationship("IOC", back_populates="analysis", cascade="all, delete-orphan")
    report = relationship("Report", back_populates="analysis", uselist=False, cascade="all, delete-orphan")


class StaticResult(Base):
    __tablename__ = "static_results"

    id = Column(String, primary_key=True, default=generate_uuid)
    analysis_id = Column(String, ForeignKey("analyses.id"), nullable=False)

    # File metadata
    file_type_detail = Column(String)
    architecture = Column(String)
    compiler = Column(String)
    packer = Column(String)
    entropy = Column(Float)
    is_packed = Column(String, default="false")

    # PE-specific
    imports = Column(JSON, default=list)
    exports = Column(JSON, default=list)
    sections = Column(JSON, default=list)
    suspicious_imports = Column(JSON, default=list)
    resources = Column(JSON, default=list)

    # Strings & signatures
    interesting_strings = Column(JSON, default=list)
    urls_found = Column(JSON, default=list)
    ips_found = Column(JSON, default=list)
    emails_found = Column(JSON, default=list)

    # YARA
    yara_matches = Column(JSON, default=list)

    # Metadata
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    analysis = relationship("Analysis", back_populates="static_result")


class DynamicResult(Base):
    __tablename__ = "dynamic_results"

    id = Column(String, primary_key=True, default=generate_uuid)
    analysis_id = Column(String, ForeignKey("analyses.id"), nullable=False)

    # Process activity
    processes_created = Column(JSON, default=list)
    process_tree = Column(JSON, default=list)

    # File system
    files_created = Column(JSON, default=list)
    files_modified = Column(JSON, default=list)
    files_deleted = Column(JSON, default=list)

    # Registry (Windows)
    registry_keys_created = Column(JSON, default=list)
    registry_keys_modified = Column(JSON, default=list)
    registry_keys_deleted = Column(JSON, default=list)

    # Network
    dns_queries = Column(JSON, default=list)
    http_requests = Column(JSON, default=list)
    tcp_connections = Column(JSON, default=list)
    udp_connections = Column(JSON, default=list)

    # Behavior
    behavior_tags = Column(JSON, default=list)
    mitre_techniques = Column(JSON, default=list)
    signatures_matched = Column(JSON, default=list)

    # Timeline
    behavior_timeline = Column(JSON, default=list)

    # Metadata
    execution_duration = Column(Float)
    sandbox_type = Column(String, default="simulated")
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    analysis = relationship("Analysis", back_populates="dynamic_result")


class IOC(Base):
    __tablename__ = "iocs"

    id = Column(String, primary_key=True, default=generate_uuid)
    analysis_id = Column(String, ForeignKey("analyses.id"), nullable=False)

    ioc_type = Column(String, nullable=False)  # IP, domain, URL, hash, mutex, file_path, email, registry
    value = Column(String, nullable=False)
    context = Column(String)  # Where it was found
    severity = Column(String, default="medium")  # low, medium, high, critical
    confidence = Column(Float, default=0.5)
    first_observed = Column(DateTime, default=datetime.utcnow)

    # TI enrichment
    ti_source = Column(String)
    ti_reputation = Column(String)
    ti_tags = Column(JSON, default=list)

    # Relationships
    analysis = relationship("Analysis", back_populates="iocs")


class Report(Base):
    __tablename__ = "reports"

    id = Column(String, primary_key=True, default=generate_uuid)
    analysis_id = Column(String, ForeignKey("analyses.id"), nullable=False)

    executive_summary = Column(Text)
    detailed_analysis = Column(Text)
    recommendations = Column(Text)
    mitre_mapping = Column(JSON, default=list)
    risk_assessment = Column(Text)

    generated_at = Column(DateTime, default=datetime.utcnow)
    generator = Column(String, default="ai")  # ai, template, manual

    # Relationships
    analysis = relationship("Analysis", back_populates="report")
