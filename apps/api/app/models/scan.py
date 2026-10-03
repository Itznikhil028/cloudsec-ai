import enum
from datetime import datetime
from sqlalchemy import Column, String, Integer, DateTime, Enum, ForeignKey, Text, JSON
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()

class ScanStatus(str, enum.Enum):
    PENDING = 'PENDING'
    SCANNING = 'SCANNING'
    ANALYZING = 'ANALYZING'
    COMPLETED = 'COMPLETED'
    FAILED = 'FAILED'

class SeverityLevel(str, enum.Enum):
    CRITICAL = 'CRITICAL'
    HIGH = 'HIGH'
    MEDIUM = 'MEDIUM'
    LOW = 'LOW'
    INFO = 'INFO'

class ScanProject(Base):
    __tablename__ = 'projects'

    id = Column(String(36), primary_key=True)
    name = Column(String(255), nullable=False)
    repo_url = Column(String(512), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    scans = relationship('ScanRun', back_populates='project', cascade='all, delete-orphan')

class ScanRun(Base):
    __tablename__ = 'scan_runs'

    id = Column(String(36), primary_key=True)
    project_id = Column(String(36), ForeignKey('projects.id'), nullable=False)
    status = Column(Enum(ScanStatus), default=ScanStatus.PENDING, nullable=False)
    total_findings = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)

    project = relationship('ScanProject', back_populates='scans')
    findings = relationship('VulnerabilityFinding', back_populates='scan', cascade='all, delete-orphan')

class VulnerabilityFinding(Base):
    __tablename__ = 'vulnerability_findings'

    id = Column(String(36), primary_key=True)
    scan_id = Column(String(36), ForeignKey('scan_runs.id'), nullable=False)
    rule_id = Column(String(100), nullable=False)
    title = Column(String(255), nullable=False)
    severity = Column(Enum(SeverityLevel), nullable=False)
    file_path = Column(String(512), nullable=False)
    line_number = Column(Integer, nullable=True)
    description = Column(Text, nullable=False)
    ai_root_cause = Column(Text, nullable=True)
    ai_suggested_patch = Column(Text, nullable=True)
    raw_metadata = Column(JSON, nullable=True)

    scan = relationship('ScanRun', back_populates='findings')
