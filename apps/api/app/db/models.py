from datetime import datetime
from sqlalchemy import Column, String, Integer, DateTime, Text, JSON
from app.db.database import Base

class ScanAudit(Base):
    __tablename__ = "scan_audits"

    id = Column(String, primary_key=True, index=True)
    project_name = Column(String, default="Production-Audit")
    status = Column(String, default="COMPLETED")
    total_findings = Column(Integer, default=0)
    raw_iac_code = Column(Text, nullable=False)
    findings_json = Column(JSON, default=list)
    created_at = Column(DateTime, default=datetime.utcnow)
