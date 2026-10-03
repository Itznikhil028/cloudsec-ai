from datetime import datetime
from typing import List, Optional, Any
from pydantic import BaseModel
from app.models.scan import ScanStatus, SeverityLevel

class FindingBase(BaseModel):
    rule_id: str
    title: str
    severity: SeverityLevel
    file_path: str
    line_number: Optional[int] = None
    description: str
    ai_root_cause: Optional[str] = None
    ai_suggested_patch: Optional[str] = None

class FindingResponse(FindingBase):
    id: str
    scan_id: str
    raw_metadata: Optional[Any] = None

    class Config:
        from_attributes = True

class ScanRunCreate(BaseModel):
    project_name: str
    repo_url: Optional[str] = None
    raw_iac_code: Optional[str] = None

class ScanRunResponse(BaseModel):
    id: str
    project_id: str
    status: ScanStatus
    total_findings: int
    created_at: datetime
    completed_at: Optional[datetime] = None
    findings: List[FindingResponse] = []

    class Config:
        from_attributes = True
