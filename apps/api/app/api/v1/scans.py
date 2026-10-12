import uuid
from datetime import datetime
from typing import List
from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.scanner import IaCScanner
from app.core.ai_remediator import AIRemediator
from app.core.database import get_db
from app.models.scan import ScanProject, ScanRun, VulnerabilityFinding, ScanStatus, SeverityLevel

router = APIRouter(prefix="/scans", tags=["Scans"])

class ScanRequest(BaseModel):
    project_name: str = "Production-Audit"
    raw_iac_code: str

class FindingResponse(BaseModel):
    id: str
    rule_id: str
    title: str
    severity: str
    file_path: str
    line_number: int
    description: str
    ai_root_cause: str
    ai_suggested_patch: str

class ScanResponse(BaseModel):
    id: str
    project_id: str
    status: str
    total_findings: int = 0
    findings: List[FindingResponse]

@router.get("/history")
def get_scan_history(limit: int = 10, db: Session = Depends(get_db)):
    runs = db.query(ScanRun).order_by(ScanRun.created_at.desc()).limit(limit).all()
    history = []
    for run in runs:
        findings_list = []
        for f in run.findings:
            findings_list.append({
                "id": f.id,
                "rule_id": f.rule_id,
                "title": f.title,
                "severity": f.severity.value if hasattr(f.severity, "value") else str(f.severity),
                "file_path": f.file_path,
                "line_number": f.line_number or 1,
                "description": f.description,
                "ai_root_cause": f.ai_root_cause or "",
                "ai_suggested_patch": f.ai_suggested_patch or ""
            })
        history.append({
            "id": run.id,
            "project_name": run.project.name if run.project else "Production-Audit",
            "status": run.status.value if hasattr(run.status, "value") else str(run.status),
            "total_findings": run.total_findings,
            "created_at": run.created_at.isoformat() if run.created_at else "",
            "findings": findings_list
        })
    return history

@router.post("/submit", response_model=ScanResponse)
def submit_scan(payload: ScanRequest, db: Session = Depends(get_db)):
    project = db.query(ScanProject).filter(ScanProject.name == payload.project_name).first()
    if not project:
        project = ScanProject(
            id=str(uuid.uuid4()),
            name=payload.project_name
        )
        db.add(project)
        db.commit()
        db.refresh(project)

    raw_findings = IaCScanner.scan_terraform_string(payload.raw_iac_code)

    scan_run_id = str(uuid.uuid4())
    scan_run = ScanRun(
        id=scan_run_id,
        project_id=project.id,
        status=ScanStatus.COMPLETED,
        total_findings=len(raw_findings),
        completed_at=datetime.utcnow()
    )
    db.add(scan_run)

    formatted_findings = []
    for item in raw_findings:
        cid = item.get("rule_id", "UNKNOWN")
        cname = item.get("title", "Security Misconfiguration")
        raw_meta = item.get("raw_metadata") or {}
        res_name = raw_meta.get("resource", "AWS Resource")
        line_num = item.get("line_number", 1)

        remediation = AIRemediator.generate_remediation(
            rule_id=cid,
            title=cname,
            resource=res_name
        )

        sev_str = (item.get("severity", "MEDIUM") or "MEDIUM").upper()
        if sev_str not in SeverityLevel.__members__:
            sev_str = "MEDIUM"

        finding_id = str(uuid.uuid4())
        finding_record = VulnerabilityFinding(
            id=finding_id,
            scan_id=scan_run_id,
            rule_id=cid,
            title=cname,
            severity=SeverityLevel[sev_str],
            file_path=item.get("file_path", "main.tf"),
            line_number=line_num,
            description=item.get("description") or f"Violates benchmark: {cname}",
            ai_root_cause=remediation["root_cause"],
            ai_suggested_patch=remediation["patch"],
            raw_metadata=raw_meta
        )
        db.add(finding_record)

        formatted_findings.append({
            "id": finding_id,
            "rule_id": cid,
            "title": cname,
            "severity": sev_str,
            "file_path": item.get("file_path", "main.tf"),
            "line_number": line_num,
            "description": item.get("description") or f"Violates benchmark: {cname}",
            "ai_root_cause": remediation["root_cause"],
            "ai_suggested_patch": remediation["patch"]
        })

    db.commit()

    return {
        "id": scan_run_id,
        "project_id": project.id,
        "status": "COMPLETED",
        "total_findings": len(formatted_findings),
        "findings": formatted_findings
    }
