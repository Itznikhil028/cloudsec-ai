import uuid
from typing import List, Optional
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from app.core.scanner import IaCScanner
from app.core.guardrails import PolicyGuardrailsEngine

router = APIRouter(prefix="/scans", tags=["Scans"])

class ScanRequest(BaseModel):
    project_name: str
    raw_iac_code: str

class FindingResponse(BaseModel):
    id: Optional[str] = None
    rule_id: str
    title: str
    severity: str
    file_path: str
    line_number: int
    description: str
    ai_root_cause: Optional[str] = None
    ai_suggested_patch: Optional[str] = None

class ScanResultResponse(BaseModel):
    id: str
    project_id: str
    status: str
    total_findings: int
    findings: List[FindingResponse]

@router.post("/submit", response_model=ScanResultResponse)
async def submit_scan(request: ScanRequest):
    scan_id = str(uuid.uuid4())
    project_id = str(uuid.uuid4())

    raw_findings = IaCScanner.scan_terraform_string(request.raw_iac_code)
    findings: List[FindingResponse] = []
    for item in raw_findings:
        if not item.get("id"):
            item["id"] = str(uuid.uuid4())
        findings.append(FindingResponse(**item))

    guardrail_findings = PolicyGuardrailsEngine.evaluate(request.raw_iac_code)
    for g in guardrail_findings:
        findings.append(FindingResponse(**g))

    return ScanResultResponse(
        id=scan_id,
        project_id=project_id,
        status="COMPLETED",
        total_findings=len(findings),
        findings=findings
    )
