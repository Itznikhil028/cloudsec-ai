import uuid
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.models.scan import ScanProject, ScanRun, VulnerabilityFinding, ScanStatus
from app.schemas.scan import ScanRunCreate, ScanRunResponse
from app.core.scanner import IaCScanner
from app.core.ai_remediator import AIRemediator

router = APIRouter(prefix='/scans', tags=['Scans'])

@router.post('/submit', response_model=ScanRunResponse)
def submit_scan(payload: ScanRunCreate, db: Session = Depends(get_db)):
    if not payload.raw_iac_code and not payload.repo_url:
        raise HTTPException(status_code=400, detail='Either raw_iac_code or repo_url must be provided.')

    project = db.query(ScanProject).filter(ScanProject.name == payload.project_name).first()
    if not project:
        project = ScanProject(
            id=str(uuid.uuid4()),
            name=payload.project_name,
            repo_url=payload.repo_url
        )
        db.add(project)
        db.commit()
        db.refresh(project)

    scan_run = ScanRun(
        id=str(uuid.uuid4()),
        project_id=project.id,
        status=ScanStatus.SCANNING
    )
    db.add(scan_run)
    db.commit()
    db.refresh(scan_run)

    if payload.raw_iac_code:
        raw_findings = IaCScanner.scan_terraform_string(payload.raw_iac_code)
        for item in raw_findings:
            remediation = AIRemediator.generate_remediation(
                rule_id=item['rule_id'],
                title=item['title'],
                resource_name=item['raw_metadata'].get('resource', 'Unknown')
            )
            finding = VulnerabilityFinding(
                id=str(uuid.uuid4()),
                scan_id=scan_run.id,
                rule_id=item['rule_id'],
                title=item['title'],
                severity=item['severity'],
                file_path=item['file_path'],
                line_number=item['line_number'],
                description=item['description'],
                raw_metadata=item['raw_metadata'],
                ai_root_cause=remediation['root_cause'],
                ai_suggested_patch=remediation['patch']
            )
            db.add(finding)

        scan_run.total_findings = len(raw_findings)
        scan_run.status = ScanStatus.COMPLETED
        scan_run.completed_at = datetime.utcnow()
        db.commit()
        db.refresh(scan_run)

    return scan_run

@router.get('/{scan_id}', response_model=ScanRunResponse)
def get_scan(scan_id: str, db: Session = Depends(get_db)):
    scan = db.query(ScanRun).filter(ScanRun.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail='Scan not found')
    return scan
