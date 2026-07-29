import logging
import re
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from sqlalchemy import select, func
from sqlalchemy.exc import IntegrityError

from app.models.scan_job import ScanJob
from app.models.project import Project
from app.models.asset import Asset
from app.models.finding import Finding
from app.models.api_key import ApiKey

logger = logging.getLogger(__name__)

_ACTIVE_STATUSES = {"queued", "initializing", "running", "aggregating"}
_TERMINAL_STATUSES = {"completed", "failed", "cancelled", "expired"}

_SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


def _strip_protocol(target: str) -> str:
    """Strip http:// or https:// from target for storage."""
    return re.sub(r"^https?://", "", target, flags=re.IGNORECASE)


def create_scan(
    db: Session,
    client_id: str,
    api_key_id: str | None,
    target: str,
    project_id: str | None = None,
    asset_id: str | None = None,
    idempotency_key: str | None = None,
) -> tuple[ScanJob, bool]:
    """
    Create a new scan job. Returns (ScanJob, is_new).
    is_new=False means idempotency key matched an existing scan.
    Raises ValueError with error code string on validation failure.
    """
    # Idempotency: return existing scan if key already used by this client
    if idempotency_key:
        existing = db.execute(
            select(ScanJob).where(
                ScanJob.client_id == client_id,
                ScanJob.idempotency_key == idempotency_key,
            )
        ).scalar_one_or_none()
        if existing:
            return existing, False

    # Monthly quota enforcement — only applies when api_key_id is set and key has a quota
    if api_key_id:
        api_key = db.get(ApiKey, api_key_id)
        if api_key and api_key.scan_quota_per_month is not None:
            now = datetime.now(timezone.utc)
            month_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
            scans_this_month = db.execute(
                select(func.count()).select_from(ScanJob).where(
                    ScanJob.api_key_id == api_key_id,
                    ScanJob.created_at >= month_start,
                )
            ).scalar_one()
            if scans_this_month >= api_key.scan_quota_per_month:
                logger.warning(
                    "Scan quota exceeded for api_key_id=%s client=%s quota=%d used=%d",
                    api_key_id, client_id, api_key.scan_quota_per_month, scans_this_month,
                )
                raise ValueError("SCAN_QUOTA_EXCEEDED")

    # Validate project belongs to this client
    if project_id:
        project = db.execute(
            select(Project).where(
                Project.id == project_id,
                Project.client_id == client_id,
            )
        ).scalar_one_or_none()
        if project is None:
            raise ValueError("PROJECT_NOT_FOUND")

    # Validate asset belongs to this client
    if asset_id:
        asset = db.execute(
            select(Asset).where(
                Asset.id == asset_id,
                Asset.client_id == client_id,
            )
        ).scalar_one_or_none()
        if asset is None:
            raise ValueError("ASSET_NOT_FOUND")

    stored_target = _strip_protocol(target)

    scan = ScanJob(
        client_id=client_id,
        api_key_id=api_key_id,
        target=stored_target,
        project_id=project_id,
        asset_id=asset_id,
        idempotency_key=idempotency_key,
        status="queued",
    )
    db.add(scan)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        # Race condition or cross-client key collision — re-fetch and return existing
        if idempotency_key:
            existing = db.execute(
                select(ScanJob).where(
                    ScanJob.client_id == client_id,
                    ScanJob.idempotency_key == idempotency_key,
                )
            ).scalar_one_or_none()
            if existing:
                return existing, False
        raise
    db.refresh(scan)
    logger.info("Scan created id=%s target=%s client=%s", scan.id, stored_target, client_id)
    return scan, True


def get_scan(db: Session, scan_id: str, client_id: str) -> ScanJob | None:
    """Fetch a scan by id, always filtered by client_id."""
    return db.execute(
        select(ScanJob).where(
            ScanJob.id == scan_id,
            ScanJob.client_id == client_id,
        )
    ).scalar_one_or_none()


def get_scan_list(
    db: Session, client_id: str, limit: int = 20, offset: int = 0
) -> tuple[list[ScanJob], int]:
    """Return (scans, total_count) ordered by created_at DESC."""
    total = db.execute(
        select(func.count()).select_from(ScanJob).where(ScanJob.client_id == client_id)
    ).scalar_one()

    scans = db.execute(
        select(ScanJob)
        .where(ScanJob.client_id == client_id)
        .order_by(ScanJob.created_at.desc())
        .limit(limit)
        .offset(offset)
    ).scalars().all()

    return list(scans), total


def delete_scan(db: Session, scan_id: str, client_id: str) -> str | None:
    """
    Delete a scan record. Returns None on success.
    Returns error code string if not found ("SCAN_NOT_FOUND")
    or still active ("SCAN_IN_PROGRESS").
    """
    scan = get_scan(db, scan_id, client_id)
    if scan is None:
        return "SCAN_NOT_FOUND"
    if scan.status in _ACTIVE_STATUSES:
        return "SCAN_IN_PROGRESS"

    db.delete(scan)
    db.commit()
    return None


def build_scan_response(scan: ScanJob) -> dict:
    """Build the full scan response dict from a ScanJob ORM object."""
    findings_data = []
    severity_counts = {s: 0 for s in _SEVERITY_ORDER}

    for f in scan.findings:
        findings_data.append({
            "id": f.id,
            "title": f.title,
            "severity": f.severity,
            "tool": f.tool,
            "status": f.status,
            "description": f.description,
            "remediation": f.remediation,
            "evidence": f.evidence_json,
            "cvss_score": f.cvss_score,
            "cwe_id": f.cwe_id,
            "owasp_category": f.owasp_category,
        })
        if f.severity in severity_counts:
            severity_counts[f.severity] += 1

    duration = None
    if scan.started_at and scan.completed_at:
        # Both timestamps are timezone-aware
        start = scan.started_at
        end = scan.completed_at
        if start.tzinfo is None:
            from datetime import timezone as _tz
            start = start.replace(tzinfo=_tz.utc)
        if end.tzinfo is None:
            from datetime import timezone as _tz
            end = end.replace(tzinfo=_tz.utc)
        duration = (end - start).total_seconds()

    summary = {
        "total_findings": len(findings_data),
        "by_severity": severity_counts,
        "tools_run": scan.tools_run or [],
        "tool_errors": {},
        "duration_seconds": duration,
    }

    return {
        "scan_id": scan.id,
        "target": scan.target,
        "status": scan.status,
        "project_id": scan.project_id,
        "asset_id": scan.asset_id,
        "created_at": scan.created_at.isoformat(),
        "started_at": scan.started_at.isoformat() if scan.started_at else None,
        "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
        "summary": summary,
        "findings": findings_data,
    }
