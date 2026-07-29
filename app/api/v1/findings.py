import logging
from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy.orm import Session
from sqlalchemy import select, func

from app.core.database import get_db
from app.core.errors import get_request_id
from app.core.auth import require_scope
from app.models.api_key import ApiKey
from app.models.finding import Finding

logger = logging.getLogger(__name__)

router = APIRouter(tags=["findings"])


@router.get("/findings")
async def list_findings(
    request: Request,
    scan_id: str | None = Query(default=None),
    severity: str | None = Query(default=None),
    tool: str | None = Query(default=None),
    status: str | None = Query(default=None),
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    api_key: ApiKey = require_scope("scan:read"),
):
    request_id = get_request_id(request)

    # Always filter by client_id — never expose cross-client data
    stmt = select(Finding).where(Finding.client_id == api_key.client_id)

    if scan_id:
        stmt = stmt.where(Finding.scan_job_id == scan_id)
    if severity:
        stmt = stmt.where(Finding.severity == severity)
    if tool:
        stmt = stmt.where(Finding.tool == tool)
    if status:
        stmt = stmt.where(Finding.status == status)

    count_stmt = select(func.count()).select_from(stmt.subquery())
    total = db.execute(count_stmt).scalar_one()

    findings = db.execute(
        stmt.order_by(Finding.created_at.desc()).limit(limit).offset(offset)
    ).scalars().all()

    page = (offset // limit) + 1 if limit else 1
    data = [
        {
            "id": f.id,
            "scan_id": f.scan_job_id,
            "title": f.title,
            "severity": f.severity,
            "tool": f.tool,
            "status": f.status,
            "created_at": f.created_at.isoformat(),
        }
        for f in findings
    ]

    return {
        "request_id": request_id,
        "data": data,
        "meta": {"total": total, "page": page, "limit": limit, "offset": offset},
    }
