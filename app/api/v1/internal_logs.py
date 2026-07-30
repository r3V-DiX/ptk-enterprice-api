"""
Internal log viewer endpoints — all require a valid admin session cookie.

GET /v1/internal/audit-logs  — audit log viewer
GET /v1/internal/api-logs    — request log viewer
"""
import logging
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, Request, Query
from sqlalchemy.orm import Session
from sqlalchemy import select, func

from app.core.database import get_db
from app.core.errors import get_request_id
from app.models.audit_log import AuditLog
from app.models.api_log import ApiLog
from app.api.v1.internal_auth import require_admin_session

logger = logging.getLogger(__name__)
router = APIRouter(tags=["internal"])


# ── GET /v1/internal/audit-logs ───────────────────────────────────────────────

@router.get("/internal/audit-logs")
async def list_audit_logs(
    request: Request,
    db: Session = Depends(get_db),
    _: str = Depends(require_admin_session),
    client_id: str | None = Query(None),
    action: str | None = Query(None),
    date_from: str | None = Query(None),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
):
    request_id = get_request_id(request)
    import asyncio

    def _query():
        stmt = select(AuditLog)
        if client_id:
            stmt = stmt.where(AuditLog.client_id == client_id)
        if action:
            stmt = stmt.where(AuditLog.action == action)
        if date_from:
            try:
                stmt = stmt.where(AuditLog.created_at >= datetime.fromisoformat(date_from))
            except ValueError:
                pass

        total = db.execute(select(func.count()).select_from(stmt.subquery())).scalar_one()
        rows = db.execute(stmt.order_by(AuditLog.created_at.desc()).limit(limit).offset(offset)).scalars().all()

        items = [{
            "id": a.id,
            "client_id": a.client_id,
            "api_key_id": a.api_key_id,
            "actor": a.actor,
            "action": a.action,
            "target_type": a.target_type,
            "target_id": a.target_id,
            "metadata": a.metadata_json,
            "ip_address": a.ip_address,
            "request_id": a.request_id,
            "created_at": a.created_at.isoformat(),
        } for a in rows]
        return total, items

    total, items = await asyncio.to_thread(_query)
    return {
        "request_id": request_id,
        "data": items,
        "meta": {"total": total, "limit": limit, "offset": offset},
    }


# ── GET /v1/internal/api-logs ─────────────────────────────────────────────────

@router.get("/internal/api-logs")
async def list_api_logs(
    request: Request,
    db: Session = Depends(get_db),
    _: str = Depends(require_admin_session),
    client_id: str | None = Query(None),
    status_code: int | None = Query(None),
    status_range: str | None = Query(None, description="2xx, 4xx, or 5xx for range matching"),
    method: str | None = Query(None),
    endpoint: str | None = Query(None),
    date_from: str | None = Query(None),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
):
    request_id = get_request_id(request)
    import asyncio

    def _query():
        stmt = select(ApiLog)
        if client_id:
            stmt = stmt.where(ApiLog.client_id == client_id)
        if status_code:
            stmt = stmt.where(ApiLog.status_code == status_code)
        elif status_range:
            _range_map = {"2xx": (200, 299), "4xx": (400, 499), "5xx": (500, 599)}
            if status_range in _range_map:
                lo, hi = _range_map[status_range]
                stmt = stmt.where(ApiLog.status_code >= lo, ApiLog.status_code <= hi)
        if method:
            stmt = stmt.where(ApiLog.method == method.upper())
        if endpoint:
            stmt = stmt.where(ApiLog.endpoint.ilike(f"%{endpoint}%"))
        if date_from:
            try:
                stmt = stmt.where(ApiLog.created_at >= datetime.fromisoformat(date_from))
            except ValueError:
                pass

        total = db.execute(select(func.count()).select_from(stmt.subquery())).scalar_one()
        rows = db.execute(stmt.order_by(ApiLog.created_at.desc()).limit(limit).offset(offset)).scalars().all()

        items = [{
            "id": a.id,
            "client_id": a.client_id,
            "company_name": a.client.company_name if a.client else None,
            "api_key_id": a.api_key_id,
            "key_label": a.api_key.label if a.api_key else None,
            "key_prefix": a.api_key.key_prefix if a.api_key else None,
            "request_id": a.request_id,
            "method": a.method,
            "endpoint": a.endpoint,
            "query_string": a.query_string,
            "status_code": a.status_code,
            "latency_ms": a.latency_ms,
            "error_code": a.error_code,
            "ip_address": a.ip_address,
            "user_agent": a.user_agent,
            "created_at": a.created_at.isoformat(),
        } for a in rows]
        return total, items

    total, items = await asyncio.to_thread(_query)
    return {
        "request_id": request_id,
        "data": items,
        "meta": {"total": total, "limit": limit, "offset": offset},
    }
