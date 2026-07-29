"""
Internal admin portal data endpoints — all require a valid admin session cookie.

GET   /v1/internal/stats                  — aggregate dashboard numbers
GET   /v1/internal/scans                  — cross-client scan list (paginated, filterable)
GET   /v1/internal/scans/{id}             — single scan detail
POST  /v1/internal/scans/{id}/cancel      — force a stuck scan to cancelled
GET   /v1/internal/findings               — cross-client findings (paginated, filterable)
GET   /v1/internal/clients/{id}/usage     — per-client usage breakdown

Log endpoints live in internal_logs.py.
"""
import asyncio
import logging
from datetime import datetime, timezone, timedelta
from fastapi import APIRouter, Depends, Request, Query
from fastapi.responses import JSONResponse, Response
from sqlalchemy.orm import Session
from sqlalchemy import select, func, and_

from app.core.database import get_db
from app.core.errors import get_request_id
from app.models.client import Client
from app.models.api_key import ApiKey
from app.models.scan_job import ScanJob
from app.models.finding import Finding
from app.models.usage_event import UsageEvent
from app.api.v1.internal_auth import require_admin_session

logger = logging.getLogger(__name__)
router = APIRouter(tags=["internal"])


def _now() -> datetime:
    return datetime.now(timezone.utc)


# ── GET /v1/internal/stats ─────────────────────────────────────────────────────

@router.get("/internal/stats")
async def get_stats(
    request: Request,
    db: Session = Depends(get_db),
    _: str = Depends(require_admin_session),
):
    request_id = get_request_id(request)
    today_start = _now().replace(hour=0, minute=0, second=0, microsecond=0)
    week_ago = _now() - timedelta(days=7)
    month_ago = _now() - timedelta(days=30)

    def _query():
        total_clients = db.execute(select(func.count()).select_from(Client)).scalar_one()
        active_clients = db.execute(select(func.count()).select_from(Client).where(Client.is_active.is_(True))).scalar_one()

        total_scans = db.execute(select(func.count()).select_from(ScanJob)).scalar_one()
        scans_today = db.execute(select(func.count()).select_from(ScanJob).where(ScanJob.created_at >= today_start)).scalar_one()
        scans_this_week = db.execute(select(func.count()).select_from(ScanJob).where(ScanJob.created_at >= week_ago)).scalar_one()
        scans_this_month = db.execute(select(func.count()).select_from(ScanJob).where(ScanJob.created_at >= month_ago)).scalar_one()

        active_scans = db.execute(
            select(func.count()).select_from(ScanJob).where(ScanJob.status.in_(["queued", "initializing", "running", "aggregating"]))
        ).scalar_one()
        failed_scans = db.execute(
            select(func.count()).select_from(ScanJob).where(ScanJob.status == "failed")
        ).scalar_one()

        total_findings = db.execute(select(func.count()).select_from(Finding)).scalar_one()
        findings_today = db.execute(select(func.count()).select_from(Finding).where(Finding.created_at >= today_start)).scalar_one()
        critical_findings = db.execute(select(func.count()).select_from(Finding).where(Finding.severity == "critical")).scalar_one()
        high_findings = db.execute(select(func.count()).select_from(Finding).where(Finding.severity == "high")).scalar_one()

        total_api_keys = db.execute(select(func.count()).select_from(ApiKey).where(ApiKey.is_active.is_(True))).scalar_one()

        from sqlalchemy import cast, Date
        rows = db.execute(
            select(
                cast(ScanJob.created_at, Date).label("day"),
                func.count().label("count"),
            )
            .where(ScanJob.created_at >= _now() - timedelta(days=14))
            .group_by("day")
            .order_by("day")
        ).all()
        scans_by_day = [{"date": str(r.day), "count": r.count} for r in rows]

        return {
            "clients": {"total": total_clients, "active": active_clients},
            "scans": {
                "total": total_scans,
                "today": scans_today,
                "this_week": scans_this_week,
                "this_month": scans_this_month,
                "active": active_scans,
                "failed": failed_scans,
            },
            "findings": {
                "total": total_findings,
                "today": findings_today,
                "critical": critical_findings,
                "high": high_findings,
            },
            "api_keys_active": total_api_keys,
            "scans_by_day": scans_by_day,
        }

    data = await asyncio.to_thread(_query)
    return {"request_id": request_id, "data": data}


# ── GET /v1/internal/scans ─────────────────────────────────────────────────────

@router.get("/internal/scans")
async def list_all_scans(
    request: Request,
    db: Session = Depends(get_db),
    _: str = Depends(require_admin_session),
    client_id: str | None = Query(None),
    status: str | None = Query(None),
    date_from: str | None = Query(None),
    date_to: str | None = Query(None),
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
):
    request_id = get_request_id(request)

    def _query():
        stmt = select(ScanJob)
        if client_id:
            stmt = stmt.where(ScanJob.client_id == client_id)
        if status:
            stmt = stmt.where(ScanJob.status == status)
        if date_from:
            try:
                stmt = stmt.where(ScanJob.created_at >= datetime.fromisoformat(date_from))
            except ValueError:
                pass
        if date_to:
            try:
                stmt = stmt.where(ScanJob.created_at <= datetime.fromisoformat(date_to))
            except ValueError:
                pass

        total = db.execute(select(func.count()).select_from(stmt.subquery())).scalar_one()
        rows = db.execute(stmt.order_by(ScanJob.created_at.desc()).limit(limit).offset(offset)).scalars().all()

        items = []
        for s in rows:
            result = s.scan_result
            summary = result.summary_json if (result and result.summary_json) else {}
            items.append({
                "scan_id": s.id,
                "client_id": s.client_id,
                "target": s.target,
                "status": s.status,
                "project_id": s.project_id,
                "asset_id": s.asset_id,
                "tools_run": s.tools_run or [],
                "total_findings": summary.get("total_findings", 0),
                "duration_seconds": summary.get("duration_seconds"),
                "error": s.error,
                "created_at": s.created_at.isoformat(),
                "started_at": s.started_at.isoformat() if s.started_at else None,
                "completed_at": s.completed_at.isoformat() if s.completed_at else None,
            })
        return total, items

    total, items = await asyncio.to_thread(_query)
    return {
        "request_id": request_id,
        "data": items,
        "meta": {"total": total, "limit": limit, "offset": offset},
    }


# ── GET /v1/internal/scans/{scan_id} ──────────────────────────────────────────

@router.get("/internal/scans/{scan_id}")
async def get_scan_detail(
    scan_id: str,
    request: Request,
    db: Session = Depends(get_db),
    _: str = Depends(require_admin_session),
):
    request_id = get_request_id(request)

    def _query():
        s = db.get(ScanJob, scan_id)
        if s is None:
            return None
        result = s.scan_result
        summary = result.summary_json if (result and result.summary_json) else {}
        return {
            "scan_id": s.id,
            "client_id": s.client_id,
            "target": s.target,
            "status": s.status,
            "project_id": s.project_id,
            "asset_id": s.asset_id,
            "tools_run": s.tools_run or [],
            "total_findings": summary.get("total_findings", 0),
            "by_severity": summary.get("by_severity", {}),
            "tool_errors": summary.get("tool_errors", {}),
            "duration_seconds": summary.get("duration_seconds"),
            "error": s.error,
            "created_at": s.created_at.isoformat(),
            "started_at": s.started_at.isoformat() if s.started_at else None,
            "completed_at": s.completed_at.isoformat() if s.completed_at else None,
        }

    data = await asyncio.to_thread(_query)
    if data is None:
        return JSONResponse(
            status_code=404,
            content={"error": {"code": "SCAN_NOT_FOUND", "message": "Scan not found.", "request_id": request_id}},
        )
    return {"request_id": request_id, "data": data}


# ── POST /v1/internal/scans/{scan_id}/cancel ──────────────────────────────────

CANCELLABLE_STATUSES = {"queued", "initializing", "running", "aggregating"}

@router.post("/internal/scans/{scan_id}/cancel", status_code=200)
async def cancel_scan(
    scan_id: str,
    request: Request,
    db: Session = Depends(get_db),
    _: str = Depends(require_admin_session),
):
    """Force a stuck/queued scan to cancelled status. Admin-only."""
    request_id = get_request_id(request)

    def _do_cancel():
        s = db.get(ScanJob, scan_id)
        if s is None:
            return "not_found", None
        if s.status not in CANCELLABLE_STATUSES:
            return "not_cancellable", s.status
        s.status = "cancelled"
        s.error = "Cancelled by admin"
        s.completed_at = _now()
        db.commit()
        logger.info("Admin cancelled scan %s (was %s)", scan_id, s.status)
        return "ok", None

    result, extra = await asyncio.to_thread(_do_cancel)

    if result == "not_found":
        return JSONResponse(
            status_code=404,
            content={"error": {"code": "SCAN_NOT_FOUND", "message": "Scan not found.", "request_id": request_id}},
        )
    if result == "not_cancellable":
        return JSONResponse(
            status_code=409,
            content={"error": {"code": "SCAN_NOT_CANCELLABLE", "message": f"Scan is already in terminal status: {extra}.", "request_id": request_id}},
        )
    return {"request_id": request_id, "data": {"scan_id": scan_id, "status": "cancelled"}}


# ── GET /v1/internal/findings ──────────────────────────────────────────────────

@router.get("/internal/findings")
async def list_all_findings(
    request: Request,
    db: Session = Depends(get_db),
    _: str = Depends(require_admin_session),
    client_id: str | None = Query(None),
    scan_id: str | None = Query(None),
    severity: str | None = Query(None),
    tool: str | None = Query(None),
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
):
    request_id = get_request_id(request)

    def _query():
        stmt = select(Finding)
        if client_id:
            stmt = stmt.where(Finding.client_id == client_id)
        if scan_id:
            stmt = stmt.where(Finding.scan_job_id == scan_id)
        if severity:
            stmt = stmt.where(Finding.severity == severity)
        if tool:
            stmt = stmt.where(Finding.tool == tool)

        total = db.execute(select(func.count()).select_from(stmt.subquery())).scalar_one()
        rows = db.execute(stmt.order_by(Finding.created_at.desc()).limit(limit).offset(offset)).scalars().all()

        items = [{
            "id": f.id,
            "scan_id": f.scan_job_id,
            "client_id": f.client_id,
            "title": f.title,
            "severity": f.severity,
            "tool": f.tool,
            "status": f.status,
            "cvss_score": f.cvss_score,
            "cwe_id": f.cwe_id,
            "owasp_category": f.owasp_category,
            "created_at": f.created_at.isoformat(),
        } for f in rows]
        return total, items

    total, items = await asyncio.to_thread(_query)
    return {
        "request_id": request_id,
        "data": items,
        "meta": {"total": total, "limit": limit, "offset": offset},
    }


# ── GET /v1/internal/clients/{id}/usage ───────────────────────────────────────

@router.get("/internal/clients/{client_id}/usage")
async def get_client_usage(
    client_id: str,
    request: Request,
    db: Session = Depends(get_db),
    _: str = Depends(require_admin_session),
):
    request_id = get_request_id(request)

    def _query():
        client = db.get(Client, client_id)
        if client is None:
            return None

        total_scans = db.execute(
            select(func.count()).select_from(ScanJob).where(ScanJob.client_id == client_id)
        ).scalar_one()
        completed_scans = db.execute(
            select(func.count()).select_from(ScanJob).where(
                and_(ScanJob.client_id == client_id, ScanJob.status == "completed")
            )
        ).scalar_one()
        total_findings = db.execute(
            select(func.count()).select_from(Finding).where(Finding.client_id == client_id)
        ).scalar_one()

        events = db.execute(
            select(UsageEvent)
            .where(UsageEvent.client_id == client_id)
            .order_by(UsageEvent.created_at.desc())
            .limit(20)
        ).scalars().all()

        return {
            "client_id": client_id,
            "company_name": client.company_name,
            "tier": client.tier,
            "total_scans": total_scans,
            "completed_scans": completed_scans,
            "total_findings": total_findings,
            "recent_events": [{
                "id": e.id,
                "event_type": e.event_type,
                "metadata": e.metadata_json,
                "created_at": e.created_at.isoformat(),
            } for e in events],
        }

    data = await asyncio.to_thread(_query)
    if data is None:
        return JSONResponse(
            status_code=404,
            content={"error": {"code": "CLIENT_NOT_FOUND", "message": "Client not found.", "request_id": request_id}},
        )
    return {"request_id": request_id, "data": data}
