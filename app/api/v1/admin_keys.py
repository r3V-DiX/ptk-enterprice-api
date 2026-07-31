"""
Admin API key endpoints: issue, list, patch, revoke.
"""
import logging
from datetime import datetime, timezone, date
from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse, Response
from sqlalchemy.orm import Session
from sqlalchemy import select, func

from fastapi import Query
from app.core.database import get_db
from app.core.errors import error_response, get_request_id
from app.models.api_key import ApiKey
from app.models.audit_log import AuditLog
from app.models.client import Client
from app.models.scan_job import ScanJob
from app.schemas.admin import (
    CreateApiKeyRequest,
    ApiKeyCreatedResponse,
    ApiKeyResponse,
    PatchApiKeyRequest,
)
from app.services.key_service import create_api_key, revoke_api_key, update_api_key
from app.services.audit_service import write_audit_log
from app.api.v1.admin_shared import _admin_auth

logger = logging.getLogger(__name__)

router = APIRouter(tags=["admin"])


def _quota_resets_at() -> str:
    """Return ISO8601 string of first day of next month (UTC)."""
    today = date.today()
    if today.month == 12:
        first_next = date(today.year + 1, 1, 1)
    else:
        first_next = date(today.year, today.month + 1, 1)
    return datetime(first_next.year, first_next.month, first_next.day, tzinfo=timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# POST /v1/admin/clients/{client_id}/keys
# ---------------------------------------------------------------------------
@router.post("/admin/clients/{client_id}/keys", status_code=201)
async def issue_api_key(
    client_id: str,
    request: Request,
    body: CreateApiKeyRequest,
    db: Session = Depends(get_db),
):
    request_id = get_request_id(request)

    ok, actor_key_id = await _admin_auth(request, db)
    if not ok:
        return error_response("ADMIN_AUTH_REQUIRED", request_id)

    client = db.get(Client, client_id)
    if client is None:
        return error_response("CLIENT_NOT_FOUND", request_id)

    new_key, plaintext = create_api_key(
        db,
        client_id=client_id,
        label=body.label,
        scopes=body.scopes,
        rate_limit_rpm=body.rate_limit_rpm,
        expires_at=body.expires_at,
        scan_quota_per_month=body.scan_quota_per_month,
        cors_origins=body.cors_origins,
    )

    write_audit_log(
        db,
        actor="admin",
        action="key_created",
        client_id=client_id,
        api_key_id=actor_key_id,
        target_type="api_key",
        target_id=new_key.id,
        metadata={"key_prefix": new_key.key_prefix, "scopes": new_key.scopes, "scan_quota_per_month": new_key.scan_quota_per_month},
        ip_address=request.client.host if request.client else None,
        request_id=request_id,
    )

    response_data = ApiKeyCreatedResponse(
        id=new_key.id,
        key_prefix=new_key.key_prefix,
        label=new_key.label,
        scopes=new_key.scopes,
        rate_limit_rpm=new_key.rate_limit_rpm,
        scan_quota_per_month=new_key.scan_quota_per_month,
        expires_at=new_key.expires_at,
        created_at=new_key.created_at,
        plaintext_key=plaintext,
        cors_origins=new_key.cors_origins,
    ).model_dump(mode="json")

    logger.info("Issued key prefix=%s for client=%s", new_key.key_prefix, client_id)

    return JSONResponse(
        status_code=201,
        content={"request_id": request_id, "data": response_data},
    )


# ---------------------------------------------------------------------------
# GET /v1/admin/clients/{client_id}/keys
# ---------------------------------------------------------------------------
@router.get("/admin/clients/{client_id}/keys")
async def list_client_keys(
    client_id: str,
    request: Request,
    db: Session = Depends(get_db),
):
    request_id = get_request_id(request)
    ok, _ = await _admin_auth(request, db)
    if not ok:
        return error_response("ADMIN_AUTH_REQUIRED", request_id)

    client = db.get(Client, client_id)
    if client is None:
        return error_response("CLIENT_NOT_FOUND", request_id)

    keys = db.execute(
        select(ApiKey)
        .where(ApiKey.client_id == client_id)
        .order_by(ApiKey.created_at.desc())
    ).scalars().all()

    # First day of current month (UTC) — for scan count window
    today = date.today()
    month_start = datetime(today.year, today.month, 1, tzinfo=timezone.utc)
    quota_reset = _quota_resets_at()

    result = []
    for k in keys:
        current_month_scans = db.execute(
            select(func.count()).select_from(ScanJob).where(
                ScanJob.api_key_id == k.id,
                ScanJob.created_at >= month_start,
            )
        ).scalar_one()

        result.append({
            "id": k.id,
            "key_prefix": k.key_prefix,
            "label": k.label,
            "scopes": k.scopes,
            "is_active": k.is_active,
            "rate_limit_rpm": k.rate_limit_rpm,
            "scan_quota_per_month": k.scan_quota_per_month,
            "expires_at": k.expires_at.isoformat() if k.expires_at else None,
            "last_used_at": k.last_used_at.isoformat() if k.last_used_at else None,
            "created_at": k.created_at.isoformat(),
            "cors_origins": k.cors_origins,
            "current_month_scans": current_month_scans,
            "quota_resets_at": quota_reset,
        })

    return {
        "request_id": request_id,
        "data": result,
    }


# ---------------------------------------------------------------------------
# PATCH /v1/admin/keys/{key_id}
# ---------------------------------------------------------------------------
@router.patch("/admin/keys/{key_id}")
async def patch_api_key(
    key_id: str,
    request: Request,
    body: PatchApiKeyRequest,
    db: Session = Depends(get_db),
):
    """Update quota, rate limit, label, active status, or cors_origins for a key."""
    request_id = get_request_id(request)
    ok, actor_key_id = await _admin_auth(request, db)
    if not ok:
        return error_response("ADMIN_AUTH_REQUIRED", request_id)

    # Determine which fields were explicitly provided in the request body
    provided = body.model_fields_set

    from app.services.key_service import _UNSET

    updated = update_api_key(
        db,
        key_id=key_id,
        client_id=None,  # admin can patch any key
        label=body.label if "label" in provided else _UNSET,
        scan_quota_per_month=body.scan_quota_per_month if "scan_quota_per_month" in provided else _UNSET,
        rate_limit_rpm=body.rate_limit_rpm if "rate_limit_rpm" in provided else _UNSET,
        is_active=body.is_active if "is_active" in provided else _UNSET,
        cors_origins=body.cors_origins if "cors_origins" in provided else _UNSET,
        expires_at=body.expires_at if "expires_at" in provided else _UNSET,
    )

    if updated is None:
        return error_response("KEY_NOT_FOUND", request_id)

    # Build changed fields dict for audit log (only provided fields)
    changed = {field: getattr(body, field) for field in provided}

    write_audit_log(
        db,
        actor="admin",
        action="key_updated",
        client_id=updated.client_id,
        api_key_id=actor_key_id,
        target_type="api_key",
        target_id=key_id,
        metadata=changed,
        ip_address=request.client.host if request.client else None,
        request_id=request_id,
    )

    response_data = ApiKeyResponse(
        id=updated.id,
        key_prefix=updated.key_prefix,
        label=updated.label,
        scopes=updated.scopes,
        rate_limit_rpm=updated.rate_limit_rpm,
        scan_quota_per_month=updated.scan_quota_per_month,
        is_active=updated.is_active,
        created_at=updated.created_at,
        last_used_at=updated.last_used_at,
        expires_at=updated.expires_at,
        cors_origins=updated.cors_origins,
    ).model_dump(mode="json")

    return {"request_id": request_id, "data": response_data}


# ---------------------------------------------------------------------------
# DELETE /v1/admin/keys/{key_id}
# ---------------------------------------------------------------------------
@router.delete("/admin/keys/{key_id}", status_code=204)
async def revoke_key(
    key_id: str,
    request: Request,
    db: Session = Depends(get_db),
):
    request_id = get_request_id(request)
    ok, actor_key_id = await _admin_auth(request, db)
    if not ok:
        return error_response("ADMIN_AUTH_REQUIRED", request_id)

    target_key = db.get(ApiKey, key_id)
    if target_key is None:
        return error_response("KEY_NOT_FOUND", request_id)

    revoked = revoke_api_key(db, key_id=key_id)
    if not revoked:
        return error_response("KEY_NOT_FOUND", request_id)

    write_audit_log(
        db,
        actor="admin",
        action="key_revoked",
        client_id=target_key.client_id,
        api_key_id=actor_key_id,
        target_type="api_key",
        target_id=key_id,
        ip_address=request.client.host if request.client else None,
        request_id=request_id,
    )

    return Response(status_code=204)


# ---------------------------------------------------------------------------
# GET /v1/admin/audit-logs
# GET /v1/admin/clients/{client_id}/audit-logs
# ---------------------------------------------------------------------------

@router.get("/admin/audit-logs")
async def list_audit_logs_global(
    request: Request,
    db: Session = Depends(get_db),
    client_id: str | None = Query(None),
    action: str | None = Query(None),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
):
    """List audit log entries across all clients, filterable by client_id and action."""
    import asyncio
    request_id = get_request_id(request)
    ok, _ = await _admin_auth(request, db)
    if not ok:
        return error_response("ADMIN_AUTH_REQUIRED", request_id)

    def _query():
        stmt = select(AuditLog)
        if client_id:
            stmt = stmt.where(AuditLog.client_id == client_id)
        if action:
            stmt = stmt.where(AuditLog.action == action)
        total = db.execute(select(func.count()).select_from(stmt.subquery())).scalar_one()
        rows = db.execute(
            stmt.order_by(AuditLog.created_at.desc()).limit(limit).offset(offset)
        ).scalars().all()
        return total, rows

    total, rows = await asyncio.to_thread(_query)
    items = [_audit_row(a) for a in rows]
    return {"request_id": request_id, "data": items, "meta": {"total": total, "limit": limit, "offset": offset}}


@router.get("/admin/clients/{client_id}/audit-logs")
async def list_client_audit_logs(
    client_id: str,
    request: Request,
    db: Session = Depends(get_db),
    action: str | None = Query(None),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
):
    """List audit log entries for a specific client."""
    import asyncio
    request_id = get_request_id(request)
    ok, _ = await _admin_auth(request, db)
    if not ok:
        return error_response("ADMIN_AUTH_REQUIRED", request_id)

    client = db.get(Client, client_id)
    if client is None:
        return error_response("CLIENT_NOT_FOUND", request_id)

    def _query():
        stmt = select(AuditLog).where(AuditLog.client_id == client_id)
        if action:
            stmt = stmt.where(AuditLog.action == action)
        total = db.execute(select(func.count()).select_from(stmt.subquery())).scalar_one()
        rows = db.execute(
            stmt.order_by(AuditLog.created_at.desc()).limit(limit).offset(offset)
        ).scalars().all()
        return total, rows

    total, rows = await asyncio.to_thread(_query)
    items = [_audit_row(a) for a in rows]
    return {"request_id": request_id, "data": items, "meta": {"total": total, "limit": limit, "offset": offset}}


def _audit_row(a: AuditLog) -> dict:
    return {
        "id": a.id,
        "client_id": a.client_id,
        "api_key_id": a.api_key_id,
        "actor": a.actor,
        "action": a.action,
        "target_type": a.target_type,
        "target_id": a.target_id,
        "metadata": a.metadata_json,
        "ip_address": a.ip_address,
        "created_at": a.created_at.isoformat(),
    }