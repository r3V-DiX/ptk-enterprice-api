"""
Admin API endpoints.

Bootstrap note: POST /v1/admin/clients and POST /v1/admin/clients/{id}/keys
accept either a valid admin API key OR the BOOTSTRAP_SECRET env var as Bearer token.
This allows provisioning the very first admin key without a chicken-and-egg problem.
Phase 6 will add a flag to disable bootstrap access once the first key exists.
"""
import logging
from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse, Response
from sqlalchemy.orm import Session
from sqlalchemy import select, func

from app.core.database import get_db
from app.core.errors import error_response, get_request_id
from app.core.config import settings
from app.models.client import Client
from app.models.api_key import ApiKey
from app.schemas.admin import (
    CreateClientRequest,
    ClientResponse,
    CreateApiKeyRequest,
    ApiKeyCreatedResponse,
    ApiKeyResponse,
)
from app.services.key_service import create_api_key, revoke_api_key
from app.services.audit_service import write_audit_log

logger = logging.getLogger(__name__)

router = APIRouter(tags=["admin"])


def _has_admin_session(request: Request, db: Session) -> bool:
    """Return True if the request carries a valid admin portal session cookie."""
    from app.services.admin_auth_service import verify_session
    token = request.cookies.get("ptk_admin_session")
    if not token:
        return False
    return bool(verify_session(token, db))


async def _admin_auth(request: Request, db: Session) -> tuple[bool, str | None]:
    """
    Accept either the portal session cookie OR a Bearer API key with admin scope.
    Returns (ok, api_key_id). api_key_id is None when authed via session/bootstrap.
    Returns (False, None) when neither is present/valid.
    """
    if _has_admin_session(request, db) or _is_bootstrap(request):
        return True, None
    from app.core.auth import get_api_key, AuthError, ScopeError
    try:
        api_key = await get_api_key(request, db)
    except (AuthError, ScopeError):
        return False, None
    if "admin" not in (api_key.scopes or []):
        return False, None
    return True, api_key.id


def _is_bootstrap(request: Request) -> bool:
    """True if the request carries a valid BOOTSTRAP_SECRET as Bearer token."""
    secret = settings.BOOTSTRAP_SECRET
    if not secret:
        return False
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return False
    return auth[len("Bearer "):] == secret


def _client_response(client: Client) -> dict:
    return ClientResponse.model_validate(client).model_dump(mode="json")


# ---------------------------------------------------------------------------
# POST /v1/admin/clients
# ---------------------------------------------------------------------------
@router.post("/admin/clients", status_code=201)
async def create_client(
    request: Request,
    body: CreateClientRequest,
    db: Session = Depends(get_db),
):
    request_id = get_request_id(request)

    ok, actor_key_id = await _admin_auth(request, db)
    if not ok:
        return error_response("ADMIN_AUTH_REQUIRED", request_id)

    # Check for duplicate email
    existing = db.execute(
        select(Client).where(Client.contact_email == body.contact_email)
    ).scalar_one_or_none()
    if existing:
        return JSONResponse(
            status_code=409,
            content={"error": {"code": "DUPLICATE_EMAIL", "message": "A client with this email already exists.", "request_id": request_id}},
        )

    client = Client(
        company_name=body.company_name,
        contact_email=body.contact_email,
        tier=body.tier,
    )
    db.add(client)
    db.commit()
    db.refresh(client)

    write_audit_log(
        db,
        actor="admin",
        action="client_created",
        client_id=client.id,
        api_key_id=actor_key_id,
        target_type="client",
        target_id=client.id,
        ip_address=request.client.host if request.client else None,
        request_id=request_id,
    )

    return JSONResponse(
        status_code=201,
        content={"request_id": request_id, "data": _client_response(client)},
    )


# ---------------------------------------------------------------------------
# GET /v1/admin/clients
# ---------------------------------------------------------------------------
@router.get("/admin/clients")
async def list_clients(
    request: Request,
    limit: int = 20,
    offset: int = 0,
    db: Session = Depends(get_db),
):
    request_id = get_request_id(request)
    ok, _ = await _admin_auth(request, db)
    if not ok:
        return error_response("ADMIN_AUTH_REQUIRED", request_id)

    total = db.execute(select(func.count()).select_from(Client)).scalar_one()
    clients = db.execute(
        select(Client).order_by(Client.created_at.desc()).limit(limit).offset(offset)
    ).scalars().all()

    page = (offset // limit) + 1 if limit else 1
    return {
        "request_id": request_id,
        "data": [_client_response(c) for c in clients],
        "meta": {"total": total, "page": page, "limit": limit},
    }


# ---------------------------------------------------------------------------
# GET /v1/admin/clients/{client_id}
# ---------------------------------------------------------------------------
@router.get("/admin/clients/{client_id}")
async def get_client(
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

    return {"request_id": request_id, "data": _client_response(client)}


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

    from sqlalchemy import select as sa_select
    keys = db.execute(
        sa_select(ApiKey)
        .where(ApiKey.client_id == client_id)
        .order_by(ApiKey.created_at.desc())
    ).scalars().all()

    return {
        "request_id": request_id,
        "data": [
            {
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
            }
            for k in keys
        ],
    }


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
# PATCH /v1/admin/clients/{client_id}
# ---------------------------------------------------------------------------
@router.patch("/admin/clients/{client_id}")
async def update_client(
    client_id: str,
    request: Request,
    db: Session = Depends(get_db),
):
    """Update a client's tier or active status."""
    request_id = get_request_id(request)
    ok, actor_key_id = await _admin_auth(request, db)
    if not ok:
        return error_response("ADMIN_AUTH_REQUIRED", request_id)

    client = db.get(Client, client_id)
    if client is None:
        return error_response("CLIENT_NOT_FOUND", request_id)

    try:
        body = await request.json()
    except Exception:
        return JSONResponse(status_code=422, content={"error": {"code": "INVALID_BODY", "message": "Invalid JSON body.", "request_id": request_id}})

    changed: dict = {}
    if "tier" in body:
        allowed_tiers = {"free", "pro", "enterprise"}
        if body["tier"] not in allowed_tiers:
            return JSONResponse(status_code=422, content={"error": {"code": "INVALID_TIER", "message": f"tier must be one of {allowed_tiers}.", "request_id": request_id}})
        client.tier = body["tier"]
        changed["tier"] = body["tier"]

    if "is_active" in body:
        if not isinstance(body["is_active"], bool):
            return JSONResponse(status_code=422, content={"error": {"code": "INVALID_VALUE", "message": "is_active must be a boolean.", "request_id": request_id}})
        client.is_active = body["is_active"]
        changed["is_active"] = body["is_active"]

    if "company_name" in body:
        name = str(body["company_name"]).strip()
        if not name:
            return JSONResponse(status_code=422, content={"error": {"code": "INVALID_VALUE", "message": "company_name cannot be empty.", "request_id": request_id}})
        client.company_name = name
        changed["company_name"] = name

    if not changed:
        return JSONResponse(status_code=422, content={"error": {"code": "NO_CHANGES", "message": "No updatable fields provided.", "request_id": request_id}})

    db.commit()
    db.refresh(client)

    write_audit_log(
        db,
        actor="admin",
        action="client_updated",
        client_id=client_id,
        api_key_id=actor_key_id,
        target_type="client",
        target_id=client_id,
        metadata=changed,
        ip_address=request.client.host if request.client else None,
        request_id=request_id,
    )

    logger.info("Client updated client_id=%s changes=%s", client_id, changed)
    return {"request_id": request_id, "data": _client_response(client)}
