"""
Admin API endpoints.

Bootstrap note: POST /v1/admin/clients and POST /v1/admin/clients/{id}/keys
accept either a valid admin API key OR the BOOTSTRAP_SECRET env var as Bearer token.
This allows provisioning the very first admin key without a chicken-and-egg problem.
Phase 6 will add a flag to disable bootstrap access once the first key exists.
"""
import logging
from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
from sqlalchemy import select, func

from app.core.database import get_db
from app.core.errors import error_response, get_request_id
from app.core.auth import require_scope
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

    # Bootstrap or admin-key auth
    if not _is_bootstrap(request):
        # Trigger scope check via dependency — must have "admin" scope
        from app.core.auth import get_api_key, ScopeError, AuthError
        from app.core.errors import error_response
        try:
            api_key = await get_api_key(request, db)
        except (AuthError, ScopeError) as exc:
            return exc.response
        if "admin" not in (api_key.scopes or []):
            return error_response("INSUFFICIENT_SCOPE", request_id)
        actor_key_id = api_key.id
    else:
        actor_key_id = None

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
    api_key: ApiKey = require_scope("admin"),
):
    request_id = get_request_id(request)

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
    api_key: ApiKey = require_scope("admin"),
):
    request_id = get_request_id(request)

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

    # Bootstrap or admin-key auth
    if not _is_bootstrap(request):
        from app.core.auth import get_api_key, ScopeError, AuthError
        try:
            api_key = await get_api_key(request, db)
        except (AuthError, ScopeError) as exc:
            return exc.response
        if "admin" not in (api_key.scopes or []):
            return error_response("INSUFFICIENT_SCOPE", request_id)
        actor_key_id = api_key.id
    else:
        actor_key_id = None

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
    )

    write_audit_log(
        db,
        actor="admin",
        action="key_created",
        client_id=client_id,
        api_key_id=actor_key_id,
        target_type="api_key",
        target_id=new_key.id,
        metadata={"key_prefix": new_key.key_prefix, "scopes": new_key.scopes},
        ip_address=request.client.host if request.client else None,
        request_id=request_id,
    )

    response_data = ApiKeyCreatedResponse(
        id=new_key.id,
        key_prefix=new_key.key_prefix,
        label=new_key.label,
        scopes=new_key.scopes,
        rate_limit_rpm=new_key.rate_limit_rpm,
        created_at=new_key.created_at,
        plaintext_key=plaintext,
    ).model_dump(mode="json")

    logger.info("Issued key prefix=%s for client=%s", new_key.key_prefix, client_id)

    return JSONResponse(
        status_code=201,
        content={"request_id": request_id, "data": response_data},
    )


# ---------------------------------------------------------------------------
# DELETE /v1/admin/keys/{key_id}
# ---------------------------------------------------------------------------
@router.delete("/admin/keys/{key_id}", status_code=204)
async def revoke_key(
    key_id: str,
    request: Request,
    db: Session = Depends(get_db),
    api_key: ApiKey = require_scope("admin"),
):
    request_id = get_request_id(request)

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
        api_key_id=api_key.id,
        target_type="api_key",
        target_id=key_id,
        ip_address=request.client.host if request.client else None,
        request_id=request_id,
    )

    return JSONResponse(status_code=204, content=None)
