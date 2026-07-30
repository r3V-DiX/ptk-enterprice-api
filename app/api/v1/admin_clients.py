"""
Admin client CRUD endpoints.
"""
import logging
from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse, Response
from sqlalchemy.orm import Session
from sqlalchemy import select, func

from app.core.database import get_db
from app.core.errors import error_response, get_request_id
from app.models.client import Client
from app.schemas.admin import CreateClientRequest
from app.services.audit_service import write_audit_log
from app.api.v1.admin_shared import _admin_auth, _client_response

logger = logging.getLogger(__name__)

router = APIRouter(tags=["admin"])


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


# ---------------------------------------------------------------------------
# DELETE /v1/admin/clients/{client_id}
# ---------------------------------------------------------------------------
@router.delete("/admin/clients/{client_id}", status_code=204)
async def delete_client(
    client_id: str,
    request: Request,
    db: Session = Depends(get_db),
):
    """Permanently delete a client and all their data (cascade)."""
    request_id = get_request_id(request)
    ok, actor_key_id = await _admin_auth(request, db)
    if not ok:
        return error_response("ADMIN_AUTH_REQUIRED", request_id)

    client = db.get(Client, client_id)
    if client is None:
        return error_response("CLIENT_NOT_FOUND", request_id)

    write_audit_log(
        db,
        actor="admin",
        action="client_deleted",
        client_id=client_id,
        api_key_id=actor_key_id,
        target_type="client",
        target_id=client_id,
        metadata={"company_name": client.company_name, "contact_email": client.contact_email},
        ip_address=request.client.host if request.client else None,
        request_id=request_id,
    )

    db.delete(client)
    db.commit()
    logger.info("Admin deleted client client_id=%s", client_id)
    return Response(status_code=204)