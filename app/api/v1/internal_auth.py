"""
Internal admin portal auth endpoints.

POST /v1/internal/auth/request-otp  — send 6-digit code to admin email
POST /v1/internal/auth/verify-otp   — verify code → set session cookie
POST /v1/internal/auth/logout        — revoke session cookie
GET  /v1/internal/auth/me            — return email if session is valid
"""
import logging
from fastapi import APIRouter, Depends, Request, Response
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.errors import error_response, get_request_id
from app.services.admin_auth_service import (
    OtpError,
    request_otp,
    verify_otp_and_create_session,
    verify_session,
    revoke_session,
)

logger = logging.getLogger(__name__)
router = APIRouter(tags=["internal-auth"])

_COOKIE_NAME = "ptk_admin_session"
_COOKIE_MAX_AGE = 86400  # 24 h


def _get_session_token(request: Request) -> str | None:
    return request.cookies.get(_COOKIE_NAME)


def require_admin_session(request: Request, db: Session = Depends(get_db)) -> str:
    """Dependency: returns admin email or raises 401."""
    token = _get_session_token(request)
    if not token:
        raise _unauth(get_request_id(request))
    email = verify_session(token, db)
    if not email:
        raise _unauth(get_request_id(request))
    return email


def _unauth(request_id: str):
    from app.core.errors import ERROR_MESSAGES
    from fastapi import HTTPException
    return HTTPException(
        status_code=401,
        detail={"code": "ADMIN_AUTH_REQUIRED", "message": "Admin authentication required.", "request_id": request_id},
    )


# ── POST /v1/internal/auth/request-otp ────────────────────────────────────────

@router.post("/internal/auth/request-otp", status_code=200)
async def request_otp_endpoint(
    request: Request,
    db: Session = Depends(get_db),
):
    request_id = get_request_id(request)
    try:
        body = await request.json()
        email = (body.get("email") or "").strip().lower()
    except Exception:
        return JSONResponse(status_code=422, content={"error": {"code": "INVALID_BODY", "message": "email is required.", "request_id": request_id}})

    if not email or "@" not in email:
        return JSONResponse(status_code=422, content={"error": {"code": "INVALID_EMAIL", "message": "A valid email address is required.", "request_id": request_id}})

    ip = request.client.host if request.client else None
    import asyncio
    try:
        await asyncio.to_thread(request_otp, email, db, ip)
    except OtpError as exc:
        code = str(exc)
        if code == "EMAIL_NOT_ALLOWED":
            # Return generic message — don't leak which emails are admin
            return JSONResponse(status_code=200, content={"request_id": request_id, "data": {"message": "If this email is registered, a code has been sent."}})
        if code == "TOO_MANY_REQUESTS":
            return JSONResponse(status_code=429, content={"error": {"code": "TOO_MANY_REQUESTS", "message": "Too many OTP requests. Wait a few minutes.", "request_id": request_id}})
        if code == "EMAIL_SEND_FAILED":
            return JSONResponse(status_code=503, content={"error": {"code": "EMAIL_SEND_FAILED", "message": "Failed to send OTP email. Try again.", "request_id": request_id}})
        return error_response("INTERNAL_ERROR", request_id)

    return {"request_id": request_id, "data": {"message": "If this email is registered, a code has been sent."}}


# ── POST /v1/internal/auth/verify-otp ─────────────────────────────────────────

@router.post("/internal/auth/verify-otp", status_code=200)
async def verify_otp_endpoint(
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
):
    request_id = get_request_id(request)
    try:
        body = await request.json()
        email = (body.get("email") or "").strip().lower()
        code = str(body.get("code") or "").strip()
    except Exception:
        return JSONResponse(status_code=422, content={"error": {"code": "INVALID_BODY", "message": "email and code are required.", "request_id": request_id}})

    if not email or not code:
        return JSONResponse(status_code=422, content={"error": {"code": "INVALID_BODY", "message": "email and code are required.", "request_id": request_id}})

    ip = request.client.host if request.client else None
    import asyncio
    try:
        token = await asyncio.to_thread(verify_otp_and_create_session, email, code, db, ip)
    except OtpError:
        return JSONResponse(status_code=401, content={"error": {"code": "INVALID_CODE", "message": "Invalid or expired code.", "request_id": request_id}})

    response.set_cookie(
        key=_COOKIE_NAME,
        value=token,
        max_age=_COOKIE_MAX_AGE,
        httponly=True,
        secure=True,
        samesite="none",
    )
    return {"request_id": request_id, "data": {"message": "Authenticated.", "email": email, "session_token": token}}


# ── POST /v1/internal/auth/logout ─────────────────────────────────────────────

@router.post("/internal/auth/logout", status_code=200)
async def logout_endpoint(
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
):
    request_id = get_request_id(request)
    token = _get_session_token(request)
    if token:
        import asyncio
        await asyncio.to_thread(revoke_session, token, db)
    response.delete_cookie(_COOKIE_NAME)
    return {"request_id": request_id, "data": {"message": "Logged out."}}


# ── GET /v1/internal/auth/me ───────────────────────────────────────────────────

@router.get("/internal/auth/me", status_code=200)
async def me_endpoint(
    request: Request,
    db: Session = Depends(get_db),
):
    request_id = get_request_id(request)
    token = _get_session_token(request)
    if not token:
        return JSONResponse(status_code=401, content={"error": {"code": "ADMIN_AUTH_REQUIRED", "message": "Not authenticated.", "request_id": request_id}})
    import asyncio
    email = await asyncio.to_thread(verify_session, token, db)
    if not email:
        return JSONResponse(status_code=401, content={"error": {"code": "ADMIN_AUTH_REQUIRED", "message": "Session expired.", "request_id": request_id}})
    return {"request_id": request_id, "data": {"email": email}}
