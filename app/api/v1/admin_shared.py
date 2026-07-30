"""
Shared helpers for admin API modules.
"""
import logging
from fastapi import Request
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.client import Client
from app.schemas.admin import ClientResponse

logger = logging.getLogger(__name__)


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