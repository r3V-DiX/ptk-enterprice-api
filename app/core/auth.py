import logging
from fastapi import Depends, Request
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.core.errors import error_response, get_request_id
from app.core.rate_limit import check_rate_limit
from app.models.api_key import ApiKey

logger = logging.getLogger(__name__)


class AuthError(Exception):
    """Raised by auth dependencies; caught by the registered exception handler."""
    def __init__(self, response: JSONResponse):
        self.response = response


class ScopeError(Exception):
    """Raised by scope dependencies; caught by the registered exception handler."""
    def __init__(self, response: JSONResponse):
        self.response = response


async def get_api_key(request: Request, db: Session = Depends(get_db)) -> ApiKey:
    """
    FastAPI dependency: extract Bearer token, rate-limit check (before DB), verify key.
    Raises AuthError on any failure — caught by exception handler in main.py.
    """
    import asyncio
    from app.services.key_service import verify_api_key as _verify

    request_id = get_request_id(request)

    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        raise AuthError(error_response("INVALID_API_KEY", request_id))

    raw_key = auth_header[len("Bearer "):]
    if not raw_key:
        raise AuthError(error_response("INVALID_API_KEY", request_id))

    # Pre-verify coarse rate limit keyed on key prefix (no DB needed yet).
    # Prevents timing-based enumeration. Limit set to 2× max real limit.
    # Use 16 chars so the bucket is unique per key, not shared across the common ptk_live_ prefix
    key_prefix_bucket = f"pre:{raw_key[:16]}"
    if not check_rate_limit(key_prefix_bucket, 120):
        raise AuthError(error_response("RATE_LIMIT_EXCEEDED", request_id))

    try:
        api_key = await asyncio.to_thread(_verify, db, raw_key)
    except ValueError as exc:
        code = str(exc)
        raise AuthError(error_response(code if code in ("EXPIRED_API_KEY",) else "INVALID_API_KEY", request_id))

    if api_key is None:
        raise AuthError(error_response("INVALID_API_KEY", request_id))

    # Expose to ApiLoggerMiddleware NOW — before any further raises so even
    # rate-limited or scope-rejected requests are attributed to the right client.
    request.state.client_id = api_key.client_id
    request.state.api_key_id = api_key.id

    # Per-key rate limit using the confirmed key id
    if not check_rate_limit(api_key.id, api_key.rate_limit_rpm):
        logger.warning("Rate limit exceeded for key prefix=%s", api_key.key_prefix)
        raise AuthError(error_response("RATE_LIMIT_EXCEEDED", request_id))

    # Per-key CORS enforcement
    # If cors_origins is set, the request MUST come from one of those origins.
    # Requests with no Origin header (curl, Postman, server-to-server) are also blocked
    # because the key is intended for browser-side use from a specific domain only.
    if api_key.cors_origins:
        origin = (request.headers.get("origin") or request.headers.get("Origin", "")).rstrip("/")
        allowed = [o.rstrip("/") for o in api_key.cors_origins]
        if not origin or origin not in allowed:
            logger.warning(
                "CORS origin rejected key_prefix=%s origin=%r (allowed=%s)",
                api_key.key_prefix, origin, allowed,
            )
            raise AuthError(error_response("CORS_ORIGIN_NOT_ALLOWED", request_id))

    return api_key


def require_scope(*required_scopes: str):
    """
    Dependency factory returning a FastAPI Depends that checks api_key.scopes.
    Usage: api_key: ApiKey = require_scope("admin")
    """
    async def _check(
        request: Request,
        api_key: ApiKey = Depends(get_api_key),
    ) -> ApiKey:
        request_id = get_request_id(request)
        key_scopes = api_key.scopes or []
        for scope in required_scopes:
            if scope not in key_scopes:
                logger.warning(
                    "Scope check failed: required=%s key_prefix=%s",
                    scope,
                    api_key.key_prefix,
                )
                raise ScopeError(error_response("INSUFFICIENT_SCOPE", request_id))
        return api_key

    return Depends(_check)
