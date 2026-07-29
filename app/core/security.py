import hashlib
import secrets
import logging
from functools import wraps
from fastapi import Depends, HTTPException
from sqlalchemy.orm import Session
from app.core.database import get_db

logger = logging.getLogger(__name__)


def generate_api_key() -> str:
    """Generate a new API key: ptk_live_<43 random base64url chars>."""
    return f"ptk_live_{secrets.token_urlsafe(32)}"


def hash_api_key(key: str) -> str:
    """Return SHA-256 hex digest of the key."""
    return hashlib.sha256(key.encode()).hexdigest()


def verify_api_key(plain_key: str, stored_hash: str) -> bool:
    """Constant-time comparison of hashed key against stored hash."""
    return secrets.compare_digest(hash_api_key(plain_key), stored_hash)


def get_key_prefix(key: str) -> str:
    """Return first 14 chars of the key for display/identification (ptk_live_XXXXX)."""
    return key[:14]


def require_scope(*required_scopes: str):
    """
    Decorator factory for scope-based authorization.
    Usage: @require_scope("scan:write")
    The decorated endpoint must already have `api_key` resolved via dependency.
    """
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            api_key = kwargs.get("api_key") or (args[0] if args else None)
            if api_key is None:
                raise HTTPException(status_code=403, detail="INSUFFICIENT_SCOPE")
            key_scopes = api_key.scopes or []
            for scope in required_scopes:
                if scope not in key_scopes:
                    logger.warning(
                        "Scope check failed: required=%s, key_prefix=%s",
                        scope,
                        api_key.key_prefix,
                    )
                    raise HTTPException(status_code=403, detail="INSUFFICIENT_SCOPE")
            return await func(*args, **kwargs)
        return wrapper
    return decorator
