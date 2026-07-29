import logging
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from sqlalchemy import select
from app.models.api_key import ApiKey
from app.core.security import generate_api_key, hash_api_key, get_key_prefix

logger = logging.getLogger(__name__)


def create_api_key(
    db: Session,
    client_id: str,
    label: str | None = None,
    scopes: list[str] | None = None,
    rate_limit_rpm: int = 60,
    expires_at: datetime | None = None,
    scan_quota_per_month: int | None = None,
) -> tuple[ApiKey, str]:
    """
    Generate a new API key for a client.
    Returns (ApiKey ORM object, plaintext_key).
    plaintext_key is shown ONCE — never stored, never returned again.
    """
    if scopes is None:
        scopes = ["scan:write", "scan:read", "usage:read"]

    plaintext = generate_api_key()
    key_hash = hash_api_key(plaintext)
    key_prefix = get_key_prefix(plaintext)

    api_key = ApiKey(
        client_id=client_id,
        key_prefix=key_prefix,
        key_hash=key_hash,
        label=label,
        scopes=scopes,
        rate_limit_rpm=rate_limit_rpm,
        expires_at=expires_at,
        scan_quota_per_month=scan_quota_per_month,
    )
    db.add(api_key)
    db.commit()
    db.refresh(api_key)

    logger.info("API key created: prefix=%s client_id=%s", key_prefix, client_id)
    return api_key, plaintext


def verify_api_key(db: Session, raw_key: str) -> ApiKey | None:
    """
    Verify an incoming API key.
    Hashes raw_key, looks up by hash, checks is_active and expires_at.
    Updates last_used_at on success. Returns None on any failure.
    """
    try:
        key_hash = hash_api_key(raw_key)
        api_key = db.execute(
            select(ApiKey).where(ApiKey.key_hash == key_hash)
        ).scalar_one_or_none()

        if api_key is None:
            return None

        if not api_key.is_active:
            logger.warning("Rejected inactive key prefix=%s", api_key.key_prefix)
            return None

        if api_key.expires_at and api_key.expires_at < datetime.now(timezone.utc):
            logger.warning("Rejected expired key prefix=%s", api_key.key_prefix)
            raise ValueError("EXPIRED_API_KEY")

        api_key.last_used_at = datetime.now(timezone.utc)
        db.commit()
        return api_key

    except Exception as exc:
        logger.error("Error during API key verification: %s", exc)
        return None


def revoke_api_key(db: Session, key_id: str, client_id: str | None = None) -> bool:
    """
    Revoke an API key by setting is_active=False.
    client_id is optional — admin can revoke any key; client-scoped calls pass client_id.
    Returns True if found and revoked, False if not found.
    """
    try:
        stmt = select(ApiKey).where(ApiKey.id == key_id)
        if client_id is not None:
            stmt = stmt.where(ApiKey.client_id == client_id)

        api_key = db.execute(stmt).scalar_one_or_none()
        if api_key is None:
            return False

        api_key.is_active = False
        db.commit()
        logger.info("API key revoked: prefix=%s id=%s", api_key.key_prefix, key_id)
        return True

    except Exception as exc:
        logger.error("Error revoking API key id=%s: %s", key_id, exc)
        db.rollback()
        return False
