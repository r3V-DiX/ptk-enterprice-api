"""
Admin portal authentication service.

Flow:
  1. request_otp(email, db) — validate email is in ADMIN_EMAILS, generate 6-digit
     code, hash + store in admin_otps, send via Resend.
  2. verify_otp(email, code, db) — verify code hash matches, not expired, not used.
     On success: create AdminSession row + return plaintext session token.
  3. verify_session(token, db) — hash token, look up AdminSession, check expiry.
     Returns email on success, None on failure.
  4. revoke_session(token, db) — mark AdminSession.is_active = False.
"""
import hashlib
import logging
import os
import secrets
from datetime import datetime, timedelta, timezone
from sqlalchemy.orm import Session
from sqlalchemy import select

from app.core.config import settings
from app.models.admin_otp import AdminOtp
from app.models.admin_session import AdminSession

logger = logging.getLogger(__name__)


# ─── helpers ──────────────────────────────────────────────────────────────────

def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _now() -> datetime:
    return datetime.now(timezone.utc)


# ─── OTP ──────────────────────────────────────────────────────────────────────

class OtpError(Exception):
    pass


def request_otp(email: str, db: Session, ip: str | None = None) -> None:
    """
    Generate a 6-digit OTP, store its hash, and send it via Resend.
    Raises OtpError on any problem (unknown email, send failure).
    """
    allowed = settings.get_admin_emails()
    if allowed and email.lower() not in allowed:
        # Don't reveal which emails are allowed — generic message
        raise OtpError("EMAIL_NOT_ALLOWED")

    # Rate-limit: at most 3 active (unused + non-expired) OTPs per email
    active_count = db.execute(
        select(AdminOtp).where(
            AdminOtp.email == email.lower(),
            AdminOtp.used.is_(False),
            AdminOtp.expires_at > _now(),
        )
    ).scalars().all()
    if len(active_count) >= 3:
        raise OtpError("TOO_MANY_REQUESTS")

    code = f"{secrets.randbelow(1_000_000):06d}"
    code_hash = _sha256(code)
    expires_at = _now() + timedelta(seconds=settings.ADMIN_OTP_TTL)

    otp = AdminOtp(
        email=email.lower(),
        code_hash=code_hash,
        expires_at=expires_at,
    )
    db.add(otp)
    db.commit()

    _send_otp_email(email, code)
    logger.info("OTP issued for admin email=%s ip=%s", email, ip)


def _send_otp_email(email: str, code: str) -> None:
    """Send OTP via Resend. Raises OtpError if send fails."""
    if not settings.RESEND_API_KEY:
        # Development fallback — print to server log
        logger.warning("RESEND_API_KEY not set — OTP code for %s is: %s", email, code)
        return

    try:
        import resend
        resend.api_key = settings.RESEND_API_KEY
        resend.Emails.send({
            "from": settings.EMAIL_FROM,
            "to": [email],
            "subject": "Your Pentoolkit Admin OTP",
            "html": _otp_email_html(code),
        })
        logger.info("OTP email sent to %s", email)
    except Exception as exc:
        logger.error("Failed to send OTP email to %s: %s", email, exc)
        raise OtpError("EMAIL_SEND_FAILED") from exc


def _otp_email_html(code: str) -> str:
    return f"""
<!DOCTYPE html>
<html>
<body style="font-family:Inter,sans-serif;background:#f8fafc;margin:0;padding:40px;">
  <div style="max-width:420px;margin:0 auto;background:#fff;border-radius:8px;
              border:1px solid #e2e8f0;padding:40px;">
    <p style="margin:0 0 8px;font-size:13px;color:#64748b;text-transform:uppercase;
              letter-spacing:.05em;font-weight:600;">Pentoolkit Admin</p>
    <h1 style="margin:0 0 24px;font-size:22px;color:#0f172a;">Your login code</h1>
    <div style="background:#f1f5f9;border-radius:6px;padding:20px;text-align:center;
                font-size:36px;letter-spacing:.25em;font-weight:700;color:#0f172a;
                font-family:monospace;">{code}</div>
    <p style="margin:20px 0 0;font-size:14px;color:#64748b;">
      This code expires in 10 minutes.<br>
      If you didn't request this, ignore this email.
    </p>
  </div>
</body>
</html>
"""


# ─── Session ──────────────────────────────────────────────────────────────────

def verify_otp_and_create_session(
    email: str, code: str, db: Session, ip: str | None = None
) -> str:
    """
    Verify OTP code for email. On success, mark OTP used, create AdminSession,
    return plaintext session token. Raises OtpError on any failure.
    """
    code_hash = _sha256(code)

    otp = db.execute(
        select(AdminOtp).where(
            AdminOtp.email == email.lower(),
            AdminOtp.code_hash == code_hash,
            AdminOtp.used.is_(False),
            AdminOtp.expires_at > _now(),
        ).order_by(AdminOtp.created_at.desc()).limit(1)
    ).scalar_one_or_none()

    if otp is None:
        logger.warning("OTP verify failed for email=%s ip=%s", email, ip)
        raise OtpError("INVALID_OR_EXPIRED_CODE")

    otp.used = True
    db.flush()

    # Create session
    plaintext_token = secrets.token_hex(32)
    token_hash = _sha256(plaintext_token)
    expires_at = _now() + timedelta(seconds=settings.ADMIN_SESSION_TTL)

    session = AdminSession(
        email=email.lower(),
        token_hash=token_hash,
        expires_at=expires_at,
        ip_address=ip,
    )
    db.add(session)
    db.commit()

    logger.info("Admin session created for email=%s ip=%s", email, ip)
    return plaintext_token


def verify_session(token: str, db: Session) -> str | None:
    """
    Verify a session token. Returns the admin email on success, None on failure.
    """
    try:
        token_hash = _sha256(token)
        session = db.execute(
            select(AdminSession).where(
                AdminSession.token_hash == token_hash,
                AdminSession.is_active.is_(True),
                AdminSession.expires_at > _now(),
            )
        ).scalar_one_or_none()

        if session is None:
            return None

        return session.email

    except Exception as exc:
        logger.error("Session verify error: %s", exc)
        return None


def revoke_session(token: str, db: Session) -> None:
    """Invalidate a session token (logout)."""
    try:
        token_hash = _sha256(token)
        session = db.execute(
            select(AdminSession).where(AdminSession.token_hash == token_hash)
        ).scalar_one_or_none()
        if session:
            session.is_active = False
            db.commit()
            logger.info("Admin session revoked for email=%s", session.email)
    except Exception as exc:
        logger.error("Session revoke error: %s", exc)
        db.rollback()
