import logging
from sqlalchemy.orm import Session
from app.models.audit_log import AuditLog

logger = logging.getLogger(__name__)


def write_audit_log(
    db: Session,
    actor: str,
    action: str,
    client_id: str | None = None,
    api_key_id: str | None = None,
    target_type: str | None = None,
    target_id: str | None = None,
    metadata: dict | None = None,
    ip_address: str | None = None,
    request_id: str | None = None,
) -> None:
    """Append one row to audit_logs. Never raises — swallows DB errors after logging."""
    try:
        row = AuditLog(
            client_id=client_id,
            api_key_id=api_key_id,
            actor=actor,
            action=action,
            target_type=target_type,
            target_id=target_id,
            metadata_json=metadata,
            ip_address=ip_address,
            request_id=request_id,
        )
        db.add(row)
        db.commit()
    except Exception as exc:
        logger.error("Failed to write audit log action=%s actor=%s: %s", action, actor, exc)
        db.rollback()
