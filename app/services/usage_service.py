import logging
from datetime import datetime, timezone, timedelta
from sqlalchemy.orm import Session
from sqlalchemy import func, select
from app.models.usage_event import UsageEvent
from app.models.scan_job import ScanJob
from app.models.finding import Finding

logger = logging.getLogger(__name__)


def write_usage_event(
    db: Session,
    client_id: str,
    event_type: str,
    api_key_id: str | None = None,
    scan_job_id: str | None = None,
    metadata: dict | None = None,
) -> None:
    """Append one row to usage_events. Never raises — swallows DB errors after logging."""
    try:
        row = UsageEvent(
            client_id=client_id,
            api_key_id=api_key_id,
            scan_job_id=scan_job_id,
            event_type=event_type,
            metadata_json=metadata,
        )
        db.add(row)
        db.commit()
    except Exception as exc:
        logger.error("Failed to write usage event type=%s client=%s: %s", event_type, client_id, exc)
        db.rollback()


def get_usage_summary(db: Session, client_id: str) -> dict:
    """Return aggregated usage counts for a client."""
    try:
        total_scans = db.execute(
            select(func.count()).select_from(ScanJob).where(ScanJob.client_id == client_id)
        ).scalar_one()

        total_findings = db.execute(
            select(func.count()).select_from(Finding).where(Finding.client_id == client_id)
        ).scalar_one()

        cutoff = datetime.now(timezone.utc) - timedelta(days=30)
        events_last_30_days = db.execute(
            select(func.count())
            .select_from(UsageEvent)
            .where(UsageEvent.client_id == client_id)
            .where(UsageEvent.created_at >= cutoff)
        ).scalar_one()

        return {
            "total_scans": total_scans,
            "total_findings": total_findings,
            "events_last_30_days": events_last_30_days,
        }
    except Exception as exc:
        logger.error("Failed to get usage summary for client=%s: %s", client_id, exc)
        return {"total_scans": 0, "total_findings": 0, "events_last_30_days": 0}
