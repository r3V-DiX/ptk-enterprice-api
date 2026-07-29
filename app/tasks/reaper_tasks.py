import logging
from app.tasks.celery_config import celery_app

logger = logging.getLogger(__name__)


@celery_app.task(name="reap_stale_scans", soft_time_limit=60, time_limit=90)
def reap_stale_scans():
    from datetime import datetime, timezone, timedelta
    from app.core.database import SessionLocal
    from app.models.scan_job import ScanJob

    with SessionLocal() as db:
        now = datetime.now(timezone.utc)
        expire_threshold = now - timedelta(minutes=30)

        # Queued scans never picked up by a worker → expired
        queued_stale = db.query(ScanJob).filter(
            ScanJob.status == "queued",
            ScanJob.created_at < expire_threshold,
        ).all()
        for scan in queued_stale:
            scan.status = "expired"
            scan.error = "Task never picked up by worker"
            logger.warning("Reaped expired scan %s (was queued)", scan.id)

        # Running/initializing/aggregating scans stuck too long → failed
        stuck_stale = db.query(ScanJob).filter(
            ScanJob.status.in_(["running", "initializing", "aggregating"]),
            ScanJob.started_at < expire_threshold,
        ).all()
        for scan in stuck_stale:
            scan.status = "failed"
            scan.error = "Scan timed out — worker did not complete within 30 minutes"
            logger.warning("Reaped stuck scan %s (was %s)", scan.id, scan.status)

        db.commit()
        total = len(queued_stale) + len(stuck_stale)
        if total:
            logger.info("Reaper: cleaned up %d stale scans", total)
