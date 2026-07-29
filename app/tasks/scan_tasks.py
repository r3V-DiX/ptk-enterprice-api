import logging
from app.tasks.celery_config import celery_app  # noqa: F401 — re-exported for celery_worker

logger = logging.getLogger(__name__)


@celery_app.task(
    name="run_scan",
    bind=True,
    max_retries=3,
    soft_time_limit=660,
    time_limit=720,
)
def run_scan(self, scan_id: str):
    """
    Stub scan task — Phase 4 replaces the inner block with real plugin calls.
    Idempotent: skips silently if scan is already past 'queued'.
    """
    from datetime import datetime, timezone
    from app.core.database import SessionLocal
    from app.models.scan_job import ScanJob
    from app.models.scan_result import ScanResult
    from app.services.usage_service import write_usage_event

    with SessionLocal() as db:
        scan = db.query(ScanJob).filter(ScanJob.id == scan_id).first()
        if not scan:
            logger.warning("run_scan: scan_id %s not found", scan_id)
            return

        # Idempotency: skip if already progressed past queued
        if scan.status != "queued":
            logger.info("run_scan: scan %s already %s, skipping", scan_id, scan.status)
            return

        logger.info("━━━ SCAN START  id=%s  target=%s", scan_id[:8], scan.target)
        try:
            scan.status = "running"
            scan.started_at = datetime.now(timezone.utc)
            db.commit()

            from app.scanner.plugin_registry import registry
            from app.models.finding import Finding

            plugins = registry.list_default()
            all_findings = []
            tools_run = []
            tool_errors = {}

            for plugin in plugins:
                logger.info("[%s] ▶ running plugin: %s", scan.target, plugin.meta.id)
                try:
                    result = plugin.run(target=scan.target, options={})
                    tools_run.append(plugin.meta.id)
                    if result.error:
                        tool_errors[plugin.meta.id] = result.error
                        logger.warning(
                            "[%s] ✗ plugin %s error: %s",
                            scan.target, plugin.meta.id, result.error,
                        )
                    else:
                        findings_count = len(result.findings)
                        for f in result.findings:
                            f["tool"] = plugin.meta.id
                        all_findings.extend(result.findings)
                        logger.info(
                            "[%s] ✓ plugin %s done — %d finding(s)",
                            scan.target, plugin.meta.id, findings_count,
                        )
                except Exception as exc:
                    tool_errors[plugin.meta.id] = str(exc)
                    logger.warning("[%s] ✗ plugin %s raised: %s", scan.target, plugin.meta.id, exc)

            # Aggregate phase
            scan.status = "aggregating"
            db.commit()

            # Persist findings
            for f in all_findings:
                finding_row = Finding(
                    scan_job_id=scan_id,
                    client_id=scan.client_id,
                    title=f["title"],
                    severity=f["severity"],
                    tool=f.get("tool", "unknown"),
                    description=f.get("description"),
                    remediation=f.get("remediation"),
                    evidence_json=f.get("evidence"),
                    cvss_score=f.get("cvss_score"),
                    cwe_id=f.get("cwe_id"),
                    owasp_category=f.get("owasp_category"),
                )
                db.add(finding_row)

            severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
            for f in all_findings:
                if f["severity"] in severity_counts:
                    severity_counts[f["severity"]] += 1

            result_row = ScanResult(
                scan_job_id=scan_id,
                result_json={"tools": tools_run, "tool_errors": tool_errors},
                summary_json={
                    "total_findings": len(all_findings),
                    "by_severity": severity_counts,
                    "tool_errors": tool_errors,
                },
            )
            db.add(result_row)

            scan.status = "completed"
            scan.completed_at = datetime.now(timezone.utc)
            scan.tools_run = tools_run
            db.commit()

            write_usage_event(
                db,
                client_id=scan.client_id,
                event_type="scan_completed",
                api_key_id=scan.api_key_id,
                scan_job_id=scan_id,
                metadata={"target": scan.target, "finding_count": len(all_findings)},
            )

            logger.info(
                "━━━ SCAN DONE   id=%s  target=%s  findings=%d  tools=%s",
                scan_id[:8], scan.target, len(all_findings), tools_run,
            )

        except Exception as exc:
            logger.error("━━━ SCAN FAILED id=%s  target=%s  error=%s", scan_id[:8], scan.target, exc)
            try:
                scan.status = "failed"
                scan.error = str(exc)
                db.commit()
            except Exception as inner:
                logger.error("Failed to mark scan %s as failed: %s", scan_id, inner)
