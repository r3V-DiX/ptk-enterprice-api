import logging
import os
from datetime import datetime, timezone, timedelta
from sqlalchemy.orm import Session
from sqlalchemy import select
from jinja2 import Environment, FileSystemLoader

from app.core.config import settings
from app.models.scan_job import ScanJob
from app.models.scan_report import ScanReport
from app.services.usage_service import write_usage_event

logger = logging.getLogger(__name__)

_SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]

_TEMPLATES_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "templates")
_jinja_env = Environment(loader=FileSystemLoader(_TEMPLATES_DIR), autoescape=True)


def get_or_generate_report(scan_job_id: str, fmt: str, db: Session) -> bytes:
    """
    Returns raw report bytes ready to stream directly to the client.
    Raises ValueError with error code on scan-not-found or not-ready.
    Generates and caches to S3 on first request; subsequent requests fetch from S3.
    """
    scan = db.get(ScanJob, scan_job_id)
    if scan is None:
        raise ValueError("SCAN_NOT_FOUND")
    if scan.status != "completed":
        raise ValueError("REPORT_NOT_READY")

    # Check for existing cached report in S3
    existing = db.execute(
        select(ScanReport).where(
            ScanReport.scan_job_id == scan_job_id,
            ScanReport.format == fmt,
        )
    ).scalar_one_or_none()

    if existing:
        return fetch_from_s3(existing.s3_key)

    # Generate fresh report
    html = render_html(scan, db)
    if fmt == "pdf":
        content = html_to_pdf(html)
    else:
        content = html.encode("utf-8") if isinstance(html, str) else html

    s3_key = upload_report(scan.client_id, scan_job_id, content, fmt)

    report_row = ScanReport(
        scan_job_id=scan_job_id,
        client_id=scan.client_id,
        format=fmt,
        s3_key=s3_key,
        size_bytes=len(content),
        generated_at=datetime.now(timezone.utc),
    )
    db.add(report_row)
    db.commit()

    write_usage_event(
        db,
        client_id=scan.client_id,
        event_type="report_generated",
        scan_job_id=scan_job_id,
        metadata={"format": fmt, "scan_job_id": scan_job_id,
                  "finding_count": len(scan.findings)},
    )

    return content


def render_html(scan: ScanJob, db: Session) -> str:
    """Render the Jinja2 HTML report template for a completed scan."""
    # Load client via relationship
    client = scan.client

    # Sort findings: critical → high → medium → low → info
    severity_rank = {s: i for i, s in enumerate(_SEVERITY_ORDER)}
    sorted_findings = sorted(
        scan.findings,
        key=lambda f: severity_rank.get(f.severity, 99),
    )

    severity_counts = {s: 0 for s in _SEVERITY_ORDER}
    for f in sorted_findings:
        if f.severity in severity_counts:
            severity_counts[f.severity] += 1

    import json
    findings_json = json.dumps(
        [
            {
                "id": f.id,
                "title": f.title,
                "severity": f.severity,
                "tool": f.tool,
                "description": f.description,
                "remediation": f.remediation,
                "evidence": f.evidence_json,
                "cvss_score": f.cvss_score,
                "cwe_id": f.cwe_id,
                "owasp_category": f.owasp_category,
            }
            for f in sorted_findings
        ],
        indent=2,
    )

    tpl = _jinja_env.get_template("report.html")
    return tpl.render(
        scan_job=scan,
        findings=sorted_findings,
        client=client,
        severity_counts=severity_counts,
        generated_at=datetime.now(timezone.utc).isoformat(),
        findings_json=findings_json,
    )


def html_to_pdf(html: str) -> bytes:
    """Convert HTML string to PDF bytes using weasyprint."""
    from weasyprint import HTML
    return HTML(string=html).write_pdf()


def upload_report(client_id: str, scan_job_id: str, content: bytes | str, fmt: str) -> str:
    """
    Upload report to S3. Falls back to /tmp in dev (no S3 configured).
    Returns s3_key (or local:// path in dev mode).
    """
    if isinstance(content, str):
        content = content.encode("utf-8")

    s3_key = f"reports/{client_id}/{scan_job_id}/report.{fmt}"

    if not settings.S3_BUCKET:
        local_path = f"/tmp/{scan_job_id}.{fmt}"
        try:
            with open(local_path, "wb") as fh:
                fh.write(content)
        except Exception as exc:
            logger.warning("Failed to write report to /tmp: %s", exc)
        return f"local:{local_path}"

    try:
        import boto3
        kwargs = {"region_name": settings.S3_REGION}
        if settings.AWS_ACCESS_KEY_ID and settings.AWS_SECRET_ACCESS_KEY:
            kwargs["aws_access_key_id"] = settings.AWS_ACCESS_KEY_ID
            kwargs["aws_secret_access_key"] = settings.AWS_SECRET_ACCESS_KEY
        s3 = boto3.client("s3", **kwargs)
        content_type = "application/pdf" if fmt == "pdf" else "text/html"
        s3.put_object(
            Bucket=settings.S3_BUCKET,
            Key=s3_key,
            Body=content,
            ContentType=content_type,
        )
        return s3_key
    except Exception as exc:
        logger.error("S3 upload failed for %s: %s", s3_key, exc)
        raise RuntimeError("REPORT_UPLOAD_FAILED") from exc


def fetch_from_s3(s3_key: str) -> bytes:
    """Fetch report bytes directly from S3 using instance role credentials."""
    if s3_key.startswith("local:"):
        local_path = s3_key[len("local:"):]
        with open(local_path, "rb") as fh:
            return fh.read()

    try:
        import boto3
        kwargs = {"region_name": settings.S3_REGION}
        if settings.AWS_ACCESS_KEY_ID and settings.AWS_SECRET_ACCESS_KEY:
            kwargs["aws_access_key_id"] = settings.AWS_ACCESS_KEY_ID
            kwargs["aws_secret_access_key"] = settings.AWS_SECRET_ACCESS_KEY
        s3 = boto3.client("s3", **kwargs)
        response = s3.get_object(Bucket=settings.S3_BUCKET, Key=s3_key)
        return response["Body"].read()
    except Exception as exc:
        logger.error("Failed to fetch report from S3 %s: %s", s3_key, exc)
        raise RuntimeError("REPORT_FETCH_FAILED") from exc
