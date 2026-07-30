import asyncio
import logging
from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import JSONResponse, Response, StreamingResponse
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.errors import error_response, get_request_id
from app.core.auth import require_scope
from app.models.api_key import ApiKey
from app.schemas.scans import SubmitScanRequest
from app.services.scan_service import (
    create_scan,
    get_scan,
    get_scan_list,
    delete_scan,
    build_scan_response,
)
from app.services.usage_service import write_usage_event
from app.services.audit_service import write_audit_log
from app.services import report_service

logger = logging.getLogger(__name__)

router = APIRouter(tags=["scans"])


@router.post("/scans", status_code=201)
async def submit_scan(
    request: Request,
    body: SubmitScanRequest,
    db: Session = Depends(get_db),
    api_key: ApiKey = require_scope("scan:write"),
):
    request_id = get_request_id(request)

    try:
        scan, is_new = create_scan(
            db,
            client_id=api_key.client_id,
            api_key_id=api_key.id,
            target=body.target,
        )
    except ValueError as exc:
        error_code = str(exc)
        if error_code == "SCAN_QUOTA_EXCEEDED":
            return error_response(error_code, request_id)
        logger.error("Unexpected error in create_scan: %s", exc)
        return error_response("INTERNAL_ERROR", request_id)

    if not is_new:
        return JSONResponse(
            status_code=200,
            content={"request_id": request_id, "data": build_scan_response(scan)},
        )

    # Write usage event for new scan (rule: do this in the endpoint, not the task)
    write_usage_event(
        db,
        client_id=api_key.client_id,
        event_type="scan_submitted",
        api_key_id=api_key.id,
        scan_job_id=scan.id,
        metadata={"target": scan.target},
    )

    # Dispatch Celery task — import here to avoid circular startup issues
    try:
        from app.tasks.scan_tasks import run_scan
        run_scan.apply_async(
            args=[scan.id],
            queue="enterprise_scans",
            soft_time_limit=660,
            time_limit=720,
        )
    except Exception as exc:
        # Worker not running is expected in dev — log but don't fail the API response
        logger.warning("Failed to dispatch scan task for %s: %s", scan.id, exc)

    return JSONResponse(
        status_code=201,
        content={"request_id": request_id, "data": build_scan_response(scan)},
    )


@router.get("/scans")
async def list_scans(
    request: Request,
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    api_key: ApiKey = require_scope("scan:read"),
):
    request_id = get_request_id(request)

    scans, total = get_scan_list(db, client_id=api_key.client_id, limit=limit, offset=offset)
    page = (offset // limit) + 1 if limit else 1

    return {
        "request_id": request_id,
        "data": [build_scan_response(s) for s in scans],
        "meta": {"total": total, "page": page, "limit": limit, "offset": offset},
    }


@router.get("/scans/{scan_id}")
async def get_scan_detail(
    scan_id: str,
    request: Request,
    db: Session = Depends(get_db),
    api_key: ApiKey = require_scope("scan:read"),
):
    request_id = get_request_id(request)

    scan = get_scan(db, scan_id=scan_id, client_id=api_key.client_id)
    if scan is None:
        return error_response("SCAN_NOT_FOUND", request_id)

    return {"request_id": request_id, "data": build_scan_response(scan)}


@router.delete("/scans/{scan_id}", status_code=204)
async def delete_scan_endpoint(
    scan_id: str,
    request: Request,
    db: Session = Depends(get_db),
    api_key: ApiKey = require_scope("scan:write"),
):
    request_id = get_request_id(request)

    error_code = delete_scan(db, scan_id=scan_id, client_id=api_key.client_id)
    if error_code:
        return error_response(error_code, request_id)

    write_audit_log(
        db,
        actor="api_key",
        action="scan_deleted",
        client_id=api_key.client_id,
        api_key_id=api_key.id,
        target_type="scan_job",
        target_id=scan_id,
        ip_address=request.client.host if request.client else None,
        request_id=request_id,
    )

    return Response(status_code=204)


@router.get("/scans/{scan_id}/report")
async def get_scan_report(
    scan_id: str,
    request: Request,
    format: str = Query(default="html", pattern="^(html|pdf)$"),
    db: Session = Depends(get_db),
    api_key: ApiKey = require_scope("scan:read"),
):
    request_id = get_request_id(request)

    # Verify the scan belongs to this client before generating report
    scan = get_scan(db, scan_id=scan_id, client_id=api_key.client_id)
    if scan is None:
        return error_response("SCAN_NOT_FOUND", request_id)

    try:
        content = await asyncio.to_thread(
            report_service.get_or_generate_report, scan_id, format, db
        )
    except ValueError as exc:
        code = str(exc)
        if code in ("SCAN_NOT_FOUND", "REPORT_NOT_READY"):
            return error_response(code, request_id)
        logger.error("Unexpected ValueError generating report for %s: %s", scan_id, exc)
        return error_response("INTERNAL_ERROR", request_id)
    except RuntimeError as exc:
        logger.error("Report generation runtime error for %s: %s", scan_id, exc)
        return error_response("INTERNAL_ERROR", request_id)

    content_type = "application/pdf" if format == "pdf" else "text/html"
    filename = f"report-{scan_id}.{format}"
    return Response(
        content=content,
        media_type=content_type,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
