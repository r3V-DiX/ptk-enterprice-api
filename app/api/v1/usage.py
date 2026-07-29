import logging
from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy.orm import Session
from sqlalchemy import select, func

from app.core.database import get_db
from app.core.errors import get_request_id
from app.core.auth import require_scope
from app.models.api_key import ApiKey
from app.models.usage_event import UsageEvent
from app.services.usage_service import get_usage_summary

logger = logging.getLogger(__name__)

router = APIRouter(tags=["usage"])


@router.get("/usage")
async def get_usage(
    request: Request,
    db: Session = Depends(get_db),
    api_key: ApiKey = require_scope("usage:read"),
):
    request_id = get_request_id(request)
    summary = get_usage_summary(db, client_id=api_key.client_id)
    return {"request_id": request_id, "data": summary}


@router.get("/usage/events")
async def list_usage_events(
    request: Request,
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    api_key: ApiKey = require_scope("usage:read"),
):
    request_id = get_request_id(request)

    total = db.execute(
        select(func.count()).select_from(UsageEvent)
        .where(UsageEvent.client_id == api_key.client_id)
    ).scalar_one()

    events = db.execute(
        select(UsageEvent)
        .where(UsageEvent.client_id == api_key.client_id)
        .order_by(UsageEvent.created_at.desc())
        .limit(limit).offset(offset)
    ).scalars().all()

    data = [
        {
            "id": e.id,
            "event_type": e.event_type,
            "scan_job_id": e.scan_job_id,
            "created_at": e.created_at.isoformat(),
            "metadata_json": e.metadata_json,
        }
        for e in events
    ]

    return {
        "request_id": request_id,
        "data": data,
        "meta": {"total": total, "limit": limit, "offset": offset},
    }
