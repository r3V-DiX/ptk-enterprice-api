import logging
from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
from sqlalchemy import select, func

from app.core.database import get_db
from app.core.errors import error_response, get_request_id
from app.core.auth import require_scope
from app.models.api_key import ApiKey
from app.models.asset import Asset
from app.models.project import Project
from app.schemas.assets import CreateAssetRequest, AssetResponse

logger = logging.getLogger(__name__)

router = APIRouter(tags=["assets"])


def _asset_dict(a: Asset) -> dict:
    return AssetResponse.model_validate(a).model_dump(mode="json")


@router.post("/assets", status_code=201)
async def create_asset(
    request: Request,
    body: CreateAssetRequest,
    db: Session = Depends(get_db),
    api_key: ApiKey = require_scope("scan:write"),
):
    request_id = get_request_id(request)

    # Validate project_id belongs to this client
    if body.project_id:
        project = db.execute(
            select(Project).where(
                Project.id == body.project_id,
                Project.client_id == api_key.client_id,
            )
        ).scalar_one_or_none()
        if project is None:
            return error_response("PROJECT_NOT_FOUND", request_id)

    asset = Asset(
        client_id=api_key.client_id,
        project_id=body.project_id,
        value=body.value,
        asset_type=body.asset_type,
    )
    db.add(asset)
    db.commit()
    db.refresh(asset)

    return JSONResponse(
        status_code=201,
        content={"request_id": request_id, "data": _asset_dict(asset)},
    )


@router.get("/assets")
async def list_assets(
    request: Request,
    project_id: str | None = Query(default=None),
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    api_key: ApiKey = require_scope("scan:read"),
):
    request_id = get_request_id(request)

    stmt = select(Asset).where(Asset.client_id == api_key.client_id)
    if project_id:
        stmt = stmt.where(Asset.project_id == project_id)

    total = db.execute(
        select(func.count()).select_from(stmt.subquery())
    ).scalar_one()

    assets = db.execute(
        stmt.order_by(Asset.created_at.desc()).limit(limit).offset(offset)
    ).scalars().all()

    page = (offset // limit) + 1 if limit else 1
    return {
        "request_id": request_id,
        "data": [_asset_dict(a) for a in assets],
        "meta": {"total": total, "page": page, "limit": limit, "offset": offset},
    }
