import logging
from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
from sqlalchemy import select, func

from app.core.database import get_db
from app.core.errors import error_response, get_request_id
from app.core.auth import require_scope
from app.models.api_key import ApiKey
from app.models.project import Project
from app.schemas.projects import CreateProjectRequest, ProjectResponse

logger = logging.getLogger(__name__)

router = APIRouter(tags=["projects"])


def _project_dict(p: Project) -> dict:
    return ProjectResponse.model_validate(p).model_dump(mode="json")


@router.post("/projects", status_code=201)
async def create_project(
    request: Request,
    body: CreateProjectRequest,
    db: Session = Depends(get_db),
    api_key: ApiKey = require_scope("scan:write"),
):
    request_id = get_request_id(request)

    project = Project(
        client_id=api_key.client_id,
        name=body.name,
        description=body.description,
    )
    db.add(project)
    db.commit()
    db.refresh(project)

    return JSONResponse(
        status_code=201,
        content={"request_id": request_id, "data": _project_dict(project)},
    )


@router.get("/projects")
async def list_projects(
    request: Request,
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    api_key: ApiKey = require_scope("scan:read"),
):
    request_id = get_request_id(request)

    total = db.execute(
        select(func.count()).select_from(Project)
        .where(Project.client_id == api_key.client_id)
    ).scalar_one()

    projects = db.execute(
        select(Project)
        .where(Project.client_id == api_key.client_id)
        .order_by(Project.created_at.desc())
        .limit(limit).offset(offset)
    ).scalars().all()

    page = (offset // limit) + 1 if limit else 1
    return {
        "request_id": request_id,
        "data": [_project_dict(p) for p in projects],
        "meta": {"total": total, "page": page, "limit": limit, "offset": offset},
    }


@router.get("/projects/{project_id}")
async def get_project(
    project_id: str,
    request: Request,
    db: Session = Depends(get_db),
    api_key: ApiKey = require_scope("scan:read"),
):
    request_id = get_request_id(request)

    project = db.execute(
        select(Project).where(
            Project.id == project_id,
            Project.client_id == api_key.client_id,
        )
    ).scalar_one_or_none()

    if project is None:
        return error_response("PROJECT_NOT_FOUND", request_id)

    return {"request_id": request_id, "data": _project_dict(project)}
