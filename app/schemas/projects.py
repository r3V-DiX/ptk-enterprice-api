from datetime import datetime
from pydantic import BaseModel


class CreateProjectRequest(BaseModel):
    name: str
    description: str | None = None


class ProjectResponse(BaseModel):
    id: str
    client_id: str
    name: str
    description: str | None
    is_active: bool
    created_at: datetime

    model_config = {"from_attributes": True}
