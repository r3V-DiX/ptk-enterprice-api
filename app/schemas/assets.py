from datetime import datetime
from pydantic import BaseModel, field_validator


class CreateAssetRequest(BaseModel):
    value: str
    asset_type: str
    project_id: str | None = None

    @field_validator("asset_type")
    @classmethod
    def validate_asset_type(cls, v: str) -> str:
        allowed = {"domain", "ip", "url"}
        if v not in allowed:
            raise ValueError(f"asset_type must be one of {allowed}")
        return v


class AssetResponse(BaseModel):
    id: str
    client_id: str
    project_id: str | None
    value: str
    asset_type: str
    created_at: datetime

    model_config = {"from_attributes": True}
