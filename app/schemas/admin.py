from datetime import datetime
from pydantic import BaseModel, EmailStr, field_validator


class CreateClientRequest(BaseModel):
    company_name: str
    contact_email: EmailStr
    tier: str = "free"

    @field_validator("tier")
    @classmethod
    def validate_tier(cls, v: str) -> str:
        allowed = {"free", "pro", "enterprise"}
        if v not in allowed:
            raise ValueError(f"tier must be one of {allowed}")
        return v


class ClientResponse(BaseModel):
    id: str
    company_name: str
    contact_email: str
    tier: str
    is_active: bool
    created_at: datetime

    model_config = {"from_attributes": True}


class CreateApiKeyRequest(BaseModel):
    label: str | None = None
    scopes: list[str] = ["scan:write", "scan:read", "usage:read"]
    rate_limit_rpm: int = 60
    expires_at: datetime | None = None


class ApiKeyCreatedResponse(BaseModel):
    """Returned ONLY on key creation. plaintext_key shown once and never again."""
    id: str
    key_prefix: str
    label: str | None
    scopes: list[str]
    rate_limit_rpm: int
    created_at: datetime
    plaintext_key: str

    model_config = {"from_attributes": True}


class ApiKeyResponse(BaseModel):
    """Safe key representation — no plaintext_key."""
    id: str
    key_prefix: str
    label: str | None
    scopes: list[str]
    rate_limit_rpm: int
    is_active: bool
    created_at: datetime
    last_used_at: datetime | None
    expires_at: datetime | None

    model_config = {"from_attributes": True}
