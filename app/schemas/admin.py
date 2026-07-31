from datetime import datetime
from pydantic import BaseModel, EmailStr, field_validator, model_validator


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
    # NULL = unlimited; set to e.g. 50 to cap this key at 50 scans per calendar month
    scan_quota_per_month: int | None = None
    cors_origins: list[str] | None = None

    @field_validator("rate_limit_rpm")
    @classmethod
    def validate_rate_limit(cls, v: int) -> int:
        if v < 1 or v > 1000:
            raise ValueError("rate_limit_rpm must be between 1 and 1000")
        return v

    @field_validator("scan_quota_per_month")
    @classmethod
    def validate_quota(cls, v: int | None) -> int | None:
        if v is not None and v < 1:
            raise ValueError("scan_quota_per_month must be at least 1")
        return v

    @field_validator("scopes")
    @classmethod
    def validate_scopes(cls, v: list[str]) -> list[str]:
        allowed = {"scan:write", "scan:read", "usage:read", "admin"}
        invalid = set(v) - allowed
        if invalid:
            raise ValueError(f"Unknown scopes: {invalid}")
        if not v:
            raise ValueError("At least one scope is required")
        return v

    @field_validator("cors_origins")
    @classmethod
    def validate_cors_origins(cls, v: list[str] | None) -> list[str] | None:
        if v is None:
            return v
        cleaned = []
        for origin in v:
            if not (origin.startswith("http://") or origin.startswith("https://")):
                raise ValueError(f"Each cors_origins entry must start with http:// or https://: {origin!r}")
            cleaned.append(origin.rstrip("/"))
        return cleaned


class PatchApiKeyRequest(BaseModel):
    label: str | None = None          # if provided, update it
    scan_quota_per_month: int | None = None  # -1 means "set to unlimited (NULL)"
    rate_limit_rpm: int | None = None  # validator: 1-1000 if set
    is_active: bool | None = None
    cors_origins: list[str] | None = None  # [] means "clear all restrictions"
    expires_at: datetime | None = None   # None means "clear expiry (no expiry)"

    @field_validator("rate_limit_rpm")
    @classmethod
    def validate_rate_limit(cls, v: int | None) -> int | None:
        if v is not None and (v < 1 or v > 1000):
            raise ValueError("rate_limit_rpm must be between 1 and 1000")
        return v

    @field_validator("cors_origins")
    @classmethod
    def validate_cors_origins(cls, v: list[str] | None) -> list[str] | None:
        if v is None:
            return v
        cleaned = []
        for origin in v:
            if not (origin.startswith("http://") or origin.startswith("https://")):
                raise ValueError(f"Each cors_origins entry must start with http:// or https://: {origin!r}")
            cleaned.append(origin.rstrip("/"))
        return cleaned


class ApiKeyCreatedResponse(BaseModel):
    """Returned ONLY on key creation. plaintext_key shown once and never again."""
    id: str
    key_prefix: str
    label: str | None
    scopes: list[str]
    rate_limit_rpm: int
    scan_quota_per_month: int | None
    expires_at: datetime | None
    created_at: datetime
    plaintext_key: str
    cors_origins: list[str] | None

    model_config = {"from_attributes": True}


class ApiKeyResponse(BaseModel):
    """Safe key representation — no plaintext_key."""
    id: str
    key_prefix: str
    label: str | None
    scopes: list[str]
    rate_limit_rpm: int
    scan_quota_per_month: int | None
    is_active: bool
    created_at: datetime
    last_used_at: datetime | None
    expires_at: datetime | None
    cors_origins: list[str] | None

    model_config = {"from_attributes": True}
