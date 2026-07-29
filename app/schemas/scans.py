from datetime import datetime
from pydantic import BaseModel, field_validator


class SubmitScanRequest(BaseModel):
    target: str
    project_id: str | None = None
    asset_id: str | None = None
    idempotency_key: str | None = None

    @field_validator("target")
    @classmethod
    def validate_target(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("target cannot be empty")
        if len(v) > 2048:
            raise ValueError("target exceeds 2048 characters")
        return v


class FindingResponse(BaseModel):
    id: str
    title: str
    severity: str
    tool: str
    status: str
    description: str | None = None
    remediation: str | None = None
    evidence: dict | None = None
    cvss_score: float | None = None
    cwe_id: str | None = None
    owasp_category: str | None = None

    model_config = {"from_attributes": True}


class ScanSummary(BaseModel):
    total_findings: int
    by_severity: dict
    tools_run: list[str]
    tool_errors: dict
    duration_seconds: float | None


class ScanResponse(BaseModel):
    scan_id: str
    target: str
    status: str
    project_id: str | None
    asset_id: str | None
    created_at: datetime
    started_at: datetime | None
    completed_at: datetime | None
    summary: ScanSummary | None
    findings: list[FindingResponse]

    model_config = {"from_attributes": True}
