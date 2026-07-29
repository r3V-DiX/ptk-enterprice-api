from datetime import datetime
from pydantic import BaseModel


class FindingListItem(BaseModel):
    id: str
    scan_id: str
    title: str
    severity: str
    tool: str
    status: str
    created_at: datetime

    model_config = {"from_attributes": True}


class FindingDetail(BaseModel):
    id: str
    scan_job_id: str
    client_id: str
    title: str
    severity: str
    tool: str
    status: str
    description: str | None
    remediation: str | None
    evidence_json: dict | None
    cvss_score: float | None
    cwe_id: str | None
    owasp_category: str | None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}
