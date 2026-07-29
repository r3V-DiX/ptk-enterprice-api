from datetime import datetime
from pydantic import BaseModel


class UsageSummaryResponse(BaseModel):
    total_scans: int
    total_findings: int
    events_last_30_days: int


class UsageEventItem(BaseModel):
    id: str
    event_type: str
    scan_job_id: str | None
    created_at: datetime
    metadata_json: dict | None

    model_config = {"from_attributes": True}
