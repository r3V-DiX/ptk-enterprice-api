import re
import ipaddress
from datetime import datetime
from pydantic import BaseModel, field_validator

# Matches a valid hostname label: letters, digits, hyphens (not at start/end)
_LABEL_RE = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$")

# Known valid single-label internal hostnames we allow (extend as needed)
_SINGLE_LABEL_ALLOWLIST: set[str] = set()


def _validate_scan_target(v: str) -> str:
    """
    Accept:
      - IPv4 address            e.g. 93.184.216.34
      - IPv4 CIDR               e.g. 10.0.0.0/24
      - IPv6 address            e.g. 2001:db8::1
      - FQDN with ≥1 dot        e.g. example.com, sub.example.co.uk
      - URL (http/https)        e.g. https://example.com/path  (host extracted)
    Reject:
      - single-label hostnames  e.g. localhost, myserver, pentoolk
      - obviously invalid chars
      - empty / too long
    """
    v = v.strip()
    if not v:
        raise ValueError("Target cannot be empty.")
    if len(v) > 2048:
        raise ValueError("Target exceeds 2048 characters.")

    # Strip http(s):// prefix so users can paste full URLs
    host = v
    if host.lower().startswith(("http://", "https://")):
        # Extract just the host part
        without_scheme = re.sub(r"^https?://", "", host, flags=re.IGNORECASE)
        host = without_scheme.split("/")[0].split("?")[0].split("#")[0]

    # Strip port if present (host:port)
    if host.count(":") == 1:
        host, _, port = host.rpartition(":")
        if not host:
            raise ValueError(f"Invalid target format: '{v}'.")

    # Try IPv4
    try:
        ipaddress.IPv4Address(host)
        return v
    except ValueError:
        pass

    # Try IPv4 CIDR
    try:
        ipaddress.IPv4Network(host, strict=False)
        return v
    except ValueError:
        pass

    # Try IPv6 (may be wrapped in brackets like [::1])
    ipv6_host = host.strip("[]")
    try:
        ipaddress.IPv6Address(ipv6_host)
        return v
    except ValueError:
        pass

    # Hostname / FQDN validation
    # Remove trailing dot (FQDN canonical form)
    hostname = host.rstrip(".")
    labels = hostname.split(".")

    if len(labels) < 2:
        raise ValueError(
            f"'{v}' does not look like a valid domain. "
            "Please enter a fully qualified domain (e.g. example.com) or an IP address."
        )

    for label in labels:
        if not label:
            raise ValueError(f"Invalid domain format: '{v}'.")
        if not _LABEL_RE.match(label):
            raise ValueError(
                f"Invalid hostname label '{label}' in target '{v}'. "
                "Labels must contain only letters, digits, and hyphens."
            )

    # TLD must be 2–6 chars and all alpha.
    # Blocks partial hostnames like 'api.pentoolk' (8-char non-TLD trailing label)
    # while allowing all real TLDs (.com, .org, .io, .co, .museum = 6 chars max).
    tld = labels[-1]
    if not tld.isalpha() or not (2 <= len(tld) <= 6):
        raise ValueError(
            f"'{v}' doesn't look like a valid target — the TLD '{tld}' is not recognised. "
            "Please enter a complete domain (e.g. example.com) or an IP address."
        )

    return v


class SubmitScanRequest(BaseModel):
    target: str
    project_id: str | None = None
    asset_id: str | None = None
    idempotency_key: str | None = None

    @field_validator("target")
    @classmethod
    def validate_target(cls, v: str) -> str:
        return _validate_scan_target(v)


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
