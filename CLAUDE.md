# ptk-enterprise-api — Claude Context
> Auto-loaded every session. Read this before touching any file.

---

## What This Service Is

`ptk-enterprise-api` is a **B2B enterprise security scanning API**.

Clients (companies) authenticate with an API key, submit a target domain/IP/URL,
and receive structured JSON findings from a suite of 12 security tools.

This is a **pure API product** — no UI, no guest OTP flow, no HTML reports by email.
Everything is JSON in, JSON out. Built for developers and security teams to integrate
into their own workflows, CI/CD pipelines, or dashboards.

**This repo is completely standalone — zero coupling to ptk-backend or rsuite-scanner.**

Production target: `api.pentoolkit.com/v1`

---

## Stack

| Layer | Technology |
|---|---|
| API | FastAPI (Python 3.12) |
| ORM | SQLAlchemy 2.x (sync) |
| DB | PostgreSQL 15 |
| Cache / Rate Limit | Redis 7 |
| Task Queue | Celery (queue: `enterprise_scans`) |
| Artifact Storage | AWS S3 |
| Migrations | Alembic |
| Container | Docker + docker-compose |
| Auth | API key (SHA-256 hash stored, plaintext never persisted) |

---

## Core Design Decisions — Never Change Without Discussion

1. **API keys are hashed with SHA-256** — show once on creation, never again
2. **Versioned API from day one** — all endpoints under `/v1/`. Adding `/v2/` later is fine, removing `/v1/` fields is not
3. **Async scan model** — submit returns `scan_id` immediately, client polls `/v1/scans/{id}`
4. **One default tool set** — v1 has no profile/tier selection. Client submits target, default 12 tools run. Profile field added later as optional with no breaking change
5. **Findings normalized to DB rows** — not only stored in JSON blob. `findings` table enables querying by severity/tool without parsing JSON
6. **Usage events are append-only** — never update/delete `usage_events` rows. Billing source of truth
7. **Audit logs are append-only** — never update/delete `audit_logs` rows
8. **Plugin architecture** — every scanner tool is a self-contained plugin file. Adding a tool = drop one file. Zero changes to runner or API
9. **Active testing tools excluded from v1** — sqlmap, commix, dalfox, ffuf require authorization acknowledgment flow. Deferred to v2
10. **Admin uses Admin API keys** — NOT a secret header. Same auth mechanism, separate scope

---

## V1 Default Tool Set (12 tools, ~8-10 min per scan)

These run on every scan in v1. All passive or safe-active. High signal, fast.

| Tool | Category | Approx Time | What It Finds |
|---|---|---|---|
| `headers` | Config | ~5s | Missing CSP, HSTS, X-Frame-Options etc |
| `cors` | Config | ~5s | Wildcard origins, credential misconfig |
| `dmarc` | Config | ~5s | SPF, DKIM, DMARC — email spoofing exposure |
| `httpx` | Recon | ~15s | Live hosts, status codes, tech stack |
| `waf` | Config | ~10s | WAF presence and fingerprint |
| `takeover` | Recon | ~15s | Dangling DNS pointing to unclaimed services |
| `dns` | Recon | ~10s | DNS records, zone transfer, dangling CNAMEs |
| `tlsinfo` | Config | ~20s | Cert expiry, weak ciphers, chain issues |
| `virustotal` | Intel | ~5s | Malware flags, domain reputation |
| `nmap` | Vuln | ~2m | Open ports, services, top 100 ports |
| `nuclei` | Vuln | ~5m | CVEs, misconfigs via 8000+ templates |
| `subfinder` | Recon | ~30s | Subdomains, expands attack surface |

Tools deferred to v2: nikto, wpscan, theharvester, gau, s3scanner, shodan, censys,
sqlmap, commix, dalfox, ffuf, scoutsuite, prowler, trivy, xon

---

## Database Schema — 11 Tables

### clients
```
id              UUID PK
company_name    VARCHAR(255) NOT NULL
contact_email   VARCHAR(255) NOT NULL UNIQUE
tier            VARCHAR(20) DEFAULT 'free'  -- free | pro | enterprise
is_active       BOOLEAN DEFAULT true
webhook_url     VARCHAR(2048) nullable
webhook_secret  VARCHAR(255) nullable       -- HMAC signing secret
webhook_enabled BOOLEAN DEFAULT false
webhook_retry_count INT DEFAULT 3
created_at      TIMESTAMPTZ DEFAULT now()
updated_at      TIMESTAMPTZ DEFAULT now()
```

### projects
```
id              UUID PK
client_id       UUID FK → clients ON DELETE CASCADE
name            VARCHAR(255) NOT NULL        -- e.g. "Production", "Staging"
description     TEXT nullable
is_active       BOOLEAN DEFAULT true
created_at      TIMESTAMPTZ DEFAULT now()
updated_at      TIMESTAMPTZ DEFAULT now()
```

### assets
```
id              UUID PK
client_id       UUID FK → clients ON DELETE CASCADE
project_id      UUID FK → projects ON DELETE SET NULL nullable
value           VARCHAR(2048) NOT NULL       -- "example.com", "10.0.0.1"
asset_type      VARCHAR(20) NOT NULL         -- domain | ip | url
created_at      TIMESTAMPTZ DEFAULT now()
```

### api_keys
```
id              UUID PK
client_id       UUID FK → clients ON DELETE CASCADE
key_prefix      VARCHAR(12) NOT NULL         -- first 8 chars for display
key_hash        VARCHAR(64) NOT NULL UNIQUE  -- SHA-256 hex digest
label           VARCHAR(100) nullable        -- "production", "staging"
scopes          JSON NOT NULL DEFAULT '["scan:write","scan:read","usage:read"]'
is_active       BOOLEAN DEFAULT true
rate_limit_rpm  INT DEFAULT 60
created_at      TIMESTAMPTZ DEFAULT now()
last_used_at    TIMESTAMPTZ nullable
expires_at      TIMESTAMPTZ nullable
```

### scan_jobs
```
id              UUID PK
client_id       UUID FK → clients ON DELETE CASCADE
project_id      UUID FK → projects ON DELETE SET NULL nullable
asset_id        UUID FK → assets ON DELETE SET NULL nullable
api_key_id      UUID FK → api_keys ON DELETE SET NULL nullable
target          VARCHAR(2048) NOT NULL       -- snapshot of value at scan time
status          VARCHAR(20) DEFAULT 'queued' -- queued|initializing|running|aggregating|completed|failed|cancelled|expired
tools_requested JSON nullable                -- what client asked for (null = default set)
tools_run       JSON nullable                -- what actually ran
idempotency_key VARCHAR(255) UNIQUE nullable -- prevents double submission
error           TEXT nullable
created_at      TIMESTAMPTZ DEFAULT now()
started_at      TIMESTAMPTZ nullable
completed_at    TIMESTAMPTZ nullable
updated_at      TIMESTAMPTZ DEFAULT now()
```

### scan_results
```
id              UUID PK
scan_job_id     UUID FK → scan_jobs ON DELETE CASCADE UNIQUE  -- 1:1
result_json     JSONB NOT NULL              -- full raw output per tool
summary_json    JSONB nullable              -- severity counts, duration, tool errors
created_at      TIMESTAMPTZ DEFAULT now()
```

### findings
```
id              UUID PK
scan_job_id     UUID FK → scan_jobs ON DELETE CASCADE
client_id       UUID FK → clients ON DELETE CASCADE
title           VARCHAR(500) NOT NULL
severity        VARCHAR(20) NOT NULL        -- critical|high|medium|low|info
tool            VARCHAR(50) NOT NULL
status          VARCHAR(20) DEFAULT 'open'  -- open|acknowledged|resolved
description     TEXT nullable
remediation     TEXT nullable
evidence_json   JSONB nullable
cvss_score      FLOAT nullable
cwe_id          VARCHAR(50) nullable
owasp_category  VARCHAR(100) nullable
created_at      TIMESTAMPTZ DEFAULT now()
updated_at      TIMESTAMPTZ DEFAULT now()
```

### artifacts
```
id              UUID PK
scan_job_id     UUID FK → scan_jobs ON DELETE CASCADE
artifact_type   VARCHAR(50) NOT NULL        -- nmap_xml|screenshot|raw_http|evidence
s3_key          VARCHAR(512) nullable
size_bytes      BIGINT nullable
created_at      TIMESTAMPTZ DEFAULT now()
```

### usage_events  (append-only — never UPDATE or DELETE)
```
id              UUID PK
client_id       UUID FK → clients ON DELETE CASCADE
api_key_id      UUID FK → api_keys ON DELETE SET NULL nullable
scan_job_id     UUID FK → scan_jobs ON DELETE SET NULL nullable
event_type      VARCHAR(50) NOT NULL        -- scan_submitted|scan_completed|finding_generated
metadata_json   JSONB nullable              -- duration, tool_count, finding_count, worker_seconds, credits
created_at      TIMESTAMPTZ DEFAULT now()
```

### audit_logs  (append-only — never UPDATE or DELETE)
```
id              UUID PK
client_id       UUID FK → clients ON DELETE CASCADE nullable
api_key_id      UUID FK → api_keys ON DELETE SET NULL nullable
actor           VARCHAR(20) NOT NULL        -- api_key|admin
action          VARCHAR(100) NOT NULL       -- key_created|key_revoked|scan_deleted|webhook_updated|...
target_type     VARCHAR(50) nullable        -- scan_job|api_key|client|webhook
target_id       VARCHAR(36) nullable
metadata_json   JSONB nullable
ip_address      VARCHAR(45) nullable
request_id      VARCHAR(32) nullable
created_at      TIMESTAMPTZ DEFAULT now()
```

### scan_reports
```
id              UUID PK
scan_job_id     UUID FK → scan_jobs ON DELETE CASCADE
client_id       UUID FK → clients ON DELETE CASCADE
format          VARCHAR(10) NOT NULL                -- html | pdf
s3_key          VARCHAR(512) NOT NULL
size_bytes      BIGINT nullable
generated_at    TIMESTAMPTZ DEFAULT now()
```

Unique constraint on `(scan_job_id, format)` — one HTML and one PDF per scan.
If client requests again, return fresh presigned URL from existing s3_key — no re-render.

### api_logs  (every request — append-only)
```
id              UUID PK
client_id       UUID FK → clients ON DELETE SET NULL nullable
api_key_id      UUID FK → api_keys ON DELETE SET NULL nullable
request_id      VARCHAR(32) NOT NULL
endpoint        VARCHAR(255) NOT NULL
method          VARCHAR(10) NOT NULL
status_code     INT NOT NULL
latency_ms      INT NOT NULL
ip_address      VARCHAR(45) nullable
created_at      TIMESTAMPTZ DEFAULT now()
```

---

## Report Generation

### Two Formats
- **HTML** — standalone file, inline CSS only, no CDN, no external fonts, opens in any browser
- **PDF** — generated from HTML using `weasyprint` (pure Python, no headless browser needed)

### Storage
Both formats uploaded to S3 under:
```
reports/{client_id}/{scan_job_id}/report.html
reports/{client_id}/{scan_job_id}/report.pdf
```

### Generation Strategy
On-demand — not auto-generated after every scan. Client requests it.

```
GET /v1/scans/{id}/report?format=html
GET /v1/scans/{id}/report?format=pdf
```

Flow:
1. Check `scan_reports` table for existing row matching `(scan_job_id, format)`
2. If exists → generate fresh presigned S3 URL (1hr expiry) → return immediately
3. If not exists → render → upload → insert `scan_reports` row → return presigned URL

Response:
```json
{
  "request_id": "...",
  "data": {
    "scan_id": "uuid",
    "format": "pdf",
    "url": "https://s3.amazonaws.com/... (presigned, 1hr)",
    "size_bytes": 142500,
    "generated_at": "2026-01-01T00:10:00Z",
    "expires_at": "2026-01-01T01:10:00Z"
  }
}
```

### Report Sections (Professional Pentest Report Style)

```
1. Cover Page
   — Client company name, target, scan date, scan ID
   — Pentoolkit branding + report classification (Confidential)

2. Executive Summary
   — Overall risk score (Critical / High / Medium / Low)
   — Severity breakdown bar chart (CSS-only, no JS)
   — Total findings count
   — Top 3 most critical findings (title + one-line description)
   — Scan metadata: tools run, duration, discovery stats

3. Findings  (sorted: critical → high → medium → low → info)
   Per finding:
   — Severity badge (color-coded), title
   — CVSS score, CWE ID, OWASP category (if available)
   — Description (what it is, why it matters)
   — Evidence (raw data, monospace block)
   — Remediation (specific fix)
   — Detection source (which tool found it)

4. Scan Coverage
   — Table of tools run with status (completed / error / skipped)
   — Duration per tool

5. Appendix
   — Raw JSON findings (collapsed in HTML via <details> tag)
```

### Severity Color Scheme (inline CSS)
```
critical  — #dc2626 (red)
high      — #ea580c (orange)
medium    — #d97706 (amber)
low       — #2563eb (blue)
info      — #6b7280 (gray)
```

### Services
```
app/services/report_service.py    — render HTML (Jinja2), convert to PDF (weasyprint),
                                    upload both to S3, manage scan_reports table,
                                    generate presigned URLs
app/templates/report.html         — Jinja2 template, inline CSS only
```

### report_service.py Public API
```python
def get_or_generate_report(scan_job_id: str, format: str, db: Session) -> ReportResult:
    # Returns: {url, size_bytes, generated_at, expires_at}
    # If already in scan_reports → presign existing S3 key and return
    # If not → render, upload, insert row, return presigned URL

def render_html(scan_job_id: str, db: Session) -> str:
    # Loads scan_job + findings + client from DB
    # Renders report.html Jinja2 template
    # Returns HTML string

def html_to_pdf(html: str) -> bytes:
    # Converts HTML string to PDF bytes using weasyprint
    # Returns raw PDF bytes

def upload_report(client_id: str, scan_job_id: str, content: bytes | str, format: str) -> str:
    # Uploads to S3, returns s3_key

def get_presigned_url(s3_key: str, expires_seconds: int = 3600) -> str:
    # Returns fresh presigned URL
```

### Requirements
Add to requirements.txt:
```
weasyprint>=60.0
Jinja2>=3.1.0
boto3>=1.34.0
```

### Usage Event on Report Generation
Write a `usage_event` row when a report is generated for the first time:
```python
event_type = "report_generated"
metadata_json = {"format": "pdf", "scan_job_id": "...", "finding_count": 12}
```
Re-downloads of existing reports do NOT write a new usage event.

---

## API Contract — Never Break After V1 Ships

### Authentication
```
Authorization: Bearer sk_live_xxxxxxxxxxxxxxxxxxxx
```
API key validated on every request. Scope checked per endpoint.

### Key Scopes
```
scan:write    — POST /v1/scans, DELETE /v1/scans/{id}
scan:read     — GET /v1/scans, GET /v1/scans/{id}, GET /v1/findings
usage:read    — GET /v1/usage, GET /v1/usage/events
admin         — all /v1/admin/* endpoints (admin-provisioned keys only)
```

### Endpoints

```
POST   /v1/scans                  scan:write   Submit target for scanning
GET    /v1/scans                  scan:read    List scan history (paginated)
GET    /v1/scans/{scan_id}        scan:read    Get status + findings
DELETE /v1/scans/{scan_id}        scan:write   Delete scan record
GET    /v1/scans/{scan_id}/report scan:read    Get presigned report URL (html|pdf)

GET    /v1/findings               scan:read    Query findings across scans

POST   /v1/projects               scan:write   Create a project
GET    /v1/projects               scan:read    List projects
GET    /v1/projects/{id}          scan:read    Get project detail

POST   /v1/assets                 scan:write   Register an asset
GET    /v1/assets                 scan:read    List assets

GET    /v1/usage                  usage:read   Aggregated usage stats
GET    /v1/usage/events           usage:read   Raw usage event log

POST   /v1/admin/clients          admin        Create a client
GET    /v1/admin/clients          admin        List all clients
GET    /v1/admin/clients/{id}     admin        Get client detail
GET    /v1/admin/clients/{id}/usage  admin     Client billing usage
POST   /v1/admin/clients/{id}/keys   admin     Issue API key for client
DELETE /v1/admin/keys/{key_id}    admin        Revoke API key

GET    /health
GET    /ready
GET    /live
GET    /version
```

### Request Shape — POST /v1/scans
```json
{
  "target": "example.com",
  "project_id": "uuid (optional)",
  "asset_id": "uuid (optional)",
  "idempotency_key": "client-generated string (optional)"
}
```

### Response Envelope — All Endpoints
Success:
```json
{
  "request_id": "a1b2c3d4",
  "data": { ... },
  "meta": { "page": 1, "total": 42, "limit": 20 }
}
```

Error:
```json
{
  "error": {
    "code": "INVALID_API_KEY",
    "message": "The supplied API key is invalid or has been revoked.",
    "request_id": "a1b2c3d4"
  }
}
```

### Scan Response Shape (inside "data")
```json
{
  "scan_id": "uuid",
  "target": "example.com",
  "status": "completed",
  "project_id": "uuid or null",
  "asset_id": "uuid or null",
  "created_at": "2026-01-01T00:00:00Z",
  "started_at": "2026-01-01T00:00:05Z",
  "completed_at": "2026-01-01T00:08:34Z",
  "summary": {
    "total_findings": 12,
    "by_severity": {
      "critical": 1, "high": 3, "medium": 5, "low": 2, "info": 1
    },
    "tools_run": ["headers", "cors", "dmarc", "httpx", "waf",
                  "takeover", "dns", "tlsinfo", "virustotal",
                  "nmap", "nuclei", "subfinder"],
    "tool_errors": {},
    "duration_seconds": 514
  },
  "findings": [
    {
      "id": "uuid",
      "title": "Missing Content-Security-Policy Response Header",
      "severity": "high",
      "tool": "headers",
      "status": "open",
      "description": "...",
      "remediation": "...",
      "cvss_score": 6.1,
      "cwe_id": "CWE-693",
      "owasp_category": "A05:2021 – Security Misconfiguration",
      "evidence": {}
    }
  ]
}
```

### Error Codes
```
INVALID_API_KEY          401
EXPIRED_API_KEY          401
INSUFFICIENT_SCOPE       403
RATE_LIMIT_EXCEEDED      429
SCAN_NOT_FOUND           404
TARGET_INVALID           422
IDEMPOTENCY_CONFLICT     409
SCAN_IN_PROGRESS         409
INTERNAL_ERROR           500
```

---

## Scan Job State Machine

```
queued → initializing → running → aggregating → completed
                                              ↘ failed
              ↘ cancelled  (from any active state)
queued → expired  (if worker never picks up within 30 min)
```

- `queued` — created in DB, Celery task dispatched
- `initializing` — worker picked it up, loading target info
- `running` — tools are executing
- `aggregating` — tools done, findings being normalized to DB rows
- `completed` — findings written, usage event recorded
- `failed` — unrecoverable error, `error` field populated
- `cancelled` — client called DELETE while scan was active
- `expired` — task never started (worker down), reaped by scheduler

---

## Scanner Plugin Architecture

Every tool is a plugin. The runner knows nothing about individual tools.

### Plugin Contract
```python
# app/scanner/plugin_base.py

class PluginMeta:
    id: str                  # "nuclei"
    display_name: str        # "Vulnerability Scanner"
    timeout_seconds: int     # 300
    requires_root: bool      # False
    safe_to_retry: bool      # True

class BaseScannerPlugin:
    meta: PluginMeta

    def run(self, target: str, options: dict) -> PluginResult:
        raise NotImplementedError

class PluginResult:
    plugin_id: str
    target: str
    findings: list[FindingDict]
    metadata: dict
    error: str | None
    duration_seconds: float
```

### Finding Dict (standard output contract — all plugins must return this)
```python
{
    "id": "uuid",
    "title": "...",
    "severity": "critical|high|medium|low|info",
    "description": "...",
    "remediation": "...",
    "evidence": {},       # raw data, tool-specific
    "cvss_score": None,   # float or None
    "cwe_id": None,       # "CWE-693" or None
    "owasp_category": None
}
```

### Plugin Registry
```python
# app/scanner/plugin_registry.py
# Auto-discovers all classes in plugins/ that extend BaseScannerPlugin
# registry.get("nuclei") → NucleiPlugin instance
# registry.list_default() → all 12 default plugins
```

### Plugin Files (one per tool)
```
app/scanner/plugins/
  headers.py
  cors.py
  dmarc.py
  httpx_plugin.py
  waf.py
  takeover.py
  dns.py
  tlsinfo.py
  virustotal.py
  nmap.py
  nuclei.py
  subfinder.py
```

---

## Folder Structure

```
ptk-enterprise-api/
├── CLAUDE.md
├── app/
│   ├── api/
│   │   └── v1/
│   │       ├── __init__.py
│   │       ├── scans.py          ← submit, poll, history, delete
│   │       ├── findings.py       ← query findings across scans
│   │       ├── projects.py       ← project CRUD
│   │       ├── assets.py         ← asset CRUD
│   │       ├── usage.py          ← usage stats + event log
│   │       └── admin.py          ← client + key management
│   ├── core/
│   │   ├── __init__.py
│   │   ├── config.py             ← Pydantic Settings, all env vars
│   │   ├── database.py           ← SQLAlchemy engine, SessionLocal, get_db
│   │   ├── security.py           ← API key hash/verify, scope check
│   │   ├── rate_limit.py         ← Redis sliding window per key
│   │   ├── request_id.py         ← middleware: X-Request-ID on every response
│   │   └── errors.py             ← error codes, structured error response builder
│   ├── models/
│   │   ├── __init__.py
│   │   ├── client.py
│   │   ├── project.py
│   │   ├── asset.py
│   │   ├── api_key.py
│   │   ├── scan_job.py
│   │   ├── scan_result.py
│   │   ├── finding.py
│   │   ├── artifact.py
│   │   ├── scan_report.py
│   │   ├── usage_event.py
│   │   ├── audit_log.py
│   │   └── api_log.py
│   ├── schemas/
│   │   ├── __init__.py
│   │   ├── scans.py              ← SubmitScan, ScanResponse, ScanStatus
│   │   ├── findings.py           ← FindingResponse, FindingList
│   │   ├── projects.py
│   │   ├── assets.py
│   │   ├── usage.py
│   │   └── admin.py
│   ├── services/
│   │   ├── __init__.py
│   │   ├── scan_service.py       ← create scan, update status, get scan
│   │   ├── key_service.py        ← generate key, hash, verify, revoke
│   │   ├── usage_service.py      ← write usage events, query for billing
│   │   ├── audit_service.py      ← write audit log entries
│   │   ├── report_service.py     ← render HTML, convert PDF, upload S3, presign
│   │   └── webhook_service.py    ← HMAC sign + dispatch webhook (v2 activate)
│   ├── templates/
│   │   └── report.html           ← Jinja2 report template, inline CSS only
│   ├── tasks/
│   │   ├── __init__.py
│   │   ├── scan_tasks.py         ← Celery task: run plugins → persist findings
│   │   └── reaper_tasks.py       ← reap expired/stuck scans (Celery beat)
│   ├── scanner/
│   │   ├── __init__.py
│   │   ├── plugin_base.py        ← BaseScannerPlugin, PluginMeta, PluginResult
│   │   ├── plugin_registry.py    ← auto-discovery, registry.get(), registry.list_default()
│   │   └── plugins/
│   │       ├── __init__.py
│   │       ├── headers.py
│   │       ├── cors.py
│   │       ├── dmarc.py
│   │       ├── httpx_plugin.py
│   │       ├── waf.py
│   │       ├── takeover.py
│   │       ├── dns.py
│   │       ├── tlsinfo.py
│   │       ├── virustotal.py
│   │       ├── nmap.py
│   │       ├── nuclei.py
│   │       └── subfinder.py
│   └── main.py                   ← FastAPI app, middleware, router registration
├── alembic/
│   ├── versions/
│   │   └── 0001_initial_schema.py
│   └── env.py
├── alembic.ini
├── celery_worker.py
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
├── .env.example
└── README.md
```

---

## Coding Rules — Follow Always

### General
1. Read the full file before editing it
2. Never break existing API response shapes — add fields, never remove or rename
3. Never edit Alembic migration files directly — autogenerate then trim
4. One focused task per session
5. Stop and report when done

### File Length
6. Hard cap: 400 lines per file
7. If a file approaches 350 lines, split it before adding more
8. Split strategy: extract helpers to `_utils.py`, split large services by concern

### Error Handling
9. No bare `except: pass` — always log with `logger.warning()` or `logger.error()`
10. Never swallow exceptions silently — if you catch it, log it
11. Every endpoint returns structured error using `errors.py` helpers — never raw HTTPException detail strings
12. Always write an audit log entry on key create/revoke/scan delete

### Database
13. Never query without `client_id` filter on client-scoped resources
14. `usage_events` and `audit_logs` are append-only — never UPDATE or DELETE these rows
15. Always use `get_db()` dependency in endpoints
16. In Celery tasks, use `SessionLocal()` as context manager — never `get_db()`

### Async / Sync Boundary
17. Never call sync functions directly in async endpoints — wrap with `asyncio.to_thread()`
18. No `time.sleep()` in async context — use `asyncio.sleep()`

### Celery Tasks
19. Always pass `queue="enterprise_scans"` on every `.apply_async()` call
20. Always set `soft_time_limit` and `time_limit` on every task
21. Tasks must be idempotent — safe to retry without creating duplicate data
22. Write `usage_event(scan_submitted)` in the API endpoint, not in the task
23. Write `usage_event(scan_completed)` in the Celery task after findings persisted

### Security
24. Never log API key plaintext — log only the prefix
25. Rate limit check happens before any DB query on every authenticated endpoint
26. Scope check is a decorator — never inline scope logic in endpoint body
27. `X-Request-ID` must be present on every response (middleware handles this)

### Plugin Rules
28. Every plugin must handle its own timeout — never hang
29. Every plugin must return `PluginResult` with `error` field set on failure — never raise
30. Never import a specific plugin directly in scan_tasks.py — always go through registry

---

## Environment Variables Reference

```bash
# Database
DATABASE_URL=postgresql://enterprise:enterprise123@localhost:5434/ptk_enterprise

# Redis
REDIS_URL=redis://localhost:6381/0

# Security
SECRET_KEY=your-secret-key-here
ADMIN_SECRET_SCOPE=admin        # scope value that grants admin access

# AWS S3 (for artifacts)
S3_BUCKET=ptk-enterprise-artifacts
S3_REGION=us-east-1
AWS_ACCESS_KEY_ID=
AWS_SECRET_ACCESS_KEY=

# VirusTotal API
VIRUSTOTAL_API_KEY=

# Shodan API (v2)
SHODAN_API_KEY=

# Celery
CELERY_BROKER_URL=redis://localhost:6381/0
CELERY_RESULT_BACKEND=redis://localhost:6381/1

# Scan limits
SCAN_EXPIRE_MINUTES=30           # mark queued scans as expired after this
MAX_CONCURRENT_SCANS_PER_CLIENT=3
DEFAULT_RATE_LIMIT_RPM=60

# App
ENV=development                  # development | production
PORT=8002
CORS_ORIGINS=["http://localhost:3000"]
```

---

## Build Phases

Complete one phase fully before starting the next. Each ends with a verification step.

### Phase 1 — Core Infrastructure
Full folder structure, all models, Alembic initial migration, config, database,
security (key hash/verify), rate_limit, request_id middleware, errors module,
health endpoints.

Verification:
```bash
find . -name "*.py" -exec python3 -m py_compile {} \; && echo "ALL OK"
alembic upgrade head
curl http://localhost:8002/health
```

### Phase 2 — Admin + Auth Layer
Admin endpoints (create client, issue key), API key scope validation decorator,
audit_service, usage_service stubs, rate limit middleware active.

Verification:
```bash
# Create a client via admin endpoint
# Issue a key
# Hit a protected endpoint with the key
# Confirm scope rejection on wrong scope
```

### Phase 3 — Scan API
POST /v1/scans, GET /v1/scans/{id}, GET /v1/scans (history), DELETE /v1/scans/{id},
idempotency key handling, Celery task wiring (stub — no real tools yet),
scan state machine transitions.

Verification:
```bash
# Submit a scan, get scan_id
# Poll status — see queued → running → completed
# Get full response with empty findings (stub result)
```

### Phase 4 — Plugin System + Real Tools
plugin_base.py, plugin_registry.py, implement all 12 default plugins,
Celery task calls registry, findings persisted to DB, scan_results stored,
usage events written on completion.

Verification:
```bash
python3 -c "
from app.scanner.plugin_registry import registry
result = registry.get('headers').run('https://example.com', {})
print(result)
"
```

### Phase 5 — Findings + Usage + Projects + Assets + Reports
GET /v1/findings with filters, GET /v1/usage, GET /v1/projects,
GET /v1/assets, full scan response includes normalized findings.
GET /v1/scans/{id}/report?format=html|pdf — render_html(), html_to_pdf(),
upload both formats to S3, insert scan_reports row, return presigned URL.
Usage event written on first-time generation only.

### Phase 6 — Hardening + Docker
Rate limit enforced end-to-end, reaper task for expired scans,
Dockerfile + docker-compose, README, .env.example final.

Verification:
```bash
docker-compose up --build -d
curl http://localhost:8002/health
curl http://localhost:8002/ready
```

---

## Key API Key Format

```
sk_live_<16 random hex chars>

Example: sk_live_a1b2c3d4e5f6g7h8

key_prefix stored in DB: "sk_live_a1"   (first 10 chars — for display/identification)
key_hash stored in DB:   SHA-256 hex digest of full key

On verify: hash the incoming key, lookup by hash.
```

## Webhook Payload Signature

```python
import hmac, hashlib, json

payload_bytes = json.dumps(payload).encode()
signature = hmac.new(
    client.webhook_secret.encode(),
    payload_bytes,
    hashlib.sha256
).hexdigest()

# Header on POST to client webhook_url:
# X-PTK-Signature: sha256=<signature>
```

---

## Common Pitfalls

- **Key display**: Show full key ONCE on `POST /v1/admin/clients/{id}/keys` response.
  Never return it again. Only `key_prefix` is stored readable.
- **Idempotency**: If `idempotency_key` already exists for this client, return the
  existing scan — do NOT create a new one. Return 200, not 201.
- **Celery DB sessions**: `SessionLocal()` as context manager only. Never pass a
  session across task boundaries.
- **Rate limit key format**: `rate:{key_id}:{unix_minute}` — sliding window in Redis.
- **Scope on admin keys**: Admin keys have `["admin"]` scope — they do NOT
  automatically have `scan:write`. Separate concerns.
- **Plugin timeout**: Each plugin manages its own subprocess timeout. The Celery task
  has a higher outer `time_limit` as a backstop only.
- **Target normalization**: Strip protocol from target for storage
  (`https://example.com` → `example.com`) but pass full URL to plugins.
