import time
import uuid
import logging
import requests
import urllib3
from app.scanner.plugin_base import BaseScannerPlugin, PluginMeta, PluginResult

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)

# (severity_if_missing, cwe_id, owasp_category, remediation_hint)
_SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "high",
        "CWE-116",
        "A05:2021 Security Misconfiguration",
        "Add a Content-Security-Policy header with at least 'default-src' or 'script-src' directives.",
    ),
    "Strict-Transport-Security": (
        "high",
        "CWE-319",
        "A02:2021 Cryptographic Failures",
        "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' to all HTTPS responses.",
    ),
    "X-Frame-Options": (
        "medium",
        "CWE-693",
        "A05:2021 Security Misconfiguration",
        "Add 'X-Frame-Options: DENY' or 'X-Frame-Options: SAMEORIGIN' to prevent clickjacking.",
    ),
    "X-Content-Type-Options": (
        "medium",
        "CWE-16",
        "A05:2021 Security Misconfiguration",
        "Add 'X-Content-Type-Options: nosniff' to prevent MIME-type sniffing.",
    ),
    "Referrer-Policy": (
        "low",
        "CWE-200",
        "A05:2021 Security Misconfiguration",
        "Add 'Referrer-Policy: strict-origin-when-cross-origin' to control referrer information.",
    ),
    "Permissions-Policy": (
        "low",
        "CWE-16",
        "A05:2021 Security Misconfiguration",
        "Add a Permissions-Policy header to restrict browser feature access (camera, mic, geolocation).",
    ),
}

_INFO_LEAK_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version"]


class HeadersPlugin(BaseScannerPlugin):
    meta = PluginMeta(
        id="headers",
        display_name="HTTP Headers Auditor",
        timeout_seconds=30,
    )

    def run(self, target: str, options: dict) -> PluginResult:
        start = time.time()
        findings = []

        url = f"https://{target}" if not target.startswith("http") else target
        resp_headers, error = self._fetch_headers(url)

        if error and url.startswith("https://"):
            http_url = url.replace("https://", "http://", 1)
            resp_headers, error = self._fetch_headers(http_url)

        if error:
            return PluginResult(plugin_id="headers", target=target, error=error,
                                duration_seconds=time.time() - start)

        headers_lower = {k.lower(): v for k, v in resp_headers.items()}

        # ── Missing / present security headers ────────────────────────────
        present = []
        missing = []
        for header, (severity, cwe, owasp, remediation) in _SECURITY_HEADERS.items():
            if header.lower() in headers_lower:
                present.append(header)
            else:
                missing.append(header)
                findings.append({
                    "id":             str(uuid.uuid4()),
                    "title":          f"Missing Security Header: {header}",
                    "severity":       severity,
                    "description": (
                        f"The HTTP response does not include the {header} header. "
                        "This header helps protect against common web vulnerabilities."
                    ),
                    "remediation":    remediation,
                    "evidence":       {"header": header, "present_headers": present[:], "missing_headers": missing[:]},
                    "cvss_score":     None,
                    "cwe_id":         cwe,
                    "owasp_category": owasp,
                })

        # ── Server information leakage ─────────────────────────────────────
        leaked = []
        for h in _INFO_LEAK_HEADERS:
            val = headers_lower.get(h.lower())
            if val:
                leaked.append(f"{h}: {val}")

        if leaked:
            findings.append({
                "id":          str(uuid.uuid4()),
                "title":       f"Server Information Disclosed ({len(leaked)} header(s))",
                "severity":    "low",
                "description": "HTTP response headers reveal server technology details that aid attacker fingerprinting.",
                "remediation": "Remove or obscure Server, X-Powered-By, and version disclosure headers from all responses.",
                "evidence":    {"leaked_headers": leaked},
                "cvss_score":  None,
                "cwe_id":      "CWE-200",
                "owasp_category": "A05:2021 Security Misconfiguration",
            })

        return PluginResult(
            plugin_id="headers",
            target=target,
            findings=findings,
            metadata={"url": url, "present_headers": present, "missing_headers": missing},
            duration_seconds=time.time() - start,
        )

    def _fetch_headers(self, url: str):
        try:
            resp = requests.get(
                url, timeout=15, allow_redirects=True, verify=False,
                headers={"User-Agent": "Mozilla/5.0 (Pentoolkit Security Scanner)"},
            )
            return dict(resp.headers), None
        except Exception as exc:
            return {}, str(exc)
