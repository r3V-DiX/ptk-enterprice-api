import time
import uuid
import logging
import requests
from app.scanner.plugin_base import BaseScannerPlugin, PluginMeta, PluginResult

logger = logging.getLogger(__name__)

_SECURITY_HEADERS = {
    "Content-Security-Policy": ("medium", "CWE-693", "A05:2021 – Security Misconfiguration"),
    "Strict-Transport-Security": ("medium", "CWE-311", "A02:2021 – Cryptographic Failures"),
    "X-Frame-Options": ("low", None, None),
    "X-Content-Type-Options": ("low", None, None),
    "Referrer-Policy": ("low", None, None),
    "Permissions-Policy": ("low", None, None),
}


class HeadersPlugin(BaseScannerPlugin):
    meta = PluginMeta(
        id="headers",
        display_name="HTTP Headers Auditor",
        timeout_seconds=30,
    )

    def run(self, target: str, options: dict) -> PluginResult:
        start = time.time()
        findings = []

        try:
            url = f"https://{target}" if not target.startswith("http") else target
            resp = requests.get(url, timeout=15, allow_redirects=True, verify=False)
            resp_headers_lower = {k.lower(): v for k, v in resp.headers.items()}

            present = []
            missing = []
            for header, (severity, cwe, owasp) in _SECURITY_HEADERS.items():
                if header.lower() in resp_headers_lower:
                    present.append(header)
                else:
                    missing.append(header)
                    findings.append({
                        "id": str(uuid.uuid4()),
                        "title": f"Missing Security Header: {header}",
                        "severity": severity,
                        "description": (
                            f"The HTTP response does not include the {header} header. "
                            "This header helps protect against common web vulnerabilities."
                        ),
                        "remediation": f"Add the {header} header to all HTTP responses.",
                        "evidence": {"present_headers": present[:], "missing_headers": missing[:]},
                        "cvss_score": None,
                        "cwe_id": cwe,
                        "owasp_category": owasp,
                    })

        except requests.exceptions.SSLError:
            # Try http fallback
            try:
                url = f"http://{target}"
                resp = requests.get(url, timeout=15, allow_redirects=True)
                resp_headers_lower = {k.lower(): v for k, v in resp.headers.items()}
                present = []
                missing = []
                for header, (severity, cwe, owasp) in _SECURITY_HEADERS.items():
                    if header.lower() not in resp_headers_lower:
                        missing.append(header)
                        findings.append({
                            "id": str(uuid.uuid4()),
                            "title": f"Missing Security Header: {header}",
                            "severity": severity,
                            "description": f"The HTTP response does not include the {header} header.",
                            "remediation": f"Add the {header} header to all HTTP responses.",
                            "evidence": {"present_headers": present[:], "missing_headers": missing[:]},
                            "cvss_score": None,
                            "cwe_id": cwe,
                            "owasp_category": owasp,
                        })
            except Exception as exc:
                logger.warning("headers plugin http fallback failed for %s: %s", target, exc)
                return PluginResult(plugin_id="headers", target=target, error=str(exc),
                                    duration_seconds=time.time() - start)
        except Exception as exc:
            logger.warning("headers plugin failed for %s: %s", target, exc)
            return PluginResult(plugin_id="headers", target=target, error=str(exc),
                                duration_seconds=time.time() - start)

        return PluginResult(
            plugin_id="headers",
            target=target,
            findings=findings,
            metadata={"url": target, "finding_count": len(findings)},
            duration_seconds=time.time() - start,
        )
