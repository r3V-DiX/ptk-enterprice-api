import time
import uuid
import logging
import requests
from app.scanner.plugin_base import BaseScannerPlugin, PluginMeta, PluginResult

logger = logging.getLogger(__name__)

_EVIL_ORIGIN = "https://evil.example.com"


class CorsPlugin(BaseScannerPlugin):
    meta = PluginMeta(
        id="cors",
        display_name="CORS Auditor",
        timeout_seconds=30,
    )

    def run(self, target: str, options: dict) -> PluginResult:
        start = time.time()
        findings = []

        urls = [f"https://{target}", f"http://{target}"]
        resp = None

        for url in urls:
            try:
                resp = requests.get(
                    url,
                    headers={"Origin": _EVIL_ORIGIN},
                    timeout=15,
                    allow_redirects=True,
                    verify=False,
                )
                break
            except Exception:
                resp = None

        if resp is None:
            return PluginResult(
                plugin_id="cors", target=target,
                error="Could not connect to target",
                duration_seconds=time.time() - start,
            )

        try:
            acao = resp.headers.get("Access-Control-Allow-Origin", "")
            acac = resp.headers.get("Access-Control-Allow-Credentials", "").lower()
            evidence = {
                "request_origin": _EVIL_ORIGIN,
                "response_acao": acao,
                "response_acac": acac,
            }

            if acao == "*" and acac == "true":
                findings.append({
                    "id": str(uuid.uuid4()),
                    "title": "Critical CORS Misconfiguration: Wildcard with Credentials",
                    "severity": "critical",
                    "description": (
                        "The server returns Access-Control-Allow-Origin: * combined with "
                        "Access-Control-Allow-Credentials: true. This combination is "
                        "rejected by browsers but indicates a dangerous misconfiguration."
                    ),
                    "remediation": "Never combine wildcard CORS with Allow-Credentials: true.",
                    "evidence": evidence,
                    "cvss_score": 9.1,
                    "cwe_id": "CWE-942",
                    "owasp_category": "A05:2021 – Security Misconfiguration",
                })
            elif acao == _EVIL_ORIGIN and acac == "true":
                findings.append({
                    "id": str(uuid.uuid4()),
                    "title": "CORS Origin Reflection with Credentials Allowed",
                    "severity": "critical",
                    "description": (
                        "The server reflects any supplied Origin header and allows credentials. "
                        "This allows any attacker-controlled site to make authenticated "
                        "cross-origin requests."
                    ),
                    "remediation": "Validate Origin against an explicit allowlist.",
                    "evidence": evidence,
                    "cvss_score": 8.8,
                    "cwe_id": "CWE-942",
                    "owasp_category": "A05:2021 – Security Misconfiguration",
                })
            elif acao == "*":
                findings.append({
                    "id": str(uuid.uuid4()),
                    "title": "Wildcard CORS Policy",
                    "severity": "high",
                    "description": (
                        "The server returns Access-Control-Allow-Origin: * allowing any "
                        "origin to read responses. Sensitive API responses should not "
                        "be accessible cross-origin."
                    ),
                    "remediation": "Replace the wildcard with an explicit allowlist of trusted origins.",
                    "evidence": evidence,
                    "cvss_score": 6.5,
                    "cwe_id": "CWE-942",
                    "owasp_category": "A05:2021 – Security Misconfiguration",
                })
            elif acao == _EVIL_ORIGIN:
                findings.append({
                    "id": str(uuid.uuid4()),
                    "title": "CORS Origin Reflection",
                    "severity": "high",
                    "description": (
                        "The server reflects the supplied Origin header back, allowing "
                        "any origin to access resources."
                    ),
                    "remediation": "Validate Origin against an explicit allowlist.",
                    "evidence": evidence,
                    "cvss_score": 6.5,
                    "cwe_id": "CWE-942",
                    "owasp_category": "A05:2021 – Security Misconfiguration",
                })

        except Exception as exc:
            logger.warning("cors plugin parse error for %s: %s", target, exc)
            return PluginResult(plugin_id="cors", target=target, error=str(exc),
                                duration_seconds=time.time() - start)

        return PluginResult(
            plugin_id="cors",
            target=target,
            findings=findings,
            metadata={"acao": acao if resp else None},
            duration_seconds=time.time() - start,
        )
