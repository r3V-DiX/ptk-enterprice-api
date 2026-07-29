import time
import uuid
import logging
import requests
from app.scanner.plugin_base import BaseScannerPlugin, PluginMeta, PluginResult
from app.core.config import settings

logger = logging.getLogger(__name__)

_VT_URL = "https://www.virustotal.com/api/v3/domains/{domain}"


class VirustotalPlugin(BaseScannerPlugin):
    meta = PluginMeta(
        id="virustotal",
        display_name="Reputation Check",
        timeout_seconds=20,
    )

    def run(self, target: str, options: dict) -> PluginResult:
        start = time.time()

        api_key = settings.VIRUSTOTAL_API_KEY
        if not api_key:
            return PluginResult(
                plugin_id="virustotal", target=target,
                error="API key not configured",
                duration_seconds=time.time() - start,
            )

        # Use bare domain (strip any path/port)
        domain = target.split("/")[0].split(":")[0]

        try:
            resp = requests.get(
                _VT_URL.format(domain=domain),
                headers={"x-apikey": api_key},
                timeout=15,
            )
        except Exception as exc:
            logger.warning("virustotal request failed for %s: %s", domain, exc)
            return PluginResult(plugin_id="virustotal", target=target, error=str(exc),
                                duration_seconds=time.time() - start)

        if resp.status_code == 404:
            return PluginResult(
                plugin_id="virustotal", target=target,
                findings=[{
                    "id": str(uuid.uuid4()),
                    "title": "Domain Not Found in VirusTotal",
                    "severity": "info",
                    "description": f"{domain} has no records in VirusTotal.",
                    "remediation": None,
                    "evidence": {"status_code": 404},
                    "cvss_score": None, "cwe_id": None, "owasp_category": None,
                }],
                duration_seconds=time.time() - start,
            )

        if resp.status_code == 401:
            return PluginResult(plugin_id="virustotal", target=target,
                                error="Invalid VirusTotal API key",
                                duration_seconds=time.time() - start)

        if resp.status_code != 200:
            return PluginResult(
                plugin_id="virustotal", target=target,
                error=f"VirusTotal API returned HTTP {resp.status_code}",
                duration_seconds=time.time() - start,
            )

        try:
            data = resp.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            harmless = stats.get("harmless", 0)
            undetected = stats.get("undetected", 0)

            evidence = {
                "malicious": malicious,
                "suspicious": suspicious,
                "harmless": harmless,
                "undetected": undetected,
            }

            if malicious > 0:
                finding = {
                    "id": str(uuid.uuid4()),
                    "title": f"Domain Flagged as Malicious by {malicious} Vendors",
                    "severity": "high",
                    "description": (
                        f"{domain} has been flagged as malicious by {malicious} security vendors "
                        f"on VirusTotal. Suspicious: {suspicious}."
                    ),
                    "remediation": (
                        "Investigate the domain's reputation. Check for malware hosting, "
                        "phishing, or command-and-control infrastructure."
                    ),
                    "evidence": evidence,
                    "cvss_score": 7.5,
                    "cwe_id": None,
                    "owasp_category": "A08:2021 – Software and Data Integrity Failures",
                }
            else:
                finding = {
                    "id": str(uuid.uuid4()),
                    "title": "Domain Reputation Clean",
                    "severity": "info",
                    "description": f"{domain} has no malicious detections on VirusTotal.",
                    "remediation": None,
                    "evidence": evidence,
                    "cvss_score": None, "cwe_id": None, "owasp_category": None,
                }

            return PluginResult(
                plugin_id="virustotal", target=target, findings=[finding],
                metadata=evidence, duration_seconds=time.time() - start,
            )

        except Exception as exc:
            logger.warning("virustotal parse error for %s: %s", domain, exc)
            return PluginResult(plugin_id="virustotal", target=target, error=str(exc),
                                duration_seconds=time.time() - start)
