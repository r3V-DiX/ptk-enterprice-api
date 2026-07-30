import json
import subprocess
import time
import uuid
import logging
import shutil
from app.scanner.plugin_base import BaseScannerPlugin, PluginMeta, PluginResult

logger = logging.getLogger(__name__)

_SECRET_SEVERITY = {
    "password": "critical", "passwd": "critical", "private key": "critical",
    "database": "critical", "db_url": "critical", "aws": "critical",
    "api key": "high", "apikey": "high", "api_key": "high",
    "token": "high", "auth_token": "high", "bearer": "high",
    "secret": "high", "secret_key": "high",
    "slack": "high", "discord": "high",
}


def _secret_severity(name: str) -> str:
    n = name.lower()
    for k, sev in _SECRET_SEVERITY.items():
        if k in n:
            return sev
    return "medium"


class CariddiPlugin(BaseScannerPlugin):
    meta = PluginMeta(
        id="cariddi",
        display_name="Secret & Endpoint Crawler",
        timeout_seconds=300,
    )

    def run(self, target: str, options: dict) -> PluginResult:
        start = time.time()

        if not shutil.which("cariddi"):
            return PluginResult(plugin_id="cariddi", target=target,
                                error="cariddi not installed",
                                duration_seconds=time.time() - start)

        url = f"https://{target}" if not target.startswith("http") else target

        try:
            proc = subprocess.run(
                ["cariddi", "-u", url, "-json", "-s", "-intensive", "1", "-d", "2"],
                capture_output=True, text=True,
                timeout=self.meta.timeout_seconds,
            )
        except subprocess.TimeoutExpired:
            return PluginResult(plugin_id="cariddi", target=target,
                                error="cariddi timed out",
                                duration_seconds=time.time() - start)
        except Exception as exc:
            logger.warning("cariddi execution error for %s: %s", target, exc)
            return PluginResult(plugin_id="cariddi", target=target, error=str(exc),
                                duration_seconds=time.time() - start)

        output = (proc.stdout or "").strip()
        findings = self._parse_output(output, url)

        logger.info("cariddi: %d finding(s) for %s", len(findings), target)
        return PluginResult(
            plugin_id="cariddi", target=target, findings=findings,
            metadata={"target": url},
            duration_seconds=time.time() - start,
        )

    def _parse_output(self, output: str, url: str) -> list:
        if not output:
            return [{
                "id":             str(uuid.uuid4()),
                "title":          "Cariddi: No Results",
                "severity":       "info",
                "description":    "Crawler produced no output — target may be unreachable or disallow crawling.",
                "remediation":    None,
                "evidence":       {"target": url},
                "cvss_score":     None,
                "cwe_id":         "CWE-200",
                "owasp_category": "A05:2021 Security Misconfiguration",
            }]

        endpoints: list[str] = []
        secrets: dict[str, list] = {}  # secret_type → list of occurrences

        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue

            # Try JSON line
            try:
                item = json.loads(line)
                ep = item.get("url") or item.get("endpoint") or item.get("path")
                if ep:
                    endpoints.append(ep)
                for s in item.get("secrets", []) or []:
                    stype = s.get("name", "Unknown")
                    secrets.setdefault(stype, []).append(s)
                continue
            except (json.JSONDecodeError, ValueError):
                pass

            # Plain URL line
            if line.startswith("http://") or line.startswith("https://"):
                endpoints.append(line)

        findings = []

        # Endpoint discovery finding
        if endpoints:
            unique = sorted(set(endpoints))
            findings.append({
                "id":       str(uuid.uuid4()),
                "title":    f"Discovered {len(unique)} Endpoint(s) via Crawl",
                "severity": "info",
                "description": (
                    f"Cariddi discovered {len(unique)} unique URL(s) by crawling the target. "
                    "These represent the active attack surface and should be tested with active scanners."
                ),
                "remediation": None,
                "evidence":    {
                    "endpoints": unique[:50],
                    "total": len(unique),
                },
                "cvss_score":     None,
                "cwe_id":         "CWE-200",
                "owasp_category": "A05:2021 Security Misconfiguration",
            })

        # Secret findings grouped by type
        for secret_type, occurrences in secrets.items():
            sev = _secret_severity(secret_type)
            evidence_items = []
            for o in occurrences[:10]:
                entry = {}
                if o.get("url"):
                    entry["url"] = o["url"]
                if o.get("match"):
                    entry["match"] = o["match"][:120]
                if entry:
                    evidence_items.append(entry)

            findings.append({
                "id":       str(uuid.uuid4()),
                "title":    f"Sensitive Data Exposed: {secret_type}",
                "severity": sev,
                "description": (
                    f"Cariddi detected {len(occurrences)} occurrence(s) of '{secret_type}' "
                    "in crawled page source, JavaScript files, or HTTP responses. "
                    "Exposed credentials and secrets can lead to account or infrastructure compromise."
                ),
                "remediation": (
                    "Remove sensitive data from client-facing source code and responses. "
                    "Rotate any exposed credentials immediately. "
                    "Use environment variables and secrets managers instead of hardcoding values."
                ),
                "evidence":    {"occurrences": evidence_items, "total": len(occurrences)},
                "cvss_score":  9.1 if sev == "critical" else 7.5,
                "cwe_id":      "CWE-312",
                "owasp_category": "A02:2021 Cryptographic Failures",
            })

        if not findings:
            findings.append({
                "id":             str(uuid.uuid4()),
                "title":          "Cariddi: Crawl Complete — Nothing Notable",
                "severity":       "info",
                "description":    "Crawl completed but no sensitive data or notable endpoints were found.",
                "remediation":    None,
                "evidence":       {"target": url},
                "cvss_score":     None,
                "cwe_id":         "CWE-200",
                "owasp_category": "A05:2021 Security Misconfiguration",
            })

        return findings
