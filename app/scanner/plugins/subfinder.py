import json
import subprocess
import time
import uuid
import logging
import shutil
from app.scanner.plugin_base import BaseScannerPlugin, PluginMeta, PluginResult

logger = logging.getLogger(__name__)


class SubfinderPlugin(BaseScannerPlugin):
    meta = PluginMeta(
        id="subfinder",
        display_name="Subdomain Mapper",
        timeout_seconds=60,
    )

    def run(self, target: str, options: dict) -> PluginResult:
        start = time.time()
        findings = []

        if not shutil.which("subfinder"):
            return PluginResult(plugin_id="subfinder", target=target,
                                error="subfinder not installed",
                                duration_seconds=time.time() - start)

        # Use bare domain
        domain = target.split("/")[0].split(":")[0]

        try:
            proc = subprocess.run(
                ["subfinder", "-d", domain, "-silent", "-json"],
                capture_output=True, text=True,
                timeout=self.meta.timeout_seconds,
            )
        except subprocess.TimeoutExpired:
            return PluginResult(plugin_id="subfinder", target=target,
                                error="subfinder timed out", duration_seconds=time.time() - start)
        except Exception as exc:
            logger.warning("subfinder execution error for %s: %s", target, exc)
            return PluginResult(plugin_id="subfinder", target=target, error=str(exc),
                                duration_seconds=time.time() - start)

        seen = set()
        for line in proc.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                host = data.get("host", "")
                if not host or host in seen:
                    continue
                seen.add(host)
                sources = data.get("sources", [])
                findings.append({
                    "id": str(uuid.uuid4()),
                    "title": f"Subdomain Discovered: {host}",
                    "severity": "info",
                    "description": (
                        f"The subdomain {host} was discovered during enumeration of {domain}. "
                        "Each subdomain expands the attack surface."
                    ),
                    "remediation": None,
                    "evidence": {"subdomain": host, "source": sources},
                    "cvss_score": None, "cwe_id": None, "owasp_category": None,
                })
            except (json.JSONDecodeError, KeyError):
                # Try plain-text fallback (subfinder without -json flag output)
                host = line.strip()
                if host and host not in seen:
                    seen.add(host)
                    findings.append({
                        "id": str(uuid.uuid4()),
                        "title": f"Subdomain Discovered: {host}",
                        "severity": "info",
                        "description": f"Subdomain {host} discovered for {domain}.",
                        "remediation": None,
                        "evidence": {"subdomain": host, "source": []},
                        "cvss_score": None, "cwe_id": None, "owasp_category": None,
                    })

        if not findings:
            findings.append({
                "id": str(uuid.uuid4()),
                "title": "No Subdomains Discovered",
                "severity": "info",
                "description": f"No subdomains were found for {domain}.",
                "remediation": None,
                "evidence": {"domain": domain},
                "cvss_score": None, "cwe_id": None, "owasp_category": None,
            })

        return PluginResult(
            plugin_id="subfinder", target=target, findings=findings,
            metadata={"domain": domain, "subdomain_count": len(findings)},
            duration_seconds=time.time() - start,
        )
