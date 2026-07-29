import json
import subprocess
import time
import uuid
import logging
import shutil
from app.scanner.plugin_base import BaseScannerPlugin, PluginMeta, PluginResult

logger = logging.getLogger(__name__)

_SEVERITY_MAP = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "info": "info",
    "unknown": "info",
}


class NucleiPlugin(BaseScannerPlugin):
    meta = PluginMeta(
        id="nuclei",
        display_name="Vuln Scanner",
        timeout_seconds=300,
    )

    def run(self, target: str, options: dict) -> PluginResult:
        start = time.time()
        findings = []

        if not shutil.which("nuclei"):
            return PluginResult(plugin_id="nuclei", target=target,
                                error="nuclei not installed",
                                duration_seconds=time.time() - start)

        url = f"https://{target}" if not target.startswith("http") else target

        try:
            proc = subprocess.run(
                [
                    "nuclei",
                    "-u", url,
                    "-json",
                    "-silent",
                    "-timeout", "5",
                    "-t", "cves/",
                    "-t", "exposures/",
                    "-t", "misconfigurations/",
                ],
                capture_output=True, text=True,
                timeout=self.meta.timeout_seconds,
            )
        except subprocess.TimeoutExpired:
            return PluginResult(plugin_id="nuclei", target=target,
                                error="nuclei timed out", duration_seconds=time.time() - start)
        except Exception as exc:
            logger.warning("nuclei execution error for %s: %s", target, exc)
            return PluginResult(plugin_id="nuclei", target=target, error=str(exc),
                                duration_seconds=time.time() - start)

        for line in proc.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                info = data.get("info", {})
                raw_severity = info.get("severity", "info").lower()
                severity = _SEVERITY_MAP.get(raw_severity, "info")
                name = info.get("name", data.get("template-id", "Unknown"))
                description = info.get("description", "")
                remediation = info.get("remediation", None)
                matched_at = data.get("matched-at", data.get("matched_at", ""))
                template_id = data.get("template-id", data.get("templateID", ""))
                curl_command = data.get("curl-command", data.get("curl_command", ""))

                findings.append({
                    "id": str(uuid.uuid4()),
                    "title": name,
                    "severity": severity,
                    "description": description,
                    "remediation": remediation,
                    "evidence": {
                        "template_id": template_id,
                        "matched_at": matched_at,
                        "curl_command": curl_command,
                    },
                    "cvss_score": None,
                    "cwe_id": None,
                    "owasp_category": None,
                })
            except (json.JSONDecodeError, KeyError):
                continue

        return PluginResult(
            plugin_id="nuclei", target=target, findings=findings,
            metadata={"templates_used": ["cves/", "exposures/", "misconfigurations/"]},
            duration_seconds=time.time() - start,
        )
