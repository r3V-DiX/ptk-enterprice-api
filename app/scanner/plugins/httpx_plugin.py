import json
import subprocess
import time
import uuid
import logging
import shutil
import requests
from app.scanner.plugin_base import BaseScannerPlugin, PluginMeta, PluginResult

logger = logging.getLogger(__name__)


class HttpxPlugin(BaseScannerPlugin):
    meta = PluginMeta(
        id="httpx",
        display_name="Web Prober",
        timeout_seconds=30,
    )

    def run(self, target: str, options: dict) -> PluginResult:
        start = time.time()
        findings = []

        if shutil.which("httpx"):
            return self._run_httpx_binary(target, start)
        return self._run_requests_fallback(target, start)

    def _run_httpx_binary(self, target: str, start: float) -> PluginResult:
        findings = []
        try:
            proc = subprocess.run(
                ["httpx", "-u", target, "-json", "-silent", "-timeout", "10"],
                capture_output=True, text=True,
                timeout=self.meta.timeout_seconds,
            )
            for line in proc.stdout.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    status = data.get("status_code", 0)
                    tech = data.get("tech", [])
                    webserver = data.get("webserver", "")
                    title = data.get("title", "")

                    if status in (0, 404) or status >= 500:
                        findings.append({
                            "id": str(uuid.uuid4()),
                            "title": "Host Unreachable or No Web Service",
                            "severity": "info",
                            "description": f"Target returned status {status}.",
                            "remediation": None,
                            "evidence": data,
                            "cvss_score": None, "cwe_id": None, "owasp_category": None,
                        })
                    elif tech:
                        tech_str = ", ".join(tech) if isinstance(tech, list) else str(tech)
                        findings.append({
                            "id": str(uuid.uuid4()),
                            "title": f"Web Technologies Detected: {tech_str}",
                            "severity": "info",
                            "description": (
                                f"The web server at {target} is running: {tech_str}. "
                                f"Web server: {webserver}. Page title: {title}."
                            ),
                            "remediation": None,
                            "evidence": data,
                            "cvss_score": None, "cwe_id": None, "owasp_category": None,
                        })
                except (json.JSONDecodeError, KeyError):
                    continue
        except subprocess.TimeoutExpired:
            return PluginResult(plugin_id="httpx", target=target,
                                error="httpx timed out", duration_seconds=time.time() - start)
        except Exception as exc:
            logger.warning("httpx binary error for %s: %s", target, exc)
            return PluginResult(plugin_id="httpx", target=target, error=str(exc),
                                duration_seconds=time.time() - start)

        return PluginResult(plugin_id="httpx", target=target, findings=findings,
                            duration_seconds=time.time() - start)

    def _run_requests_fallback(self, target: str, start: float) -> PluginResult:
        findings = []
        urls = [f"https://{target}", f"http://{target}"]
        for url in urls:
            try:
                resp = requests.get(url, timeout=10, allow_redirects=True, verify=False)
                server = resp.headers.get("Server", "")
                powered = resp.headers.get("X-Powered-By", "")
                tech_parts = [s for s in [server, powered] if s]
                tech_str = ", ".join(tech_parts) if tech_parts else "unknown"
                findings.append({
                    "id": str(uuid.uuid4()),
                    "title": f"Web Technologies Detected: {tech_str}",
                    "severity": "info",
                    "description": f"Target responded with HTTP {resp.status_code}. Server: {server}.",
                    "remediation": None,
                    "evidence": {
                        "url": url, "status_code": resp.status_code,
                        "server": server, "x_powered_by": powered,
                    },
                    "cvss_score": None, "cwe_id": None, "owasp_category": None,
                })
                break
            except requests.exceptions.ConnectionError:
                findings.append({
                    "id": str(uuid.uuid4()),
                    "title": "Host Unreachable or No Web Service",
                    "severity": "info",
                    "description": f"Could not connect to {url}.",
                    "remediation": None,
                    "evidence": {"url": url},
                    "cvss_score": None, "cwe_id": None, "owasp_category": None,
                })
            except Exception as exc:
                logger.warning("httpx fallback error for %s: %s", url, exc)

        return PluginResult(plugin_id="httpx", target=target, findings=findings,
                            duration_seconds=time.time() - start)
