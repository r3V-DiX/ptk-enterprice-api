import subprocess
import time
import uuid
import logging
import shutil
from app.scanner.plugin_base import BaseScannerPlugin, PluginMeta, PluginResult

logger = logging.getLogger(__name__)


class CrlfuzzPlugin(BaseScannerPlugin):
    meta = PluginMeta(
        id="crlfuzz",
        display_name="CRLF Injection Scanner",
        timeout_seconds=180,
    )

    def run(self, target: str, options: dict) -> PluginResult:
        start = time.time()
        findings = []

        if not shutil.which("crlfuzz"):
            return PluginResult(plugin_id="crlfuzz", target=target,
                                error="crlfuzz not installed",
                                duration_seconds=time.time() - start)

        url = f"https://{target}" if not target.startswith("http") else target

        try:
            proc = subprocess.run(
                ["crlfuzz", "-u", url, "-s", "-c", "25"],
                capture_output=True, text=True,
                timeout=self.meta.timeout_seconds,
            )
        except subprocess.TimeoutExpired:
            return PluginResult(plugin_id="crlfuzz", target=target,
                                error="crlfuzz timed out",
                                duration_seconds=time.time() - start)
        except Exception as exc:
            logger.warning("crlfuzz execution error for %s: %s", target, exc)
            return PluginResult(plugin_id="crlfuzz", target=target, error=str(exc),
                                duration_seconds=time.time() - start)

        output = (proc.stdout or "").strip()

        if not output:
            return PluginResult(
                plugin_id="crlfuzz", target=target,
                findings=[{
                    "id":             str(uuid.uuid4()),
                    "title":          "CRLF Injection: Not Detected",
                    "severity":       "info",
                    "description":    "No CRLF injection vulnerabilities detected.",
                    "remediation":    None,
                    "evidence":       {"target": url},
                    "cvss_score":     None,
                    "cwe_id":         "CWE-93",
                    "owasp_category": "A03:2021 Injection",
                }],
                duration_seconds=time.time() - start,
            )

        vulnerable_urls = []
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
            if line.startswith("[VUL!]"):
                vulnerable_urls.append(line.replace("[VUL!]", "").strip())
            elif line.startswith("http://") or line.startswith("https://"):
                vulnerable_urls.append(line)

        if not vulnerable_urls:
            findings.append({
                "id":             str(uuid.uuid4()),
                "title":          "CRLF Injection: Not Detected",
                "severity":       "info",
                "description":    "No CRLF injection vulnerabilities detected.",
                "remediation":    None,
                "evidence":       {"raw_output": output[:500]},
                "cvss_score":     None,
                "cwe_id":         "CWE-93",
                "owasp_category": "A03:2021 Injection",
            })
        else:
            for vuln_url in vulnerable_urls:
                findings.append({
                    "id":       str(uuid.uuid4()),
                    "title":    "CRLF Injection Detected",
                    "severity": "high",
                    "description": (
                        "The server reflects CR (\\r) and LF (\\n) characters injected into "
                        "URL parameters back in HTTP response headers. An attacker can exploit "
                        "this to inject arbitrary headers, perform HTTP response splitting, "
                        "set malicious cookies, or conduct reflected XSS attacks."
                    ),
                    "remediation": (
                        "Sanitize all user-supplied input before including it in HTTP response "
                        "headers. Strip or encode CR (\\r, %0d) and LF (\\n, %0a) characters. "
                        "Use a web framework that handles header encoding automatically."
                    ),
                    "evidence":       {"vulnerable_url": vuln_url},
                    "cvss_score":     7.2,
                    "cwe_id":         "CWE-93",
                    "owasp_category": "A03:2021 Injection",
                })

        logger.info("crlfuzz: %d finding(s) for %s", len(findings), target)
        return PluginResult(
            plugin_id="crlfuzz", target=target, findings=findings,
            metadata={"vulnerable_count": len(vulnerable_urls)},
            duration_seconds=time.time() - start,
        )
