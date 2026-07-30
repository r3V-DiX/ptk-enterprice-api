import json
import subprocess
import time
import uuid
import logging
import shutil
import requests
from app.scanner.plugin_base import BaseScannerPlugin, PluginMeta, PluginResult

logger = logging.getLogger(__name__)

_WAF_HEADERS = {
    "cf-ray": "Cloudflare",
    "x-sucuri-id": "Sucuri",
    "x-sucuri-cache": "Sucuri",
    "x-firewall-protection": "Generic Firewall",
    "x-cdn": "CDN/WAF",
    "x-iinfo": "Incapsula",
    "x-cdn-forward": "CDN",
    "x-akamai-transformed": "Akamai",
    "x-waf-status": "Generic WAF",
    "x-powered-by-plesk": "Plesk WAF",
    "server": None,  # checked separately for WAF signatures
}

_SERVER_WАFS = {
    "cloudflare": "Cloudflare",
    "sucuri": "Sucuri",
    "incapsula": "Incapsula",
    "akamai": "Akamai",
    "aws": "AWS WAF",
    "imperva": "Imperva",
    "f5": "F5 BIG-IP",
    "barracuda": "Barracuda",
    "modsecurity": "ModSecurity",
}


class WafPlugin(BaseScannerPlugin):
    meta = PluginMeta(
        id="waf",
        display_name="WAF Detector",
        timeout_seconds=20,
    )

    def run(self, target: str, options: dict) -> PluginResult:
        start = time.time()

        if shutil.which("wafw00f"):
            return self._run_wafw00f(target, start)
        return self._run_heuristic(target, start)

    def _run_wafw00f(self, target: str, start: float) -> PluginResult:
        try:
            url = f"https://{target}" if not target.startswith("http") else target
            proc = subprocess.run(
                ["wafw00f", url, "-o", "-", "-f", "json"],
                capture_output=True, text=True,
                timeout=self.meta.timeout_seconds,
            )
            data = json.loads(proc.stdout or "[]")
            waf_name = None
            if isinstance(data, list) and data:
                waf_name = data[0].get("firewall") or data[0].get("waf")

            return self._make_result(target, waf_name, "wafw00f", {}, start)
        except subprocess.TimeoutExpired:
            return PluginResult(plugin_id="waf", target=target,
                                error="wafw00f timed out", duration_seconds=time.time() - start)
        except Exception as exc:
            logger.warning("wafw00f error for %s: %s", target, exc)
            return self._run_heuristic(target, start)

    def _run_heuristic(self, target: str, start: float) -> PluginResult:
        urls = [f"https://{target}", f"http://{target}"]
        resp = None
        for url in urls:
            try:
                probe = f"{url}/?<script>alert(1)</script>"
                resp = requests.get(probe, timeout=10, allow_redirects=True,
                                    verify=False, headers={"User-Agent": "Mozilla/5.0"})
                break
            except Exception:
                pass

        if resp is None:
            return PluginResult(plugin_id="waf", target=target,
                                error="Could not connect", duration_seconds=time.time() - start)

        resp_headers_lower = {k.lower(): v for k, v in resp.headers.items()}
        waf_name = None
        evidence_headers = {}

        for hdr, name in _WAF_HEADERS.items():
            if hdr in resp_headers_lower:
                val = resp_headers_lower[hdr]
                evidence_headers[hdr] = val
                if hdr == "server":
                    val_lower = val.lower()
                    for sig, wname in _SERVER_WАFS.items():
                        if sig in val_lower:
                            waf_name = wname
                            break
                elif name:
                    waf_name = name

        if resp.status_code in (403, 406, 429):
            waf_name = waf_name or "Unknown WAF (blocked probe request)"

        return self._make_result(target, waf_name, "heuristic", evidence_headers, start)

    def _make_result(self, target, waf_name, method, headers_evidence, start):
        evidence = {"waf_name": waf_name, "detection_method": method, "headers": headers_evidence}
        if waf_name:
            finding = {
                "id": str(uuid.uuid4()),
                "title": f"WAF Detected: {waf_name}",
                "severity": "info",
                "description": f"A Web Application Firewall ({waf_name}) was detected in front of {target}.",
                "remediation": None,
                "evidence": evidence,
                "cvss_score": None, "cwe_id": None, "owasp_category": None,
            }
        else:
            finding = {
                "id": str(uuid.uuid4()),
                "title": "No WAF Detected — Direct Origin Exposure",
                "severity": "low",
                "description": (
                    f"No WAF signatures detected for {target}. "
                    "The origin server may be directly reachable and unprotected by a web application firewall."
                ),
                "remediation": "Consider deploying a WAF (e.g. Cloudflare, AWS WAF) to protect against common web attacks.",
                "evidence": evidence,
                "cvss_score": 3.1,
                "cwe_id": "CWE-693",
                "owasp_category": "A05:2021 – Security Misconfiguration",
            }
        return PluginResult(plugin_id="waf", target=target, findings=[finding],
                            metadata=evidence, duration_seconds=time.time() - start)
