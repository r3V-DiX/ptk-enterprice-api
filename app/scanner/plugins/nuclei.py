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
    "high":     "high",
    "medium":   "medium",
    "low":      "low",
    "info":     "info",
    "unknown":  "info",
}

# Maps nuclei OWASP tags → human-readable category stored in owasp_category
_OWASP_TAG_MAP = {
    "owasp-a01": "A01:2021 Broken Access Control",
    "owasp-a02": "A02:2021 Cryptographic Failures",
    "owasp-a03": "A03:2021 Injection",
    "owasp-a04": "A04:2021 Insecure Design",
    "owasp-a05": "A05:2021 Security Misconfiguration",
    "owasp-a06": "A06:2021 Vulnerable and Outdated Components",
    "owasp-a07": "A07:2021 Identification and Authentication Failures",
    "owasp-a08": "A08:2021 Software and Data Integrity Failures",
    "owasp-a09": "A09:2021 Security Logging and Monitoring Failures",
    "owasp-a10": "A10:2021 Server-Side Request Forgery",
    # 2017 tags still appear in older templates
    "owasp-a1":  "A1:2017 Injection",
    "owasp-a2":  "A2:2017 Broken Authentication",
    "owasp-a3":  "A3:2017 Sensitive Data Exposure",
    "owasp-a4":  "A4:2017 XML External Entities",
    "owasp-a5":  "A5:2017 Broken Access Control",
    "owasp-a6":  "A6:2017 Security Misconfiguration",
    "owasp-a7":  "A7:2017 Cross-Site Scripting",
    "owasp-a8":  "A8:2017 Insecure Deserialization",
    "owasp-a9":  "A9:2017 Using Components with Known Vulnerabilities",
    "owasp-a10": "A10:2017 Insufficient Logging",
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
                finding = self._parse_finding(data)
                findings.append(finding)
            except (json.JSONDecodeError, KeyError):
                continue

        return PluginResult(
            plugin_id="nuclei", target=target, findings=findings,
            metadata={"templates_used": ["cves/", "exposures/", "misconfigurations/"]},
            duration_seconds=time.time() - start,
        )

    def _parse_finding(self, data: dict) -> dict:
        info          = data.get("info", {})
        template_id   = data.get("template-id") or data.get("templateID") or ""
        name          = info.get("name", template_id or "Unknown")
        raw_severity  = info.get("severity", "info").lower()
        severity      = _SEVERITY_MAP.get(raw_severity, "info")
        description   = info.get("description", "")
        matched_at    = data.get("matched-at") or data.get("matched_at") or ""
        curl_command  = data.get("curl-command") or data.get("curl_command") or ""

        # ── Classification ─────────────────────────────────────────────────
        classification = info.get("classification", {})

        # CVSS score
        cvss_score = classification.get("cvss-score") or classification.get("cvss_score")
        if cvss_score is not None:
            try:
                cvss_score = round(float(cvss_score), 1)
            except (TypeError, ValueError):
                cvss_score = None

        # CWE IDs
        cwe_list = classification.get("cwe-id", [])
        if isinstance(cwe_list, str):
            cwe_list = [cwe_list] if cwe_list and cwe_list.lower() != "null" else []
        cwe_list = [c for c in cwe_list if c and c.lower() != "null"]
        cwe_id = cwe_list[0] if cwe_list else None

        # CVE IDs
        cve_list = classification.get("cve-id", [])
        if isinstance(cve_list, str):
            cve_list = [cve_list] if cve_list and cve_list.lower() != "null" else []
        cve_list = [c for c in cve_list if c and c.lower() != "null"]

        # OWASP category from tags
        tags = info.get("tags", [])
        if isinstance(tags, str):
            tags = [t.strip() for t in tags.split(",") if t.strip()]
        owasp_category = None
        for tag in (tags or []):
            mapped = _OWASP_TAG_MAP.get(tag.lower())
            if mapped:
                owasp_category = mapped
                break

        # ── Remediation ────────────────────────────────────────────────────
        remediation = info.get("remediation") or info.get("fix")
        if remediation and str(remediation).lower() in ("null", "none", ""):
            remediation = None

        # ── References → append to description ────────────────────────────
        references = info.get("reference", [])
        if isinstance(references, str):
            references = [references]
        references = [r for r in references if r and r.lower() != "null"]

        full_description = description
        if references:
            full_description += "\n\nReferences:\n" + "\n".join(f"- {r}" for r in references[:5])

        # ── Evidence ───────────────────────────────────────────────────────
        evidence: dict = {"template_id": template_id, "matched_at": matched_at}
        if curl_command:
            evidence["curl_command"] = curl_command
        if cve_list:
            evidence["cve_ids"] = cve_list
        if cwe_list:
            evidence["cwe_ids"] = cwe_list

        return {
            "id":             str(uuid.uuid4()),
            "title":          name,
            "severity":       severity,
            "description":    full_description,
            "remediation":    remediation,
            "evidence":       evidence,
            "cvss_score":     cvss_score,
            "cwe_id":         cwe_id,
            "owasp_category": owasp_category,
        }
