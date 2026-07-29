import time
import uuid
import logging

try:
    import dns.resolver
    _DNS_AVAILABLE = True
except ImportError:
    _DNS_AVAILABLE = False

from app.scanner.plugin_base import BaseScannerPlugin, PluginMeta, PluginResult

logger = logging.getLogger(__name__)


class DmarcPlugin(BaseScannerPlugin):
    meta = PluginMeta(
        id="dmarc",
        display_name="Email Security Auditor",
        timeout_seconds=20,
    )

    def run(self, target: str, options: dict) -> PluginResult:
        start = time.time()
        findings = []

        if not _DNS_AVAILABLE:
            return PluginResult(
                plugin_id="dmarc", target=target,
                error="dnspython not installed",
                duration_seconds=time.time() - start,
            )

        dmarc_record = None
        spf_record = None

        # Query DMARC
        try:
            answers = dns.resolver.resolve(f"_dmarc.{target}", "TXT", lifetime=10)
            for rdata in answers:
                txt = b"".join(rdata.strings).decode("utf-8", errors="ignore")
                if "v=DMARC1" in txt:
                    dmarc_record = txt
                    break
        except Exception:
            pass

        # Query SPF
        try:
            answers = dns.resolver.resolve(target, "TXT", lifetime=10)
            for rdata in answers:
                txt = b"".join(rdata.strings).decode("utf-8", errors="ignore")
                if "v=spf1" in txt:
                    spf_record = txt
                    break
        except Exception:
            pass

        evidence = {"dmarc_record": dmarc_record, "spf_record": spf_record}

        if not dmarc_record:
            findings.append({
                "id": str(uuid.uuid4()),
                "title": "DMARC Record Not Configured",
                "severity": "high",
                "description": (
                    f"No DMARC record found for _dmarc.{target}. Without DMARC, "
                    "the domain is vulnerable to email spoofing and phishing attacks."
                ),
                "remediation": (
                    "Add a DMARC TXT record to _dmarc.{target}. "
                    "Start with p=none for monitoring, then move to p=quarantine or p=reject."
                ),
                "evidence": evidence,
                "cvss_score": 6.5,
                "cwe_id": "CWE-290",
                "owasp_category": "A05:2021 – Security Misconfiguration",
            })
        elif "p=none" in dmarc_record:
            findings.append({
                "id": str(uuid.uuid4()),
                "title": "DMARC Policy Set to None (No Enforcement)",
                "severity": "medium",
                "description": (
                    "DMARC record exists but policy is p=none, meaning no action is "
                    "taken on failing messages. This provides no protection against spoofing."
                ),
                "remediation": "Change DMARC policy to p=quarantine or p=reject.",
                "evidence": evidence,
                "cvss_score": 4.3,
                "cwe_id": "CWE-290",
                "owasp_category": "A05:2021 – Security Misconfiguration",
            })

        if not spf_record:
            findings.append({
                "id": str(uuid.uuid4()),
                "title": "SPF Record Not Configured",
                "severity": "high",
                "description": (
                    f"No SPF record found for {target}. Without SPF, anyone can "
                    "send email appearing to originate from this domain."
                ),
                "remediation": (
                    "Add an SPF TXT record to the domain. "
                    "Example: v=spf1 include:_spf.google.com ~all"
                ),
                "evidence": evidence,
                "cvss_score": 6.5,
                "cwe_id": "CWE-290",
                "owasp_category": "A05:2021 – Security Misconfiguration",
            })

        return PluginResult(
            plugin_id="dmarc",
            target=target,
            findings=findings,
            metadata={"dmarc_found": dmarc_record is not None, "spf_found": spf_record is not None},
            duration_seconds=time.time() - start,
        )
