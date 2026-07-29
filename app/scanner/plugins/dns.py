import time
import uuid
import logging

try:
    import dns.resolver
    import dns.query
    import dns.zone
    import dns.exception
    _DNS_AVAILABLE = True
except ImportError:
    _DNS_AVAILABLE = False

from app.scanner.plugin_base import BaseScannerPlugin, PluginMeta, PluginResult

logger = logging.getLogger(__name__)

_RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]


class DnsPlugin(BaseScannerPlugin):
    meta = PluginMeta(
        id="dns",
        display_name="DNS Recon",
        timeout_seconds=20,
    )

    def run(self, target: str, options: dict) -> PluginResult:
        start = time.time()
        findings = []

        if not _DNS_AVAILABLE:
            return PluginResult(plugin_id="dns", target=target,
                                error="dnspython not installed",
                                duration_seconds=time.time() - start)

        records = {}
        nameservers = []

        # Enumerate all record types
        for rtype in _RECORD_TYPES:
            try:
                answers = dns.resolver.resolve(target, rtype, lifetime=8)
                records[rtype] = [str(r) for r in answers]
                if rtype == "NS":
                    nameservers = [str(r).rstrip(".") for r in answers]
            except dns.resolver.NXDOMAIN:
                records[rtype] = []
            except dns.resolver.NoAnswer:
                records[rtype] = []
            except Exception:
                records[rtype] = []

        # Attempt zone transfer against each NS
        zone_transfer_success = False
        for ns in nameservers:
            try:
                xfr = dns.query.xfr(ns, target, timeout=5, lifetime=8)
                zone = dns.zone.from_xfr(xfr)
                zone_records = [str(n) for n in zone.nodes.keys()]
                zone_transfer_success = True
                findings.append({
                    "id": str(uuid.uuid4()),
                    "title": "DNS Zone Transfer Allowed",
                    "severity": "critical",
                    "description": (
                        f"The nameserver {ns} allowed a full DNS zone transfer for {target}. "
                        "This exposes all DNS records (subdomains, internal hosts, mail servers) "
                        "to any external party."
                    ),
                    "remediation": (
                        "Restrict zone transfers to authorized secondary nameservers only. "
                        "Configure ACLs on your DNS server."
                    ),
                    "evidence": {
                        "nameserver": ns,
                        "zone_records_sample": zone_records[:20],
                        "total_records": len(zone_records),
                    },
                    "cvss_score": 7.5,
                    "cwe_id": "CWE-200",
                    "owasp_category": "A05:2021 – Security Misconfiguration",
                })
                break
            except Exception:
                pass

        # Always emit an info finding with all enumerated records
        findings.append({
            "id": str(uuid.uuid4()),
            "title": "DNS Records Enumerated",
            "severity": "info",
            "description": f"DNS records successfully enumerated for {target}.",
            "remediation": None,
            "evidence": {
                "records": records,
                "zone_transfer_allowed": zone_transfer_success,
            },
            "cvss_score": None, "cwe_id": None, "owasp_category": None,
        })

        return PluginResult(
            plugin_id="dns", target=target, findings=findings,
            metadata={"record_types_queried": _RECORD_TYPES, "nameservers": nameservers},
            duration_seconds=time.time() - start,
        )
