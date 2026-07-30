import ssl
import socket
import time
import uuid
import logging
from datetime import datetime, timezone

from app.scanner.plugin_base import BaseScannerPlugin, PluginMeta, PluginResult

logger = logging.getLogger(__name__)


class TlsInfoPlugin(BaseScannerPlugin):
    meta = PluginMeta(
        id="tlsinfo",
        display_name="TLS Auditor",
        timeout_seconds=20,
    )

    def run(self, target: str, options: dict) -> PluginResult:
        start = time.time()
        findings = []

        # Strip port if present
        host = target.split(":")[0]
        port = 443

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        try:
            with socket.create_connection((host, port), timeout=10) as raw_sock:
                with ctx.wrap_socket(raw_sock, server_hostname=host) as ssl_sock:
                    cert = ssl_sock.getpeercert()
                    protocol = ssl_sock.version()
                    cipher = ssl_sock.cipher()
        except (socket.timeout, ConnectionRefusedError, OSError) as exc:
            findings.append({
                "id": str(uuid.uuid4()),
                "title": "No TLS/HTTPS on Port 443",
                "severity": "info",
                "description": f"Could not establish a TLS connection to {host}:443. Error: {exc}",
                "remediation": "Ensure HTTPS is properly configured on port 443.",
                "evidence": {"error": str(exc)},
                "cvss_score": None, "cwe_id": None, "owasp_category": None,
            })
            return PluginResult(plugin_id="tlsinfo", target=target, findings=findings,
                                duration_seconds=time.time() - start)
        except Exception as exc:
            logger.warning("tlsinfo unexpected error for %s: %s", target, exc)
            return PluginResult(plugin_id="tlsinfo", target=target, error=str(exc),
                                duration_seconds=time.time() - start)

        evidence = {
            "subject": dict(x[0] for x in cert.get("subject", [])) if cert else {},
            "issuer": dict(x[0] for x in cert.get("issuer", [])) if cert else {},
            "protocol": protocol,
            "cipher": cipher[0] if cipher else None,
        }

        # Certificate expiry
        not_after_str = cert.get("notAfter", "") if cert else ""
        if not_after_str:
            try:
                not_after = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
                not_after = not_after.replace(tzinfo=timezone.utc)
                now = datetime.now(timezone.utc)
                days_left = (not_after - now).days
                evidence["expiry"] = not_after.isoformat()
                evidence["days_until_expiry"] = days_left

                if days_left < 0:
                    findings.append({
                        "id": str(uuid.uuid4()),
                        "title": "TLS Certificate Expired",
                        "severity": "critical",
                        "description": f"The TLS certificate for {host} expired {abs(days_left)} days ago.",
                        "remediation": "Renew the TLS certificate immediately.",
                        "evidence": evidence,
                        "cvss_score": 7.5,
                        "cwe_id": "CWE-298",
                        "owasp_category": "A02:2021 – Cryptographic Failures",
                    })
                elif days_left < 30:
                    findings.append({
                        "id": str(uuid.uuid4()),
                        "title": f"TLS Certificate Expires in {days_left} Days",
                        "severity": "high",
                        "description": f"The TLS certificate for {host} expires in {days_left} days.",
                        "remediation": "Renew the TLS certificate before it expires.",
                        "evidence": evidence,
                        "cvss_score": 5.3,
                        "cwe_id": "CWE-298",
                        "owasp_category": "A02:2021 – Cryptographic Failures",
                    })
            except ValueError:
                pass

        # Self-signed check
        if cert:
            subject = dict(x[0] for x in cert.get("subject", []))
            issuer = dict(x[0] for x in cert.get("issuer", []))
            if subject and subject == issuer:
                findings.append({
                    "id": str(uuid.uuid4()),
                    "title": "Self-Signed TLS Certificate",
                    "severity": "medium",
                    "description": (
                        f"The TLS certificate for {host} is self-signed. "
                        "Clients will receive browser security warnings."
                    ),
                    "remediation": "Replace with a certificate signed by a trusted CA.",
                    "evidence": evidence,
                    "cvss_score": 4.8,
                    "cwe_id": "CWE-295",
                    "owasp_category": "A02:2021 – Cryptographic Failures",
                })

        # Weak protocol check — exact match only (TLSv1.3 must NOT match TLSv1)
        _WEAK_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.0", "TLSv1.1"}
        if protocol and protocol in _WEAK_PROTOCOLS:
            findings.append({
                "id": str(uuid.uuid4()),
                "title": f"Weak TLS Protocol in Use: {protocol}",
                "severity": "high",
                "description": (
                    f"The server negotiated {protocol}, which is considered weak and vulnerable."
                ),
                "remediation": "Disable TLS 1.0 and 1.1. Configure minimum TLS 1.2 or higher.",
                "evidence": evidence,
                "cvss_score": 6.5,
                "cwe_id": "CWE-326",
                "owasp_category": "A02:2021 – Cryptographic Failures",
            })

        return PluginResult(
            plugin_id="tlsinfo", target=target, findings=findings,
            metadata=evidence, duration_seconds=time.time() - start,
        )
