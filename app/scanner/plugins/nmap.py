import subprocess
import time
import uuid
import logging
import shutil
import xml.etree.ElementTree as ET
from app.scanner.plugin_base import BaseScannerPlugin, PluginMeta, PluginResult

logger = logging.getLogger(__name__)

_HIGH_RISK_PORTS = {
    # Remote access — brute force targets
    22:    ("medium", "SSH Port Exposed on Port 22",
            "SSH exposed to the internet is a common brute-force target. Restrict access using firewall rules or allowlists, and disable password authentication in favour of key-based auth."),
    23:    ("high", "Telnet Service Exposed on Port 23",
            "Telnet transmits all data including credentials in plaintext. Disable Telnet and use SSH instead."),
    3389:  ("high", "RDP Service Exposed on Port 3389",
            "Remote Desktop Protocol is frequently targeted for brute-force and ransomware delivery. Restrict to VPN/allowlisted IPs only."),
    5900:  ("high", "VNC Service Exposed",
            "VNC is often deployed without strong authentication. Restrict to VPN/allowlisted IPs."),
    # Unencrypted web
    80:    ("low", "HTTP Service Exposed on Port 80 (Unencrypted)",
            "HTTP traffic is unencrypted. Ensure all HTTP traffic is redirected to HTTPS."),
    # FTP
    21:    ("medium", "FTP Service Exposed on Port 21",
            "FTP transmits credentials in plaintext. Use SFTP or FTPS instead."),
    # Databases — should never be public
    3306:  ("high", "MySQL Database Port Publicly Exposed",
            "MySQL port should not be publicly accessible. Restrict to localhost or private network."),
    5432:  ("high", "PostgreSQL Database Port Publicly Exposed",
            "PostgreSQL port should not be publicly accessible. Restrict to localhost or private network."),
    1433:  ("high", "MSSQL Database Port Publicly Exposed",
            "MSSQL port should not be publicly accessible. Restrict to localhost or private network."),
    1521:  ("high", "Oracle Database Port Publicly Exposed",
            "Oracle DB port should not be publicly accessible."),
    6379:  ("high", "Redis Port Exposed — Potential Unauthenticated Access",
            "Redis is often deployed without authentication. Bind to localhost only and require a strong password."),
    27017: ("high", "MongoDB Port Publicly Exposed",
            "MongoDB port should not be publicly accessible. Restrict to localhost or private network."),
    9200:  ("high", "Elasticsearch Port Publicly Exposed",
            "Elasticsearch is often deployed without authentication. Restrict to localhost or private network."),
    5984:  ("high", "CouchDB Port Publicly Exposed",
            "CouchDB port should not be publicly accessible."),
    11211: ("high", "Memcached Port Exposed — Potential Unauthenticated Access",
            "Memcached is often deployed without authentication and can be abused for DDoS amplification. Bind to localhost only."),
    # SMB / Windows shares
    445:   ("high", "SMB Port Exposed on Port 445",
            "SMB exposed to the internet is a critical risk — exploited by ransomware (EternalBlue/WannaCry). Block port 445 at the firewall."),
    139:   ("high", "NetBIOS/SMB Port Exposed on Port 139",
            "NetBIOS/SMB exposed to the internet is a critical risk. Block at the firewall."),
    # Other sensitive services
    2375:  ("critical", "Docker Daemon Exposed (Unauthenticated) on Port 2375",
            "Unauthenticated Docker API allows full container and host compromise. Disable or restrict immediately."),
    2376:  ("high", "Docker Daemon Exposed on Port 2376",
            "Docker TLS API exposed publicly. Restrict to authorised clients only."),
    8500:  ("high", "Consul Service Exposed on Port 8500",
            "Consul API is often unauthenticated. Restrict to internal network."),
}


class NmapPlugin(BaseScannerPlugin):
    meta = PluginMeta(
        id="nmap",
        display_name="Port Scanner",
        timeout_seconds=120,
    )

    def run(self, target: str, options: dict) -> PluginResult:
        start = time.time()
        findings = []

        if not shutil.which("nmap"):
            return PluginResult(plugin_id="nmap", target=target,
                                error="nmap not installed",
                                duration_seconds=time.time() - start)

        # Strip any path or port from target for nmap
        host = target.split("/")[0].split(":")[0]

        try:
            proc = subprocess.run(
                ["nmap", "-F", "--open", "-oX", "-", host],
                capture_output=True, text=True,
                timeout=self.meta.timeout_seconds,
            )
        except subprocess.TimeoutExpired:
            return PluginResult(plugin_id="nmap", target=target,
                                error="nmap timed out", duration_seconds=time.time() - start)
        except Exception as exc:
            logger.warning("nmap execution error for %s: %s", target, exc)
            return PluginResult(plugin_id="nmap", target=target, error=str(exc),
                                duration_seconds=time.time() - start)

        open_ports = []
        try:
            root = ET.fromstring(proc.stdout)
            for port_elem in root.iter("port"):
                state_elem = port_elem.find("state")
                if state_elem is None or state_elem.get("state") != "open":
                    continue
                portid = int(port_elem.get("portid", 0))
                protocol = port_elem.get("protocol", "tcp")
                service_elem = port_elem.find("service")
                service_name = service_elem.get("name", "unknown") if service_elem is not None else "unknown"
                product = service_elem.get("product", "") if service_elem is not None else ""

                open_ports.append({
                    "port": portid,
                    "protocol": protocol,
                    "service": service_name,
                    "product": product,
                    "state": "open",
                })

                if portid in _HIGH_RISK_PORTS:
                    severity, title, remediation = _HIGH_RISK_PORTS[portid]
                    findings.append({
                        "id": str(uuid.uuid4()),
                        "title": title,
                        "severity": severity,
                        "description": f"Port {portid}/{protocol} ({service_name}) is open on {host}.",
                        "remediation": remediation,
                        "evidence": {"port": portid, "protocol": protocol,
                                     "service": service_name, "product": product},
                        "cvss_score": None, "cwe_id": None, "owasp_category": None,
                    })
                else:
                    findings.append({
                        "id": str(uuid.uuid4()),
                        "title": f"Open Port {portid}: {service_name}",
                        "severity": "info",
                        "description": f"Port {portid}/{protocol} is open and running {service_name}.",
                        "remediation": None,
                        "evidence": {"port": portid, "protocol": protocol,
                                     "service": service_name, "product": product},
                        "cvss_score": None, "cwe_id": None, "owasp_category": None,
                    })

        except ET.ParseError as exc:
            logger.warning("nmap XML parse error for %s: %s", target, exc)
            return PluginResult(plugin_id="nmap", target=target,
                                error=f"XML parse error: {exc}",
                                duration_seconds=time.time() - start)

        return PluginResult(
            plugin_id="nmap", target=target, findings=findings,
            metadata={"open_ports": open_ports, "host": host},
            duration_seconds=time.time() - start,
        )
