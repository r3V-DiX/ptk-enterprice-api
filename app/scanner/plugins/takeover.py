import time
import uuid
import logging
import requests

try:
    import dns.resolver
    import dns.exception
    _DNS_AVAILABLE = True
except ImportError:
    _DNS_AVAILABLE = False

from app.scanner.plugin_base import BaseScannerPlugin, PluginMeta, PluginResult

logger = logging.getLogger(__name__)

_TAKEOVER_SERVICES = {
    "github.io": "GitHub Pages",
    "amazonaws.com": "AWS S3",
    "s3.amazonaws.com": "AWS S3",
    "azurewebsites.net": "Azure Web Apps",
    "netlify.app": "Netlify",
    "surge.sh": "Surge.sh",
    "bitbucket.io": "Bitbucket",
    "cloudfront.net": "CloudFront",
    "fastly.net": "Fastly",
    "heroku.com": "Heroku",
    "herokussl.com": "Heroku",
    "herokudns.com": "Heroku",
    "unbouncepages.com": "Unbounce",
    "ghost.io": "Ghost",
    "readme.io": "ReadMe",
}

_TAKEOVER_BODY_PATTERNS = [
    "nosuchbucket", "no such bucket",
    "there is no app here", "no such app",
    "404 not found", "repository not found",
    "project not found", "this site can't be reached",
    "page not found", "does not exist",
]


class TakeoverPlugin(BaseScannerPlugin):
    meta = PluginMeta(
        id="takeover",
        display_name="Subdomain Takeover Checker",
        timeout_seconds=30,
    )

    def run(self, target: str, options: dict) -> PluginResult:
        start = time.time()
        findings = []

        if not _DNS_AVAILABLE:
            return PluginResult(plugin_id="takeover", target=target,
                                error="dnspython not installed",
                                duration_seconds=time.time() - start)

        cname = None
        try:
            answers = dns.resolver.resolve(target, "CNAME", lifetime=10)
            for rdata in answers:
                cname = str(rdata.target).rstrip(".")
                break
        except dns.resolver.NoAnswer:
            pass
        except dns.exception.DNSException:
            pass
        except Exception as exc:
            logger.warning("takeover CNAME lookup failed for %s: %s", target, exc)

        if not cname:
            return PluginResult(plugin_id="takeover", target=target,
                                findings=[], metadata={"cname": None},
                                duration_seconds=time.time() - start)

        matched_service = None
        for pattern, service in _TAKEOVER_SERVICES.items():
            if cname.endswith(pattern):
                matched_service = service
                break

        if not matched_service:
            return PluginResult(plugin_id="takeover", target=target,
                                findings=[], metadata={"cname": cname},
                                duration_seconds=time.time() - start)

        # Check HTTP response for takeover indicators
        http_status = None
        body_snippet = ""
        try:
            resp = requests.get(f"https://{target}", timeout=10, verify=False, allow_redirects=True)
            http_status = resp.status_code
            body_snippet = resp.text[:500].lower()
        except Exception:
            try:
                resp = requests.get(f"http://{target}", timeout=10, allow_redirects=True)
                http_status = resp.status_code
                body_snippet = resp.text[:500].lower()
            except Exception:
                pass

        is_vulnerable = (
            http_status in (404, 410, None) or
            any(pattern in body_snippet for pattern in _TAKEOVER_BODY_PATTERNS)
        )

        if is_vulnerable:
            findings.append({
                "id": str(uuid.uuid4()),
                "title": f"Potential Subdomain Takeover via {matched_service}",
                "severity": "high",
                "description": (
                    f"{target} has a CNAME record pointing to {cname} ({matched_service}), "
                    "but the resource appears to be unclaimed. An attacker could register "
                    "this resource and serve malicious content under your domain."
                ),
                "remediation": (
                    "Remove the dangling CNAME record or claim the resource on the "
                    f"{matched_service} platform."
                ),
                "evidence": {
                    "cname": cname,
                    "service": matched_service,
                    "http_status": http_status,
                    "body_snippet": body_snippet[:200],
                },
                "cvss_score": 7.4,
                "cwe_id": "CWE-350",
                "owasp_category": "A05:2021 – Security Misconfiguration",
            })

        return PluginResult(
            plugin_id="takeover", target=target, findings=findings,
            metadata={"cname": cname, "service": matched_service, "vulnerable": is_vulnerable},
            duration_seconds=time.time() - start,
        )
