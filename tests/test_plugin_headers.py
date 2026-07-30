"""Unit tests for the HTTP Headers Auditor plugin."""
from unittest.mock import patch

import pytest

from app.scanner.plugins.headers import HeadersPlugin


@pytest.fixture
def plugin():
    return HeadersPlugin()


def _ok(headers: dict):
    """Return value of _fetch_headers on success: (headers_dict, None)."""
    return headers, None


def _err(msg: str = "Connection refused"):
    """Return value of _fetch_headers on failure: ({}, error_str)."""
    return {}, msg


class TestHeadersAllPresent:
    def test_no_missing_headers_returns_no_security_findings(self, plugin):
        all_headers = {
            "Content-Security-Policy": "default-src 'self'",
            "Strict-Transport-Security": "max-age=31536000",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "geolocation=()",
        }
        with patch.object(plugin, "_fetch_headers", return_value=_ok(all_headers)):
            result = plugin.run("example.com", {})
        assert result.error is None
        missing_findings = [f for f in result.findings if "Missing" in f["title"]]
        assert len(missing_findings) == 0


class TestHeadersMissing:
    def test_missing_csp_produces_high_finding(self, plugin):
        headers = {
            "Strict-Transport-Security": "max-age=31536000",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer",
            "Permissions-Policy": "geolocation=()",
        }
        with patch.object(plugin, "_fetch_headers", return_value=_ok(headers)):
            result = plugin.run("example.com", {})
        csp_findings = [f for f in result.findings if "Content-Security-Policy" in f["title"]]
        assert len(csp_findings) == 1
        assert csp_findings[0]["severity"] == "high"
        assert csp_findings[0]["cwe_id"] == "CWE-116"
        assert csp_findings[0]["owasp_category"] == "A05:2021 Security Misconfiguration"

    def test_missing_hsts_produces_high_finding(self, plugin):
        headers = {
            "Content-Security-Policy": "default-src 'self'",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer",
            "Permissions-Policy": "geolocation=()",
        }
        with patch.object(plugin, "_fetch_headers", return_value=_ok(headers)):
            result = plugin.run("example.com", {})
        hsts_findings = [f for f in result.findings if "Strict-Transport-Security" in f["title"]]
        assert len(hsts_findings) == 1
        assert hsts_findings[0]["severity"] == "high"
        assert hsts_findings[0]["cwe_id"] == "CWE-319"
        assert hsts_findings[0]["owasp_category"] == "A02:2021 Cryptographic Failures"

    def test_missing_x_frame_options_produces_medium_finding(self, plugin):
        headers = {
            "Content-Security-Policy": "default-src 'self'",
            "Strict-Transport-Security": "max-age=31536000",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer",
            "Permissions-Policy": "geolocation=()",
        }
        with patch.object(plugin, "_fetch_headers", return_value=_ok(headers)):
            result = plugin.run("example.com", {})
        findings = [f for f in result.findings if "X-Frame-Options" in f["title"]]
        assert len(findings) == 1
        assert findings[0]["severity"] == "medium"
        assert findings[0]["cwe_id"] == "CWE-693"

    def test_missing_referrer_policy_produces_low_finding(self, plugin):
        headers = {
            "Content-Security-Policy": "default-src 'self'",
            "Strict-Transport-Security": "max-age=31536000",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Permissions-Policy": "geolocation=()",
        }
        with patch.object(plugin, "_fetch_headers", return_value=_ok(headers)):
            result = plugin.run("example.com", {})
        findings = [f for f in result.findings if "Referrer-Policy" in f["title"]]
        assert len(findings) == 1
        assert findings[0]["severity"] == "low"

    def test_all_missing_produces_six_findings(self, plugin):
        with patch.object(plugin, "_fetch_headers", return_value=_ok({})):
            result = plugin.run("example.com", {})
        missing_findings = [f for f in result.findings if "Missing" in f["title"]]
        assert len(missing_findings) == 6

    def test_each_missing_header_has_remediation(self, plugin):
        with patch.object(plugin, "_fetch_headers", return_value=_ok({})):
            result = plugin.run("example.com", {})
        missing_findings = [f for f in result.findings if "Missing" in f["title"]]
        for f in missing_findings:
            assert f["remediation"] is not None


class TestHeadersInfoLeak:
    def test_server_header_leakage_detected(self, plugin):
        headers = {
            "Content-Security-Policy": "default-src 'self'",
            "Strict-Transport-Security": "max-age=31536000",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer",
            "Permissions-Policy": "geolocation=()",
            "Server": "Apache/2.4.50 (Ubuntu)",
            "X-Powered-By": "PHP/7.4",
        }
        with patch.object(plugin, "_fetch_headers", return_value=_ok(headers)):
            result = plugin.run("example.com", {})
        leak_findings = [f for f in result.findings if "Information Disclosed" in f.get("title", "")]
        assert len(leak_findings) == 1
        assert leak_findings[0]["cwe_id"] == "CWE-200"
        assert leak_findings[0]["severity"] == "low"


class TestHeadersFetchError:
    def test_connection_error_returns_error_result(self, plugin):
        with patch.object(plugin, "_fetch_headers", return_value=_err("Connection refused")):
            result = plugin.run("example.com", {})
        assert result.error is not None
        assert result.findings == []

    def test_https_fallback_to_http_on_error(self, plugin):
        all_headers = {
            "Strict-Transport-Security": "max-age=31536000",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer",
            "Permissions-Policy": "geolocation=()",
        }
        call_count = 0

        def fake_fetch(url):
            nonlocal call_count
            call_count += 1
            if "https" in url:
                return _err("SSL error")
            return _ok(all_headers)

        with patch.object(plugin, "_fetch_headers", side_effect=fake_fetch):
            result = plugin.run("example.com", {})

        assert call_count == 2  # tried https, then fell back to http
        assert result.error is None
