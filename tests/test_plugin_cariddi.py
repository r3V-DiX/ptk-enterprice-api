"""Unit tests for the Cariddi plugin."""
import json
from unittest.mock import MagicMock, patch

import pytest

from app.scanner.plugins.cariddi import CariddiPlugin, _secret_severity


@pytest.fixture
def plugin():
    return CariddiPlugin()


class TestSecretSeverity:
    def test_password_is_critical(self):
        assert _secret_severity("password") == "critical"

    def test_aws_is_critical(self):
        assert _secret_severity("AWS_SECRET_ACCESS_KEY") == "critical"

    def test_api_key_is_high(self):
        assert _secret_severity("api_key") == "high"

    def test_token_is_high(self):
        assert _secret_severity("auth_token") == "high"

    def test_unknown_defaults_to_medium(self):
        assert _secret_severity("some_random_field") == "medium"


class TestCariddiNotInstalled:
    def test_returns_error_when_binary_missing(self, plugin):
        with patch("shutil.which", return_value=None):
            result = plugin.run("example.com", {})
        assert result.error == "cariddi not installed"
        assert result.findings == []


class TestCariddiEmptyOutput:
    def test_empty_output_returns_info_finding(self, plugin):
        mock_proc = MagicMock(stdout="", returncode=0)
        with patch("shutil.which", return_value="/usr/bin/cariddi"), \
             patch("subprocess.run", return_value=mock_proc):
            result = plugin.run("example.com", {})
        assert result.error is None
        assert len(result.findings) == 1
        f = result.findings[0]
        assert f["severity"] == "info"
        assert "No Results" in f["title"]


class TestCariddiEndpoints:
    def test_json_url_field_parsed_as_endpoint(self, plugin):
        line = json.dumps({"url": "https://example.com/api/v1/users", "secrets": []})
        mock_proc = MagicMock(stdout=line, returncode=0)
        with patch("shutil.which", return_value="/usr/bin/cariddi"), \
             patch("subprocess.run", return_value=mock_proc):
            result = plugin.run("example.com", {})
        assert len(result.findings) == 1
        f = result.findings[0]
        assert "Endpoint" in f["title"]
        assert f["severity"] == "info"
        assert "https://example.com/api/v1/users" in f["evidence"]["endpoints"]

    def test_plain_url_line_parsed_as_endpoint(self, plugin):
        mock_proc = MagicMock(stdout="https://example.com/admin", returncode=0)
        with patch("shutil.which", return_value="/usr/bin/cariddi"), \
             patch("subprocess.run", return_value=mock_proc):
            result = plugin.run("example.com", {})
        f = result.findings[0]
        assert "https://example.com/admin" in f["evidence"]["endpoints"]

    def test_multiple_endpoints_deduped(self, plugin):
        lines = "\n".join([
            json.dumps({"url": "https://example.com/a"}),
            json.dumps({"url": "https://example.com/a"}),  # duplicate
            json.dumps({"url": "https://example.com/b"}),
        ])
        mock_proc = MagicMock(stdout=lines, returncode=0)
        with patch("shutil.which", return_value="/usr/bin/cariddi"), \
             patch("subprocess.run", return_value=mock_proc):
            result = plugin.run("example.com", {})
        f = result.findings[0]
        assert f["evidence"]["total"] == 2  # deduplicated

    def test_endpoint_finding_has_correct_cwe_and_owasp(self, plugin):
        line = json.dumps({"url": "https://example.com/api"})
        mock_proc = MagicMock(stdout=line, returncode=0)
        with patch("shutil.which", return_value="/usr/bin/cariddi"), \
             patch("subprocess.run", return_value=mock_proc):
            result = plugin.run("example.com", {})
        f = result.findings[0]
        assert f["cwe_id"] == "CWE-200"
        assert f["owasp_category"] == "A05:2021 Security Misconfiguration"


class TestCariddiSecrets:
    def test_password_secret_is_critical(self, plugin):
        line = json.dumps({
            "url": "https://example.com/",
            "secrets": [{"name": "password", "match": "password=s3cr3t", "url": "https://example.com/"}]
        })
        mock_proc = MagicMock(stdout=line, returncode=0)
        with patch("shutil.which", return_value="/usr/bin/cariddi"), \
             patch("subprocess.run", return_value=mock_proc):
            result = plugin.run("example.com", {})

        secret_findings = [f for f in result.findings if "Sensitive Data" in f["title"]]
        assert len(secret_findings) == 1
        f = secret_findings[0]
        assert f["severity"] == "critical"
        assert f["cvss_score"] == 9.1
        assert f["cwe_id"] == "CWE-312"
        assert f["owasp_category"] == "A02:2021 Cryptographic Failures"

    def test_api_key_secret_is_high(self, plugin):
        line = json.dumps({
            "url": "https://example.com/",
            "secrets": [{"name": "api_key", "match": "api_key=abc123"}]
        })
        mock_proc = MagicMock(stdout=line, returncode=0)
        with patch("shutil.which", return_value="/usr/bin/cariddi"), \
             patch("subprocess.run", return_value=mock_proc):
            result = plugin.run("example.com", {})

        secret_findings = [f for f in result.findings if "Sensitive Data" in f["title"]]
        assert secret_findings[0]["severity"] == "high"
        assert secret_findings[0]["cvss_score"] == 7.5

    def test_secret_has_remediation(self, plugin):
        line = json.dumps({
            "url": "https://example.com/",
            "secrets": [{"name": "token", "match": "token=xyz"}]
        })
        mock_proc = MagicMock(stdout=line, returncode=0)
        with patch("shutil.which", return_value="/usr/bin/cariddi"), \
             patch("subprocess.run", return_value=mock_proc):
            result = plugin.run("example.com", {})

        secret_findings = [f for f in result.findings if "Sensitive Data" in f["title"]]
        assert secret_findings[0]["remediation"] is not None

    def test_multiple_secret_types_produce_separate_findings(self, plugin):
        line = json.dumps({
            "url": "https://example.com/",
            "secrets": [
                {"name": "api_key", "match": "key=abc"},
                {"name": "password", "match": "pass=xyz"},
            ]
        })
        mock_proc = MagicMock(stdout=line, returncode=0)
        with patch("shutil.which", return_value="/usr/bin/cariddi"), \
             patch("subprocess.run", return_value=mock_proc):
            result = plugin.run("example.com", {})

        secret_findings = [f for f in result.findings if "Sensitive Data" in f["title"]]
        assert len(secret_findings) == 2

    def test_evidence_truncated_at_10_occurrences(self, plugin):
        secrets = [{"name": "token", "match": f"token=x{i}", "url": "https://example.com/"} for i in range(20)]
        line = json.dumps({"url": "https://example.com/", "secrets": secrets})
        mock_proc = MagicMock(stdout=line, returncode=0)
        with patch("shutil.which", return_value="/usr/bin/cariddi"), \
             patch("subprocess.run", return_value=mock_proc):
            result = plugin.run("example.com", {})

        secret_findings = [f for f in result.findings if "Sensitive Data" in f["title"]]
        assert len(secret_findings[0]["evidence"]["occurrences"]) <= 10
        assert secret_findings[0]["evidence"]["total"] == 20


class TestCariddiCombined:
    def test_both_endpoints_and_secrets_in_one_run(self, plugin):
        lines = "\n".join([
            json.dumps({"url": "https://example.com/admin"}),
            json.dumps({
                "url": "https://example.com/",
                "secrets": [{"name": "aws", "match": "AKIA...", "url": "https://example.com/"}]
            }),
        ])
        mock_proc = MagicMock(stdout=lines, returncode=0)
        with patch("shutil.which", return_value="/usr/bin/cariddi"), \
             patch("subprocess.run", return_value=mock_proc):
            result = plugin.run("example.com", {})

        titles = [f["title"] for f in result.findings]
        assert any("Endpoint" in t for t in titles)
        assert any("Sensitive Data" in t for t in titles)

    def test_nothing_notable_finding_when_no_secrets_or_endpoints(self, plugin):
        mock_proc = MagicMock(stdout='{"irrelevant": "data"}', returncode=0)
        with patch("shutil.which", return_value="/usr/bin/cariddi"), \
             patch("subprocess.run", return_value=mock_proc):
            result = plugin.run("example.com", {})

        assert len(result.findings) == 1
        assert "Nothing Notable" in result.findings[0]["title"]


class TestCariddiTimeout:
    def test_timeout_returns_error(self, plugin):
        import subprocess
        with patch("shutil.which", return_value="/usr/bin/cariddi"), \
             patch("subprocess.run", side_effect=subprocess.TimeoutExpired("cariddi", 300)):
            result = plugin.run("example.com", {})
        assert "timed out" in result.error
        assert result.findings == []
