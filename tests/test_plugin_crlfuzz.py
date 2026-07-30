"""Unit tests for the CRLFuzz plugin."""
import uuid
from unittest.mock import MagicMock, patch

import pytest

from app.scanner.plugins.crlfuzz import CrlfuzzPlugin


@pytest.fixture
def plugin():
    return CrlfuzzPlugin()


class TestCrlfuzzNotInstalled:
    def test_returns_error_when_binary_missing(self, plugin):
        with patch("shutil.which", return_value=None):
            result = plugin.run("example.com", {})
        assert result.error == "crlfuzz not installed"
        assert result.findings == []


class TestCrlfuzzNoVulnerabilities:
    def test_empty_output_returns_info_finding(self, plugin):
        mock_proc = MagicMock(stdout="", returncode=0)
        with patch("shutil.which", return_value="/usr/bin/crlfuzz"), \
             patch("subprocess.run", return_value=mock_proc):
            result = plugin.run("example.com", {})
        assert result.error is None
        assert len(result.findings) == 1
        f = result.findings[0]
        assert f["severity"] == "info"
        assert "Not Detected" in f["title"]
        assert f["cwe_id"] == "CWE-93"
        assert f["owasp_category"] == "A03:2021 Injection"

    def test_non_vul_output_returns_info_finding(self, plugin):
        mock_proc = MagicMock(stdout="Scanning...\nDone.", returncode=0)
        with patch("shutil.which", return_value="/usr/bin/crlfuzz"), \
             patch("subprocess.run", return_value=mock_proc):
            result = plugin.run("example.com", {})
        assert len(result.findings) == 1
        assert result.findings[0]["severity"] == "info"


class TestCrlfuzzVulFound:
    def test_vul_prefix_line_creates_high_finding(self, plugin):
        output = "[VUL!] https://example.com/?q=%0d%0aX-Evil:injected"
        mock_proc = MagicMock(stdout=output, returncode=0)
        with patch("shutil.which", return_value="/usr/bin/crlfuzz"), \
             patch("subprocess.run", return_value=mock_proc):
            result = plugin.run("example.com", {})
        assert len(result.findings) == 1
        f = result.findings[0]
        assert f["severity"] == "high"
        assert f["title"] == "CRLF Injection Detected"
        assert f["cvss_score"] == 7.2
        assert f["cwe_id"] == "CWE-93"
        assert f["owasp_category"] == "A03:2021 Injection"
        assert "https://example.com" in f["evidence"]["vulnerable_url"]

    def test_raw_url_line_creates_finding(self, plugin):
        output = "https://example.com/path?x=%0d%0a"
        mock_proc = MagicMock(stdout=output, returncode=0)
        with patch("shutil.which", return_value="/usr/bin/crlfuzz"), \
             patch("subprocess.run", return_value=mock_proc):
            result = plugin.run("example.com", {})
        assert len(result.findings) == 1
        assert result.findings[0]["severity"] == "high"

    def test_multiple_vul_urls_produce_multiple_findings(self, plugin):
        output = (
            "[VUL!] https://example.com/a?q=%0d%0a\n"
            "[VUL!] https://example.com/b?p=%0d%0a"
        )
        mock_proc = MagicMock(stdout=output, returncode=0)
        with patch("shutil.which", return_value="/usr/bin/crlfuzz"), \
             patch("subprocess.run", return_value=mock_proc):
            result = plugin.run("example.com", {})
        assert len(result.findings) == 2
        assert result.metadata["vulnerable_count"] == 2

    def test_remediation_is_present(self, plugin):
        output = "[VUL!] https://example.com/?x=%0d%0a"
        mock_proc = MagicMock(stdout=output, returncode=0)
        with patch("shutil.which", return_value="/usr/bin/crlfuzz"), \
             patch("subprocess.run", return_value=mock_proc):
            result = plugin.run("example.com", {})
        assert result.findings[0]["remediation"] is not None
        assert len(result.findings[0]["remediation"]) > 10


class TestCrlfuzzTimeout:
    def test_timeout_returns_error(self, plugin):
        import subprocess
        with patch("shutil.which", return_value="/usr/bin/crlfuzz"), \
             patch("subprocess.run", side_effect=subprocess.TimeoutExpired("crlfuzz", 180)):
            result = plugin.run("example.com", {})
        assert "timed out" in result.error
        assert result.findings == []


class TestCrlfuzzTargetNormalization:
    def test_adds_https_prefix_when_missing(self, plugin):
        captured_cmd = []

        def fake_run(cmd, **kwargs):
            captured_cmd.extend(cmd)
            return MagicMock(stdout="", returncode=0)

        with patch("shutil.which", return_value="/usr/bin/crlfuzz"), \
             patch("subprocess.run", side_effect=fake_run):
            plugin.run("example.com", {})

        assert "https://example.com" in captured_cmd

    def test_preserves_existing_http_prefix(self, plugin):
        captured_cmd = []

        def fake_run(cmd, **kwargs):
            captured_cmd.extend(cmd)
            return MagicMock(stdout="", returncode=0)

        with patch("shutil.which", return_value="/usr/bin/crlfuzz"), \
             patch("subprocess.run", side_effect=fake_run):
            plugin.run("http://example.com", {})

        assert "http://example.com" in captured_cmd
