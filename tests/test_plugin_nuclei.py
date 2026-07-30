"""Unit tests for the Nuclei plugin's parse logic."""
import json
from unittest.mock import MagicMock, patch

import pytest

from app.scanner.plugins.nuclei import NucleiPlugin


@pytest.fixture
def plugin():
    return NucleiPlugin()


def _nuclei_line(**kwargs) -> str:
    """Build a minimal nuclei JSON line."""
    base = {
        "template-id": "test-template",
        "info": {
            "name": "Test Finding",
            "severity": "high",
            "description": "Test description",
            "tags": [],
            "classification": {},
        },
        "matched-at": "https://example.com/test",
    }
    base.update(kwargs)
    return json.dumps(base)


class TestNucleiNotInstalled:
    def test_returns_error_when_binary_missing(self, plugin):
        with patch("shutil.which", return_value=None):
            result = plugin.run("example.com", {})
        assert result.error == "nuclei not installed"
        assert result.findings == []


class TestNucleiCvssExtraction:
    def test_cvss_score_extracted(self, plugin):
        line = _nuclei_line(info={
            "name": "CVE Test",
            "severity": "critical",
            "tags": [],
            "classification": {"cvss-score": 9.8},
        })
        mock_proc = MagicMock(stdout=line, returncode=0)
        with patch("shutil.which", return_value="/usr/bin/nuclei"), \
             patch("subprocess.run", return_value=mock_proc):
            result = plugin.run("example.com", {})
        assert result.findings[0]["cvss_score"] == 9.8

    def test_cvss_score_rounded(self, plugin):
        line = _nuclei_line(info={
            "name": "CVE Test",
            "severity": "high",
            "tags": [],
            "classification": {"cvss-score": 7.123456},
        })
        mock_proc = MagicMock(stdout=line, returncode=0)
        with patch("shutil.which", return_value="/usr/bin/nuclei"), \
             patch("subprocess.run", return_value=mock_proc):
            result = plugin.run("example.com", {})
        assert result.findings[0]["cvss_score"] == 7.1

    def test_missing_cvss_is_none(self, plugin):
        line = _nuclei_line()
        mock_proc = MagicMock(stdout=line, returncode=0)
        with patch("shutil.which", return_value="/usr/bin/nuclei"), \
             patch("subprocess.run", return_value=mock_proc):
            result = plugin.run("example.com", {})
        assert result.findings[0]["cvss_score"] is None


class TestNucleiCweExtraction:
    def test_cwe_extracted_from_list(self, plugin):
        line = _nuclei_line(info={
            "name": "Test",
            "severity": "medium",
            "tags": [],
            "classification": {"cwe-id": ["CWE-79", "CWE-80"]},
        })
        mock_proc = MagicMock(stdout=line, returncode=0)
        with patch("shutil.which", return_value="/usr/bin/nuclei"), \
             patch("subprocess.run", return_value=mock_proc):
            result = plugin.run("example.com", {})
        assert result.findings[0]["cwe_id"] == "CWE-79"

    def test_null_cwe_string_ignored(self, plugin):
        line = _nuclei_line(info={
            "name": "Test",
            "severity": "low",
            "tags": [],
            "classification": {"cwe-id": ["null"]},
        })
        mock_proc = MagicMock(stdout=line, returncode=0)
        with patch("shutil.which", return_value="/usr/bin/nuclei"), \
             patch("subprocess.run", return_value=mock_proc):
            result = plugin.run("example.com", {})
        assert result.findings[0]["cwe_id"] is None

    def test_cwe_as_string_handled(self, plugin):
        line = _nuclei_line(info={
            "name": "Test",
            "severity": "medium",
            "tags": [],
            "classification": {"cwe-id": "CWE-200"},
        })
        mock_proc = MagicMock(stdout=line, returncode=0)
        with patch("shutil.which", return_value="/usr/bin/nuclei"), \
             patch("subprocess.run", return_value=mock_proc):
            result = plugin.run("example.com", {})
        assert result.findings[0]["cwe_id"] == "CWE-200"


class TestNucleiOwaspMapping:
    def test_owasp_2021_tag_mapped(self, plugin):
        line = _nuclei_line(info={
            "name": "Test",
            "severity": "high",
            "tags": ["owasp-a03", "xss"],
            "classification": {},
        })
        mock_proc = MagicMock(stdout=line, returncode=0)
        with patch("shutil.which", return_value="/usr/bin/nuclei"), \
             patch("subprocess.run", return_value=mock_proc):
            result = plugin.run("example.com", {})
        assert result.findings[0]["owasp_category"] == "A03:2021 Injection"

    def test_owasp_2017_tag_mapped(self, plugin):
        line = _nuclei_line(info={
            "name": "Test",
            "severity": "high",
            "tags": ["owasp-a6", "misconfig"],
            "classification": {},
        })
        mock_proc = MagicMock(stdout=line, returncode=0)
        with patch("shutil.which", return_value="/usr/bin/nuclei"), \
             patch("subprocess.run", return_value=mock_proc):
            result = plugin.run("example.com", {})
        assert result.findings[0]["owasp_category"] == "A6:2017 Security Misconfiguration"

    def test_no_owasp_tag_is_none(self, plugin):
        line = _nuclei_line(info={
            "name": "Test",
            "severity": "low",
            "tags": ["cve", "rce"],
            "classification": {},
        })
        mock_proc = MagicMock(stdout=line, returncode=0)
        with patch("shutil.which", return_value="/usr/bin/nuclei"), \
             patch("subprocess.run", return_value=mock_proc):
            result = plugin.run("example.com", {})
        assert result.findings[0]["owasp_category"] is None

    def test_tags_as_comma_string_handled(self, plugin):
        line = _nuclei_line(info={
            "name": "Test",
            "severity": "medium",
            "tags": "owasp-a05,misconfig",
            "classification": {},
        })
        mock_proc = MagicMock(stdout=line, returncode=0)
        with patch("shutil.which", return_value="/usr/bin/nuclei"), \
             patch("subprocess.run", return_value=mock_proc):
            result = plugin.run("example.com", {})
        assert result.findings[0]["owasp_category"] == "A05:2021 Security Misconfiguration"


class TestNucleiRemediation:
    def test_remediation_extracted(self, plugin):
        line = _nuclei_line(info={
            "name": "Test",
            "severity": "high",
            "tags": [],
            "classification": {},
            "remediation": "Apply patch X and restart the server.",
        })
        mock_proc = MagicMock(stdout=line, returncode=0)
        with patch("shutil.which", return_value="/usr/bin/nuclei"), \
             patch("subprocess.run", return_value=mock_proc):
            result = plugin.run("example.com", {})
        assert result.findings[0]["remediation"] == "Apply patch X and restart the server."

    def test_null_remediation_is_none(self, plugin):
        line = _nuclei_line(info={
            "name": "Test",
            "severity": "info",
            "tags": [],
            "classification": {},
            "remediation": "null",
        })
        mock_proc = MagicMock(stdout=line, returncode=0)
        with patch("shutil.which", return_value="/usr/bin/nuclei"), \
             patch("subprocess.run", return_value=mock_proc):
            result = plugin.run("example.com", {})
        assert result.findings[0]["remediation"] is None


class TestNucleiMultipleFindings:
    def test_multiple_json_lines_produce_multiple_findings(self, plugin):
        lines = "\n".join([
            _nuclei_line(info={"name": "Finding 1", "severity": "high", "tags": [], "classification": {}}),
            _nuclei_line(info={"name": "Finding 2", "severity": "critical", "tags": [], "classification": {}}),
            "invalid json line",
        ])
        mock_proc = MagicMock(stdout=lines, returncode=0)
        with patch("shutil.which", return_value="/usr/bin/nuclei"), \
             patch("subprocess.run", return_value=mock_proc):
            result = plugin.run("example.com", {})
        assert len(result.findings) == 2

    def test_empty_output_returns_no_findings(self, plugin):
        mock_proc = MagicMock(stdout="", returncode=0)
        with patch("shutil.which", return_value="/usr/bin/nuclei"), \
             patch("subprocess.run", return_value=mock_proc):
            result = plugin.run("example.com", {})
        assert result.findings == []


class TestNucleiTimeout:
    def test_timeout_returns_error(self, plugin):
        import subprocess
        with patch("shutil.which", return_value="/usr/bin/nuclei"), \
             patch("subprocess.run", side_effect=subprocess.TimeoutExpired("nuclei", 300)):
            result = plugin.run("example.com", {})
        assert "timed out" in result.error
