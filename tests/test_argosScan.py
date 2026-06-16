"""
ArgosScan - Unit Tests
Run with: python -m pytest tests/ -v
"""

import sys
from pathlib import Path

# Ensure project root is on path
sys.path.insert(0, str(Path(__file__).parent.parent))

import json
import pytest

from utils.validator import validate_target
from utils.cache import cache_get, cache_set, cache_clear
from reporters.cli_reporter import CLIReporter
from reporters.json_reporter import JSONReporter
from reporters.html_reporter import HTMLReporter


# ─────────────────────────────────────────────────────────────
# Validator tests
# ─────────────────────────────────────────────────────────────

class TestValidator:
    def test_valid_domain(self):
        assert validate_target("example.com") is True

    def test_valid_subdomain(self):
        assert validate_target("sub.example.co.uk") is True

    def test_valid_ipv4(self):
        assert validate_target("192.168.1.1") is True

    def test_valid_cidr(self):
        assert validate_target("10.0.0.0/24") is True

    def test_localhost(self):
        assert validate_target("localhost") is True

    def test_empty_string(self):
        assert validate_target("") is False

    def test_invalid_target(self):
        assert validate_target("not_a_target!!") is False

    def test_none(self):
        assert validate_target(None) is False  # type: ignore


# ─────────────────────────────────────────────────────────────
# Cache tests
# ─────────────────────────────────────────────────────────────

class TestCache:
    def setup_method(self):
        cache_clear()

    def teardown_method(self):
        cache_clear()

    def test_set_and_get(self):
        cache_set("test_key", {"data": 42})
        result = cache_get("test_key")
        assert result == {"data": 42}

    def test_miss_returns_none(self):
        assert cache_get("nonexistent") is None

    def test_expired_returns_none(self):
        cache_set("expiring", "value", ttl=-1)  # already expired
        assert cache_get("expiring") is None

    def test_overwrite(self):
        cache_set("k", "old")
        cache_set("k", "new")
        assert cache_get("k") == "new"


# ─────────────────────────────────────────────────────────────
# Reporter tests
# ─────────────────────────────────────────────────────────────

SAMPLE_RESULTS = {
    "target": "example.com",
    "timestamp": "2024-01-01T00:00:00+00:00",
    "scan_params": {"ports": "1-1024", "speed": "normal"},
    "open_ports": [
        {"port": 80, "protocol": "tcp", "state": "open", "name": "http",
         "product": "nginx", "version": "1.18.0", "extrainfo": "", "cpe": ""}
    ],
    "services": [],
    "vulnerabilities": [
        {
            "cve_id": "CVE-2021-12345",
            "description": "A test vulnerability.",
            "severity": "HIGH",
            "cvss_score": 7.5,
            "affected_product": "nginx",
            "affected_version": "1.18.0",
            "port": 80,
            "published": "2021-01-01T00:00:00",
            "url": "https://nvd.nist.gov/vuln/detail/CVE-2021-12345",
            "remediation": "Update nginx.",
        }
    ],
    "ssl_analysis": None,
    "summary": {
        "total": 1, "critical": 0, "high": 1,
        "medium": 0, "low": 0, "unknown": 0, "risk_score": 20.0
    }
}


class TestJSONReporter:
    def test_generates_valid_json(self, tmp_path):
        out = str(tmp_path / "test.json")
        JSONReporter(SAMPLE_RESULTS).generate(out)
        with open(out) as f:
            data = json.load(f)
        assert data["target"] == "example.com"
        assert data["summary"]["total"] == 1

    def test_file_created(self, tmp_path):
        out = str(tmp_path / "out.json")
        JSONReporter(SAMPLE_RESULTS).generate(out)
        assert Path(out).exists()


class TestHTMLReporter:
    def test_generates_html(self, tmp_path):
        out = str(tmp_path / "test.html")
        HTMLReporter(SAMPLE_RESULTS).generate(out)
        content = Path(out).read_text()
        assert "ArgosScan" in content
        assert "CVE-2021-12345" in content
        assert "nginx" in content

    def test_contains_summary_numbers(self, tmp_path):
        out = str(tmp_path / "test.html")
        HTMLReporter(SAMPLE_RESULTS).generate(out)
        content = Path(out).read_text()
        assert "7.5" in content   # CVSS score


class TestCLIReporter:
    def test_runs_without_error(self, capsys):
        CLIReporter(SAMPLE_RESULTS).print_report()
        captured = capsys.readouterr()
        assert "example.com" in captured.out
        assert "CVE-2021-12345" in captured.out

    def test_empty_vulns(self, capsys):
        results = dict(SAMPLE_RESULTS)
        results["vulnerabilities"] = []
        results["summary"] = {**SAMPLE_RESULTS["summary"], "total": 0}
        CLIReporter(results).print_report()
        captured = capsys.readouterr()
        assert "No vulnerabilities" in captured.out


# ─────────────────────────────────────────────────────────────
# Summary builder test (via argosScan entrypoint)
# ─────────────────────────────────────────────────────────────

class TestSummaryBuilder:
    def test_risk_score_caps_at_100(self):
        from argosScan import _build_summary
        vulns = [{"severity": "CRITICAL"}] * 10
        s = _build_summary(vulns)
        assert s["risk_score"] <= 100

    def test_empty_vulns(self):
        from argosScan import _build_summary
        s = _build_summary([])
        assert s["total"] == 0
        assert s["risk_score"] == 0.0
