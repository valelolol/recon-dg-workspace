"""Tests for src.web.osv_normalizer — scan-to-report path."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from src.web.osv_normalizer import normalize, severity_label


# ── fixtures ───────────────────────────────────────────────────────────────────

def _write(tmp: Path, obj: object) -> Path:
    p = tmp / "osv.json"
    p.write_text(json.dumps(obj), encoding="utf-8")
    return p


def _clean_scan() -> dict:
    """Return a minimal OSV-Scanner v2.x JSON for a clean scan."""
    return {"results": [], "experimental_config": {"licenses": {"summary": False}}}


def _two_vulns() -> dict:
    """Return OSV-Scanner JSON with 2 grouped vulnerabilities."""
    return {
        "results": [
            {
                "packages": [
                    {
                        "package": {"name": "numpy", "version": "1.24.0", "ecosystem": "PyPI"},
                        "groups": [
                            {
                                "ids": ["CVE-2024-22195", "GHSA-abc123"],
                                "aliases": ["GHSA-abc123", "CVE-2024-22195"],
                                "max_severity": 7.5,
                                "published": "2024-03-15T00:00:00Z",
                                "vulnerability_spec": "numpy < 1.24.1 allows RCE via crafted array",
                                "fixed_versions": ["1.24.1"],
                            }
                        ],
                    },
                    {
                        "package": {"name": "requests", "version": "2.31.0", "ecosystem": "PyPI"},
                        "groups": [
                            {
                                "ids": ["CVE-2024-35195"],
                                "aliases": ["CVE-2024-35195"],
                                "max_severity": 9.8,
                                "published": "2024-04-01T00:00:00Z",
                                "vulnerability_spec": "requests < 2.32.0 SSRF via redirect",
                                "fixed_versions": ["2.32.0"],
                            }
                        ],
                    },
                ]
            }
        ],
        "experimental_config": {"licenses": {"summary": False}},
    }


def _aliases_same_vuln() -> dict:
    """Two groups referencing the same vulnerability via different IDs (aliases)."""
    return {
        "results": [
            {
                "packages": [
                    {
                        "package": {"name": "flask", "version": "3.0.0", "ecosystem": "PyPI"},
                        "groups": [
                            {
                                "ids": ["CVE-2024-12345"],
                                "aliases": ["GHSA-flask-abc"],
                                "max_severity": 5.0,
                                "fixed_versions": ["3.0.1"],
                            },
                            {
                                "ids": ["GHSA-flask-abc"],
                                "aliases": ["CVE-2024-12345"],
                                "max_severity": 7.0,
                                "fixed_versions": ["3.0.2"],
                            },
                        ],
                    }
                ]
            }
        ],
        "experimental_config": {"licenses": {"summary": False}},
    }


def _malformed_missing_ids() -> dict:
    """Groups without 'ids' — should be skipped."""
    return {
        "results": [
            {
                "packages": [
                    {
                        "package": {"name": "pkg", "version": "1.0", "ecosystem": "PyPI"},
                        "groups": [
                            {"aliases": ["GHSA-xxx"], "max_severity": 6.0},
                        ],
                    }
                ]
            }
        ],
        "experimental_config": {"licenses": {"summary": False}},
    }


# ── tests ──────────────────────────────────────────────────────────────────────

class TestCleanScan:
    def test_empty_report_structure(self, tmp_path: Path) -> None:
        report = normalize(str(_write(tmp_path, _clean_scan())))
        assert report["findings"] == []
        assert report["findings_count"] == 0
        assert report["high_severity_count"] == 0
        assert report["total_unique_vulnerabilities"] == 0
        assert report["risk"]["status"] == "unavailable"
        assert report["risk"]["score"] is None
        assert report["summary"].startswith("OSV-Scanner scan")

    def test_no_fabricated_edges(self, tmp_path: Path) -> None:
        report = normalize(str(_write(tmp_path, _clean_scan())))
        # Must not invent PHEI scores or edges when topology unavailable
        assert report["risk"]["status"] == "unavailable"
        assert report["risk"]["score"] is None


class TestFindingsSchema:
    def test_dashboard_fields_present(self, tmp_path: Path) -> None:
        report = normalize(str(_write(tmp_path, _two_vulns())))
        assert len(report["findings"]) == 2
        for f in report["findings"]:
            assert "package_name" in f
            assert "version" in f
            assert "severity_score" in f
            assert "vulnerability_id" in f
            assert "aliases" in f
            assert "ecosystem" in f
            assert "published" in f
            assert "vulnerability_spec" in f
            assert "fixed_versions" in f
            assert "ai_explanations" in f
            assert "risk_level" not in f  # no categorical label

    def test_severity_score_is_numeric(self, tmp_path: Path) -> None:
        report = normalize(str(_write(tmp_path, _two_vulns())))
        for f in report["findings"]:
            if f["severity_score"] is not None:
                assert isinstance(f["severity_score"], float)

    def test_no_categorical_severity_labels(self, tmp_path: Path) -> None:
        report = normalize(str(_write(tmp_path, _two_vulns())))
        for f in report["findings"]:
            assert "risk_level" not in f
            assert "severity" not in f  # old field name gone


class TestGrouping:
    def test_aliases_merged_one_finding(self, tmp_path: Path) -> None:
        """Two groups with overlapping IDs → exactly one finding with merged aliases."""
        report = normalize(str(_write(tmp_path, _aliases_same_vuln())))
        assert len(report["findings"]) == 1
        f = report["findings"][0]
        assert f["vulnerability_id"] == "CVE-2024-12345"
        assert "GHSA-flask-abc" in f["aliases"]
        assert "CVE-2024-12345" in f["aliases"]
        # highest severity wins
        assert f["severity_score"] == 7.0
        assert f["fixed_versions"] == ["3.0.2"]

    def test_empty_ids_skipped(self, tmp_path: Path) -> None:
        report = normalize(str(_write(tmp_path, _malformed_missing_ids())))
        assert len(report["findings"]) == 0


class TestSeverityLabel:
    def test_critical(self) -> None:
        assert severity_label(9.0) == "critical"
        assert severity_label(9.9) == "critical"

    def test_high(self) -> None:
        assert severity_label(7.0) == "high"
        assert severity_label(8.9) == "high"

    def test_medium(self) -> None:
        assert severity_label(4.0) == "medium"
        assert severity_label(6.9) == "medium"

    def test_low(self) -> None:
        assert severity_label(0.0) == "low"
        assert severity_label(3.9) == "low"


class TestReportJsonValid:
    def test_returned_dict_has_schema(self, tmp_path: Path) -> None:
        report = normalize(str(_write(tmp_path, _two_vulns())))
        assert "findings" in report
        assert "risk" in report
        assert isinstance(report["risk"], dict)
        assert "vulnerability_id" in report["findings"][0]
