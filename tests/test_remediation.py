"""Deterministic tests for evidence-grounded remediation planning and
after-scan verification.

These exercise :func:`build_remediation_plan` and :func:`verify_remediation`
in ``src/agent/agent.py`` plus the ``after_scan_report`` pipeline parameter
in ``src/agent/pipeline.py``.  They are pure: no OSV-Scanner binary, no
network, no enrichment — only the checked-in OSV-Scanner 2.6.0-shape fixture
(``tests/data/osv-scanner.json``) and the normalised :class:`ScanResult`.

The contract these tests pin down (the December "severity honesty" rule):

* The plan is built from *normalized scanner evidence only* — one item per
  baseline finding, with the scanner-reported ``fixed_versions`` taken
  verbatim (never "latest"/"best-ified").
* Numeric severity is left ``None`` (unknown) in every plan item; the CVSS
  *vector strings* are preserved as evidence but no numeric score and no
  high/low category is ever computed or implied.
* Without a user-supplied after scan, verification is ``not_run`` and makes
  **no** resolution claim.  With an after scan, a baseline finding is counted
  ``resolved`` only when its ``(package, version, vulnerability_id)`` key is
  *absent* from the after scan; an unchanged finding is **never** counted as
  fixed; the same package+advisory at a *different* version is flagged
  ``regressed``.
* An unusable / missing after report fails closed to ``not_run`` and makes no
  resolution claim; the baseline report is preserved untouched.

Fixture ground-truth (5 findings, 4 packages, each with a scanner-reported
``fixed`` event):

    PyYAML 5.1  GHSA-p6qc-x272-q48w  fixed 5.2b1   (severity: null)
    PyYAML 5.1  GHSA-757q-h92x-p438  fixed 5.4.1   (CVSS_V3)
    requests 2.28.0 GHSA-394q-gx7c-w5v9  fixed 2.28.1 (CVSS_V3 + CVSS_V4)
    urllib3 1.21.1  GHSA-93h9-824q-92x3  fixed 1.26.0 (CVSS_V3)
    setuptools 58.0.0 GHSA-994q-cg23-2p48 fixed 60.0.0 (CVSS_V3 + CVSS_V4)
"""
from __future__ import annotations

import copy
import json
import os
import tempfile
import unittest
from typing import Any

from src.agent.agent import (
    EvidenceTrail,
    build_remediation_plan,
    verify_remediation,
)
from src.agent.pipeline import investigate_from_json
from src.agent.normalizer import normalize_scan, ScanResult

FIXTURE_JSON = os.path.join(os.path.dirname(__file__), "data", "osv-scanner.json")


def _load_osv() -> dict[str, Any]:
    with open(FIXTURE_JSON, "r", encoding="utf-8") as f:
        return json.load(f)


def _write_raw(text: str, suffix: str = ".json") -> str:
    """Write raw (possibly non-JSON) text to a temp file; returns its path.
    Used to exercise the malformed/missing-after-report fail-closed paths."""
    with tempfile.NamedTemporaryFile(
        "w", suffix=suffix, delete=False, encoding="utf-8",
    ) as f:
        f.write(text)
        path = f.name
    return path


def _write_json(payload: dict[str, Any], name: str) -> str:
    """Write a JSON-serialisable ``payload`` to a temp file; returns path."""
    return _write_raw(json.dumps(payload), name)


# ---------------------------------------------------------------------------
# Helpers for building after-scans against the fixture
# ---------------------------------------------------------------------------
def _drop_packages(raw: dict[str, Any], names: set[str]) -> dict[str, Any]:
    """Return a copy of ``raw`` with packages named in ``names`` removed
    (the 'upgraded away' / resolved case)."""
    out = copy.deepcopy(raw)
    for result in out["results"]:
        result["packages"] = [
            p for p in result["packages"] if p["package"]["name"] not in names
        ]
    return out


def _change_package_version(
    raw: dict[str, Any], name: str, old_ver: str, new_ver: str,
) -> dict[str, Any]:
    """Return a copy of ``raw`` where ``name`` at ``old_ver`` is bumped to
    ``new_ver`` (the regressed case: same advisory at a different version).
    The package's vulnerabilities (and therefore advisory IDs) are preserved,
    so the finding keys survive while the version changes."""
    out = copy.deepcopy(raw)
    for result in out["results"]:
        for p in result["packages"]:
            if p["package"]["name"] == name and p["package"]["version"] == old_ver:
                p["package"]["version"] = new_ver
    return out


class TestBuildRemediationPlan(unittest.TestCase):
    """``build_remediation_plan`` — one item per baseline finding, grounded
    only in normalised scanner evidence."""

    def test_one_item_per_baseline_finding(self) -> None:
        scan = normalize_scan(_load_osv())
        plan = build_remediation_plan(scan)
        self.assertEqual(scan.count(), 5)
        self.assertEqual(plan["findings_count"], 5)
        self.assertEqual(len(plan["items"]), 5)

    def test_fixed_versions_are_verbatim_from_scanner(self) -> None:
        scan = normalize_scan(_load_osv())
        plan = build_remediation_plan(scan)
        by_adv = {i["vulnerability_id"]: i["fixed_versions"]
                  for i in plan["items"]}
        self.assertEqual(by_adv["GHSA-p6qc-x272-q48w"], ["5.2b1"])
        self.assertEqual(by_adv["GHSA-757q-h92x-p438"], ["5.4.1"])
        self.assertEqual(by_adv["GHSA-394q-gx7c-w5v9"], ["2.28.1"])
        self.assertEqual(by_adv["GHSA-93h9-824q-92x3"], ["1.26.0"])
        self.assertEqual(by_adv["GHSA-994q-cg23-2p48"], ["60.0.0"])

    def test_has_fixed_version_flags_present_and_absent(self) -> None:
        scan = normalize_scan(_load_osv())
        plan = build_remediation_plan(scan)
        for i in plan["items"]:
            self.assertTrue(i["has_fixed_version"])
            self.assertTrue(i["fixed_versions"])

    def test_no_invented_version_when_scanner_gives_none(self) -> None:
        """A finding with no ``fixed`` event must carry an empty
        ``fixed_versions`` tuple and a 'cannot assert' action — never a
        guessed 'latest'/'best' version."""
        raw = copy.deepcopy(_load_osv())
        # Strip every ``fixed`` event from the fixture.
        for result in raw["results"]:
            for p in result["packages"]:
                for vuln in p.get("vulnerabilities", []):
                    for a in vuln.get("affected", []):
                        for r in a.get("ranges", []):
                            for e in r.get("events", []):
                                e.pop("fixed", None)
        scan = normalize_scan(raw)
        plan = build_remediation_plan(scan)
        for i in plan["items"]:
            self.assertEqual(i["fixed_versions"], [])
            self.assertFalse(i["has_fixed_version"])
            # The action must not invent a target version.
            self.assertNotIn("latest", i["recommended_action"].lower())
            self.assertNotIn("best", i["recommended_action"].lower())

    def test_action_names_scanner_fixed_version(self) -> None:
        """When a fixed version exists the action names it explicitly."""
        scan = normalize_scan(_load_osv())
        plan = build_remediation_plan(scan)
        item = next(i for i in plan["items"]
                    if i["vulnerability_id"] == "GHSA-p6qc-x272-q48w")
        self.assertIn("5.2b1", item["recommended_action"])
        self.assertIn("PyYAML", item["recommended_action"])

    def test_severity_left_null_never_numeric(self) -> None:
        """The severity-honesty rule: numeric severity is ``None`` for every
        item — the plan never computes or implies a numeric CVSS score."""
        scan = normalize_scan(_load_osv())
        plan = build_remediation_plan(scan)
        for i in plan["items"]:
            self.assertIsNone(i["severity_score"],
                             "severity_score must be None (unknown)")

    def test_vectors_preserved_but_no_high_low_category(self) -> None:
        """CVSS *vector strings* are preserved as evidence, but no high/low
        category string is ever asserted from them."""
        scan = normalize_scan(_load_osv())
        plan = build_remediation_plan(scan)
        item = next(i for i in plan["items"]
                    if i["vulnerability_id"] == "GHSA-757q-h92x-p438")
        # This finding carries a real CVSS_V3 vector string.
        self.assertIsNotNone(item["severity_vector"])
        self.assertEqual(len(item["severity_vectors"]), 1)
        self.assertIn("CVSS:3.1/", item["severity_vectors"][0])
        # A multi-scheme finding (CVSS_V3 + CVSS_V4) preserves both vectors.
        item_multi = next(i for i in plan["items"]
                          if i["vulnerability_id"] == "GHSA-394q-gx7c-w5v9")
        self.assertEqual(len(item_multi["severity_vectors"]), 2)
        self.assertEqual(list(item_multi["severity_types"]),
                         ["CVSS_V3", "CVSS_V4"])
        # No high/low category is implied anywhere in the item.
        for i in plan["items"]:
            self.assertNotIn("high", i["severity_types"])
            self.assertNotIn("low", i["severity_types"])

    def test_null_severity_finding_stays_null_with_no_vector(self) -> None:
        """The PyYAML null-severity finding carries no vector and no score."""
        scan = normalize_scan(_load_osv())
        plan = build_remediation_plan(scan)
        item = next(i for i in plan["items"]
                    if i["vulnerability_id"] == "GHSA-p6qc-x272-q48w")
        self.assertIsNone(item["severity_score"])
        self.assertIsNone(item["severity_vector"])
        self.assertEqual(item["severity_vectors"], [])

    def test_item_carries_grounding_fields(self) -> None:
        """Each item must carry the advisory, package, installed version,
        and affected range so a reviewer can trace it to the scan."""
        scan = normalize_scan(_load_osv())
        plan = build_remediation_plan(scan)
        for i in plan["items"]:
            self.assertTrue(i["vulnerability_id"])
            self.assertTrue(i["package_name"])
            self.assertTrue(i["installed_version"])
            self.assertIsInstance(i["aliases"], list)
            self.assertIsInstance(i["affected_range"], str)


class TestVerifyRemediation(unittest.TestCase):
    """``verify_remediation`` — reconciles a plan against an after scan with
    strict severity/reconciliation honesty."""

    def _before(self) -> "ScanResult":
        return normalize_scan(_load_osv())

    def test_no_after_scan_is_not_run_with_no_resolution_claim(self) -> None:
        scan = self._before()
        plan = build_remediation_plan(scan)
        v = verify_remediation(scan, plan, after_scan=None)
        self.assertEqual(v["status"], "not_run")
        self.assertFalse(v["resolution_claim"])
        self.assertEqual(v["summary"],
                         {"new_count": 0, "resolved_count": 0,
                          "unchanged_count": 0, "regression_count": 0})
        self.assertEqual(v["resolved"], [])
        self.assertEqual(v["unchanged"], [])
        self.assertEqual(v["regressed"], [])
        self.assertEqual(v["new"], [])
        # An auditable evidence entry is still present even with no after scan.
        self.assertIn("evidence", v)
        self.assertEqual(
            v["evidence"]["steps"][0]["tool"], "verify_remediation")

    def test_unchanged_findings_never_counted_as_resolved(self) -> None:
        """Identical before/after scan: everything persists, nothing is fixed."""
        before = self._before()
        plan = build_remediation_plan(before)
        after = self._before()
        v = verify_remediation(before, plan, after)
        self.assertEqual(v["status"], "verified")
        self.assertTrue(v["resolution_claim"])
        self.assertEqual(v["summary"]["resolved_count"], 0)
        self.assertEqual(v["summary"]["unchanged_count"], 5)
        self.assertEqual(v["summary"]["new_count"], 0)
        self.assertEqual(v["summary"]["regression_count"], 0)

    def test_resolved_when_baseline_key_absent(self) -> None:
        """Drop PyYAML entirely from the after scan -> both PyYAML findings
        resolved; the others persist unchanged."""
        before = self._before()
        plan = build_remediation_plan(before)
        after = normalize_scan(_drop_packages(_load_osv(), {"PyYAML"}))
        v = verify_remediation(before, plan, after)
        self.assertEqual(v["summary"]["resolved_count"], 2)
        self.assertEqual(v["summary"]["unchanged_count"], 3)
        resolved = {r["vulnerability_id"] for r in v["resolved"]}
        self.assertEqual(resolved,
                         {"GHSA-p6qc-x272-q48w", "GHSA-757q-h92x-p438"})
        unchanged = {u["vulnerability_id"] for u in v["unchanged"]}
        self.assertEqual(unchanged,
                         {"GHSA-394q-gx7c-w5v9", "GHSA-93h9-824q-92x3",
                          "GHSA-994q-cg23-2p48"})

    def test_regressed_when_advisory_persists_at_different_version(self) -> None:
        """requests 2.28.0 -> 2.31.0 (same advisory, different installed
        version) must be flagged regressed, *never* resolved."""
        before = self._before()
        plan = build_remediation_plan(before)
        after = normalize_scan(
            _change_package_version(_load_osv(), "requests", "2.28.0", "2.31.0"))
        v = verify_remediation(before, plan, after)
        self.assertEqual(v["summary"]["regression_count"], 1)
        regressed = [r["vulnerability_id"] for r in v["regressed"]]
        self.assertIn("GHSA-394q-gx7c-w5v9", regressed)
        # Not counted as resolved.
        resolved = {r["vulnerability_id"] for r in v["resolved"]}
        self.assertNotIn("GHSA-394q-gx7c-w5v9", resolved)
        self.assertEqual(v["summary"]["resolved_count"], 0)
        # Regressed items carry the after versions as evidence.
        self.assertEqual(
            next(r for r in v["regressed"] if r["vulnerability_id"] ==
                 "GHSA-394q-gx7c-w5v9")["regressed_versions"], ["2.31.0"])

    def test_mixed_resolution_resolved_unchanged_regressed(self) -> None:
        """One after-scan exercise: drop PyYAML (resolved), bump requests
        2.28.0 -> 2.31.0 (regressed), keep urllib3/setuptools (unchanged)."""
        before = self._before()
        plan = build_remediation_plan(before)
        raw = _change_package_version(_load_osv(), "requests", "2.28.0", "2.31.0")
        raw = _drop_packages(raw, {"PyYAML"})
        after = normalize_scan(raw)
        v = verify_remediation(before, plan, after)
        self.assertEqual(v["summary"]["resolved_count"], 2)
        self.assertEqual(v["summary"]["unchanged_count"], 2)
        self.assertEqual(v["summary"]["regression_count"], 1)

    def test_new_findings_in_after_reported_not_attributed(self) -> None:
        """Findings present in the after scan but not in the plan (new) are
        reported via the raw delta, not asserted as fixed."""
        before = self._before()
        plan = build_remediation_plan(before)
        # Keep all baseline findings (unchanged) AND add a fresh, new
        # vulnerability in the after scan.
        raw = copy.deepcopy(_load_osv())
        new_pkg = {
            "package": {"name": "flask", "version": "2.0.0",
                        "ecosystem": "PyPI"},
            "vulnerabilities": [{
                "id": "GHSA-new-0000-0000",
                "aliases": [],
                "type": "MAINTAINER_ADVISORY",
                "published": "2026-01-01T00:00:00Z",
                "affected": [{"ranges": [{"events":
                     [{"introduced": "2.0.0"}, {"fixed": "2.0.1"}]}]}],
                "severity": None, "groups": []},
            ],
            "groups": [],
        }
        raw["results"][0]["packages"].append(new_pkg)
        after = normalize_scan(raw)
        v = verify_remediation(before, plan, after)
        self.assertGreaterEqual(v["summary"]["new_count"], 1)

    def test_risk_preserved_and_unavailable_when_no_topology(self) -> None:
        """A flat requirements input has no dependency topology, so PHEI is
        unavailable; verification preserves that honest state and invents no
        numeric risk."""
        before = self._before()
        plan = build_remediation_plan(before)
        after = self._before()
        v = verify_remediation(before, plan, after)
        self.assertIsNotNone(v["before_risk"])
        self.assertIsNotNone(v["after_risk"])
        # Edge-less graph -> PHEI unavailable (no fabricated score).
        self.assertEqual(v["before_risk"]["status"], "unavailable")
        self.assertIsNone(v["before_risk"]["score"])
        self.assertEqual(v["after_risk"]["status"], "unavailable")
        self.assertIsNone(v["after_risk"]["score"])

    def test_evidence_trail_appended_when_supplied(self) -> None:
        """When the caller supplies its own ``evidence_trail`` (e.g. the
        agent's own trail), verification also appends an auditable entry there,
        so 'no after scan' is traceable in the full trail."""
        before = self._before()
        plan = build_remediation_plan(before)
        trail = EvidenceTrail()
        verify_remediation(before, plan, after_scan=None, evidence_trail=trail)
        self.assertEqual(len(trail.steps), 1)
        self.assertEqual(trail.steps[0].tool, "verify_remediation")
        self.assertEqual(trail.steps[0].args["status"], "not_run")

    def test_evidence_trail_appended_when_after_supplied(self) -> None:
        before = self._before()
        plan = build_remediation_plan(before)
        trail = EvidenceTrail()
        verify_remediation(before, plan, after_scan=self._before(),
                          evidence_trail=trail)
        self.assertEqual(len(trail.steps), 1)
        self.assertEqual(trail.steps[0].args["status"], "verified")

    def test_unusable_plan_dict_still_fails_closed(self) -> None:
        """A missing/malformed ``plan`` must still fail closed to not_run
        counts rather than raising."""
        before = self._before()
        v = verify_remediation(before, {}, after_scan=None)
        self.assertEqual(v["status"], "not_run")
        self.assertFalse(v["resolution_claim"])
        self.assertEqual(v["summary"]["resolved_count"], 0)


class TestPipelineAfterScan(unittest.TestCase):
    """The ``after_scan_report`` parameter of ``investigate_from_json``: the
    plan is layered on the report, and verification is reconciled only when an
    after report is supplied."""

    def _baseline_report(self) -> dict[str, Any]:
        return investigate_from_json(FIXTURE_JSON, max_turns=12)

    def test_no_after_scan_report_leaves_remediation_none(self) -> None:
        report = self._baseline_report()
        # Baseline still fully populated.
        self.assertTrue(report["scanner_success"])
        self.assertEqual(report["findings_count"], 5)
        self.assertIsNone(report["remediation"],
                         "no after scan -> no remediation, no resolution claim")

    def test_good_after_report_layers_plan_and_verification(self) -> None:
        report = investigate_from_json(
            FIXTURE_JSON,
            after_scan_report=_write_json(
                _drop_packages(_load_osv(), {"PyYAML"}), "after"),
            max_turns=12)
        rem = report["remediation"]
        self.assertIsNotNone(rem)
        self.assertEqual(rem["plan"]["findings_count"], 5)
        v = rem["verification"]
        self.assertEqual(v["status"], "verified")
        self.assertTrue(v["resolution_claim"])
        self.assertEqual(v["summary"]["resolved_count"], 2)
        self.assertEqual(v["summary"]["unchanged_count"], 3)

    def test_malformed_after_report_fails_closed_to_not_run(self) -> None:
        """An unreadable after report must NOT block the baseline report and
        must make no resolution claim."""
        bad = _write_json({"results": "not-a-list"}, "bad")
        report = investigate_from_json(
            FIXTURE_JSON, after_scan_report=bad, max_turns=12)
        # Baseline preserved untouched.
        self.assertTrue(report["scanner_success"])
        self.assertEqual(report["findings_count"], 5)
        rem = report["remediation"]
        self.assertIsNotNone(rem)
        self.assertEqual(rem["plan"]["findings_count"], 5,
                         "plan is still built from the baseline")
        v = rem["verification"]
        self.assertEqual(v["status"], "not_run")
        self.assertFalse(v["resolution_claim"])
        self.assertEqual(v["summary"]["resolved_count"], 0)
        self.assertIn("evidence", v)

    def test_missing_after_report_path_fails_closed(self) -> None:
        report = investigate_from_json(
            FIXTURE_JSON, after_scan_report="/tmp/definitely-not-here.json",
            max_turns=12)
        v = report["remediation"]["verification"]
        self.assertEqual(v["status"], "not_run")
        self.assertFalse(v["resolution_claim"])

    def test_baseline_not_blocked_by_after_report(self) -> None:
        """Even with a failing after report, the baseline findings and evidence
        trail are intact."""
        bad = _write_raw("not json at all")
        report = investigate_from_json(
            FIXTURE_JSON, after_scan_report=bad, max_turns=12)
        self.assertEqual(report["findings_count"], 5)
        self.assertTrue(report["evidence"]["steps"])
        # remediation IS present (plan + not_run verification); the point is
        # the baseline is untouched.
        self.assertEqual(
            report["remediation"]["verification"]["status"], "not_run")


if __name__ == "__main__":
    unittest.main()
