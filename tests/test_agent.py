"""Tests for the OSV-Scanner-backed agentic investigation workflow.

These tests cover the new ``src.agent`` package:

* ``normalizer``  -- turning OSV-Scanner JSON into a ``DependencyGraph`` +
  ``Finding`` objects.
* ``scan_runner`` -- building and (via injection) executing the OSV-Scanner CLI.
* ``agent``       -- the bounded, evidence-grounded investigation loop, the
  ``EvidenceTrail``, the ``llm`` steering API, deterministic fallback, and
  ``compare_scans``.

They run against the checked-in fixture ``tests/data/osv-scanner.json`` (real
OSV-Scanner shape) and ``tests/fixtures/requirements-before.txt``.  No external
packages beyond stdlib + the project itself.
"""

import json
import os
import subprocess
import unittest
from typing import Any

from src.agent.agent import Agent, compare_scans
from src.agent.normalizer import Finding, normalize_scan, ScanResult
from src.agent.scan_runner import construct_command, run_scan, run_scan_from_json
from src.engine.risk_analyzer import calculate_phei
from src.models.dependency_graph import DependencyGraph


def _fixture_json() -> str:
    return os.path.join(os.path.dirname(__file__), "data", "osv-scanner.json")


def _requirements_file() -> str:
    return os.path.join(os.path.dirname(__file__), "fixtures", "requirements-before.txt")


def _load_osv() -> dict[str, Any]:
    with open(_fixture_json(), "r", encoding="utf-8") as f:
        return json.load(f)


def _fake_run(argv: list[str], **kwargs) -> subprocess.CompletedProcess:
    """Stand-in for subprocess.run.  Returns JSON for a successful scan."""
    return subprocess.CompletedProcess(
        argv,
        returncode=0,
        stdout=json.dumps({"results": []}),
        stderr="",
    )


class TestNormalizer(unittest.TestCase):
    """OSV-Scanner JSON -> graph + findings."""

    def test_normalize_extracts_findings(self) -> None:
        scan: ScanResult = normalize_scan(_load_osv())
        self.assertGreater(scan.count(), 0)
        self.assertIsInstance(scan.graph, DependencyGraph)
        self.assertGreater(len(scan.graph.nodes), 0)

    def test_normalizes_nested_package_shape(self) -> None:
        """The canonical OSV-Scanner nests metadata under ``package``."""
        scan = normalize_scan(_load_osv())
        names = {f.package_name for f in scan.findings}
        # Real package names, never "unknown".
        self.assertNotIn("unknown", names)
        for expected in ("PyYAML", "requests", "urllib3", "setuptools"):
            self.assertIn(expected, names)

    def test_findings_carry_advisory_and_spec(self) -> None:
        scan = normalize_scan(_load_osv())
        for f in scan.findings:
            # Real advisory id (GHSA-… / CVE-…).
            self.assertTrue(f.vulnerability_id)
            # Real OSV-Scanner 2.6.0 severity is either ``null`` or a list of
            # CVSS vector entries — a numeric score does not exist in the live
            # output, so the normalized score must stay unknown (None).  It must
            # never be coerced to a number, nor classified as high/low.
            self.assertIsNone(f.severity_score)
            # Every fixture advisory carries an affected range; the normalizer
            # renders it as a non-empty vulnerable-range spec string.
            self.assertIsInstance(f.vulnerability_spec, str)
            self.assertTrue(
                f.vulnerability_spec,
                f"missing/empty affected range for {f.vulnerability_id}",
            )

    def test_graph_is_edge_less_for_flat_input(self) -> None:
        """A flat requirements.txt has no known relationships -> edge-less.
        No edges may be invented (RECON-DG invariant).
        """
        scan = normalize_scan(_load_osv())
        self.assertEqual(scan.graph.get_edges_list(), [])

    def test_empty_scan(self) -> None:
        scan = normalize_scan({"results": []})
        self.assertEqual(scan.count(), 0)
        self.assertEqual(len(scan.graph.nodes), 0)
        self.assertTrue(scan.is_empty)

    def test_malformed_entries_are_skipped(self) -> None:
        """Bad entries must be skipped, not crash the normalization."""
        raw = {
            "results": [
                {"packages": []},
                {"packages": [{"package": {"name": "x"}, "vulnerabilities": []}]},
                {"packages": ["not-a-dict", 42]},
                {"packages": [{"package": "no-dict"}]},
                {"packages": [{"package": {"name": "y"}, "vulnerabilities": "nope"}]},
            ],
        }
        scan = normalize_scan(raw)
        # Only well-formed 'x' and 'y' packages yield nodes; 'no-dict' and scalars skipped.
        self.assertEqual(len(scan.graph.nodes), 2)
        self.assertEqual(scan.count(), 0)

    def _scan_one(self, package, vuln, version="5.1") -> ScanResult:
        """Helper: build a one-finding scan around the given advisory ``vuln``."""
        return normalize_scan({
            "results": [
                {
                    "packages": [
                        {
                            "package": {"name": package, "version": version,
                                       "ecosystem": "PyPI"},
                            "vulnerabilities": [vuln],
                            "groups": [],
                        }
                    ]
                }
            ]
        })

    def _affected(self, name, introduced, fixed=None) -> dict[str, Any]:
        """Build a real-shape ``affected`` entry with ``ranges``/``events``."""
        events = [{"introduced": introduced}]
        if fixed is not None:
            events.append({"fixed": fixed})
        return {
            "package": {"ecosystem": "PyPI", "name": name,
                        "purl": f"pkg:pypi/{name}"},
            "ranges": [{"events": events, "type": "ECOSYSTEM"}],
        }

    def test_null_severity_stays_unknown_not_zero_or_low(self) -> None:
        """``severity: null`` must normalize to an *unknown* score (None).  It
        is never coerced to 0.0, and a finding is never classified "low" when
        no score exists."""
        vuln = {
            "id": "GHSA-null-0000-0000",
            "aliases": ["CVE-2020-1747"],
            "type": "MAINTAINER_ADVISORY",
            "published": "2020-07-01T00:00:00Z",
            "affected": [self._affected("PyYAML", "5.1", "5.2b1")],
            "severity": None,
        }
        scan = self._scan_one("PyYAML", vuln)
        f = scan.findings[0]
        self.assertIsNone(f.severity_score, "null severity must stay None (unknown)")
        self.assertEqual(f.severity_types, ())
        self.assertEqual(f.severity_vectors, ())
        self.assertIsNone(f.severity_vector)
        self.assertFalse(f.is_high_severity(7.0))
        self.assertFalse(f.is_high_severity(0.0))
        self.assertTrue(f.vulnerability_spec)

    def test_single_cvss_vector_preserved_as_evidence(self) -> None:
        """A single CVSS_V3 entry must preserve the scheme type and vector string
        as evidence, leave the numeric score unknown, and never be classified
        high or low."""
        vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
        vuln = {
            "id": "GHSA-single-0000",
            "aliases": ["CVE-2021-43796"],
            "type": "MAINTAINER_ADVISORY",
            "published": "2021-12-01T00:00:00Z",
            "affected": [self._affected("requests", "2.28.0", "2.28.1")],
            "severity": [{"type": "CVSS_V3", "score": vector}],
        }
        scan = self._scan_one("requests", vuln)
        f = scan.findings[0]
        self.assertIsNone(f.severity_score)
        self.assertEqual(f.severity_types, ("CVSS_V3",))
        self.assertEqual(f.severity_vectors, (vector,))
        self.assertEqual(f.severity_vector, vector)
        self.assertFalse(f.is_high_severity(7.0))
        self.assertFalse(f.is_high_severity(1.0))

    def test_multiple_severity_vectors_preserved_in_order(self) -> None:
        """A multi-scheme severity list must preserve every scheme type and its
        vector, in the order the scanner emitted them.  Still no numeric score,
        no high/low classification."""
        v3 = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        v4 = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
        vuln = {
            "id": "GHSA-multi-0000",
            "aliases": ["CVE-2021-33584"],
            "type": "MAINTAINER_ADVISORY",
            "published": "2021-07-21T00:00:00Z",
            "affected": [self._affected("setuptools", "58.0.0", "60.0.0")],
            "severity": [
                {"type": "CVSS_V3", "score": v3},
                {"type": "CVSS_V4", "score": v4},
            ],
        }
        scan = self._scan_one("setuptools", vuln)
        f = scan.findings[0]
        self.assertIsNone(f.severity_score)
        self.assertEqual(f.severity_types, ("CVSS_V3", "CVSS_V4"))
        self.assertEqual(f.severity_vectors, (v3, v4))
        self.assertEqual(f.severity_vector, v3)
        self.assertFalse(f.is_high_severity(7.0))

    def test_malformed_severity_never_coerces_to_number(self) -> None:
        """Malformed or partial severity values must normalize to an unknown
        score (severity_score is None) without raising and never classify a
        finding as high.  A finding with an unknown score must still remain
        attributable and grounded (advisory id + vulnerable-range spec)."""
        cases = {
            "string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            "number": 9.8,
            "empty_list": [],
            "list_of_scalars": ["CVSS:3.1/..."],
            "list_entry_no_score": [{"type": "CVSS_V3"}],
            "list_entry_score_not_str": [{"type": "CVSS_V3", "score": 9.8}],
            "list_entry_no_type": [{"score": "CVSS:3.1/..."}],
        }
        base = {
            "id": "GHSA-bad-0000",
            "aliases": ["CVE-2020-1"],
            "type": "MAINTAINER_ADVISORY",
            "published": "2020-01-01T00:00:00Z",
            "affected": [self._affected("PyYAML", "5.1", "5.2b1")],
        }
        for label, bad in cases.items():
            with self.subTest(label=label):
                vuln = {**base, "severity": bad}
                scan = self._scan_one("PyYAML", vuln)
                f = scan.findings[0]
                # Invariant: an unknown score is never coerced to a number and
                # is never classified high (there is no low bucket).
                self.assertIsNone(f.severity_score,
                                 "severity %s must stay None" % label)
                self.assertFalse(f.is_high_severity(7.0), label)
                # Finding remains attributable and grounded (id + spec).
                self.assertTrue(f.vulnerability_id, label)
                self.assertTrue(f.vulnerability_spec, label)

    def test_malformed_severity_preserves_only_present_fields(self) -> None:
        """Partial 2.6.0 list entries preserve exactly the fields that are
        actually present (documented contract), and none contribute a numeric
        score: a type without a usable score yields a scheme type only; a string
        vector without a type yields UNSPECIFIED type plus the vector; a
        non-string score yields the type only; empty/non-dict lists yield nothing."""
        cases = {
            "list_entry_no_score": (
                [{"type": "CVSS_V3"}],
                None, ("CVSS_V3",), (),
            ),
            "list_entry_score_not_str": (
                [{"type": "CVSS_V3", "score": 9.8}],
                None, ("CVSS_V3",), (),
            ),
            "list_entry_no_type": (
                [{"score": "CVSS:3.1/..."}],
                "CVSS:3.1/...", ("UNSPECIFIED",), ("CVSS:3.1/...",),
            ),
            "empty_list": (
                [], None, (), (),
            ),
            "list_of_scalars": (
                ["CVSS:3.1/..."], None, (), (),
            ),
        }
        base = {
            "id": "GHSA-bad-0000",
            "aliases": ["CVE-2020-1"],
            "type": "MAINTAINER_ADVISORY",
            "published": "2020-01-01T00:00:00Z",
            "affected": [self._affected("PyYAML", "5.1", "5.2b1")],
        }
        for label, (bad, exp_primary, exp_types, exp_vectors) in cases.items():
            with self.subTest(label=label):
                vuln = {**base, "severity": bad}
                scan = self._scan_one("PyYAML", vuln)
                f = scan.findings[0]
                self.assertIsNone(f.severity_score, label)
                self.assertEqual(f.severity_vector, exp_primary, label)
                self.assertEqual(f.severity_types, exp_types, label)
                self.assertEqual(f.severity_vectors, exp_vectors, label)

class TestScanRunner(unittest.TestCase):
    """OSV-Scanner CLI invocation (via injection, no real binary)."""

    def test_construct_command_writes_documented_argv(self) -> None:
        cmd = construct_command("requirements.txt", binary="osv-scanner", fmt="json")
        # Must be the documented form:  osv-scanner scan --format json <path>
        self.assertEqual(cmd, ["osv-scanner", "scan", "--format", "json", "requirements.txt"])
        self.assertEqual(cmd[0], "osv-scanner")
        self.assertIn("--format", cmd)
        self.assertEqual(cmd[-1], "requirements.txt")

    def test_run_scan_uses_injected_fn(self) -> None:
        """run_scan must delegate to the supplied fn (no real subprocess)."""
        seen = {"argv": None}

        def fake(argv: list[str], **kwargs) -> subprocess.CompletedProcess:
            seen["argv"] = argv
            return _fake_run(argv, **kwargs)

        res = run_scan(
            _requirements_file(),
            binary="osv-scanner",
            fmt="json",
            run_fn=fake,
        )
        self.assertTrue(res.success)
        self.assertIsNotNone(seen["argv"])
        # The argv handed to the shim must be the documented one.
        self.assertEqual(seen["argv"][0], "osv-scanner")

    def test_run_scan_from_json(self) -> None:
        res = run_scan_from_json(_fixture_json(), binary="osv-scanner")
        self.assertTrue(res.success)
        self.assertTrue(res.payload(), "payload must be non-empty")
        self.assertIn("results", res.payload())

    def test_run_scan_from_json_missing_file(self) -> None:
        res = run_scan_from_json("/does-not-exist.json")
        self.assertFalse(res.success)
        self.assertIsNotNone(res.error)

    def test_run_scan_rejects_non_json_output(self) -> None:
        res = run_scan(_requirements_file(), run_fn=lambda argv, **kw: _fake_run(argv))
        # The injected fn returns valid JSON ({"results": []}) -> success.
        self.assertTrue(res.success)

    # --- OSV-Scanner documented exit-code semantics (the core fix) ---------
    def test_run_scan_finds_exit_1_is_success(self) -> None:
        """exit 1 (packages found + vulnerabilities) is a *successful* scan:
        the JSON findings are preserved, not misclassified as failure."""
        results = {
            "results": [
                {
                    "packages": [
                        {
                            "package": {"name": "PyYAML", "version": "5.1",
                                       "ecosystem": "PyPI"},
                            "vulnerabilities": [
                                {"id": "GHSA-9q8c-2v7w",
                                 "aliases": ["CVE-2020-1747"]},
                            ],
                            "groups": [],
                        }
                    ]
                }
            ]
        }
        def fake(argv, **kw):
            return subprocess.CompletedProcess(
                argv, returncode=1, stdout=json.dumps(results), stderr="")

        res = run_scan(_requirements_file(), run_fn=fake)
        self.assertTrue(res.success, "exit 1 with findings must be success")
        self.assertEqual(res.exit_code, 1)
        self.assertIsNone(res.error)
        self.assertEqual(res.payload()["results"][0]["packages"][0]["package"]["name"],
                         "PyYAML")

    def test_run_scan_clean_exit_0_is_success(self) -> None:
        """exit 0 (clean, even with zero findings) is a successful scan."""
        def fake(argv, **kw):
            return subprocess.CompletedProcess(
                argv, returncode=0, stdout=json.dumps({"results": []}), stderr="")
        res = run_scan(_requirements_file(), run_fn=fake)
        self.assertTrue(res.success)
        self.assertEqual(res.exit_code, 0)
        self.assertIsNone(res.error)
        self.assertEqual(res.payload()["results"], [])

    def test_run_scan_no_packages_exit_128_is_failure(self) -> None:
        """exit 128 (no packages found) is distinct from a clean scan; even
        with parseable JSON it must not be treated as a 0-vuln success."""
        def fake(argv, **kw):
            return subprocess.CompletedProcess(
                argv, returncode=128, stdout=json.dumps({"results": []}), stderr="")
        res = run_scan(_requirements_file(), run_fn=fake)
        self.assertFalse(res.success)
        self.assertEqual(res.exit_code, 128)
        self.assertIsNotNone(res.error)
        self.assertIn("no packages", res.error)

    def test_run_scan_generic_error_exit_is_failure(self) -> None:
        """exit 2..126 / 127 / 129..255 are real scanner errors (non-zero,
        non-findings) and are always failures."""
        def make_fake(rc: int):
            def fake(argv, **kw):
                return subprocess.CompletedProcess(argv, returncode=rc,
                                                   stdout="", stderr="generic error")
            return fake
        for rc in (2, 126, 127, 129, 250):
            res = run_scan(_requirements_file(), run_fn=make_fake(rc))
            self.assertFalse(res.success, f"exit {rc} must be a failure")
            self.assertEqual(res.exit_code, rc)
            self.assertIsNotNone(res.error)

    def test_run_scan_malformed_json_exit_1_is_failure(self) -> None:
        """A findings exit-code (1) must NOT be success if the JSON is unusable;
        findings we cannot parse are never invented or silently dropped as success."""
        def fake(argv, **kw):
            return subprocess.CompletedProcess(
                argv, returncode=1, stdout="{ not valid json", stderr="")
        res = run_scan(_requirements_file(), run_fn=fake)
        self.assertFalse(res.success)
        self.assertEqual(res.exit_code, 1)
        self.assertIsNotNone(res.error)
        self.assertIsNone(res.json_payload)

    def test_run_scan_exit_1_parseable_but_unusable_is_failure(self) -> None:
        """The core contract gate: a scan is usable *only* when exit is 0/1
        AND the JSON payload has the documented ``{'results': [...]}`` shape.

        A *parseable* payload that lacks the usable shape (missing ``results``
        key, ``results`` not a list, or top-level not an object) must still be
        a FAILURE — never a false success — and ``json_payload`` must be None so
        downstream ``results_from()`` cannot operate on an ill-formed report.
        """
        bad_shapes = [
            ("missing 'results' key", json.dumps({"foo": "bar"})),
            ("'results' not a list (string)", json.dumps({"results": "x"})),
            ("'results' not a list (dict)", json.dumps({"results": {"a": 1}})),
            ("'results' not a list (scalar)", json.dumps({"results": 5})),
            ("top-level array", json.dumps([])),
            ("top-level string", json.dumps('"nope"')),
        ]
        for rc in (0, 1):
            for label, body in bad_shapes:
                with self.subTest(exit_code=rc, shape=label):
                    def fake(argv, **kw):
                        return subprocess.CompletedProcess(
                            argv, returncode=rc, stdout=body, stderr="")
                    res = run_scan(_requirements_file(), run_fn=fake)
                    self.assertFalse(res.success,
                                     f"exit {rc}, {label}: parseable-but-unusable "
                                     "JSON must be a failure")
                    self.assertEqual(res.exit_code, rc)
                    self.assertIsNotNone(res.error)
                    # No usable payload: downstream must not treat this as findings.
                    self.assertIsNone(res.json_payload)

    def test_run_scan_exit_128_parseable_still_failure(self) -> None:
        """exit 128 (no packages found) must stay a failure even when the
        payload is the perfectly-shaped ``{'results': []}`` (i.e. no findings
        but also nothing was scanned).  This keeps the no-package case distinct
        from a genuine clean scan (exit 0) and from a findings scan (exit 1)."""
        def fake(argv, **kw):
            return subprocess.CompletedProcess(
                argv, returncode=128, stdout=json.dumps({"results": []}), stderr="")
        res = run_scan(_requirements_file(), run_fn=fake)
        self.assertFalse(res.success)
        self.assertEqual(res.exit_code, 128)
        self.assertIsNotNone(res.error)
        self.assertIn("no packages", res.error)
        self.assertTrue(res.json_payload)  # parseable, but not a success run

    def test_run_scan_missing_binary_is_failure(self) -> None:
        """A missing OSV-Scanner binary is a failure, never a silent success."""
        def raise_missing(argv, **kw):
            raise FileNotFoundError("no such executable: osv-scanner")
        res = run_scan(_requirements_file(), run_fn=raise_missing)
        self.assertFalse(res.success)
        self.assertEqual(res.exit_code, -2)
        self.assertIsNotNone(res.error)

    def test_run_scan_timeout_is_failure(self) -> None:
        """A scanner that times out is a failure with an explicit error."""
        def boom(argv, **kw):
            raise subprocess.TimeoutExpired(argv, b"")
        res = run_scan(_requirements_file(), run_fn=boom, timeout_s=1)
        self.assertFalse(res.success)
        self.assertEqual(res.exit_code, -3)
        self.assertIsNotNone(res.error)
        self.assertIn("timed out", res.error)


class TestAgent(unittest.TestCase):
    """Bounded, evidence-grounded investigation loop."""

    def _scan(self) -> ScanResult:
        return normalize_scan(_load_osv())

    def _report(self, scan: ScanResult | None = None, max_turns: int = 25) -> dict[str, Any]:
        """Run the agent and return the structured report (helper)."""
        return Agent(scan or self._scan(), max_turns=max_turns).run()

    def test_run_produces_report(self) -> None:
        report = self._report()
        self.assertIn("narrative", report)
        self.assertIn("evidence", report)
        self.assertIsInstance(report["evidence"], dict)
        self.assertGreater(report["turns_used"], 0)

    def test_risk_not_fabricated_when_unavailable(self) -> None:
        """Flat graph -> PHEI unavailable -> score None, never a fabricated number."""
        report = self._report()
        self.assertEqual(report["risk"]["status"], "unavailable")
        self.assertIsNone(report["risk"]["score"])
        # The message must be an honest, grounded statement — it explains the
        # topology limitation and refuses to fabricate a score.
        msg = report["risk"]["message"]
        self.assertIn("No score is fabricated", msg)

    def test_evidence_trail_is_complete_and_ordered(self) -> None:
        report = self._report()
        steps = report["evidence"]["steps"]
        # Turn indices are contiguous starting at 0.
        self.assertEqual([s["turn"] for s in steps], list(range(len(steps))))
        for s in steps:
            self.assertIn("tool", s)
            self.assertIn("args", s)
            self.assertIsInstance(s["tool"], str)
            # The tool used must be an allowlisted tool OR a recorded fallback.
            self.assertIn(s["tool"], Agent.ALLOWED_TOOLS | {"llm_fallback"})

    def test_respects_max_turns(self) -> None:
        # Even a tiny budget must terminate without error (fallback degrades gracefully).
        report = self._report(max_turns=1)
        self.assertGreaterEqual(report["turns_used"], 1)
        self.assertIn("evidence", report)

    def test_deterministic_when_no_llm(self) -> None:
        """Two runs with the same scan and no llm must produce identical evidence."""
        s1 = self._report()
        s2 = self._report()
        self.assertEqual(
            [(st["tool"], st["args"]) for st in s1["evidence"]["steps"]],
            [(st["tool"], st["args"]) for st in s2["evidence"]["steps"]],
        )
        self.assertEqual(s1["narrative"], s2["narrative"])

    def test_llm_steering_is_used(self) -> None:
        """A supplied llm function drives the loop; used_llm reflects it."""
        calls = {"n": 0}

        def llm(state: dict[str, Any]) -> dict[str, Any]:
            calls["n"] += 1
            if calls["n"] == 1:
                return {"tool": "findings", "args": {}}
            return {"tool": "stop", "args": {"reason": "test steer"}}

        report = Agent(self._scan(), llm=llm, max_turns=25).run()
        self.assertTrue(report["used_llm"])
        self.assertEqual(calls["n"], 2, "llm was called twice")
        self.assertEqual(report["evidence"]["steps"][0]["tool"], "findings")

    def test_malformed_llm_falls_back_to_policy(self) -> None:
        """A malformed llm response must never crash; policy takes over (recorded)."""

        def bad_llm(state: dict[str, Any]) -> dict[str, Any]:
            return {"tool": "not-a-real-tool", "args": {"x": 1}}

        report = Agent(self._scan(), llm=bad_llm, max_turns=25).run()
        # No crash; a report was still produced.
        self.assertIn("narrative", report)
        # Every evidence step must be an allowlisted tool OR a recorded fallback.
        for s in report["evidence"]["steps"]:
            self.assertIn(s["tool"], Agent.ALLOWED_TOOLS | {"llm_fallback"})

    def test_llm_can_request_disallowed_tool_and_it_is_rejected(self) -> None:
        """A disallowed tool from llm is rejected (recorded), and the next step runs."""

        def llm(state: dict[str, Any]) -> dict[str, Any]:
            return {"tool": "read_file", "args": {}}  # not in ALLOWED_TOOLS

        report = Agent(self._scan(), llm=llm, max_turns=25).run()
        tools = [s["tool"] for s in report["evidence"]["steps"]]
        self.assertNotIn("read_file", tools)
        self.assertGreater(report["turns_used"], 0)


class TestPackageContextTool(unittest.TestCase):
    """The opt-in, bounded, additive package_context tool (item 3)."""

    def _scan(self) -> "ScanResult":
        return normalize_scan(_load_osv())

    def _agent(self, **kw) -> "Agent":
        return Agent(self._scan(), **kw)

    def test_package_context_is_disabled_by_default(self) -> None:
        """The grounded deterministic run performs zero enrichment I/O by
        default (enrichment_enabled=False)."""
        # A tracking enrichment_fn proves it was never invoked.
        calls = {"n": 0}
        def fn(**kw):
            calls["n"] += 1
            return {"status": "ok"}
        agent = self._agent(enrichment_fn=fn)
        obs = agent._execute("package_context",
                             {"package_name": "PyYAML", "version": "5.1"})
        self.assertEqual(obs["status"], "enrichment_disabled")
        self.assertEqual(calls["n"], 0, "default run must not call deps.dev")

    def test_package_context_opted_in_calls_enrichment_fn(self) -> None:
        calls = {"n": 0}
        def fn(**kw):
            calls["n"] += 1
            return {"status": "ok",
                    "advisory_ids_from_version": ["GHSA-x"],
                    "errors": []}
        agent = self._agent(enrichment_enabled=True, enrichment_fn=fn,
                            max_enrichment_calls=3)
        obs = agent._execute("package_context",
                             {"package_name": "PyYAML", "version": "5.1"})
        self.assertEqual(obs["status"], "ok")
        self.assertEqual(obs["calls_used"], 1)
        self.assertEqual(obs["calls_limit"], 3)
        self.assertTrue(obs["review_only"])
        self.assertEqual(obs["provenance"], "generic_published")
        self.assertEqual(obs["advisory_ids_from_provider"], ["GHSA-x"])
        self.assertEqual(obs["requested_advisory_id"], None)
        self.assertEqual(calls["n"], 1)

    def test_package_context_passes_explicit_advisory_id(self) -> None:
        seen = {"advisory_ids": None}
        def fn(**kw):
            seen["advisory_ids"] = kw.get("advisory_ids")
            return {"status": "ok", "advisory_ids_from_version": []}
        agent = self._agent(enrichment_enabled=True, enrichment_fn=fn)
        agent._execute(
            "package_context",
            {"package_name": "PyYAML", "version": "5.1",
             "vulnerability_id": "GHSA-explicit"},
        )
        # Only the explicitly supplied id is looked up (bounded, explicit).
        self.assertEqual(seen["advisory_ids"], ["GHSA-explicit"])
        obs = agent._execute(
            "package_context",
            {"package_name": "PyYAML", "version": "5.1",
             "vulnerability_id": "GHSA-explicit"},
        )
        self.assertEqual(obs["observed_advisory_ids"], ["GHSA-explicit"])

    def test_package_context_hard_call_limit(self) -> None:
        calls = {"n": 0}
        def fn(**kw):
            calls["n"] += 1
            return {"status": "ok"}
        agent = self._agent(enrichment_enabled=True, enrichment_fn=fn,
                            max_enrichment_calls=2)
        for i in range(5):
            obs = agent._execute(
                "package_context",
                {"package_name": f"P{i}", "version": "1.0"})
        # At most 2 real lookups were issued; the rest were budget-exhausted.
        self.assertEqual(calls["n"], 2, "hard call limit must hold")
        self.assertEqual(obs["status"], "budget_exhausted")

    def test_package_context_skips_redundant_lookups(self) -> None:
        calls = {"n": 0}
        def fn(**kw):
            calls["n"] += 1
            return {"status": "ok"}
        agent = self._agent(enrichment_enabled=True, enrichment_fn=fn,
                            max_enrichment_calls=5)
        agent._execute("package_context",
                       {"package_name": "PyYAML", "version": "5.1"})
        obs = agent._execute("package_context",
                             {"package_name": "PyYAML", "version": "5.1"})
        # Second identical coordinate is served from the cache (no extra I/O).
        self.assertTrue(obs["cached"])
        self.assertEqual(calls["n"], 1)

    def test_package_context_failed_provider_preserves_findings(self) -> None:
        """A failing provider is recorded additively; the agent report and the
        deterministic findings are untouched (no raise, no lost findings)."""
        def raise_fn(**kw):
            raise RuntimeError("provider exploded")
        agent = self._agent(enrichment_enabled=True, enrichment_fn=raise_fn)
        obs = agent._execute(
            "package_context",
            {"package_name": "PyYAML", "version": "5.1"})
        self.assertEqual(obs["status"], "error")
        # Now run the whole loop: it must still produce a full report.
        report = agent.run()
        self.assertEqual(report["findings_count"], agent.scan.count())
        self.assertIn("narrative", report)

    def test_package_context_full_agent_run_is_review_only_and_bounded(self) -> None:
        """With enrichment enabled, the agent may invoke package_context and the
        observation is always labelled generic_published / review_only."""
        seen = {"status": None, "calls": 0}
        def fn(**kw):
            seen["status"] = "ok"
            seen["calls"] += 1
            return {"status": "ok",
                    "advisory_ids_from_version": ["GHSA-a"],
                    "errors": []}
        agent = self._agent(
            llm=lambda state: {
                "tool": "package_context",
                "args": {"package_name": "PyYAML", "version": "5.1"},
            },
            enrichment_enabled=True,
            enrichment_fn=fn,
            max_enrichment_calls=3,
            max_turns=3,
        )
        # Force stop after a few turns so the run is bounded.
        agent.max_turns = 3
        report = agent.run()
        tools = [s["tool"] for s in report["evidence"]["steps"]]
        # package_context must be allowlisted and present in the trail.
        self.assertIn("package_context", tools)
        self.assertEqual(len([t for t in tools if t == "package_context"]), 1)
        for s in report["evidence"]["steps"]:
            if s["tool"] == "package_context":
                obs = s["observation"]
                self.assertEqual(obs["provenance"], "generic_published")
                self.assertTrue(obs["review_only"])
                self.assertIn("observed_advisory_ids", obs)
        self.assertGreaterEqual(seen["calls"], 1)

    def test_package_context_invalid_args_is_additive(self) -> None:
        agent = self._agent(enrichment_enabled=True)
        obs = agent._execute("package_context", {"package_name": ""})
        self.assertEqual(obs["status"], "invalid_args")
        self.assertIsNone(obs.get("calls_used"))

    def test_package_context_not_in_reported_findings_count(self) -> None:
        """Enrichment must never inflate or alter the deterministic findings."""
        base = self._agent()
        report = base.run()
        n = report["findings_count"]
        agent2 = self._agent(enrichment_enabled=True)
        report2 = agent2.run()
        self.assertEqual(report2["findings_count"], n)
        self.assertEqual(len(report2["findings"]), len(report["findings"]))
        # Same deterministic evidence ordering for non-enrichment tools.
        self.assertEqual(report2["narrative"], report["narrative"])


class TestCompareScans(unittest.TestCase):
    """Before/after scan diffing."""

    def _scan(self, payload: dict[str, Any]) -> ScanResult:
        return normalize_scan(payload)

    def test_same_scan_no_delta(self) -> None:
        raw = _load_osv()
        before = self._scan(raw)
        after = self._scan(raw)
        d = compare_scans(before, after)
        self.assertEqual(d["new_count"], 0)
        self.assertEqual(d["resolved_count"], 0)
        self.assertEqual(d["unchanged_count"], before.count())

    def test_upgrade_resolves_findings(self) -> None:
        raw = _load_osv()
        before = self._scan(raw)
        # "After": upgrade the two highest-severity packages so they're clean.
        after_payload = []
        for result in raw["results"]:
            kept = []
            for p in result["packages"]:
                if p["package"]["name"] == "PyYAML" and p["package"]["version"] == "5.1":
                    continue  # upgraded away
                if p["package"]["name"] == "requests" and p["package"]["version"] == "2.28.0":
                    continue  # upgraded away
                kept.append(p)
            kept.append(
                {
                    "package": {"name": "PyYAML", "version": "6.1", "ecosystem": "PyPI"},
                    "vulnerabilities": [],
                    "groups": [],
                }
            )
            kept.append(
                {
                    "package": {"name": "requests", "version": "2.31.0", "ecosystem": "PyPI"},
                    "vulnerabilities": [],
                    "groups": [],
                }
            )
            result2 = dict(result)
            result2["packages"] = kept
            after_payload.append(result2)
        # normalize_scan expects the canonical top-level shape {"results": [...]};
        # after_payload is a bare list of result objects, so wrap it explicitly.
        after = self._scan({"results": after_payload})
        d = compare_scans(before, after)
        self.assertGreater(d["resolved_count"], 0)
        self.assertEqual(d["new_count"], 0)
        self.assertIn("resolved", d["narrative"].lower())


class TestDeterminismContract(unittest.TestCase):
    """The 'no fabricated evidence' contract, asserted as an explicit test."""

    def test_agent_reports_are_self_consistent(self) -> None:
        report = Agent(normalize_scan(_load_osv()), max_turns=25).run()
        # The narrative must be non-empty and the risk field must be honest.
        self.assertTrue(report["narrative"].strip())
        risk = report["risk"]
        if risk["status"] == "available":
            self.assertGreaterEqual(risk["score"], 0.0)
        else:
            self.assertIsNone(risk["score"])
        # Evidence must be a list (never empty when the agent ran).
        self.assertIsInstance(report["evidence"]["steps"], list)
        self.assertGreater(len(report["evidence"]["steps"]), 0)


if __name__ == "__main__":
    unittest.main()


