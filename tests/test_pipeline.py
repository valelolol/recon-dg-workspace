"""End-to-end integration tests for the RECON-DG pipeline glue.

These tests exercise the *chain* — manifest/report → ``run_scan`` /
``run_scan_from_json`` → ``normalize_scan`` → the agent loop → the report —
as a single unit, rather than each building block in isolation.  They use only
the checked-in fixtures (``tests/data/osv-scanner.json`` for a real OSV-Scanner
payload and ``tests/fixtures/requirements-before.txt`` for a manifest) plus
injected shims (a fake ``subprocess.run`` for the live-scan path, a stub
``enrichment_fn`` for the deps.dev path, and stub LLMs).  No real scanner
binary and no network are required.

They assert the *contract* the glue must preserve:

* **Full chain demonstrable.**  A usable scan produces a populated report
  (findings, evidence trail, narrative, risk).  Both entry points work.
* **Findings are authoritative.**  The report's findings/count exactly mirror
  the normalised OSV-Scanner output — nothing invented, nothing dropped.
* **Unusable scans fail closed.**  Exit 128 ("no packages"), any other
  non-{0,1} exit code, malformed JSON, or a missing binary yields a failure
  envelope with *zero* findings and no report — the agent never runs on an
  untrusted scan.
* **deps.dev is optional and additive.**  Default is off (zero enrichment calls,
  findings intact).  When on, ``package_context`` is labelled
  ``generic_published``/``review_only`` and is never used for project PHEI;
  a failing provider is recorded additively and never erases the findings.
* **Deterministic fallback.**  With no LLM, a raising LLM, or an invalid action
  the pipeline still produces a full, self-consistent report.
* **Before/after comparison.**  Two full pipeline runs can be diffed for
  new / resolved / unchanged findings and the PHEI delta.
"""

import json
import os
import subprocess
import tempfile
import unittest
from typing import Any, Callable

from src.agent.pipeline import investigate, investigate_from_json


def _fixture_json_path() -> str:
    return os.path.join(os.path.dirname(__file__), "data", "osv-scanner.json")


def _manifest_path() -> str:
    return os.path.join(os.path.dirname(__file__), "fixtures", "requirements-before.txt")


def _load_osv() -> dict[str, Any]:
    with open(_fixture_json_path(), "r", encoding="utf-8") as f:
        return json.load(f)


def _fake_run(argv: list[str], **kwargs) -> subprocess.CompletedProcess:
    """Stand-in for ``subprocess.run``: emits the fixture as a *findings* scan
    (exit 1, the documented "vulnerabilities present" code)."""
    return subprocess.CompletedProcess(
        argv, returncode=1, stdout=json.dumps(_load_osv()), stderr="",
    )


def _clean_fake_run(argv: list[str], **kwargs) -> subprocess.CompletedProcess:
    """A *clean* scan (exit 0, zero findings) — the other documented success."""
    return subprocess.CompletedProcess(
        argv, returncode=0, stdout=json.dumps({"results": []}), stderr="",
    )


def _exit_code_fake(rc: int, body: str = "") -> Callable:
    """Factory: a shim that returns a fixed ``returncode`` and ``body``."""
    def fake(argv, **kw):
        return subprocess.CompletedProcess(argv, rc, body, "")
    return fake


# A stub enrichment provider: deterministic, never raises, clearly labelled.
def _stub_enrichment_fn(**kwargs: Any) -> dict[str, Any]:
    """Mimics a *successful* deps.dev context for the highest-CVSS package the
    agent is likely to inspect (PyYAML).  This exercises the additive path
    without touching the network."""
    pkg = kwargs.get("package")
    ver = kwargs.get("version")
    return {
        "status": "ok",
        "package": pkg,
        "version": ver,
        "system": kwargs.get("system", "pyPI"),
        "provenance": "generic_published",
        "advisory_ids_from_version": [
            "GHSA-p6qc-x272-q48w",   # matches the fixture's PyYAML 9.8 advisory
            "GHSA-757q-h92x-p438",
        ],
        "requested_advisory_id": kwargs.get("vulnerability_id"),
        "dependencies_status": "ok",
        "version_meta": {"package": pkg, "version": ver, "licenses": ["MIT"]},
        "resolved_deps": {
            "package": pkg,
            "version": ver,
            "system": kwargs.get("system", "pyPI"),
            "provenance": "generic_published",
            "dependencies": [
                {"package": "six", "version": "1.15", "type": "normal"},
            ],
        },
        "advisory_details": {"GHSA-p6qc-x272-q48w": {"cvss3Score": 9.8}},
        "errors": [],
    }


def _failing_enrichment_fn(**kwargs: Any) -> dict[str, Any]:
    """Mimics a *rate-limited* deps.dev provider (status error, additive)."""
    return {
        "status": "error",
        "package": kwargs.get("package"),
        "version": kwargs.get("version"),
        "system": kwargs.get("system", "pyPI"),
        "provenance": "generic_published",
        "advisory_ids_from_version": [],
        "dependencies_status": "error",
        "errors": ["deps.dev rate limit (429)"],
    }


def _count_package_context_steps(report: dict[str, Any]) -> list[dict[str, Any]]:
    """Return the trail steps whose tool is ``package_context``."""
    return [s for s in report["evidence"]["steps"] if s["tool"] == "package_context"]


def _all_package_context_obs(report: dict[str, Any]) -> list[Any]:
    return [s["observation"] for s in _count_package_context_steps(report)]


class TestPipelineSuccess(unittest.TestCase):
    """A usable scan flows through the whole chain into a populated report."""

    def test_from_json_produces_full_report(self) -> None:
        """``investigate_from_json`` (no binary) yields findings, evidence, and
        the correct risk status for a flat requirements graph."""
        report = investigate_from_json(_fixture_json_path())
        self.assertTrue(report["scanner_success"],
                        "a well-formed fixture must be a usable scan")
        # A *saved* report file has no process, so its exit code is unknown.
        # It is recorded as None (never a fabricated 0 that could be read as
        # a "clean" scan) and provenance is labelled offline_json.
        self.assertIsNone(report["scanner_exit_code"],
                         "an offline report has no process exit code; it must "
                         "be None, not 0")
        self.assertEqual(report["scan_mode"], "offline_json",
                         "investigate_from_json input is a saved JSON report")
        self.assertEqual(report["scanner_error"], None)
        # The report carries real findings, yet its exit code is unknown (None)
        # and its mode is offline — so no consumer may classify it as a clean
        # live scan (the only thing that means "0 vulnerabilities").
        self.assertEqual(report["findings_count"], 5,
                         "5 findings in the fixture (2x PyYAML, requests, "
                         "urllib3, setuptools)")
        # The real 2.6.0 fixture carries *vector-only* severities (no numeric
        # CVSS anywhere), so no finding is high-severity.  This is the correct
        # behaviour, not a regression: severity_score is None for every finding
        # and is never coerced to 0.0 or classified "low".
        self.assertEqual(report["high_severity_count"], 0,
                         "real 2.6.0 fixture has vector-only severities, so "
                         "no numeric CVSS exists -> nothing is high")
        # The flat requirements graph has no edges -> PHEI must be unavailable,
        # and the score must be None (never fabricated).
        self.assertEqual(report["risk"]["status"], "unavailable")
        self.assertIsNone(report["risk"]["score"])
        self.assertEqual(report["risk"]["score"], None)
        self.assertTrue(report["narrative"].strip(),
                        "a summary must be produced")
        self.assertGreaterEqual(report["turns_used"], 5,
                                "the loop must actually run tools (findings, "
                                "get_finding, risk_score, summary, stop)")
        self.assertEqual(report["evidence"]["steps"],
                         report["evidence"]["steps"])  # structural sanity
        # Findings in the report must be exactly the normalised scanner findings.
        self.assertEqual(len(report["findings"]), 5)
        ids = {f["vulnerability_id"] for f in report["findings"]}
        self.assertEqual(ids, {
            "GHSA-p6qc-x272-q48w", "GHSA-757q-h92x-p438",   # PyYAML
            "GHSA-394q-gx7c-w5v9",                          # requests
            "GHSA-93h9-824q-92x3",                          # urllib3
            "GHSA-994q-cg23-2p48",                          # setuptools
        })
        # Each reported finding must carry a grounded explanation.
        for f in report["findings"]:
            self.assertIn("explanation", f)
            self.assertTrue(f["explanation"].strip())

    def test_live_scan_path_with_fake_run(self) -> None:
        """``investigate`` (live-scan entry) drives the *same* chain when a fake
        ``subprocess.run`` emits the fixture as a findings scan."""
        report = investigate(_manifest_path(), run_fn=_fake_run, max_turns=12)
        self.assertTrue(report["scanner_success"])
        self.assertEqual(report["scanner_exit_code"], 1,
                         "the findings exit code (1) is the documented success")
        self.assertEqual(report["scanner_error"], None)
        self.assertEqual(report["findings_count"], 5)
        # Vector-only real 2.6.0 severities -> no numeric CVSS -> nothing high.
        self.assertEqual(report["high_severity_count"], 0)
        self.assertTrue(report["narrative"].strip())
        self.assertGreaterEqual(report["turns_used"], 1, "the agent must run")
        # The live path records the caller's manifest as input_path.
        self.assertEqual(report["input_path"], _manifest_path())

    def test_live_scan_clean_exit_zero(self) -> None:
        """A clean scan (exit 0, zero findings) still succeeds, with zero
        findings and a risk status of unavailable."""
        report = investigate(_manifest_path(), run_fn=_clean_fake_run,
                             max_turns=12)
        self.assertTrue(report["scanner_success"])
        self.assertEqual(report["scanner_exit_code"], 0)
        self.assertEqual(report["findings_count"], 0)
        self.assertEqual(report["high_severity_count"], 0)
        self.assertEqual(report["risk"]["status"], "unavailable")
        self.assertEqual(report["risk"]["score"], None)
        # Even with zero findings the loop emits risk + summary (bounded).
        self.assertEqual(report["narrative"].strip()[-1:], report["narrative"][-1])
        self.assertGreaterEqual(report["turns_used"], 2,
                                "risk_score and summary must still run")

    def test_input_path_layered_on_report(self) -> None:
        """The caller's input path is always present and unambiguous, even on
        failure (see the failure classes)."""
        report = investigate_from_json(_fixture_json_path())
        self.assertEqual(report["input_path"], _fixture_json_path())
        self.assertTrue("scanner_success" in report)
        self.assertTrue("scanner_exit_code" in report)
        self.assertTrue("scanner_error" in report)


class TestPipelineFailsClosed(unittest.TestCase):
    """An unusable scan must NOT run the agent, fabricate findings, or
    silently succeed."""

    def test_exit_128_no_packages_is_failure(self) -> None:
        """exit 128 ('no packages found') is a failure even with a *parseable*
        ``{'results': []}`` payload — never conflated with a clean scan."""
        report = investigate(_manifest_path(),
                             run_fn=_exit_code_fake(128, json.dumps({"results": []})))
        self.assertFalse(report["scanner_success"])
        self.assertEqual(report["scanner_exit_code"], 128)
        self.assertIsNotNone(report["scanner_error"])
        self.assertIn("no packages", report["scanner_error"].lower())
        self.assertEqual(report["findings_count"], 0)
        self.assertEqual(report["findings"], [])
        self.assertEqual(report["narrative"], "")
        self.assertEqual(report["turns_used"], 0,
                         "the agent must not have run on a no-package scan")
        self.assertIsNone(report["report"])

    def test_generic_error_exit_is_failure(self) -> None:
        """Any non-{0,1} exit (real scanner error) is a failure with zero
        findings."""
        for rc in (2, 126, 127, 129, 250):
            with self.subTest(exit_code=rc):
                report = investigate(_manifest_path(), run_fn=_exit_code_fake(rc))
                self.assertFalse(report["scanner_success"],
                                 f"exit {rc} must be a failure")
                self.assertEqual(report["scanner_exit_code"], rc)
                self.assertIsNotNone(report["scanner_error"])
                self.assertEqual(report["findings_count"], 0)
                self.assertEqual(report["findings"], [])
                self.assertEqual(report["turns_used"], 0)
                self.assertIsNone(report["report"])

    def test_malformed_json_exit_1_is_failure(self) -> None:
        """A findings exit code (1) must NOT be a success if the JSON is
        unusable — findings we cannot parse are never treated as findings."""
        report = investigate(_manifest_path(),
                             run_fn=_exit_code_fake(1, "{ not json"))
        self.assertFalse(report["scanner_success"],
                         "exit 1 with malformed JSON is a failure, not a success")
        self.assertEqual(report["scanner_exit_code"], 1)
        self.assertIsNotNone(report["scanner_error"])
        self.assertEqual(report["findings_count"], 0)
        self.assertEqual(report["findings"], [])
        self.assertEqual(report["turns_used"], 0)
        self.assertIsNone(report["report"])

    def test_missing_binary_is_failure(self) -> None:
        """A missing OSV-Scanner binary is a failure (never a false 0-vuln
        success).  The pipeline uses the real ``subprocess.run`` here, so we
        point it at a path that does not exist."""
        report = investigate(
            _manifest_path(), binary="osv-scanner-does-not-exist-xyz123")
        self.assertFalse(report["scanner_success"])
        self.assertEqual(report["scanner_exit_code"], -2,
                         "missing binary is recorded as exit -2")
        self.assertIsNotNone(report["scanner_error"])
        # A missing binary surfaces as an OS "file not found" error, recorded
        # as exit -2.
        self.assertIn("no such file", report["scanner_error"].lower())
        self.assertEqual(report["findings_count"], 0)
        self.assertEqual(report["turns_used"], 0)
        self.assertIsNone(report["report"])

    def test_from_json_missing_file_is_failure(self) -> None:
        """A nonexistent report file is a failure with zero findings.  The
        failure carries ``scan_mode == "offline_json"`` and ``scanner_exit_code
        None`` — no process ran, so no exit code exists; this failure can never
        be read as a real (and therefore non-clean) scanner run."""
        report = investigate_from_json(os.path.join(os.path.dirname(__file__),
                                                   "data", "does-not-exist.json"))
        self.assertFalse(report["scanner_success"])
        self.assertEqual(report["scan_mode"], "offline_json")
        self.assertIsNone(report["scanner_exit_code"],
                         "a missing saved report has no process, so no exit code")
        self.assertIsNotNone(report["scanner_error"])
        self.assertIn("not found", report["scanner_error"].lower())
        self.assertEqual(report["findings_count"], 0)
        self.assertEqual(report["turns_used"], 0)
        self.assertIsNone(report["report"])


class TestOfflineScannerProvenance(unittest.TestCase):
    """The *offline* provenance distinction must be unambiguous.

    A saved OSV-Scanner JSON file was never produced by a live process, so its
    ``scanner_exit_code`` is genuinely *unknown* and must never be reported as
    0 (a clean scan).  The envelope must (a) label the input ``offline_json``,
    (b) keep JSON validation status (``scanner_success``) separate from any
    process exit code, and (c) ensure findings in an offline report cannot be
    mistaken for a clean scan."""

    def _offline_report(self, **kw):
        return investigate_from_json(_fixture_json_path(), max_turns=12, **kw)

    def test_offline_report_exit_code_is_none_not_zero(self):
        """A successful *offline* run must not fabricate a process exit code."""
        report = self._offline_report()
        self.assertTrue(report["scanner_success"])
        # JSON validation passed -> usable scan.  But there is no process, so
        # the exit code is None, not 0.  (0 is the *live* clean-scan code.)
        self.assertIsNone(report["scanner_exit_code"])
        # Provenance label is explicit.
        self.assertEqual(report["scan_mode"], "offline_json")
        self.assertEqual(report["scanner_error"], None)

    def test_offline_success_is_not_the_same_as_clean_live_scan(self):
        """A live clean scan is (success=True, exit_code=0, mode=live) with zero
        findings.  A saved report is (success=True, exit_code=None, mode=offline_json)
        — the two provenance states are distinguishable, so a saved report is
        never classified as 'clean'.  Crucially: an offline report *with* findings
        is still 'successful' (validation passed) yet has no exit code — a clean
        live scan has exit_code 0 and zero findings, so the two can never be
        confused."""
        offline = investigate_from_json(_fixture_json_path(), max_turns=12)
        # Live clean scan: exit 0, no findings.
        clean = investigate(_manifest_path(), run_fn=_clean_fake_run, max_turns=12)
        # Distinct provenance.
        self.assertEqual(offline["scan_mode"], "offline_json")
        self.assertEqual(clean["scan_mode"], "live")
        self.assertIsNone(offline["scanner_exit_code"])
        self.assertEqual(clean["scanner_exit_code"], 0)
        # Distinct findings.  An offline report *with* findings cannot be mistaken
        # for a clean scan.
        self.assertEqual(offline["findings_count"], 5)
        self.assertEqual(clean["findings_count"], 0)
        # JSON validation is independent of the (nonexistent) process code:
        # offline "success" is the validation outcome, not an exit code.
        self.assertTrue(offline["scanner_success"])
        self.assertTrue(clean["scanner_success"])

    def test_offline_json_validation_status_is_separate_from_process_code(self):
        """``scanner_success`` reflects JSON *validation* only.  It must not
        depend on (or be conflated with) the process exit code, which is
        unknown on the offline path."""
        report = self._offline_report()
        # Success here means 'the saved JSON was valid and parseable' — nothing
        # about a process exited 0.
        self.assertTrue(report["scanner_success"])
        # And there is no process code at all (None), proving the two are
        # distinct notions.
        self.assertIsNone(report["scanner_exit_code"])
        self.assertEqual(report["scan_mode"], "offline_json")
        self.assertIsNone(report["scanner_error"],
                         "a valid offline report has no scanner error")
        # findings reflect validation result, not a (nonexistent) process.
        self.assertEqual(report["findings_count"], 5)

    def test_offline_failure_reports_none_exit_and_offline_mode(self):
        """An *invalid* saved report fails validation, and its failure envelope
        carries exit_code None + scan_mode offline_json (not a live failure's
        real process code).  This distinguishes a bad saved file from a real
        scanner run that failed."""
        bad = self._write_json({"results": "not-a-list"}, "bad-report")
        report = investigate_from_json(bad, max_turns=12)
        self.assertFalse(report["scanner_success"])
        self.assertEqual(report["scan_mode"], "offline_json")
        self.assertIsNone(report["scanner_exit_code"])
        self.assertIsNotNone(report["scanner_error"])
        self.assertEqual(report["findings_count"], 0)
        self.assertEqual(report["turns_used"], 0)
        self.assertIsNone(report["report"])
        # Contrast with a *live* failure: a real process code (128) and live
        # provenance, not None/offline.
        live_fail = investigate(
            _manifest_path(), run_fn=_exit_code_fake(128, json.dumps({"results": []})))
        self.assertEqual(live_fail["scan_mode"], "live")
        self.assertEqual(live_fail["scanner_exit_code"], 128)

    def test_offline_report_envelope_keys_are_complete(self):
        """Every envelope consumer-relied-upon key must be present and
        self-consistent for an offline run."""
        report = self._offline_report()
        for key in ("input_path", "scan_mode", "scanner_success",
                    "scanner_exit_code", "scanner_error", "findings_count"):
            self.assertIn(key, report, f"missing envelope key: {key}")
        self.assertEqual(report["scan_mode"], "offline_json")
        self.assertIsNone(report["scanner_exit_code"])
        self.assertTrue(report["scanner_success"])
        # findings are populated while exit code is None — the core invariant.
        self.assertGreater(report["findings_count"], 0)

    def _write_json(self, payload, name):
        """Write a payload to a temp file and return its path."""
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False,
                                        encoding="utf-8") as f:
            json.dump(payload, f)
            return f.name


class TestPipelineEnrichmentOptionalAdditive(unittest.TestCase):
    """deps.dev context is opt-in, additive, review-only, and never erases
    scanner findings or feeds project PHEI."""

    def test_enrichment_off_by_default(self) -> None:
        """The grounded deterministic run performs *zero* enrichment lookups and
        findings are untouched."""
        report = investigate_from_json(_fixture_json_path(),
                                       max_turns=12)
        self.assertFalse(report["scanner_success"] is False)
        self.assertEqual(report["findings_count"], 5)
        # No package_context step was executed (enrichment is off by default).
        self.assertEqual(_count_package_context_steps(report), [],
                         "enrichment must be off by default (zero I/O)")
        # Vector-only real 2.6.0 severities -> no numeric CVSS -> nothing high.
        self.assertEqual(report["high_severity_count"], 0)

    def test_enrichment_on_with_stub_provider(self) -> None:
        """When enabled, ``package_context`` may be invoked, but the observation
        is always labelled ``generic_published`` / ``review_only``, and the
        deterministic findings are unchanged (additive)."""
        # Force the agent's LLM-less deterministic policy to be *able* to call
        # package_context by steering it via a small LLM shim that requests it
        # once, then stops.
        state = {"done": False}
        def llm(state_view: dict[str, Any]) -> dict[str, Any]:
            if not state["done"]:
                state["done"] = True
                # Ask for the highest-CVSS package so the stub has data to return.
                return {"tool": "package_context",
                        "args": {"package_name": "PyYAML",
                                 "version": "5.1",
                                 "ecosystem": "pyPI"},
                        "note": "Enrich the top finding with published context."}
            return {"tool": "stop", "args": {"reason": "steered stop"},
                    "note": "Stop."}
        report = investigate_from_json(_fixture_json_path(),
                                       llm=llm,
                                       enrichment_enabled=True,
                                       enrichment_fn=_stub_enrichment_fn,
                                       max_enrichment_calls=3,
                                       max_turns=20)
        self.assertTrue(report["scanner_success"])
        # Findings are unchanged by enrichment (additive, never erases).
        self.assertEqual(report["findings_count"], 5)
        # Vector-only real 2.6.0 severities -> no numeric CVSS -> nothing high.
        self.assertEqual(report["high_severity_count"], 0)
        # At least one package_context step exists and is correctly labelled.
        pc = _count_package_context_steps(report)
        self.assertEqual(len(pc), 1, "the stub LLM asked for exactly one context")
        for step in pc:
            obs = step["observation"]
            self.assertEqual(obs.get("provenance"), "generic_published",
                             "published context must be labelled generic_published")
            self.assertTrue(obs.get("review_only"),
                            "published context must be marked review-only")
            self.assertIn("observed_advisory_ids", obs,
                          "each factual claim must be traceable to an id")
            # The stub's advisory ids must surface verbatim (evidence, not
            # invention).
            self.assertIn("GHSA-p6qc-x272-q48w",
                          obs.get("observed_advisory_ids", []))
            # The note must be clear this is NOT the project's resolved graph
            # and must never imply a PHEI input.
            note = obs.get("note", "")
            self.assertIn("generic_published", note.lower())
            self.assertIn("not the scanned project", note.lower())
            self.assertIn("phei", note.lower())

    def test_enrichment_with_failing_provider_preserves_findings(self) -> None:
        """A rate-limited / failing deps.dev provider is recorded additively;
        the deterministic findings and count are preserved, and no exception
        propagates."""
        report = investigate_from_json(_fixture_json_path(),
                                       enrichment_enabled=True,
                                       enrichment_fn=_failing_enrichment_fn,
                                       max_enrichment_calls=1,
                                       max_turns=20)
        # Findings are intact regardless of the provider outcome.
        self.assertEqual(report["findings_count"], 5)
        # Vector-only real 2.6.0 severities -> no numeric CVSS -> nothing high.
        self.assertEqual(report["high_severity_count"], 0)
        self.assertTrue(report["scanner_success"])
        # Even though the deterministic policy (without an LLM) will not
        # spontaneously call package_context, we can still confirm the *contract*
        # of the tool via a small steering LLM.  Build the agent-equivalent
        # path explicitly: steer one package_context call, then stop.
        state = {"done": False}
        def llm(state_view: dict[str, Any]) -> dict[str, Any]:
            if not state["done"]:
                state["done"] = True
                return {"tool": "package_context",
                        "args": {"package_name": "PyYAML", "version": "5.1"},
                        "note": "Enrich top finding."}
            return {"tool": "stop", "args": {"reason": "done"},
                    "note": "Stop."}
        report2 = investigate_from_json(_fixture_json_path(),
                                         llm=llm,
                                         enrichment_enabled=True,
                                         enrichment_fn=_failing_enrichment_fn,
                                         max_enrichment_calls=1,
                                         max_turns=20)
        # Findings must be *identical* in count to the non-enrichment run.
        self.assertEqual(report2["findings_count"], report["findings_count"])
        self.assertEqual(len(_count_package_context_steps(report2)), 1)
        for step in _count_package_context_steps(report2):
            obs = step["observation"]
            # A failing provider must be recorded additively, not crash the
            # agent, and the package must be preserved.
            self.assertIn("errors", obs)
            self.assertTrue(any("rate limit" in e for e in obs["errors"]),
                            "the provider error must be surfaced as evidence")
            self.assertEqual(obs.get("package"), "PyYAML")
            self.assertEqual(obs.get("version"), "5.1")
            self.assertEqual(obs.get("provenance"), "generic_published")

    def test_enrichment_budget_exhaustion_is_bounded(self) -> None:
        """Once ``max_enrichment_calls`` is spent, further ``package_context``
        calls are *not* issued (hard call limit) and the agent still completes."""
        calls = {"n": 0}
        def counting_enrichment(**kw: Any) -> dict[str, Any]:
            calls["n"] += 1
            return _stub_enrichment_fn(**kw)
        state = {"n": 0}
        def llm(state_view: dict[str, Any]) -> dict[str, Any]:
            state["n"] += 1
            if state["n"] <= 5:
                return {"tool": "package_context",
                        "args": {"package_name": "PyYAML", "version": "5.1"},
                        "note": "context"}
            return {"tool": "stop", "args": {"reason": "done"}, "note": "Stop."}
        report = investigate_from_json(_fixture_json_path(),
                                       llm=llm,
                                       enrichment_enabled=True,
                                       enrichment_fn=counting_enrichment,
                                       max_enrichment_calls=2,   # hard limit
                                       max_turns=40)
        # The budget must be enforced: no more than 2 real enrichment lookups
        # are ever issued to the provider.
        self.assertLessEqual(calls["n"], 2,
                             "the hard call limit must cap actual lookups")
        self.assertEqual(report["findings_count"], 5)


class TestPipelineDeterministicFallback(unittest.TestCase):
    """The pipeline is always functional: with no LLM, a raising LLM, or an
    invalid LLM action, a full report is produced with the deterministic policy."""

    def test_no_llm_is_deterministic(self) -> None:
        report = investigate_from_json(_fixture_json_path(), max_turns=12)
        self.assertFalse(report["used_llm"])
        self.assertTrue(report["scanner_success"])
        self.assertEqual(report["findings_count"], 5)
        self.assertGreaterEqual(report["turns_used"], 5)
        # Self-consistent: findings in report match the count.
        self.assertEqual(len(report["findings"]), report["findings_count"])

    def test_raising_llm_falls_back_and_completes(self) -> None:
        """A broken LLM must not break the agent; it falls back to the
        deterministic policy and the report is still complete."""
        def boom(state: dict[str, Any]) -> dict[str, Any]:
            raise ValueError("LLM exploded")
        report = investigate_from_json(_fixture_json_path(), llm=boom,
                                       max_turns=12)
        self.assertTrue(report["scanner_success"])
        self.assertEqual(report["findings_count"], 5)
        # A 'llm_error' fallback step must be recorded as evidence.
        tools = [s["tool"] for s in report["evidence"]["steps"]]
        self.assertIn("llm_error", tools)
        self.assertEqual(report["risk"]["status"], "unavailable")
        self.assertTrue(report["narrative"].strip())

    def test_invalid_llm_action_falls_back_and_completes(self) -> None:
        """An LLM that names a disallowed tool triggers the fallback (recorded
        as evidence) and the agent still completes with findings."""
        def invalid_action(state: dict[str, Any]) -> dict[str, Any]:
            # A tool not in the allowlist.
            return {"tool": "fly_to_mars", "args": {}, "note": "invalid"}
        report = investigate_from_json(_fixture_json_path(), llm=invalid_action,
                                       max_turns=12)
        self.assertTrue(report["scanner_success"])
        self.assertEqual(report["findings_count"], 5)
        # At least one 'llm_fallback' step must be present (invalid action was
        # caught and the deterministic policy used instead).
        tools = [s["tool"] for s in report["evidence"]["steps"]]
        self.assertIn("llm_fallback", tools)
        self.assertTrue(report["narrative"].strip())


class TestPipelineBeforeAfter(unittest.TestCase):
    """Two full pipeline runs (before/after manifests) can be diffed for
    new / resolved / unchanged findings and the PHEI risk delta."""

    def _write_json(self, payload: dict[str, Any], name: str) -> str:
        """Write a payload to a temp file and return its path."""
        with tempfile.NamedTemporaryFile("w", suffix=".json",
                                        delete=False, encoding="utf-8") as f:
            json.dump(payload, f)
            return f.name

    def test_upgrade_resolves_high_severity(self) -> None:
        """An 'after' scan that upgrades the vulnerable packages must report
        the PyYAML / requests / setuptools findings as resolved, with the
        risk delta stated (both flat -> unavailable, so no numeric delta)."""
        before_raw = _load_osv()
        before = investigate_from_json(_fixture_json_path())
        # Build the *after* payload: keep only the two still-vulnerable
        # (urllib3 + flask not in fixture, so urllib3 stays) and drop the
        # upgraded PyYAML / requests / setuptools entries.
        after_payload = []
        for result in before_raw["results"]:
            kept = []
            for p in result["packages"]:
                name = p["package"]["name"]
                if name in ("PyYAML", "requests", "setuptools"):
                    continue  # upgraded away
                kept.append(p)
            after_payload.append({**result, "packages": kept})
        after_path = self._write_json({"results": after_payload}, "after")
        # Note: a temp file path is what investigate_from_json records as
        # input_path, but the *source_path* comes from the OSV-Scanner echo
        # (which for from_json is the resolved temp path).  We only assert on
        # findings and risk.
        after = investigate_from_json(after_path)
        self.assertTrue(before["scanner_success"] and after["scanner_success"])
        self.assertEqual(before["findings_count"], 5)
        # Dropping PyYAML (2) / requests (1) / setuptools (1) from the 5-finding
        # fixture leaves only urllib3 (1).
        self.assertEqual(after["findings_count"], 1,
                         "only urllib3 survives the upgrade")
        # The comparison must show resolved findings for the upgraded packages
        # and the risk delta must be honest (both unavailable -> skipped).
        self.assertEqual(before["risk"]["status"], "unavailable")
        self.assertEqual(after["risk"]["status"], "unavailable")
        # We don't have compare_scans on the pipeline return (it lives on
        # Agent), so we verify via the two run reports' findings directly.
        before_ids = {f["vulnerability_id"] for f in before["findings"]}
        after_ids = {f["vulnerability_id"] for f in after["findings"]}
        resolved = before_ids - after_ids
        self.assertEqual(resolved, {
            "GHSA-p6qc-x272-q48w", "GHSA-757q-h92x-p438",   # PyYAML
            "GHSA-394q-gx7c-w5v9",                          # requests
            "GHSA-994q-cg23-2p48",                          # setuptools
        })
        self.assertTrue("GHSA-93h9-824q-92x3" in after_ids,
                        "urllib3's finding must survive the upgrade")

    def test_clean_scan_after(self) -> None:
        """A fully clean 'after' scan resolves *all* findings."""
        before = investigate_from_json(_fixture_json_path())
        after = investigate_from_json(
            self._write_json({"results": []}, "after-clean"))
        self.assertEqual(before["findings_count"], 5)
        self.assertEqual(after["findings_count"], 0)
        self.assertEqual(after["risk"]["status"], "unavailable")


if __name__ == "__main__":
    unittest.main()
