"""End-to-end investigation pipeline: manifest -> scan -> normalize -> agent -> report.

This module is the glue that chains the individual, already-tested RECON-DG
building blocks into a single, demonstrable flow.  It adds no new scanning,
normalising, or scoring logic — it composes the existing pieces:

    1. :mod:`src.agent.scan_runner`   — ``run_scan`` / ``run_scan_from_json``
       (the OSV-Scanner subprocess wrapper; the *authoritative* scanner).
    2. :mod:`src.agent.normalizer`    — ``normalize_scan`` (raw OSV JSON ->
       :class:`DependencyGraph` + :class:`Finding`s).
    3. :mod:`src.agent.agent`         — :class:`Agent` (bounded, evidence-grounded
       tool loop, with optional *additive* deps.dev ``package_context``).

Two entry points, mirroring the scan runner's split:

* :func:`investigate`           — scan a *requirements manifest* with the live
  OSV-Scanner binary (needs ``osv-scanner`` on the path).  Tests inject a fake
  ``subprocess.run`` via ``run_fn`` so the whole flow is exercised without a
  real binary.
* :func:`investigate_from_json` — investigate a *pre-existing* OSV-Scanner JSON
  report with **no** binary (used in CI and whenever the scanner is unavailable).

Contract (the invariants this glue must never break):

* **OSV-Scanner findings are authoritative.**  If the scan is *not usable*
  (exit 128 "no packages", any other non-{0,1} exit code, malformed JSON, a
  timeout, or a missing binary), the pipeline returns a **failure envelope** and
  does *not* run the agent or fabricate findings.  A parseable-but-unusable
  payload is treated as a failure, exactly like ``scan_runner`` does.
* **deps.dev context is optional and additive.**  ``enrichment_enabled`` is
  False by default (zero network I/O on the grounded deterministic run).  When
  opted in, ``package_context`` is labelled ``generic_published``, is
  *review-only*, and is *never* used for project PHEI.  A failing provider is
  recorded additively and never erases the scanner findings.
* **Deterministic fallback.**  When the LLM is absent, returns an invalid
  action, or raises, the agent falls back to its grounded deterministic policy.
  The pipeline is always functional end-to-end.

Return shape (uniform on success *and* failure — callers may rely on these keys):

    input_path          -- the manifest / report path the caller asked about
    source_path         -- what OSV-Scanner echoed it scanned ("" on failure)
    scanner_success     -- bool; True only when the scan was usable
    scan_mode           -- "live" when the OSV-Scanner *binary* was invoked and
                           produced the payload, "offline_json" when the input
                           was a pre-existing saved JSON report (no process ran;
                           the envelope's scanner_exit_code is then None).
                           This is the authoritative, unambiguous provenance
                           label.
    scanner_exit_code   -- the true OSV-Scanner process exit code (int) on a live
                           scan; None on the offline path (a saved file has no
                           process, so the code is *unknown* and never reported
                           as 0, which could be mistaken for a clean scan).
    scanner_error       -- human-readable error (None on success)
    findings_count      -- number of findings (0 on failure)
    high_severity_count -- high-severity findings (0 on failure)
    severity_threshold  -- CVSS cutoff used for "high severity"
    risk                -- PHEI dict or None (never a fabricated score)
    narrative           -- plain-language summary ("" on failure)
    findings            -- list of finding dicts ([] on failure)
    evidence            -- the agent's evidence trail dict ({} empty steps on
                          failure)
    turns_used          -- trail step count (0 on failure)
    max_turns           -- loop cap
    used_llm            -- whether an LLM was supplied (not whether it drove)
    report              -- on failure only: ``None`` sentinel meaning "no report
                           was produced because the scan was unusable".
    remediation         -- on success, a dict with ``plan`` (the baseline remediation
                           plan) and ``verification`` (reconciled against an
                           after scan only when ``after_scan_report`` was supplied;
                           ``None`` when no after scan is supplied, so no resolution
                           claim is ever made without one).

Note: on *success* the returned dict *is* the agent report (with the extra
``scanner_*`` / ``input_path`` keys layered on); on *failure* it is a failure
envelope with ``report`` set to ``None``.
"""

from __future__ import annotations

import subprocess
from typing import Any, Callable, Optional

from src.agent.agent import (
    Agent,
    build_remediation_plan,
    verify_remediation,
)
from src.agent.normalizer import normalize_scan
from src.agent.scan_runner import run_scan, run_scan_from_json

# The ``run_fn`` injected into :func:`investigate` for tests is called exactly
# as :func:`run_scan` calls it: ``run_fn(argv, capture_output=..., text=...,
# timeout=...)`` where ``argv`` is the list built by ``construct_command``.  So
# the honest signature is a variadic callable returning a ``CompletedProcess``.
_RunFn = Optional[Callable[..., subprocess.CompletedProcess]]


def _failure_envelope(
    input_path: str,
    scanner_exit_code: int,
    scanner_error: str,
    *,
    max_turns: int,
    used_llm: bool,
    severity_threshold: float,
    scan_mode: str,
) -> dict[str, Any]:
    """Uniform failure shape: no scan was usable, so no findings, no report.

    ``scanner_exit_code`` is the true process code on a *live* failure (e.g. 128
    "no packages") and is ``None`` when the *offline* path failed validation —
    no process ran, so there is no exit code to report.  ``scan_mode`` is the
    unambiguous provenance label so the envelope can never be read as a real
    scanner run (and never as a clean scan).
    """
    return {
        "input_path": str(input_path),
        "source_path": "",
        "scanner_success": False,
        "scan_mode": scan_mode,
        "scanner_exit_code": scanner_exit_code,
        "scanner_error": scanner_error,
        "findings_count": 0,
        "high_severity_count": 0,
        "severity_threshold": severity_threshold,
        "risk": None,
        "narrative": "",
        "findings": [],
        "evidence": {"steps": []},
        "turns_used": 0,
        "max_turns": max_turns,
        "used_llm": used_llm,
        "report": None,
    }


def _run_agent(
    json_payload: Optional[dict[str, Any]],
    input_path: str,
    *,
    scanner_result: Any,
    llm: Optional[Callable[[dict[str, Any]], Optional[dict[str, Any]]]] = None,
    max_turns: int = 25,
    severity_threshold: float = 7.0,
    package_info_source: Optional[str] = None,
    enrichment_enabled: bool = False,
    enrichment_fn: Optional[Callable[..., dict[str, Any]]] = None,
    max_enrichment_calls: int = 5,
    after_scan_report: Optional[str] = None,
) -> dict[str, Any]:
    """Common body of ``investigate`` / ``investigate_from_json``.

    ``scanner_result`` is a :class:`ScanRunResult` (from either entry point).
    On an unusable scan we return the failure envelope *before* touching the
    normaliser or the agent — we never normalise or investigate a scan we
    cannot trust.  On a usable scan we normalise, run the agent, and layer the
    scanner metadata onto the agent report.

    When ``after_scan_report`` is supplied (a saved OSV-Scanner JSON report for
    a *subsequent* run), the baseline scan is turned into a remediation plan
    and that plan is verified against the after scan via :func:`verify_remediation`;
    the resulting ``remediation`` dict is layered onto the report.  A missing /
    unusable after report simply leaves verification ``not_run`` — it never
    blocks the baseline investigation and never makes a resolution claim.
    """
    used_llm = llm is not None

    # Authoritative gate: never run the agent (or fabricate findings) when the
    # OSV-Scanner run was not usable.  scan_runner has already classified the
    # exit code + payload shape; this simply honors that classification.
    if not scanner_result.success:
        return _failure_envelope(
            input_path, scanner_result.exit_code, scanner_result.error or "",
            max_turns=max_turns, used_llm=used_llm,
            severity_threshold=severity_threshold,
            # Unambiguous provenance: a live run that failed is "live"; a
            # saved-report file that failed to load/validate is "offline_json".
            scan_mode="offline_json" if scanner_result.offline_scan else "live",
        )

    scan = normalize_scan(scanner_result.json_payload)

    agent = Agent(
        scan,
        llm=llm,
        max_turns=max_turns,
        severity_threshold=severity_threshold,
        package_info_source=package_info_source,
        enrichment_enabled=enrichment_enabled,
        enrichment_fn=enrichment_fn,
        max_enrichment_calls=max_enrichment_calls,
    )

    report = agent.run()

    # Layer the caller's input path on top.  ``source_path`` is left as the
    # OSV-Scanner echo (the scanner's own statement of what it scanned);
    # ``input_path`` is unambiguously the file the caller asked about, so a
    # reviewer / dashboard can always answer "what was this report about?".
    report["input_path"] = str(input_path)
    report["scanner_success"] = True
    # Provenance: a live run carries the *true* process exit code (0 clean,
    # 1 findings).  An *offline* run (a saved report file) has no process, so
    # its exit code is genuinely unknown — recorded as None, never fabricated
    # as 0 (which would let a saved file be mistaken for a clean scan).
    # ``scan_mode`` is the explicit provenance label that makes this unambiguous.
    report["scan_mode"] = "offline_json" if scanner_result.offline_scan else "live"
    report["scanner_exit_code"] = scanner_result.exit_code
    report["scanner_error"] = None

    # Optional after-scan verification (bounded, evidence-grounded).  The plan
    # is built from the baseline scan and reconciled against the after scan only
    # when the caller explicitly supplies an after report path.  An unusable
    # after report fails closed to ``not_run`` and makes no resolution claim.
    if after_scan_report is None:
        report["remediation"] = None
    else:
        plan = build_remediation_plan(scan)
        after_run = run_scan_from_json(after_scan_report, binary="osv-scanner")
        if after_run.success:
            after_payload = after_run.json_payload
            # scan_runner guarantees a usable dict payload with ``results`` when
            # ``success`` is True; assert the invariant so the type checker
            # narrows to a non-None dict and the normaliser receives one.
            assert after_payload is not None, (
                "scan_runner sets json_payload whenever success is True"
            )
            after_scan = normalize_scan(after_payload)
            report["remediation"] = {
                "plan": plan,
                "verification": verify_remediation(scan, plan, after_scan),
            }
        else:
            # Malformed / missing after report: fail closed, no resolution
            # claim.  The baseline report is preserved untouched.
            report["remediation"] = {
                "plan": plan,
                "verification": {
                    "status": "not_run",
                    "resolution_claim": False,
                    "reason": (
                        f"after-scan report at {after_scan_report!r} is not "
                        f"usable ({after_run.error!r}); no verification was "
                        "run and no resolution claim is made."
                    ),
                    "summary": {"new_count": 0, "resolved_count": 0,
                                "unchanged_count": 0, "regression_count": 0},
                    "resolved": [], "unchanged": [], "regressed": [], "new": [],
                    "evidence": {
                        "steps": [
                            {
                                "turn": 0,
                                "tool": "verify_remediation",
                                "args": {
                                    "status": "not_run",
                                    "after_scan_supplied": True,
                                    "after_scan_error": after_run.error or "",
                                },
                                "observation": {
                                    "status": "not_run",
                                    "after_scan_supplied": True,
                                    "counts": {"new_count": 0, "resolved_count": 0,
                                                "unchanged_count": 0,
                                                "regression_count": 0},
                                },
                                "note": (
                                    "After-scan report could not be loaded or "
                                    "validated; verification was not run and no "
                                    "resolution claim is made."
                                ),
                            }
                        ]
                    },
                },
            }
    return report


def investigate(
    manifest: str,
    *,
    binary: str = "osv-scanner",
    fmt: str = "json",
    timeout_s: float = 300.0,
    llm: Optional[Callable[[dict[str, Any]], Optional[dict[str, Any]]]] = None,
    max_turns: int = 25,
    severity_threshold: float = 7.0,
    package_info_source: Optional[str] = None,
    enrichment_enabled: bool = False,
    enrichment_fn: Optional[Callable[..., dict[str, Any]]] = None,
    max_enrichment_calls: int = 5,
    run_fn: Optional[_RunFn] = None,
    after_scan_report: Optional[str] = None,
) -> dict[str, Any]:
    """Scan a *requirements manifest* with OSV-Scanner and run the investigation.

    This is the **live-scan** entry point.  It drives the real OSV-Scanner
    binary via :func:`run_scan`; ``run_fn`` exists only for tests (it replaces
    ``subprocess.run``) so the full pipeline — scan, validate, normalise,
    agent-loop, report — can be exercised without a real executable.

    Args:
        manifest: Path to the ``requirements.txt`` / lockfile to scan (file or
            directory).
        binary: OSV-Scanner executable (default ``osv-scanner``).
        fmt: Scanner output format (default ``json``).
        timeout_s: Subprocess timeout in seconds.
        llm: Optional pluggable LLM ("tool-selection brain").  May only name
            allowlisted tools; invalid / out-of-band selections fall back to
            the deterministic policy and are recorded as evidence.
        max_turns: Hard cap on the agent loop.
        severity_threshold: CVSS cutoff marking a finding "high severity".
        package_info_source: Label for where package metadata comes from.
        enrichment_enabled: Opt-in for *additive* deps.dev ``package_context``
            (review-only, ``generic_published``, never used for project PHEI).
            Default is False so the grounded run (and CI) does zero network I/O.
        enrichment_fn: Replaceable ``build_package_context``-shaped callable
            (defaults to the deps.dev client in ``src.enrichment``).
        max_enrichment_calls: Hard cap on enrichment lookups.
        run_fn: Injected ``subprocess.run``-shim (tests only).
    after_scan_report: Optional path to a saved OSV-Scanner JSON report for a
        *subsequent* run.  When supplied, the baseline scan is turned into a
        remediation plan and that plan is verified against the after scan
        (see :func:`verify_remediation`); the result is under ``report['remediation']``.
        When omitted (the default) verification is not run and
        ``remediation`` is ``None`` — no resolution claim is ever made without
        an explicit after scan.  A missing/malformed after report fails closed
        to ``not_run`` and makes no resolution claim.

    Returns:
        The uniform report dict (see module docstring).
    """
    scan_run = run_scan(
        manifest,
        binary=binary,
        fmt=fmt,
        timeout_s=timeout_s,
        run_fn=run_fn,
    )
    return _run_agent(
        scan_run.json_payload, manifest, scanner_result=scan_run,
        llm=llm, max_turns=max_turns, severity_threshold=severity_threshold,
        package_info_source=package_info_source,
        enrichment_enabled=enrichment_enabled, enrichment_fn=enrichment_fn,
        max_enrichment_calls=max_enrichment_calls,
        after_scan_report=after_scan_report,
    )


def investigate_from_json(
    scan_report: str,
    *,
    binary: str = "osv-scanner",
    llm: Optional[Callable[[dict[str, Any]], Optional[dict[str, Any]]]] = None,
    max_turns: int = 25,
    severity_threshold: float = 7.0,
    package_info_source: Optional[str] = None,
    enrichment_enabled: bool = False,
    enrichment_fn: Optional[Callable[..., dict[str, Any]]] = None,
    max_enrichment_calls: int = 5,
    after_scan_report: Optional[str] = None,
) -> dict[str, Any]:
    """Investigate a *pre-existing* OSV-Scanner JSON report (no binary needed).

    The **offline** entry point: reads a saved OSV-Scanner JSON report (top-level
    ``{"results": [...]}``) via :func:`run_scan_from_json` — which performs the
    exact same payload validation as a live scan — normalises it, and runs the
    agent.  This is what makes the prototype demonstrable in CI and on machines
    without OSV-Scanner installed.

    Args:
        scan_report: Path to the OSV-Scanner JSON report file.
        binary: OSV-Scanner binary name (only used as the recorded source label).
        llm: Optional LLM steering (same contract as :func:`investigate`).
        max_turns / severity_threshold / package_info_source: Agent options.
        enrichment_enabled / enrichment_fn / max_enrichment_calls: deps.dev
            enrichment options (same contract as :func:`investigate`).
        after_scan_report: Optional path to a saved OSV-Scanner JSON report for a
            *subsequent* run; when supplied, the baseline scan is turned into a
            remediation plan and verified against it (see the :func:`investigate`
            docstring for the ``remediation`` return shape and the fail-closed
            semantics).

    Returns:
        The uniform report dict (see module docstring).
    """
    scan_run = run_scan_from_json(scan_report, binary=binary)
    return _run_agent(
        scan_run.json_payload, scan_report, scanner_result=scan_run,
        llm=llm, max_turns=max_turns, severity_threshold=severity_threshold,
        package_info_source=package_info_source,
        enrichment_enabled=enrichment_enabled, enrichment_fn=enrichment_fn,
        max_enrichment_calls=max_enrichment_calls,
        after_scan_report=after_scan_report,
    )
