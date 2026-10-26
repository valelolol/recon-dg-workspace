"""Thin OSV-Scanner subprocess wrapper.

RECON-DG does not re-implement scanning; it drives the established
open-source **OSV-Scanner** (https://github.com/google/osv-scanner) via a
subprocess. This module is the *only* place the scanner binary is invoked and
the raw JSON is parsed. It keeps the integration to a deliberately small,
well-documented surface:

- :func:`construct_command`  -- builds the exact argv for ``osv-scanner``.
- :func:`run_scan`           -- runs the scanner, validates the process, and
  returns a :class:`ScanRunResult` (exit code, JSON payload, error capture).
- :func:`run_scan_from_json` -- reads a pre-existing JSON report file (used in
  tests / when the scanner binary is unavailable) and validates it.
- :class:`ScanRunResult`     -- the single return object every consumer uses.

The wrapper is *evidence-grounded*: it never rewrites a finding, it records the
real OSV-Scanner JSON as-is, and it reports the true exit code. It implements
the documented OSV-Scanner return codes
(https://google.github.io/osv-scanner/output/#return-codes)::

    exit 0        packages found, no vulnerabilities/findings -> clean
    exit 1        packages found, vulnerabilities present     -> findings
                                                          (a *successful* scan)
    exit 2..126   reserved vulnerability-result related errors -> failure
    exit 127      general error                             -> failure
    exit 128      no packages found (scanned nothing)       -> no-package case
    exit 129..255 non-result related errors                 -> failure

A scan is therefore *usable* (we preserve and parse its findings) exactly when
the process exits 0 (clean) or 1 (findings) and emits a valid JSON payload with
a ``results`` list.  A "no packages found" run (128), any other exit code,
malformed JSON, a timeout, or a missing binary is a failure that the caller sees
explicitly — it is never collapsed into a false "0 vulnerabilities" result.
"""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Optional


# OSV-Scanner documented return codes (see the module docstring for the table).
#   0      packages found, no vulnerabilities/findings
#   1      packages found, vulnerabilities/findings present  (a *successful*
#          scan WITH findings — not an error)
#   2..126 reserved for vulnerability-result related errors
#   127    general error
#   128    no packages found (scanned nothing / unsupported file)
#   129..255 reserved for non-result related errors
_SUCCESS_EXIT_CODES = {0, 1}
_NO_PACKAGES_EXIT_CODE = 128


@dataclass
class ScanRunResult:
    """Result of one OSV-Scanner run.

    Attributes
    ----------
    exit_code : int
        The true exit code from the OSV-Scanner process (0 clean, 1 findings,
        128 config error).  ``None`` on the *offline* path (`run_scan_from_json`)
        — a saved report has no process, so no real exit code exists; it is never
        reported as 0.
    stdout : str
        Raw stdout (the JSON report on success).
    stderr : str
        Raw stderr (warnings/errors).
    json_payload : Optional[dict[str, Any]]
        Parsed JSON (top-level ``{"results": [...]}``) when parseable; ``None``
        otherwise.
    source_path : str
        The file scanned (absolute path) on success.
    success : bool
        True when the scan is *usable*: the process exited 0 (clean) or 1
        (findings present — a real, successful scan) AND emitted valid JSON with
        a ``results`` list. Every other outcome — "no packages found" (128), any
        other exit code, malformed JSON, a timeout, a missing binary — is False
        with an explicit ``error``. A "0 vulns / clean" scan (exit 0, empty
        results) is success; a "no packages found" scan (exit 128) is *not*
        success, so the two are never conflated.
    error : Optional[str]
        A human-readable error when ``success`` is False.
    offline_scan : bool
        True when this run came from the *offline* path (:func:`run_scan_from_json`,
        i.e. a pre-existing JSON report file, not a live OSV-Scanner process).
        A live run is False.  Consumers must never treat an ``offline_scan``
        run's ``exit_code`` as a real process exit code — it is only present so
        callers can distinguish "we ran the binary" from "we validated a saved
        report".
    """

    exit_code: Optional[int]
    stdout: str = ""
    stderr: str = ""
    json_payload: Optional[dict[str, Any]] = None
    source_path: str = ""
    success: bool = False
    error: Optional[str] = None
    offline_scan: bool = False

    def payload(self) -> dict[str, Any]:
        """Return the parsed payload, or raise ValueError when absent."""
        if self.json_payload is None:
            raise ValueError("scan did not produce parseable JSON")
        return self.json_payload


def construct_command(source: str, binary: str = "osv-scanner", fmt: str = "json") -> list[str]:
    """Build the argv for OSV-Scanner.

    Args
    ---
    source : str
        The file/directory to scan (the ``requirements.txt`` / lockfile).
    binary : str
        Path or name of the OSV-Scanner executable.
    fmt : str
        Output format; ``json`` is what RECON-DG consumes.

    Returns
    -------
    list[str]
        The exact command line, in the form documented by OSV-Scanner
        (<https://google.github.io/osv-scanner/usage/>)::

            osv-scanner scan --format json <path>

        i.e. ``[binary, "scan", "--format", fmt, source]``.  The ``scan``
        subcommand is the documented default ("scan source" is the default
        subcommand), so we include it explicitly for clarity.  The format is
        the long ``--format`` flag (the short ``-f`` is a generic clap flag
        that is *not* documented for OSV-Scanner).
    """
    return [binary, "scan", "--format", fmt, source]


def run_scan(
    source: str,
    binary: str = "osv-scanner",
    fmt: str = "json",
    timeout_s: float = 300.0,
    run_fn: Optional[Callable[[str], subprocess.CompletedProcess]] = None,
) -> ScanRunResult:
    """Run OSV-Scanner against ``source`` and return a :class:`ScanRunResult`.

    The ``run_fn`` hook exists so tests can inject a fake ``subprocess.run``
    (no real binary needed) while still exercising the *same* validation
    path the production call takes.

    Args
    ---
    source : str
        File/directory to scan.
    binary : str
        OSV-Scanner binary (default ``osv-scanner``).
    fmt : str
        Output format (default ``json``).
    timeout_s : float
        Subprocess timeout in seconds.
    run_fn : callable
        Injected ``subprocess.run``-shim. Must be ``run_fn(argv) ->
        CompletedProcess``. Used in tests to avoid a real binary.
    """
    argv = construct_command(source, binary, fmt)
    if run_fn is None:
        run_fn = subprocess.run
    try:
        proc = run_fn(argv, capture_output=True, text=True, timeout=timeout_s)
    except FileNotFoundError as exc:
        return ScanRunResult(
            exit_code=-2,
            stderr=f"OSV-Scanner binary not found at {binary!r}",
            success=False,
            error=str(exc),
        )
    except subprocess.TimeoutExpired as exc:
        return ScanRunResult(
            exit_code=-3,
            stderr=str(exc),
            success=False,
            error=f"scanner timed out after {timeout_s}s",
        )

    raw_out = proc.stdout or ""
    raw_err = proc.stderr or ""
    payload: Optional[dict[str, Any]] = None
    error: Optional[str] = None
    try:
        parsed = json.loads(raw_out)
    except json.JSONDecodeError as exc:
        error = f"scanner JSON is not valid JSON: {exc}"
    else:
        # The payload is *usable* only when it is an object whose "results"
        # value is a list (the documented OSV-Scanner shape).  On any shape
        # violation the parsed value is discarded (payload stays None) so the
        # success gate below treats a parseable-but-unusable report as a
        # failure rather than a successful scan.
        if not isinstance(parsed, dict):
            error = "scanner JSON top level is not an object"
        elif "results" not in parsed:
            error = "scanner JSON missing required 'results' key"
        elif not isinstance(parsed["results"], list):
            error = "scanner JSON 'results' is not a list"
        else:
            payload = parsed

    exit_code = proc.returncode
    # A scan is *usable* (we preserve and parse its findings) only when the
    # OSV-Scanner process exits 0 (clean) or 1 (findings present) AND emitted a
    # valid JSON payload with a ``results`` list.  Exit 1 with findings is a
    # successful scan, not an error (see the module docstring for the full
    # documented return-code table).
    success = exit_code in _SUCCESS_EXIT_CODES and payload is not None
    if not success:
        if error is None and exit_code == _NO_PACKAGES_EXIT_CODE:
            error = (
                "scanner exit code 128: no packages were found (scanned file "
                "unsupported or empty). This is not a clean scan; no findings "
                "are produced."
            )
        elif error is None:
            if exit_code in _SUCCESS_EXIT_CODES:
                # Exited clean/findings but no usable JSON payload to preserve.
                error = (
                    f"scanner exited with code {exit_code} but produced no "
                    f"usable JSON payload (stdout={raw_out[:80]!r}); findings "
                    f"cannot be preserved."
                )
            else:
                # Any other non-success exit (2..126, 127, 129..255) is a real
                # scanner error.
                error = (
                    f"scanner exit code {exit_code} is not a clean (0) or "
                    f"findings (1) code per the OSV-Scanner docs; "
                    f"stdout={raw_out[:80]!r} stderr={raw_err[:80]!r}"
                )
    return ScanRunResult(
        exit_code=exit_code,
        stdout=raw_out,
        stderr=raw_err,
        json_payload=payload,
        source_path=str(source),
        success=success,
        error=error,
    )


def run_scan_from_json(path: str, binary: str = "osv-scanner") -> ScanRunResult:
    """Read a pre-existing OSV-Scanner JSON report and validate it.

    This is the *offline* path used in tests and when the binary is absent:
    it still performs the exact same payload validation as :func:`run_scan`,
    so a malformed file is never silently accepted.

    Args
    ---
    path : str
        Path to the JSON report (top-level ``{"results": [...]}``).
    """
    p = Path(path)
    if not p.exists():
        return ScanRunResult(
            exit_code=None,
            error=f"scan report file not found: {p}",
            success=False,
            offline_scan=True,
        )
    try:
        payload = json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return ScanRunResult(
            exit_code=None,
            stderr=str(exc),
            error=f"scan report JSON is not valid JSON: {exc}",
            success=False,
            offline_scan=True,
        )
    if not isinstance(payload, dict):
        return ScanRunResult(exit_code=None, error="report top level is not a JSON object", success=False, offline_scan=True)
    if "results" not in payload:
        return ScanRunResult(exit_code=None, error="report missing required 'results' key", success=False, offline_scan=True)
    if not isinstance(payload["results"], list):
        return ScanRunResult(exit_code=None, error="report 'results' is not a list", success=False, offline_scan=True)
    return ScanRunResult(
        # A saved report has *no process*, so no real exit code exists.
        # exit_code stays None rather than a fabricated 0.  ``success`` (True)
        # is the JSON-validation outcome, kept separate from any process code;
        # ``offline_scan`` / the envelope's ``scan_mode`` label identifies the
        # input as offline.  This is deliberately *not* 0: 0 is a real "clean"
        # live result, and a saved file can never be mistaken for a clean scan.
        exit_code=None,
        json_payload=payload,
        source_path=str(p.resolve()),
        success=True,
        offline_scan=True,
    )


def results_from(result: ScanRunResult):
    """Return the parsed ``results`` list from a successful run (else raise)."""
    return result.payload()["results"]
