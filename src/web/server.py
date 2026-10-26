"""Minimal dashboard server (stdlib only — no Flask, no third-party deps).

This is the *minimal* end-to-end dashboard surface for the December deliverable:
it serves the self-contained ``src/web/dashboard.html`` page and a
``/report.json`` endpoint that returns the structured RECON-DG report (with the
additive ``ai_explanations`` field, if it was added) as JSON.

* It uses only the standard library (``http.server``) so it runs without any
  install — matching the constraint that the deterministic core (and the user)
  must not add third-party dependencies.
* It is a *read-only* server: it serves a report file and its page.  It does
  **not** re-run scans, edit manifests, or make any network call to an external
  service.  It does not accept or store user input, credentials, or API keys;
  any model endpoint is configured purely through the ``OPENAI_BASE_URL`` /
  ``OPENAI_API_KEY`` env vars (see ``src.explanation``) and the server never
  echoes them.
* It binds to ``127.0.0.1`` by default (the local endpoint is not exposed to
  the network).  A host/port can be overridden on the command line.
* The ``--model`` flag defaults to **OFF** (deterministic only).  When **ON**
  and both ``OPENAI_BASE_URL`` and ``OPENAI_API_KEY`` are set, per-finding
  data (package name, version, advisory ID, severity, affected range, fixed
  versions, recommended action) is transmitted to the configured endpoint over
  the transport in ``OPENAI_BASE_URL`` (unencrypted HTTP or HTTPS) along with
  the API key in the ``Authorization`` header.  The dashboard and report
  ``explanation_source`` summary never echo the key or endpoint.  Remote
  endpoint use is not approved by default; it requires explicit ``--model ON``.

Run:
    python -m src.web [--report FILE] [--port N] [--host HOST] [--model ON/OFF]
  where ``--model OFF`` (default) forces grounded deterministic text and
  ``--model ON`` enables the optional local-model explanation backend
  (falls back to deterministic per finding).
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, List, Optional

from src.explanation import add_explanations


def _resolve_report_path(report_arg: Optional[str]) -> str:
    """Resolve the report path: argument, env var, else the repo root."""
    if report_arg:
        return os.path.abspath(report_arg)
    env = os.environ.get("RECON_DG_REPORT")
    if env:
        return os.path.abspath(env)
    return os.path.abspath(os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "report.json"))


def _resolve_dashboard_path() -> str:
    return os.path.abspath(os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "dashboard.html"))


# ---------------------------------------------------------------------------
# Report preparation (done once at server start; the report is a snapshot)
# ---------------------------------------------------------------------------
def _prepare_report(report_path: str, use_model: bool) -> Dict[str, Any]:
    """Load the report, add the (additive) explanation layer, return it."""
    try:
        with open(report_path, "r", encoding="utf-8") as f:
            report: Any = json.load(f)
    except FileNotFoundError:
        report = {"findings": [], "findings_count": 0, "high_severity_count": 0}
    except Exception:
        report = {"error": "report is not valid JSON"}
    if not isinstance(report, dict):
        report = {"findings": [], "findings_count": 0, "high_severity_count": 0}

    # Add the explanation layer.  When use_model is True and a model endpoint/key
    # are configured, the local-model client is used (per-finding deterministic
    # fallback on any failure); otherwise the grounded deterministic text is
    # used directly.  add_explanations is additive and never modifies existing
    # fields.
    add_explanations(report, use_model=use_model)
    return report


# ---------------------------------------------------------------------------
# Handler
# ---------------------------------------------------------------------------
class _ReportHandler(BaseHTTPRequestHandler):
    """Serve the dashboard page (/) and the structured report (/report.json)."""

    report_bytes: bytes = b""
    dashboard_bytes: bytes = b"<!doctype html><title>loading</title>"
    report_path: str = ""

    # Class attributes are set in _build_server before the server starts, so
    # every request reads the same immutable snapshot.
    def _send(self, status: int, content_type: str, payload: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self) -> None:
        path = self.path.split("?", 1)[0]
        if path in ("/", "/index.html", "/dashboard.html"):
            self._send(200, "text/html; charset=utf-8", self.dashboard_bytes)
        elif path == "/report.json":
            self._send(200, "application/json; charset=utf-8", self.report_bytes)
        else:
            self._send(404, "text/plain; charset=utf-8", b"Not Found")

    # Quiet the default per-request log lines (the server prints its own banner).
    def log_message(self, format: str, *args: Any) -> None:
        pass


def _build_server(host: str, port: int, report_path: str, use_model: bool) -> ThreadingHTTPServer:
    report = _prepare_report(report_path, use_model)
    report_bytes = json.dumps(report, indent=2, ensure_ascii=False).encode("utf-8")
    with open(_resolve_dashboard_path(), "rb") as f:
        dashboard_bytes = f.read()
    _ReportHandler.report_bytes = report_bytes
    _ReportHandler.dashboard_bytes = dashboard_bytes
    _ReportHandler.report_path = report_path
    return ThreadingHTTPServer((host, port), _ReportHandler)


def main(argv: Optional[list] = None) -> int:
    ap = argparse.ArgumentParser(
        description="RECON-DG dashboard (stdlib http.server).")
    ap.add_argument("--report", type=str, default=None,
        help="Path to the JSON report to serve "
             "(default: $RECON_DG_REPORT, else report.json in the repo root)")
    ap.add_argument("--port", type=int, default=8000)
    ap.add_argument("--host", type=str, default="127.0.0.1")
    ap.add_argument("--model", type=str, default="OFF",
        help="OFF (default) forces grounded deterministic text. "
             "ON enables the optional local-model explanation backend "
             "(falls back to deterministic per finding). "
             "When ON and OPENAI_BASE_URL/OpenAI_API_KEY are configured, "
             "each finding's package name, version, advisory ID, severity, "
             "affected range, fixed versions, and recommended action are "
             "sent to the configured endpoint (HTTP or HTTPS) along with "
             "the API key in the Authorization header.")
    args = ap.parse_args(argv)

    report_path = _resolve_report_path(args.report)
    use_model = args.model.upper() == "ON"
    try:
        server = _build_server(args.host, args.port, report_path, use_model)
    except Exception as exc:
        print(f"error: could not build server: {exc}", file=sys.stderr)
        return 1

    url = f"http://{args.host}:{args.port}"
    print(f"RECON-DG dashboard -> {url}/  (page)  and  {url}/report.json",
          file=sys.stderr)
    print(f"report: {report_path}", file=sys.stderr)
    print("bind: local only (host=%s). Ctrl-C to stop." % args.host,
          file=sys.stderr)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
