"""RECON-DG minimal web dashboard (stdlib only).

``python -m src.web`` serves the self-contained ``dashboard.html`` page at
``/`` and the structured report at ``/report.json``.  This module exposes the
server-building helper and the report-preparation helper for programmatic /
test use; the CLI entry point lives in ``__main__.py``.

No third-party dependencies (no Flask).  Bind to localhost by default.
"""

from __future__ import annotations

from .server import (
    _build_server as build_server,
    _prepare_report as prepare_report,
    _resolve_dashboard_path,
    _resolve_report_path,
    main,
)

__all__ = [
    "build_server",
    "prepare_report",
    "resolve_dashboard_path",
    "resolve_report_path",
    "main",
]
