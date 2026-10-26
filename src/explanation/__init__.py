"""RECON-DG explanation layer (default + optional local-model backend).

This package adds *additive* human-friendly explanations to an already-built
report dict.  The default backend is :func:`deterministic.explain_findings`
(grounded, no network, no model) — this is the guaranteed fallback and is what
is used when no model endpoint is configured.  The optional
:class:`local_model.OpenAILocalClient` targets a single OpenAI-compatible local
``/v1/chat/completions`` endpoint (stdlib ``urllib`` only, env-only credentials,
hardly-bounded requests) and falls back per-finding to the deterministic text
on any failure.

By default, ``add_explanations()`` uses the deterministic backend only
(``use_model=False``).  When ``use_model=True`` and both ``OPENAI_BASE_URL``
and ``OPENAI_API_KEY`` are set, per-finding data (package name, version,
advisory ID, severity, affected range, fixed versions, recommended action)
is transmitted to the configured endpoint over the transport in
``OPENAI_BASE_URL`` (unencrypted HTTP or HTTPS) along with the API key in
the ``Authorization`` header.  The dashboard and report
``explanation_source`` summary never echo the key or endpoint.  Remote
endpoint use is not approved by default; it requires explicit opt-in.

This package never modifies finding facts, the remediation block, the
after-scan verification block, the PHEI risk, or any severity value; it only
adds a new top-level key (``report["ai_explanations"]``) and a summary
(``report["explanation_source"]``) that never repeats the API key or endpoint.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from .deterministic import (
    explain_findings,
    explain_finding,
    severity_status,
    fixed_version_text,
)
from .local_model import (
    LocalModelError,
    LocalModelConfig,
    OpenAILocalClient,
    explain as explain_local,
)

__all__ = [
    "add_explanations",
    "explain_finding",
    "explain_findings",
    "severity_status",
    "fixed_version_text",
    "OpenAILocalClient",
    "LocalModelConfig",
    "LocalModelError",
    "explain_local",
]


def add_explanations(
    report: Dict[str, Any],
    config: Optional[LocalModelConfig] = None,
    use_model: bool = False,  # safe default: no remote requests unless explicitly enabled
) -> Dict[str, Any]:
    """Add an ``ai_explanations`` key to an already-built report.

    * ``use_model`` — if True and a model endpoint/key is configured, the
      local-model client is used; it falls back to the deterministic text per
      finding on any failure.  If ``use_model`` is False (or nothing is
      configured) the grounded deterministic text is used directly.
      **Default is False** so that the dashboard and reporter do not send
      findings to a remote endpoint unless the user explicitly enables it.
    * **Additive and non-throwing.** The function mutates and returns the same
      report dict, adding only ``ai_explanations`` (a list aligned with
      ``report["findings"]``) and ``explanation_source`` (a summary that counts
      model vs deterministic entries; it never contains the API key or endpoint
      URL).  A malformed ``report`` (no ``findings``) yields an empty list.

    Returns the mutated report so callers can do ``report = add_explanations(report)``.
    """
    findings = report.get("findings") or []
    if not isinstance(findings, list):
        findings = []
    remediation = report.get("remediation")
    plan = None
    if isinstance(remediation, dict):
        plan = remediation.get("plan")

    model_configured = False
    if use_model:
        cfg = config
        if cfg is None:
            cfg = LocalModelConfig()
        # A model is only "configured" when both an endpoint and a key exist.
        model_configured = bool(cfg.base_url and cfg.api_key)
        if model_configured:
            entries = OpenAILocalClient(cfg).explain(findings, plan)
        else:
            entries = [{"text": t, "source": "deterministic"} for t
                       in _deterministic_entries(findings, plan)]
    else:
        entries = [{"text": t, "source": "deterministic"} for t
                   in _deterministic_entries(findings, plan)]

    model_count = sum(1 for e in entries if e.get("source") == "model")
    det_count = len(entries) - model_count
    report["ai_explanations"] = entries
    report["explanation_source"] = {
        "model": model_count,
        "deterministic": det_count,
        "model_configured": model_configured,
        "total": len(entries),
    }
    return report


def _deterministic_entries(findings: List[Dict[str, Any]],
                          plan: Optional[Dict[str, Any]]) -> List[str]:
    """Grounded deterministic text per finding (used when no model is used)."""
    by_id: Dict[str, Dict[str, Any]] = {}
    if isinstance(plan, dict):
        for item in plan.get("items") or []:
            if isinstance(item, dict) and item.get("vulnerability_id"):
                by_id[item["vulnerability_id"]] = item
    out: List[str] = []
    for f in findings:
        adv = f.get("vulnerability_id")
        item = by_id.get(adv) if isinstance(adv, str) else None
        out.append(explain_finding(f, item))
    return out
