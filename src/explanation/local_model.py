"""OpenAI-compatible local model backend (stdlib only).

A client for an *OpenAI-compatible* local model endpoint (e.g. a local llama.cpp
server, Ollama in OpenAI-compat mode, or a user-provided model) that can be used
as the optional AI explanation backend.  It talks only to the single
``/v1/chat/completions`` endpoint over plain HTTP(S) via the standard library
(``urllib.request``) — **no third-party package is required** (the user must not
install anything for the deterministic core, and the *default* explanation
backend is the deterministic one anyway).

Safety invariants (these match the project's rules for the AI layer):

* The client is **strictly additive**. It produces a per-finding human
  explanation that is stored in a *new* key (``report['ai_explanations']``); it
  never edits any finding field, the remediation block, the after-scan
  verification block, the PHEI risk, or any severity value.
* **Deterministic fallback is guaranteed.** On *any* per-finding failure — a
  network error, a timeout, a non-2xx status, a malformed body, an empty or
  non-string completion, or an API key/base URL not being set — that finding
  falls back to the grounded deterministic explanation.  A missing/broken
  backend therefore never blocks or corrupts the report; it only loses the
  "model" label on that finding.
* **Credentials come only from the environment** (``OPENAI_API_KEY`` and
  ``OPENAI_BASE_URL``), never from a file checked into the repo and never
  written back into any report, log, or dashboard payload.  The base URL is
  *user-provided* (a local endpoint), so this client makes no assumption about
  any specific service.
* The request is **bounded**: a hard request timeout, a hard ``max_tokens`` cap,
  and a hard cap on the number of requests issued (default: one per finding).

The client can be invoked directly by the reporter/dashboard to add the
``ai_explanations`` field to an already-built report dict, or wrapped as a
``llm``-style hook for agent steering.  It is *not* wired into the agent loop
here, because the agent already has its own deterministic policy; this module
only adds the human-facing AI explanation field.
"""

from __future__ import annotations

import json
import os
import urllib.request
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, cast

from src.explanation.deterministic import explain_finding as _deterministic_single


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
@dataclass
class LocalModelConfig:
    """Configuration for the OpenAI-compatible local backend.

    Defaults are chosen to be *safe on a machine with no local model running*:
    if ``base_url`` is unset, no request is ever issued (immediate deterministic
    fallback).  ``api_key`` defaults to the ``OPENAI_API_KEY`` env var so that
    secrets live only in the environment.
    """

    base_url: str = ""
    api_key: Optional[str] = None
    model: str = "gpt-3.5-turbo"
    temperature: float = 0.0
    top_p: float = 1.0
    max_tokens: int = 256
    timeout_s: float = 10.0
    # Hard cap on the number of requests this client will issue per invocation.
    max_calls: Optional[int] = None  # None -> one per finding

    def __post_init__(self) -> None:
        if self.api_key is None:
            self.api_key = os.environ.get("OPENAI_API_KEY") or ""
        if not self.base_url:
            self.base_url = os.environ.get("OPENAI_BASE_URL", "")
        self.timeout_s = max(0.0, float(self.timeout_s))
        self.max_tokens = max(1, int(self.max_tokens))


# ---------------------------------------------------------------------------
# Raw HTTP transport (stdlib urllib)
# ---------------------------------------------------------------------------
class LocalModelError(Exception):
    """Any failure to reach or use the model endpoint (network, status, decode)."""


def _chat_completions_request(
    base_url: str,
    api_key: Optional[str],
    model: str,
    messages: List[Dict[str, str]],
    *,
    temperature: float = 0.0,
    top_p: float = 1.0,
    max_tokens: int = 256,
    timeout_s: float = 10.0,
    transport: Optional[Callable[..., Any]] = None,
) -> Dict[str, Any]:
    """Build and issue a single /v1/chat/completions request.

    Returns the parsed JSON body.  The ``transport`` parameter is the injection
    seam for tests: it is called as ``transport(request)`` and must return a raw
    HTTP response object (something with ``.status``/``.code`` and ``.read()``).
    Passing ``None`` uses the real ``urllib.request.urlopen`` with a one-shot
    timeout.
    """
    endpoint = base_url.rstrip("/") + "/v1/chat/completions"
    body = {
        "model": model,
        "messages": messages,
        "temperature": float(temperature),
        "top_p": float(top_p),
        "max_tokens": int(max_tokens),
        "stream": False,
    }
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key or ''}",
        "Accept": "application/json",
    }
    req = urllib.request.Request(
        endpoint,
        data=json.dumps(body).encode("utf-8"),
        headers=headers,
        method="POST",
    )
    if transport is None:
        resp = urllib.request.urlopen(req, timeout=timeout_s)
    else:
        resp = transport(req)
    raw = resp.read()
    resp_code = getattr(resp, "status", None) or getattr(resp, "code", 200)
    text = raw.decode("utf-8", "replace")
    if int(resp_code) not in (200,):
        raise LocalModelError(f"model endpoint returned status {resp_code}")
    return json.loads(text)


def _extract_completion(payload: Dict[str, Any]) -> str:
    """Return the single model text from a chat-completions payload (or raise)."""
    choices = payload.get("choices")
    if not isinstance(choices, list) or not choices:
        raise LocalModelError("model response had no choices")
    choice = choices[0]
    if not isinstance(choice, dict):
        raise LocalModelError("model response choice is not an object")
    message = choice.get("message")
    if not isinstance(message, dict):
        raise LocalModelError("model response message is not an object")
    content = message.get("content")
    if not isinstance(content, str) or not content.strip():
        raise LocalModelError("model returned empty or non-string completion")
    return content.strip()


# ---------------------------------------------------------------------------
# Prompt building (grounded — the model may only restate what we give it)
# ---------------------------------------------------------------------------
def _finding_prompt(f: Dict[str, Any],
                   item: Optional[Dict[str, Any]]) -> str:
    """System + user prompt for *one* finding, carrying only grounded facts.

    The model is explicitly instructed to restate only these fields and to
    never invent a numeric score, a version, or a CVE.  This is what makes the
    model output safe to display alongside the deterministic finding.
    """
    pkg = f.get("package_name", "unknown")
    ver = f.get("version", "unknown")
    adv = f.get("vulnerability_id", "unknown")
    aliases = f.get("aliases") or []
    aliases_str = f" (aliases: {', '.join(aliases)})" if aliases else f" (advisory {adv})"
    spec = f.get("vulnerability_spec") or "unspecified"
    score = f.get("severity_score")
    score_str = f"CVSS {float(score):.1f}" if score is not None else "none reported"
    vec = f.get("severity_vector")
    vec_str = f" severity_vector={vec}" if vec else ""
    types = f.get("severity_types") or []
    types_str = f" severity_types={types}" if types else ""
    pub = f.get("published") or "unspecified"
    fixed = [str(v) for v in (f.get("fixed_versions") or []) if str(v)]
    fixed_str = ", ".join(fixed) or "none provided"
    action = (
        item.get("recommended_action", "")
        if isinstance(item, dict)
        else ""
    )
    action_str = f" Recommended action (from the deterministic plan): {action}." if action else ""

    return (
        "You are RECON-DG's plain-language explainer. Explain exactly the "
        "single vulnerability finding below in 2-3 sentences, in plain "
        "language for a developer. Restate ONLY the facts listed; do NOT invent "
        "a numeric CVSS score, a version number, a CVE identifier, or any "
        "fact not present. If no numeric CVSS score is reported, say so and do "
        "not fabricate one. Do not claim the vulnerability is resolved or that "
        "a fix was verified; you only explain the finding and the recommended "
        "action.\n\n"
        "Facts (grounded, from the OSV-Scanner scan):\n"
        f"- package_name: {pkg}\n"
        f"- version: {ver}\n"
        f"- vulnerability_id: {adv}\n"
        f"- advisory_type: {f.get('advisory_type', 'MAINTAINER_ADVISORY')}\n"
        f"- published: {pub}\n"
        f"- affected range: {spec}\n"
        f"- numeric severity_score: {score_str}\n"
        f"{vec_str}{types_str}\n"
        f"- scanner-provided fixed versions: {fixed_str}\n"
        f"Recommended action (deterministic, authoritative for the action line): "
        f"{action or 'none'}\n"
    )


def _system_prompt() -> str:
    return (
        "You explain RECON-DG vulnerability findings in plain, concise "
        "language. Never invent a numeric CVSS score, a version, a CVE, or "
        "any fact not explicitly given. Never claim a fix is verified or that "
        "the finding is resolved. Output the explanation text only (no markdown "
        "fences, no extra commentary)."
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
class OpenAILocalClient:
    """Explain findings via an OpenAI-compatible local endpoint (with
    guaranteed deterministic fallback)."""

    def __init__(self, config: Optional[LocalModelConfig] = None,
                 transport: Optional[Callable[..., Any]] = None) -> None:
        self.config = config or LocalModelConfig()
        self._transport = transport  # injected seam for tests; None -> urllib

    def explain(
        self,
        findings: List[Dict[str, Any]],
        remediation_plan: Optional[Dict[str, Any]] = None,
    ) -> List[Dict[str, str]]:
        """Return per-finding AI explanations with provenance.

        Each result is a dict ``{"text": str, "source": "model"|"deterministic"}``.
        ``source`` is ``"model"`` only when that specific finding was answered
        by the local model and the answer is non-empty; every other failure
        path (including the base case of no configured endpoint/key) yields
        ``"deterministic"`` with the grounded deterministic text.  The returned
        list is always aligned one-to-one with ``findings``.
        """
        # Build the deterministic baseline up front — it is the guaranteed
        # fallback and is used when the endpoint is not configured at all.
        by_id: Dict[str, Dict[str, Any]] = {}
        if isinstance(remediation_plan, dict):
            for item in remediation_plan.get("items") or []:
                if isinstance(item, dict) and item.get("vulnerability_id"):
                    by_id[item["vulnerability_id"]] = item

        def det_for(i: int) -> str:
            f = findings[i]
            adv = f.get("vulnerability_id")
            item = by_id.get(adv) if isinstance(adv, str) else None
            return _deterministic_single(f, item)

        cfg = self.config
        # No configured base_url OR no API key -> no request is ever issued;
        # return the grounded deterministic explanations immediately.
        if not cfg.base_url or not cfg.api_key:
            return [{"text": det_for(i), "source": "deterministic"} for i in range(len(findings))]

        calls = 0
        limit = cfg.max_calls if cfg.max_calls is not None else len(findings)
        out: List[Dict[str, str]] = []
        for i, f in enumerate(findings):
            if calls >= limit:
                # Hard cap: stop issuing requests; the rest fall back.
                out.append({"text": det_for(i), "source": "deterministic"})
                continue
            calls += 1
            adv = cast("str", f.get("vulnerability_id"))
            item = by_id.get(adv) if adv else None
            try:
                text = self._one_call(cfg, f, item)
                if not isinstance(text, str) or not text.strip():
                    raise LocalModelError("empty model completion")
                out.append({"text": text.strip(), "source": "model"})
            except Exception:
                # Any failure (network, timeout, status, decode, empty) falls
                # back to the deterministic text.  We do not echo the API key
                # or the payload body here — credentials are never repeated.
                out.append({"text": det_for(i), "source": "deterministic"})
        return out

    def _one_call(
        self, cfg: LocalModelConfig, f: Dict[str, Any],
        item: Optional[Dict[str, Any]],
    ) -> str:
        messages = [
            {"role": "system", "content": _system_prompt()},
            {"role": "user", "content": _finding_prompt(f, item)},
        ]
        payload = _chat_completions_request(
            base_url=cfg.base_url, api_key=cfg.api_key, model=cfg.model,
            messages=messages,
            temperature=cfg.temperature, top_p=cfg.top_p,
            max_tokens=cfg.max_tokens, timeout_s=cfg.timeout_s,
            transport=self._transport,
        )
        return _extract_completion(payload)


def explain(findings: List[Dict[str, Any]],
            remediation_plan: Optional[Dict[str, Any]] = None,
            config: Optional[LocalModelConfig] = None,
            transport: Optional[Callable[..., Any]] = None) -> List[Dict[str, str]]:
    """Explain findings via the local OpenAI-compatible backend.

    See :class:`OpenAILocalClient` for the safety invariants.  Returns a list
    aligned with ``findings`` of ``{"text": str, "source": "model"|"deterministic"}``.
    """
    return OpenAILocalClient(config=config, transport=transport).explain(
        findings, remediation_plan)
