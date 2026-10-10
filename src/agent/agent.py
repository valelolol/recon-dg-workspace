"""The bounded, conditional agent loop that investigates a normalized scan.

This is the *agentic* heart of RECON-DG. It is deliberately **not** "OSV-Scanner
with an LLM summary." The agent:

- operates on the **real** OSV-Scanner output (normalized :class:`ScanResult`);
- runs a **bounded** loop (``max_turns`` cap *and* a natural stopping rule);
- makes **conditional** tool selections each turn — it looks at its own state
  (which findings exist, which are high-severity, whether topology is known)
  before deciding which tool to call next;
- records **every** tool call, its arguments and its observation into an
  append-only :class:`EvidenceTrail`; that trail is the *observable* artifact a
  reviewer / dashboard / downstream AI reads to audit *why* each conclusion was
  drawn;
- never invents data. A claim about a finding is always backed by a field
  from the OSV-Scanner output (id, CVE, CVSS, vulnerable_spec, published).

A pluggable ``llm`` callable may drive tool-selection (the product's AI
backend). It is **only** allowed to pick from an allowlisted tool set and must
return valid args; if it returns anything out of band, the agent falls back to
the grounded deterministic policy and records that fallback as evidence. This
keeps the agent fully functional without an LLM (deterministic policy) while
letting a real model steer it when one is available — and keeps the *evidence*
grounded in either case.

Tools (allowlisted, all grounded in repo data):

| tool              | args                        | observation                       |
|-------------------|-----------------------------|-----------------------------------|
| ``findings``      |                             | list of all findings (count + ids)|
| ``get_finding``   | ``vulnerability_id``        | one :class:`Finding` as dict      |
| ``package_info``  | ``package_name``, ``version``| vuln map for a package node      |
| ``package_context``| ``package_name``, ``version`` (opt ``ecosystem``, ``vulnerability_id``) | deps.dev published context, labelled ``generic_published``; strictly additive, review-only |
| ``high_severity`` | ``threshold``               | high-severity findings only       |
| ``risk_score``    |                             | PHEI (path-max) or "unavailable"  |
| ``summary``       |                             | plain-language narrative          |
| ``stop``          | ``reason``                  | terminal                        |
"""

from __future__ import annotations

import itertools
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Sequence

from src.agent.normalizer import Finding, ScanResult

# Lazy import so the agent module is importable even if the engine is not
# (and to avoid any import-time side effects in risk_analyzer).
from src.engine.risk_analyzer import calculate_phei, UnavailableTopologyError

# Enrichment (deps.dev) is *optional and additive*: it is never required for a
# usable report.  The client is stdlib-only and :func:`build_package_context`
# never raises, so a missing or rate-limited deps.dev leaves the deterministic
# loop and the OSV-Scanner findings intact.  Default is OFF (no network I/O in
# the grounded deterministic run); opt in via ``enrichment_enabled``.
from src.enrichment import build_package_context as _default_enrichment_fn


# ---------------------------------------------------------------------------
# Evidence trail
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class EvidenceStep:
    """One recorded tool interaction (the unit of the evidence trail)."""

    turn: int
    tool: str
    args: dict[str, Any]
    observation: Any
    note: str  # plain-language rationale for *why* this tool was used

    def to_dict(self) -> dict[str, Any]:
        return {
            "turn": self.turn,
            "tool": self.tool,
            "args": self.args,
            "observation": self.observation,
            "note": self.note,
        }


@dataclass
class EvidenceTrail:
    """Append-only log of every tool call the agent made.

    This is the *observable* artifact: a reviewer can read it to see exactly
    which tools the agent invoked, in which order, with which arguments, and what
    each returned. It is the thing that makes the investigation auditable.
    """

    steps: List[EvidenceStep] = field(default_factory=list)

    def append(self, tool: str, args: dict[str, Any], observation: Any, note: str) -> None:
        self.steps.append(
            EvidenceStep(turn=len(self.steps), tool=tool, args=args,
                         observation=observation, note=note)
        )

    def to_dict(self) -> dict[str, Any]:
        return {"steps": [s.to_dict() for s in self.steps]}

    def render(self) -> str:
        """Render the trail as a plain-language narrative of the investigation."""
        if not self.steps:
            return "(no tool calls recorded)"
        lines = ["### Investigation evidence trail", ""]
        for s in self.steps:
            lines.append(f"**Turn {s.turn} — {s.tool}({s.args})**")
            obs = self._fmt_observation(s.observation)
            lines.append(f"  → {obs}")
            if s.note:
                lines.append(f"  *why:* {s.note}")
            lines.append("")
        return "\n".join(lines).rstrip() + "\n"

    @staticmethod
    def _fmt_observation(obs: Any) -> str:
        if isinstance(obs, dict):
            # Prefer a small, readable projection.
            if "message" in obs:
                return str(obs["message"])
            if "summary" in obs:
                return str(obs["summary"])
            return str(obs)[:240]
        return str(obs)[:240]


# ---------------------------------------------------------------------------
# Agent
# ---------------------------------------------------------------------------
class Agent:
    """Investigate a normalized OSV-Scanner scan with a bounded tool loop."""

    ALLOWED_TOOLS = {
        "findings", "get_finding", "package_info", "package_context",
        "high_severity", "risk_score", "summary", "stop",
    }

    def __init__(
        self,
        scan: ScanResult,
        llm: Optional[Callable[[dict[str, Any]], Optional[dict[str, Any]]]] = None,
        max_turns: int = 25,
        severity_threshold: float = 7.0,
        package_info_source: Optional[str] = None,
        enrichment_enabled: bool = False,
        enrichment_fn: Optional[Callable[..., dict[str, Any]]] = None,
        max_enrichment_calls: int = 5,
    ) -> None:
        """
        Args
        ---
        scan : ScanResult
            The normalized OSV-Scanner output to investigate.
        llm : callable, optional
            A pluggable "brain". Given the agent's current state it returns
            ``{"tool": <name>, "args": {...}}``. Must only name allowlisted
            tools with valid args; anything else triggers a deterministic
            fallback (recorded as evidence). When omitted, the agent uses its
            own grounded deterministic policy.
        max_turns : int
            Hard cap on the loop.
        severity_threshold : float
            CVSS score that marks a finding as "high severity" (default 7.0).
        package_info_source : str
            Optional label describing where package metadata comes from
            (used in the evidence note). Defaults to "OSV-Scanner".
        enrichment_enabled : bool
            Whether the ``package_context`` tool may reach deps.dev.  Default is
            False so the grounded, deterministic run (and CI) performs zero
            network I/O.  When True the agent may call ``package_context`` to
            fetch *additive* published context (labelled ``generic_published``
            and never used for project PHEI).
        enrichment_fn : callable, optional
            Replaceable ``build_package_context``-shaped function
            ``(package, version, system, **kwargs) -> dict`` (defaults to the
            deps.dev client).  Injected for tests / alternative providers.
        max_enrichment_calls : int
            Hard cap on enrichment lookups (a hard call limit).  Reaching it
            makes ``package_context`` return "budget exhausted" and the agent
            never exceeds it.
        """
        self.scan = scan
        self.llm = llm
        self.max_turns = max(max_turns, 1)
        self.severity_threshold = severity_threshold
        self.package_info_source = package_info_source or "OSV-Scanner"
        self.enrichment_enabled = bool(enrichment_enabled)
        # Resolve the enrichment function (defaults to the deps.dev client).
        if enrichment_fn is None:
            enrichment_fn = _default_enrichment_fn
        self._enrichment_fn = enrichment_fn
        self._max_enrichment_calls = max(int(max_enrichment_calls), 0)
        self._enrichment_calls = 0
        self._package_context_cache: Dict[tuple, dict[str, Any]] = {}

        self.trail = EvidenceTrail()
        self._state: Dict[str, Any] = {}
        self._done_findings: set[str] = set()
        self._risk: Optional[Dict[str, Any]] = None
        self._final_summary: Optional[str] = None
        self._final_report: Optional[dict[str, Any]] = None

        # Pre-compute the investigation queue (deterministic, severity-ordered).
        self._findings_sorted = sorted(
            self.scan.findings,
            key=lambda f: (
                (f.severity_score is None),
                -(f.severity_score or 0.0),
                f.package_name,
                f.version,
            ),
        )
        self._high_sev = [f for f in self._findings_sorted
                          if f.severity_score is not None
                          and f.severity_score >= self.severity_threshold]

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def run(self) -> dict[str, Any]:
        """Execute the investigation loop and return the structured report."""
        self.trail = EvidenceTrail()
        self._done_findings = set()
        self._risk = None
        self._final_summary = None
        self._final_report = None
        # Fresh budget each run (a re-investigation must not consume the prior
        # run's enrichment allowance).
        self._enrichment_calls = 0
        self._package_context_cache = {}

        turn = 0
        while turn < self.max_turns:
            action = self._choose_action()
            tool = action["tool"]
            args = action.get("args", {})

            # Validate (safety). If out of band, fall back + record.
            if tool not in self.ALLOWED_TOOLS:
                self._record_fallback(action, f"llm chose disallowed tool {tool!r}")
                action = self._default_action(turn)
                tool = action["tool"]
                args = action.get("args", {})

            # A redundant package_context for an already-enriched coordinate is
            # a no-op: the canonical published context is already in the trail
            # and the enrichment cache. Re-executing it would only re-emit
            # identical evidence and burn a turn, so we advance via the
            # deterministic policy instead (no second trail entry, no I/O).
            if tool == "package_context":
                pc_key = (
                    args.get("ecosystem", "pyPI"),
                    args.get("package_name"),
                    args.get("version"),
                )
                if all(pc_key) and pc_key in self._package_context_cache:
                    self._record_fallback(
                        action,
                        "package_context re-request for an already-enriched "
                        "package@version (cached); advanced via deterministic "
                        "policy instead of re-executing.",
                    )
                    action = self._default_action(turn)
                    tool = action["tool"]
                    args = action.get("args", {})

            observation = self._execute(tool, args)
            note = action.get("note", "")

            # If this tool's call is what advances the loop, record it.
            self.trail.append(tool, args, observation, note)
            turn += 1

            # Stop conditions: explicit stop(), natural completion, or budget.
            if tool == "stop" or self._natural_complete(turn):
                break

        # Always close with a summary so the report is complete.
        self._execute_summary(turn)
        report = self._build_report()
        self._final_report = report
        return report

    # ------------------------------------------------------------------
    # Action selection: deterministic policy + optional LLM steering
    # ------------------------------------------------------------------
    def _state_view(self) -> dict[str, Any]:
        """State the LLM (or a human) can see when deciding the next action."""
        return {
            "turn_budget_used": len(self.trail.steps),
            "max_turns": self.max_turns,
            "findings_count": len(self.scan.findings),
            "high_severity_count": len(self._high_sev),
            "uninvestigated_high_severity": len(self._high_sev) - len(self._done_findings),
            "risk_computed": self._risk is not None,
            "severity_threshold": self.severity_threshold,
            "enrichment_enabled": self.enrichment_enabled,
            "enrichment_calls_used": self._enrichment_calls,
            "enrichment_calls_remaining": max(
                self._max_enrichment_calls - self._enrichment_calls, 0),
        }

    def _default_action(self, turn: int) -> dict[str, Any]:
        """Grounded deterministic policy: the default "brain"."""
        n = len(self.trail.steps)
        # 1) see the inventory
        if n == 0:
            return {"tool": "findings", "args": {},
                    "note": "Inventory all findings before deciding which to investigate."}
        # 2) investigate the next finding in the queue.  Prefer high-severity
        # findings (those with a known score >= threshold) when any exist;
        # otherwise — e.g. the real OSV-Scanner 2.6.0 "severity: null" /
        # vector-only shape, where NO numeric score is available — fall back to
        # the full findings queue (severity-ordered, then name/version) so the
        # investigation trail still inspects real findings rather than skipping
        # straight to risk + summary with zero per-finding evidence.
        queue = self._high_sev or self._findings_sorted
        for f in queue:
            if f.vulnerability_id not in self._done_findings:
                sev = (f"CVSS {f.severity_score:g}"
                       if f.severity_score is not None
                       else "severity unavailable")
                return {
                    "tool": "get_finding",
                    "args": {"vulnerability_id": f.vulnerability_id},
                    "note": (f"Investigate {f.package_name}@{f.version} "
                             f"({f.vulnerability_id}, {sev}) before other "
                             f"findings."),
                }
        self._done_findings = set(self._done_findings) | {f.vulnerability_id
                                                         for f in queue}
        # 3) risk score (PHEI)
        if self._risk is None:
            return {"tool": "risk_score", "args": {},
                    "note": "Compute the PHEI path-max systemic risk (or record "
                            "topology-unavailable if no dependency relationships)."}
        # 4) summary
        if self._final_summary is None:
            return {"tool": "summary", "args": {},
                    "note": "Produce the plain-language narrative."}
        # 5) stop
        return {"tool": "stop", "args": {"reason": "all high-severity findings "
                                                  "investigated; risk + summary emitted"},
                "note": "Investigation complete."}

    def _choose_action(self) -> dict[str, Any]:
        """Pick the next action: LLM-steered when provided, else deterministic."""
        if self.llm is None:
            return self._default_action(len(self.trail.steps))
        try:
            llm_action = self.llm(self._state_view())
        except Exception as exc:  # a broken llm must not break the agent
            self.trail.append("llm_error", {}, {"error": str(exc)},
                              f"llm raised {exc!r}; falling back to deterministic policy.")
            return self._default_action(len(self.trail.steps))
        if llm_action is None or not isinstance(llm_action, dict):
            return self._default_action(len(self.trail.steps))
        return llm_action

    def _record_fallback(self, bad_action: dict[str, Any], reason: str) -> None:
        self.trail.append(
            "llm_fallback", {}, {"requested": bad_action, "reason": reason},
            f"LLM action invalid ({reason}); used deterministic policy instead.")

    # ------------------------------------------------------------------
    # Tool execution (each returns a structured observation)
    # ------------------------------------------------------------------
    def _execute(self, tool: str, args: dict[str, Any]) -> Any:
        if tool == "findings":
            return {
                "count": len(self.scan.findings),
                "ids": [f.vulnerability_id for f in self._findings_sorted],
                "packages": sorted({(f.package_name, f.version) for f in self.scan.findings}),
            }
        if tool == "get_finding":
            vid = args.get("vulnerability_id")
            f = self._finding_by_id(vid)
            if f is None:
                return {"error": f"no finding with id {vid!r}"}
            obs = f.to_dict()
            obs["explanation"] = self._plain_explain(f)
            self._done_findings.add(vid)
            return obs
        if tool == "package_info":
            name = args.get("package_name", "")
            version = args.get("version", "")
            node = self.scan.graph.nodes.get((name, version))
            if node is None:
                return {"error": f"no node ({name}, {version})"}
            return {
                "package": name,
                "version": version,
                "vulnerabilities": list(node.vulnerabilities.items()),
                "source": self.package_info_source,
            }
        if tool == "package_context":
            return self._execute_package_context(args)
        if tool == "high_severity":
            threshold = float(args.get("threshold", self.severity_threshold))
            hits = [f for f in self.scan.findings if f.is_high_severity(threshold)]
            return {
                "threshold": threshold,
                "count": len(hits),
                "findings": [{"id": f.vulnerability_id, "package": f.package_name,
                              "version": f.version, "cvss": f.severity_score}
                             for f in hits],
            }
        if tool == "risk_score":
            risk = self._compute_risk()
            self._risk = risk
            return risk
        if tool == "summary":
            summary = self._build_summary()
            self._final_summary = summary
            return {"summary": summary}
        if tool == "stop":
            return {"stopped": True, "reason": args.get("reason", "")}
        raise ValueError(f"unknown tool {tool!r}")

    def _execute_package_context(self, args: dict[str, Any]) -> Any:
        """Look up *additive* deps.dev published context for a package.

        Rules (conditional, bounded, evidence-grounded):
        * **opt-in only** — if ``enrichment_enabled`` is False this tool is a
          no-op (the grounded deterministic run performs zero network I/O).
        * **hard call limit** — once ``max_enrichment_calls`` lookups have been
          performed, further calls return ``budget_exhausted`` and are counted
          zero (no extra network I/O).
        * **skip redundant lookups** — the result is cached per
          ``(system, package, version)`` key; an already-investigated package
          returns the cached observation with a ``cached`` note rather than
          re-querying.
        * **additive, never erases findings** — the enrichment function
          (``build_package_context``) never raises and returns ``status``
          ``ok``/``partial``/``error``; all three are recorded as evidence and
          the deterministic findings are preserved regardless.
        * **review-only, provenance-labelled** — the returned observation is
          always labelled ``generic_published`` (a standalone resolved graph
          for the package, *not* the scanned project's resolved graph) and is
          *never* fed to PHEI scoring.
        * **evidence ids recorded** — the advisory ids observed on deps.dev
          (and the requested advisory id, if any) are surfaced in the
          observation so each factual claim can be traced to a concrete id.
        """
        name = args.get("package_name", "")
        version = args.get("version", "")
        ecosystem = args.get("ecosystem", "pyPI")
        # The advisory id is optional and is only looked up when explicitly
        # supplied (bounded, explicit coordinates only — never guessed).
        advisory_id = args.get("vulnerability_id")

        if not self.enrichment_enabled:
            return {
                "status": "enrichment_disabled",
                "package": name,
                "version": version,
                "message": ("package_context is disabled (enrichment is off). "
                            "No network lookup was performed; the OSV-Scanner "
                            "finding itself is unaffected."),
            }
        if not name or not version:
            return {
                "status": "invalid_args",
                "package": name,
                "version": version,
                "message": "package_context needs both package_name and version.",
            }
        key = (ecosystem, name, version)

        # Skip redundant lookups: already enriched this exact coordinate.
        if key in self._package_context_cache:
            cached = self._package_context_cache[key]
            return {
                "status": cached.get("status", "cached"),
                "cached": True,
                "calls_used_this_lookup": False,
                **cached,
                "message": ("Cached published context for "
                            f"{name}@{version}; no further deps.dev "
                            "lookup was issued."),
            }

        # Hard call limit.
        if self._enrichment_calls >= self._max_enrichment_calls:
            return {
                "status": "budget_exhausted",
                "package": name,
                "version": version,
                "calls_used": self._enrichment_calls,
                "calls_limit": self._max_enrichment_calls,
                "message": ("Enrichment call budget exhausted "
                            f"({self._enrichment_calls}/{self._max_enrichment_calls}); "
                            "no further deps.dev lookup was issued. "
                            "The deterministic OSV-Scanner finding is preserved."),
            }

        # Perform the additive lookup.  build_package_context never raises,
        # so this cannot wipe out findings; it records failures additively.
        self._enrichment_calls += 1
        try:
            context = self._enrichment_fn(
                package=name, version=version, system=ecosystem,
                advisory_ids=[advisory_id] if advisory_id else None,
            )
        except Exception as exc:  # a provider bug must never break the agent
            context = {
                "status": "error",
                "package": name,
                "version": version,
                "errors": [f"enrichment_fn raised: {exc!r}"],
                "provenance": "generic_published",
            }
        # Build a review-only observation: label provenance clearly, surface
        # the observed advisory ids as evidence, and never imply this is the
        # project's resolved graph.
        observed = {
            "status": context.get("status", "unknown"),
            "calls_used": self._enrichment_calls,
            "calls_limit": self._max_enrichment_calls,
            "provenance": "generic_published",
            "package": name,
            "version": version,
            "system": ecosystem,
            "advisory_ids_from_provider": list(context.get("advisory_ids_from_version", [])),
            "requested_advisory_id": advisory_id,
            "observed_advisory_ids": context.get("advisory_ids_from_version", [])
                                        + ([advisory_id] if advisory_id
                                           else []),
            "dependencies_status": context.get("dependencies_status"),
            "version_meta": context.get("version_meta"),
            "resolved_deps": context.get("resolved_deps"),
            "advisory_details": context.get("advisory_details"),
            "errors": context.get("errors", []),
            "review_only": True,
            "note": ("Published deps.dev context only (generic_published). "
                     "Not the scanned project's resolved graph; not used for "
                     "project PHEI. Review by a human before action."),
        }
        # Cache the (possibly failed) *observed* projection so a later redundant
        # call is skipped and still carries provenance / advisory ids.
        self._package_context_cache[key] = observed

        # Always record the tool call + evidence ids on the trail regardless of
        # provider outcome (the trail is the audit artifact).
        return observed

    def _finding_by_id(self, vid: str) -> Optional[Finding]:
        for f in self.scan.findings:
            if f.vulnerability_id == vid:
                return f
        return None

    def _compute_risk(self) -> Dict[str, Any]:
        """Attempt the PHEI path-max; record 'unavailable' if no topology.

        This is the *evidence-grounded* risk statement: we never fabricate a
        score. A flat requirements.txt graph has no edges, so the PHEI path-max
        is not computable, and we say so explicitly (matching RECON-DG's rule
        that inventory-only input must not produce invented edges / scores).
        """
        try:
            score = calculate_phei(self.scan.graph)
            return {
                "status": "available",
                "method": "phei",
                "score": float(score),
                "message": f"PHEI path-max systemic risk = {score:.3f}.",
            }
        except UnavailableTopologyError:
            return {
                "status": "unavailable",
                "method": "phei",
                "score": None,
                "message": (
                    "PHEI path-max not computable: the scan graph has no known "
                    "dependency relationships (flat requirements.txt). No score "
                    "is fabricated; this is an inventory-only result."
                ),
            }

    def _natural_complete(self, turn: int) -> bool:
        """The loop is 'naturally' complete once high-sev findings, risk and
        summary have all been emitted."""
        if not self._high_sev and self._risk is not None and self._final_summary is not None:
            return True
        return False

    def _execute_summary(self, turn: int) -> None:
        """Guarantee a summary in the trail + report, even if the loop ran out
        of budget before emitting one."""
        if self._final_summary is None:
            summary = self._build_summary()
            self._final_summary = summary
            self.trail.append("summary", {}, {"summary": summary},
                              "Emitting final plain-language summary.")

    # ------------------------------------------------------------------
    # Grounded plain-language explanations
    # ------------------------------------------------------------------
    def _plain_explain(self, f: Finding) -> str:
        """One grounded explanation per finding (references only real fields)."""
        spec = f.vulnerability_spec
        spec_str = f" (affected range: `{spec}`)" if spec else ""
        cve = ", ".join(f.aliases) if f.aliases else f.vulnerability_id
        score = f.severity_score
        sev_str = f"CVSS {score:g}" if score is not None else "severity unspecified"
        pub = f" (published {f.published})" if f.published else ""
        return (
            f"**{f.package_name}@{f.version}** is vulnerable via advisory "
            f"{f.vulnerability_id} ({cve}), {f.advisory_type}{pub}, "
            f"{sev_str}{spec_str}. This is an evidence-grounded finding from "
            f"OSV-Scanner; upgrade the package to a version outside the "
            f"affected range to remediate."
        )

    def _build_summary(self) -> str:
        """Plain-language narrative of the whole investigation."""
        n = len(self.scan.findings)
        high = len(self._high_sev)
        parts = [f"# RECON-DG investigation summary",
                 f"", f"Scan path: `{self.scan.source_path or '(unnamed)'}`",
                 f"", f"- **Findings:** {n} across "
                 f"{len({(f.package_name, f.version) for f in self.scan.findings})} package "
                 f"versions.",
                 f"- **High-severity (CVSS ≥ {self.severity_threshold:g}):** {high}."]
        if self._risk is not None:
            r = self._risk
            if r["score"] is not None:
                parts.append(f"- **Systemic risk (PHEI path-max):** {r['score']:.3f} "
                             f"({r['status']}).")
            else:
                parts.append(f"- **Systemic risk:** {r['status']} — "
                             f"no fabricated score (topology unavailable).")
        parts.append("")
        parts.append("### Top findings (highest CVSS first)")
        for f in self._findings_sorted[:5]:
            parts.append(f"- {self._plain_explain(f)}")
        if n > 5:
            parts.append(f"- … and {n - 5} more (see evidence trail).")
        return "\n".join(parts)

    # ------------------------------------------------------------------
    # Report assembly
    # ------------------------------------------------------------------
    def _build_report(self) -> dict[str, Any]:
        return {
            "source_path": self.scan.source_path,
            "findings_count": len(self.scan.findings),
            "high_severity_count": len(self._high_sev),
            "severity_threshold": self.severity_threshold,
            "risk": dict(self._risk) if self._risk else None,
            "narrative": self._final_summary or "",
            "findings": [
                {**f.to_dict(), "explanation": self._plain_explain(f)}
                for f in self._findings_sorted
            ],
            "evidence": self.trail.to_dict(),
            "turns_used": len(self.trail.steps),
            "max_turns": self.max_turns,
            "used_llm": self.llm is not None,
        }


# ---------------------------------------------------------------------------
# compare_scans
# ---------------------------------------------------------------------------
def compare_scans(before: ScanResult, after: ScanResult) -> dict[str, Any]:
    """Compare two normalized scans and produce a plain-language delta.

    Returns a structured dict: which findings are **new**, **resolved**,
    **unchanged**, plus the PHEI risk delta (when both have topology).

    A finding is keyed by ``(package_name, version, vulnerability_id)``.  A
    finding is "resolved" when it was present in ``before`` but absent in
    ``after`` (same package/version no longer vulnerable — e.g. a successful
    upgrade).
    """
    def _key_set(scan: ScanResult) -> Dict[str, Finding]:
        out: Dict[str, Finding] = {}
        for f in scan.findings:
            out[(f.package_name, f.version, f.vulnerability_id)] = f
        return out

    before_set = _key_set(before)
    after_set = _key_set(after)

    before_keys = set(before_set)
    after_keys = set(after_set)

    new_keys = after_keys - before_keys
    resolved_keys = before_keys - after_keys
    unchanged_keys = before_keys & after_keys

    def _pkg(f: Finding) -> str:
        return f"{f.package_name}@{f.version}"

    new = [after_set[k] for k in new_keys]
    resolved = [before_set[k] for k in resolved_keys]
    unchanged = [after_set[k] for k in unchanged_keys]

    before_risk = _risk_status(before)
    after_risk = _risk_status(after)

    if before_risk["score"] is None or after_risk["score"] is None:
        delta_text = "Systemic risk comparison skipped (one or both scans have " \
                     "no known dependency topology, so PHEI is unavailable)."
    else:
        delta = after_risk["score"] - before_risk["score"]
        word = "worse" if delta > 0 else "improved" if delta < 0 else "stable"
        delta_text = (
            f"PHEI path-max: {before_risk['score']:.3f} → {after_risk['score']:.3f} "
            f"({delta:+.3f}) → {word} systemic risk."
        )

    return {
        "new_count": len(new),
        "resolved_count": len(resolved),
        "unchanged_count": len(unchanged),
        "new": [f.to_dict() for f in new],
        "resolved": [f.to_dict() for f in resolved],
        "unchanged": [f.to_dict() for f in unchanged],
        "before_risk": before_risk,
        "after_risk": after_risk,
        "risk_delta": delta_text,
        "narrative": _compare_narrative(
            before, after, new, resolved, unchanged, before_risk, after_risk, delta_text),
    }


def _risk_status(scan: ScanResult) -> Dict[str, Any]:
    """Return the PHEI risk as a dict.  When the topology is unavailable the
    dict has ``score = None`` (never a fabricated score)."""
    try:
        score = calculate_phei(scan.graph)
        return {"status": "available", "method": "phei", "score": float(score)}
    except UnavailableTopologyError:
        return {"status": "unavailable", "method": "phei", "score": None}


def _compare_narrative(before: ScanResult, after: ScanResult,
                       new: List[Finding], resolved: List[Finding],
                       unchanged: List[Finding],
                       before_risk: Optional[dict], after_risk: Optional[dict],
                       risk_delta: str) -> str:
    parts = ["# RECON-DG before/after comparison", "",
             f"- **Before:** {len(before.findings)} findings.",
             f"- **After:** {len(after.findings)} findings.",
             f"",
             f"- **New vulnerabilities:** {len(new)}.",
             f"- **Resolved (no longer vulnerable):** {len(resolved)}.",
             f"- **Unchanged:** {len(unchanged)}.",
             f"",
             f"- **{risk_delta}"]
    if new:
        parts.append("\n### New findings (highest CVSS first)")
        for f in sorted(new, key=lambda x: -(x.severity_score or 0.0)):
            parts.append(f"- {f.package_name}@{f.version}: {f.vulnerability_id} "
                         f"(CVSS {f.severity_score})")
    if resolved:
        parts.append("\n### Resolved findings")
        for f in sorted(resolved, key=lambda x: -(x.severity_score or 0.0)):
            parts.append(f"- {f.package_name}@{f.version}: {f.vulnerability_id} "
                         f"(CVSS {f.severity_score})")
    return "\n".join(parts)
