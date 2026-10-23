# DECISIONS.md — Architectural Decision Log

## 2026-09-05: Removed `src/reporter/report_generator.py`
The file `src/reporter/report_generator.py` was **temporarily removed** due to syntax errors that prevented parsing — specifically, unterminated f-strings and malformed multi-line strings. The reporter module (`src/reporter/`) **currently contains** `__init__.py`, `interface.py`, `report_generator.py`, and `inventory.py`. The file was restored and is now implemented (122 lines). **Decision:** Do not attempt to repair the broken file. Instead, write `report_generator.py` from scratch in Phase 3, following the structured output and pathway-summary requirements defined in TASKS.md and the project charter.

## 2026-09-05: PHEI Scoring Formula Discrepancy — Path-Max vs Global-Sum
`docs/specs/design_spec.md` defines the PHEI (Predictive Vulnerability Index) as the maximum risk over all paths through the dependency graph (`max over paths P`). However, `src/engine/risk_analyzer.py` implemented a global-sum aggregation: it summed weighted edge risk across the entire graph, averaged over edge count, and amplified by `√(node_count)`. These are fundamentally different algorithms producing different threat models (path-maximum vs. system-wide aggregation). **Decision:** Defer resolution to Phase 2. The scoring formula must be aligned with the PHEI spec before integrating real CVE data, since the lookup and scoring logic are tightly coupled.

## 2026-09-17: Scoring Formula Resolution — adopt PHEI path-maximum
Adopted path-maximum scoring (PHEI Index) over global-sum. Rationale: the threat model
defines catastrophic failure as emerging from the weakest link in the longest chain, not
cumulative exposure; global-sum dilutes critical pathway signals. `calculate_path_weight()`,
`calculate_impact_multiplicity()`, and `calculate_systemic_risk()` / `calculate_phei()`
implement `max_P [sum_edge_weights(P) × ImpactMultiplicity(P)]`, capped at 10.0, with an
`UnavailableTopologyError` guard requiring explicitly `edge_availability == "known"`.

## 2026-09-28: Scope framing — dependency-risk mapper, NOT a source-code scanner
**Decision:** recon-dg's December deliverable is a **dependency risk mapper**: (1) scan a
project's dependency graph, (2) look up known CVEs (NVD + OSV), (3) score *systemic*
risk — low-severity flaws combining along critical paths via PHEI path-max — (4) render
results in a clear dashboard, and (5) explain each finding in plain language via an AI
backend, including prioritization and package-connectivity analysis.

**Rationale:** The repo contains two distinct scanner tracks that were being conflated:
- **Core (December deliverable):** dependency/CVE assessment over the graph —
  `src/parser`, `src/models`, `src/engine`, `src/reporter`, `src/agent`, dashboard.
- **Source-audit (removed from scope):** source-code static analysis via Bandit was a
  useful signal (vulns *in* the code) and a good pipeline/harness exercise, but **not**
  the deliverable. It was removed from the project scope; the referenced files
  (`examples/source-audit-week1/`, `src/scanner/`) no longer exist.

**Consequences:**
- December's critical path is parser → real NVD/OSV → PHEI on real data → dashboard →
  AI explanations.

## 2026-10-03: Agent layer design — bounded, evidence-grounded investigation, not
"OSV-Scanner + LLM summary"

**Decision:** `src/agent/` implements the investigation loop as a bounded, conditional
tool loop over normalized OSV-Scanner output, grounded in an allowlisted tool set
(`findings`, `get_finding`, `package_info`, `high_severity`, `risk_score`, `summary`,
`stop`). Every call is recorded in an append-only `EvidenceTrail`; the agent never
invents data, and risk is reported as `unavailable`/`None` when topology is unavailable
(no fabricated score).

**Rationale:**
- A raw LLM summary over scan output would be unverifiable and could hallucinate findings
  or scores — the opposite of the evidence contract this project follows.
- Bounding the loop (a `max_turns` cap plus a natural stop rule) and restricting tool
  selection to an allowlist makes the behavior testable and reviewable, with the model
  acting as a *steering* input, not the source of truth.
- Recording an `EvidenceTrail` per turn is what lets a reviewer / downstream dashboard /
  downstream AI audit *why* each conclusion was drawn — the observable artifact that a
  plain summary cannot provide.
- An optional pluggable `llm` callable may steer, but out-of-band / invalid choices
  fall back to a grounded deterministic policy (recorded as evidence), so the agent
  runs fully without a model and degrades gracefully rather than crashing.

**Consequences / follow-ups:**
- A **real** model backend is a *pending* decision (local llama.cpp endpoint vs.
  user-provided API key) and is **not yet wired**; current runs use the deterministic
  policy (`used_llm=False`).
- Verified by `tests/test_agent.py` (22 passing) against the checked-in flat fixture
  (`tests/data/osv-scanner.json`: 5 findings, 4 packages, 0 edges → `risk.status ==
  "unavailable"`, `risk.score is None`, 7-turn run, no fabricated score).
