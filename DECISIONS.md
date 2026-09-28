# DECISIONS.md — Architectural Decision Log

## 2026-09-05: Removed `src/reporter/report_generator.py`
The file `src/reporter/report_generator.py` was removed from the codebase because it contained syntax errors that prevented parsing — specifically, unterminated f-strings and malformed multi-line strings. The reporter module (`src/reporter/`) currently contains only an empty `__init__.py`, confirming the file was deleted. **Decision:** Do not attempt to repair the broken file. Instead, write `report_generator.py` from scratch in Phase 3, following the structured output and pathway-summary requirements defined in TASKS.md and the project charter.

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
- **Supporting sub-track (Week 1):** source-code static analysis via Bandit —
  `examples/source-audit-week1/`, `src/scanner/`. A useful signal (vulns *in* the code)
  and a good pipeline/harness exercise, but **not** the deliverable.

**Consequences:**
- Source-audit findings must stay **separate** from dependency findings.
- The source-audit rule-mapping correction (shell→B602, deserialization→B301, B704=
  markupsafe XSS, not deserialization; rule ID is in `test_id` never `test_name`, which is
  always `"blacklist"`; rc=1 means findings, rc>=2 means error, no rc=5) applies to the
  source-audit track only.
- December's critical path is parser → real NVD/OSV → PHEI on real data → dashboard →
  AI explanations. The source-audit track does not gate the December deliverable.
