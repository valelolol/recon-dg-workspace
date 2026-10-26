# Predictive Vulnerability Mapping — Architecture

## Project Overview

Current security methods are reactive, assessing only known CVEs and failing to predict systemic risk arising from interconnected exploitation of multiple low-severity issues across complex software dependency graphs. This project shifts vulnerability assessment to a proactive stance by predicting catastrophic failure through multi-node component interaction analysis, strengthening the software supply chain before exploitable pathways emerge.

## Module Structure

| Module | Description |
| --- | --- |
| `src/parser` | Ingests and normalizes dependency manifest formats (e.g., `requirements.txt`, `package.json`, `pyproject.toml`, `go.mod`, `Cargo.toml`) into shared `DependencyGraph` IR. |
| `src/models` | Defines the directed, weighted graph data structures representing component dependencies, their relationships, and associated metadata. |
| `src/engine` | Implements the core risk-scoring algorithms (NVD API integration, OSV fallback, rate-limiting, caching) and PHEI path-maximum scoring formula. |
| `src/reporter` | Generates structured JSON reports, human-readable summaries, and LLM explanations with deterministic fallback behavior. |
| `src/explanation` | Optional AI explanation layer: a grounded deterministic explainer (default) plus an OpenAI-compatible local-model client (env-only credentials, per-finding deterministic fallback, additive `ai_explanations` field). Uncommitted; toward the December AI-explainations step. |
| `src/web` | Minimal read-only dashboard: serves `dashboard.html` and `report.json` via stdlib `http.server` (no third-party deps). Uncommitted; toward the December dashboard step (full Flask+D3 is T-DE-04). |

## Graph Schema

| Class | Purpose | Key Attributes |
| --- | --- | --- |
| `DependencyNode` | Represents a single package component (identified by name and version) and stores its known vulnerabilities as a `{CVE ID: Severity}` mapping. | `package_name: str` — unique package name; `version: str` — package version; `is_critical: bool` — whether the node represents a critical dependency; `vulnerabilities: dict[str, float]` — CVE-to-severity mapping. |
| `DependencyGraph` | Manages the full directed acyclic graph of dependencies using NetworkX, tracking nodes by `(package, version)` keys and edges by source–target tuples with an associated risk weight. | `graph: DiGraph` — NetworkX digraph backing all traversal operations; `nodes: dict` — lookup by `(package, version)`; `edge_weights: dict` — risk weights per `(source, target)` pair. Provides `add_node`, `add_edge`, `get_nodes_list`, and `get_edges_list` for graph construction and iteration. |

## Risk Scoring

**PHEI (Predictive Vulnerability) Index** — Path-maximum scoring with functional-domain multipliers.

Formula: `PHEI(G) = max_P [ (Σ_edge_weights(P)) × ImpactMultiplicity(P) ]`

### Implementation Stages:
1. **Max CVE severity per node** — `get_cve_severity()` queries NVD API (with OSV fallback for npm/PyPI/Go/Rust), returning `{CVE_ID: severity}` dict. Node risk = max severity across CVEs (0.0 if none).
2. **Path traversal** — All paths from leaf nodes to critical assets are enumerated via NetworkX.
3. **Edge weight accumulation** — For each path P, sum edge weights `w_uv` (dependency criticality, trust boundaries, interaction depth).
4. **Impact multiplicity** — Paths traversing multiple functional domains (Network → Auth → File I/O) receive exponential multiplier.
5. **PHEI calculation** — Maximum path risk across all paths determines systemic risk, capped at 10.0.

The implementation penalizes the most dangerous single pathway, not the sum of all risks. This matches the threat model: catastrophic failure emerges from the weakest link in the longest chain, not cumulative exposure.

## Agent Layer

The `src/agent` module is the agentic investigation layer. It is deliberately **not**
"OSV-Scanner with an LLM summary." It:

- normalizes real OSV-Scanner output into the repo's `DependencyGraph` + `Finding`
  objects (`normalizer.py`) and runs the OSV-Scanner CLI through a thin,
  injection-tested wrapper (`scan_runner.py`);
- runs a **bounded** loop (`max_turns` cap + natural stop rule) that makes a
  **conditional** tool choice each turn based on the agent's own state;
- records every tool call (tool, args, observation, rationale) in an append-only
  **`EvidenceTrail`** — the observable artifact a reviewer, dashboard, or downstream
  AI reads to audit *why* each conclusion was drawn;
- never invents data; every finding claim is backed by a field from the OSV-Scanner
  output, and risk is reported as `unavailable`/`None` when topology is unavailable
  (no fabricated score).

A pluggable `llm` callable may steer tool selection (the product's AI backend, local
llama.cpp endpoint or user API key — a pending decision), but it is restricted to an
**allowlisted** tool set (`findings`, `get_finding`, `package_info`, `package_context`,
`high_severity`, `risk_score`, `summary`, `stop`); anything out of band falls back to a
grounded deterministic policy (recorded as evidence). The `package_context` tool is
an opt-in, additive enrichment lookup over deps.dev (published, resolved, labelled
`generic_published`; never fed to PHEI scoring). Deterministic scan orchestration and
risk scoring operate independently of any model. Structured reports persist when no
model is configured, with deterministic plain-language fallback. Hermes is a
development tool and is not a runtime dependency of recon-dg.

`compare_scans(before, after)` produces the before/after delta (new / resolved /
unchanged findings + the PHEI risk delta, skipped when topology is unavailable).

The agent layer also carries a **remediation** stage (`build_remediation_plan` +
`verify_remediation` in `agent.py`):
- `build_remediation_plan(scan)` is pure — one item per baseline finding using only
  normalized scanner evidence: the advisory ID + aliases, package, installed version,
  the affected range, the scanner-provided **fixed versions verbatim** (never invented
  / never "latest"), an explicit `has_fixed_version` flag, and severity *evidence only*
  (`severity_score` left `None` — never a numeric CVSS score or a high/low category;
  scheme types + vector strings preserved). A plain recommended action names a fixed
  version only when the scanner supplies one.
- `verify_remediation(before_scan, plan, after_scan=None)` reconciles the plan against
  a **user-supplied** after scan (no network; the caller supplies the scan). No after
  scan → `status == "not_run"` with **no resolution claim**. With an after scan, each
  plan item is classified on the `(package, version, vulnerability_id)` key: same
  version = `unchanged` (never counted as fixed), key absent = `resolved`, same advisory
  at a different version = `regressed`. New after-scan findings not in the plan are
  reported as `new_count`, not attributed to the plan. Risk/PHEI is preserved from
  the comparison and left `unavailable` when topology is unavailable. Verification
  appends a step to the caller's `EvidenceTrail` (and always carries its own auditable
  `evidence`).
- A malformed / missing / unusable after report fails closed to `status == "not_run"`
  and makes no resolution claim; the baseline investigation is always preserved.

## Architecture Decisions

### **Scoring Formula Resolution (2026-09-17)**

**Decision:** Adopt path-maximum scoring (PHEI Index) over global-sum.

**Rationale:**
- The threat model defines catastrophic failure as emerging from the weakest link in the longest chain, not cumulative exposure
- Global-sum averages risk across all edges, diluting critical pathway signals
- Path-maximum identifies the single most dangerous exploitation route
- Functional-domain multipliers amplify paths crossing trust boundaries (e.g., Network → Auth → File I/O)

**Implementation:**
- `calculate_path_weight()` computes sum of edge risks along each path
- `calculate_impact_multiplicity()` adds exponential factor for paths crossing multiple functional domains
- `calculate_systemic_risk()` implements PHEI: `max_P [sum_edge_weights(P) × ImpactMultiplicity(P)]`
- Documented in `ARCHITECTURE.md`

**Alignment:** Matches `docs/specs/design_spec.md` Section 3 formula.

## NVD/OSV Integration

The `src/engine/nvd_client.py` module implements:
- **NVD API client** with rate-limiting (`RateLimiter`), exponential backoff, and `CachedResponse`
- **OSV API fallback** for npm/PyPI/Go/Rust ecosystems
- **Key format:** `{ecosystem}:{package}:{version}:{cve_id}`
- **Severity normalization:** NVD CVSS → OSV severity → PHEI scale

## Reporter Interface

The `src/reporter/` module provides:
- **`RiskReport` dataclass** (`interface.py`) — structured report schema with
  metadata (`report_id`, `timestamp`, `graph_version`), core systemic-risk metrics
  (`current_systemic_risk`, `previous_systemic_risk`, `risk_delta`,
  `risk_percent_change`, `overall_risk_level`), node/edge analysis, change
  tracking (`node_changes`), risk breakdown (`vuln_risk`, `centrality_risk`,
  `edge_risk`), `top_risks`, `recommendations`, and a fallback flag
  (`fallback_applied` / `fallback_reason`); `to_dict()` / `to_json()` /
  `generate_summary()` / `generate_full_report()` for structured and human-readable
  output.
- **Before/after plain-language report** (`report_generator.py`) — compares two
  dependency graphs and renders the PHEI (path-max) risk update plus topology changes
  and a summary. It routes through `calculate_phei`; unavailable topology reports risk
  as `unavailable` (no fabricated score).
- **Inventory serializer** (`inventory.py`) — Mode A v0.1 serializer for edgeless
  graphs.
- **Deterministic fallback** when external APIs are unavailable — the report still
  renders with an honest `unavailable`/fallback marker rather than a fabricated score.
- **Tests:** `tests/test_inventory_reporter.py`, `tests/test_report_generator.py`
  (reporter), and `tests/test_agent.py` (agent layer, see above), plus
  `tests/test_enrichment.py` (deps.dev enrichment, stdlib-only, no network at
  import time), `tests/test_remediation.py` (remediation planning + after-scan
  verification, 24 tests), and — for the provisional uncommitted layer —
  `tests/test_explanation.py` (20), `tests/test_explanation_http.py` (7, a real
  local `/v1/chat/completions` server driven by real `urllib` requests), and
  `tests/test_dashboard.py` (9, real loopback HTTP GETs to `/` and
  `/report.json`). The full suite currently runs **241 passed, 29 subtests, 2
  warnings** (re-run 2026-10-10): 53 reporter, 45 agent, 26 enrichment, 23
  pipeline, 24 remediation, 11 NVD integration, 10 parser, 8 report generator,
  5 risk analyzer, 20 explanation, 7 explanation-HTTP, 9 dashboard.
