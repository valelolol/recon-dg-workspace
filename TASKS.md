# TASKS.md — Predictive Risk Mapping Agent

## Project Scope (December deliverable)

recon-dg is a **dependency risk mapper**. One command must, for a given project:

1. **Scan** → build a dependency graph (which third-party packages are used + how they
   connect).
2. **Check** → look up known CVEs for each package via **OSV-Scanner** (the project's
   external vulnerability scanner — the project does *not* build a scanner from scratch);
   NVD/OSV data feeds the *engine's* enrichment layer, not the scanner.
3. **Score systemic risk** → not "this package has a flaw," but whether low-severity
   flaws combine along critical dependency paths into a real threat (PHEI path-max).
4. **Display** → a clear dashboard showing the graph, per-package risk, and the top
   risk paths.
5. **Explain** → an AI backend that turns each finding into plain-language explanations
   and helps developers prioritize what to fix.

**Constraint:** inventory-only input must not produce invented dependency edges. Risk
scoring requires an explicitly "known" topology; with inventory-only input the edges
array stays empty and risk is unavailable.

**Synthetic data rule:** synthetic graph/advisory data is only for clearly labeled offline tests or a separate demo. It is **never** scanner evidence. Real scanner output (OSV-Scanner JSON) is the only valid input for the agent and PHEI scoring.

### December-critical path (in order)
1. **Dec 3 (Thu):** candidate freeze — all deliverables locked for review.
2. **Dec 4 (Fri):** team demo (internal).
3. **Dec 7 (Mon):** team demo (internal).
4. **Dec 8 (Tue):** rehearsal/buffer.
5. **Dec 9 (Wed):** presentation.

> **Interim-demo scope:** The Dec 9 presentation is an interim demonstration of progress toward the larger RECON-DG project — not a declaration that the full project is complete. The December deliverable is a working prototype (scan → graph → OSV findings → systemic risk → dashboard → AI explanation → bounded fix → human approval → rescan → verified results), not a finished application.

6. Parser: enough manifest formats to scan a real project.
7. Engine: wire NVD/OSV into the graph so **real** CVE data flows into PHEI.
8. Reporter: structured report schema + deterministic fallback.
9. Dashboard: web app (graph + risks + per-package risk).
10. AI explanations: `src/agent/` pluggable model layer (plain-language + prioritization).

## Task register

Stable IDs used by `docs/STATUS.md`, the handoffs, and the plan files in `docs/weekly-plan/`. (`docs/WEEKLY.md` is historical and not an active reference.) "Unverified"
means a completion claim that is not yet backed by a run command or a passing test in
the tree — treat it as not done until verified.

| Task ID | Title | Track | Owner | Status | Depends on |
|---------|-------|-------|-------|--------|-----------|
| T-DE-01 | Parser: multi-format manifest support | Core | Vale | In progress | v0.1 contract (done) |
| || T-DE-02 | Engine: real CVE lookups + PHEI reconciliation | Core | Vale | **Partial** (⚠️ T-DE-02 audit 2026-11-03: NVD/OSV wiring exists + 15 tests + clean scan, but live CVE data NOT demonstrated flowing into PHEI on a real project. Severity-to-PHEI mapping is an implementation gap (topology-only PHEI is the agreed target; severity is handled by `calculate_systemic_risk()`, not PHEI). W10 must demonstrate end-to-end: real scan → real CVE data → `calculate_systemic_risk()` on a controlled project.) | T-DE-01 |
| || T-DE-03 | Reporter schema + deterministic fallback | Core | Vale | **Partial** (⚠️ Mode A: report schema + fallback — done; Mode B: dependency-graph serializer unimplemented per ROADMAP §W3 — blocks CVE→systemic-risk demo) | T-DE-01, T-DE-02 |
| T-DE-04 | Dashboard: graph + risk + per-package view | Core | Aliyan (provisional) | Not started | T-DE-02, T-DE-03 |
| T-DE-05 | Standalone GUI (Windows/Linux): dashboard + local-model explanations | Core | Team | Not started | T-DE-04 |

## M-DE-CORE — One-Week Demo Dependency-Risk Report (historical; not current track)

> **Status:** the *plan* below is committed (HEAD `b4fc87c`). The *implementation* it
> describes (known-topology loader, Mode B serializer, `src/cli.py`, viewer, reference
> output, E2E test) is **not in the tree yet** — these are the deliverables the handoffs
> assign. Do not read any file below as "already built."

Goal: one command → a **v0.1 `report.json`** with **no live NVD/OSV calls**, in two
modes:
- **Mode A — inventory** (unchanged): `requirements.txt` → edgeless graph,
  `analysis_mode: inventory`, `topology_status: unavailable`, `edges: []`, risk unavailable.
  Acceptance: existing fields/behavior preserved and existing tests pass.
- **Mode B — dependency-graph** (new this week): a clearly-labeled synthetic
  `known_topology.json` + `cve_fixture.json` → graph with `edge_availability: known`
  → **topology-based PHEI** score (**6.0**) → `report.json` (packages, edges,
  `findings`, `vulnerability_lookup`, `warnings`) + a static HTML
  view (`report.html`, no framework).

**Score wording (all outputs must carry it):** *"This is a labeled synthetic
dependency-risk demo. Graph and CVE data are fictional fixtures. The PHEI score
6.0 is topology-based (edge weights × node multiplicity). Advisory severity is
unspecified — `findings[].severity` is `null` per v0.1 — and is not included in the
score (edge-weight function resolved: topology-only, no edge weight needed). This is a
topology PHEI report, not a complete vulnerability-risk score."*

**Out of scope this week:** live NVD/OSV, the full dashboard framework (Phase 4
Flask+D3 is T-DE-04's December meaning and is preserved, not rewritten — the viewer
is a provisional spike toward it), the AI layer, Docker, severity-in-score, and
LOW/MEDIUM/HIGH/CRITICAL labels (level thresholds deferred).

**Contract checkpoint C0 (sign before parallel work):** the Mode B field mapping below
and the **proposed input-fixture contract** (§ C0-prereq). All emitted fields are
spec-defined v0.1 fields — **no out-of-spec extension is emitted this week**; a
risk-path field (e.g. `top_risk_path`) is deferred to a separate schema decision.
Scope: C0 gates Nick's fixture authoring and the downstream fixture-consuming steps
(Vale's E2E + generated reference, Christian's running assertions, Aliyan's viewer)
— it does not gate drafting the loader/serializer/CLI or the handoff review (see
`docs/STATUS.md` §C0).

| Subtask | Parent | Owner | Owned file(s) — exactly one owner each | First checkpoint | Acceptance |
|---------|--------|-------|----------------------------------------|------------------|------------|
| W1-DE-01.F | T-DE-01 | Nick | `examples/fixtures/known_topology.json` | Fixture loads; 3 unique nodes, 2 directed unit-weight edges; labeled synthetic | Round-trips to a `known` graph; no duplicate IDs |
| W1-DE-02.S | T-DE-02 | Nick | `examples/fixtures/cve_fixture.json`, `docs/limitations.md` | Fixture loads; IDs `SYNTH-2026-xxxx`; limitations note names source + severity-not-in-score limit | Synthetic-labeled; no real identifiers |
| W1-DE-01.L | T-DE-01 | Vale | `src/parser/parser.py` | `load_known_topo_json()` → graph `edge_availability="known"`; correct nodes/edges/weights | `calculate_phei` on it == 6.0; `parse_requirements` untouched |
| W1-DE-02.R | T-DE-02 | Vale | `src/engine/risk_analyzer.py`, `src/reporter/report_generator.py` | `calculate_phei` returns the argmax scalar score (6.0); `generate_report` calls PHEI (path-max), not `calculate_systemic_risk` (global-sum); edge-weight function resolved as topology-only | Score numerics preserved (6.0) and invariant to severity; no formula change/invented; no path field emitted; severity not in score. **Complete 2026-10-03 (uncommitted):** `generate_report()` wired to `calculate_phei`; unavailable topology → "unavailable" risk (no fabricated score); `calculate_systemic_risk` kept as legacy; latent `KeyError` in "removed" section fixed (reads `previous_graph`); new `tests/test_report_generator.py` (8 tests). Verification: `python -m pytest tests/test_report_generator.py tests/test_parser.py tests/test_risk_analyzer.py tests/test_inventory_reporter.py -q` → 76 passed; `git diff --check` clean. |
| W1-DE-03.R | T-DE-03 | Vale | `src/reporter/inventory.py`, `src/cli.py`, `examples/fixtures/sample_risk_report.json` | `sample_risk_report.json`: `input.type=="file"`, `input.format=="synthetic-graph"`, `risk.score==6.0`, `method=="phei"`, 3 findings, synthetic-labeled, no path field | Matches v0.1; Mode A fields/behavior preserved + existing tests pass; offline, deterministic |
| W1-DE-04.V | T-DE-04 | Aliyan (provisional) | `src/web/dashboard.html` | `dashboard.html` (served at `/` by `python -m src.web`) renders findings table, risk summary, remediation plan; **no level labels** | Data-driven; no framework; numeric score + status only |
| W1-DE-03.T | T-DE-02/03 | Christian | `tests/test_e2e_risk.py`, `docs/E2E_EXPECTED_RESULTS.md` | Passing offline test asserts the 6.0 reference (and no path field) | Deterministic: run twice with the same fixed scan_id and created_at and compare outputs. **Partial 2026-11-02 (Christian):** test module and `docs/E2E_EXPECTED_RESULTS.md` written. Verification: `python -m pytest tests/test_e2e_risk.py -v` -> 6 passed, 7 skipped (Windows, Python 3.15); the 7 skips need W1-DE-01.F, W1-DE-01.L, and W1-DE-03.R, so the reference and byte-identity assertions are not yet verified. |

**Resolved field mapping (all spec-supported; see STATUS.md Verified/Proposed/Unverified):**
- `input = { type: file, filename: "known_topology.json", format:
  "synthetic-graph" }` — the known-topology case is a JSON file, so its `type` is
  `file`; `format` is a free string and `synthetic-graph` is a spec-valid value (the
  spec lists it as an example; the committed demo uses it). `type` is a separate
  field with enum `directory`/`lockfile`/`manual`/`file`.
- `analysis_mode: dependency_graph`, `topology_status: known`.
- `packages[]`: id, name, version, hash (null). `edges[]`: id, source_id, target_id,
  type (edge weight is an input consumed by PHEI, not an output field).
- `vulnerability_lookup`: `{ status, total_packages, checked_package_ids, matched }`
  only — **no `advisory_source`** in the lookup (it belongs on each finding, not the
  lookup). `matched` = the number of **distinct** package IDs with at least one finding
  — 3 here only because each of the 3 findings is on a different checked package.
- `findings[]`: one per synthetic advisory — required `id`, `package_id` (references a
  checked package), `advisory_source` (e.g. `synthetic-fixture`), `advisory_id`
  (`SYNTH-2026-xxxx`), `severity` **`null`** (v0.1 defines no severity values yet),
  `title`, `description` (marked synthetic). Synthetic findings are included; severity
  is unspecified and does not affect the score.
- `risk`: `{ status: available, score: 6.0, method: phei, reason }` — risk status enum
  is `available`/`unavailable` (NOT `complete`); `available` here because a numeric
  PHEI score is present. Reason: topology-based (edge weights × node multiplicity); severity
  is unspecified (`findings[].severity` is `null`) and is not in the score.
- **No path field emitted.** v0.1 defines no risk-path field; a risk-path (e.g. a
  `top_risk_path`) is **not** part of this week's report and is deferred to a
  separate schema decision. **`packages[].risk_score`: deferred** (node-level PHEI
  undefined; emitting it would require inventing a definition).
- `warnings[]`: carries (a) "CVE/advisory data is a synthetic fixture, not a live lookup; `findings[].severity` is unspecified (`null`) and not in the score; edge-weight function resolved as topology-only."

**PHEI argmax (how the 6.0 is obtained; no path field is emitted this week):**
`calculate_phei` computes each path's value as
`path_phei = sum_edge_weights(P) × impact_multiplicity(P)` and returns the scalar
maximum (`max_path_phei`). For the 3-node unit chain (A→B, B→C): 2 edges × 1.0 =
path weight 2.0, × 3 nodes = 6.0. The score is this argmax value, capped at 10.0,
and is invariant to CVE severity (severity is `null` per v0.1 and does not enter the
score).
`calculate_phei` returns **only the scalar score** — its return shape is **unchanged**.
v0.1 defines **no** risk-path field, so no path (e.g. a `top_risk_path`) is emitted,
rendered, or asserted in this week's report or tests. Any risk-path output is a
**proposed** out-of-spec addition to be decided separately (not this week); it is
deferred, not added.

### C0-prereq — Proposed input-fixture contract (APPROVAL REQUIRED before Nick authors)

There is **no committed input-fixture shape** in the repository yet (the spec and the
committed demo define only the *output* report; `examples/fixtures/` does not exist).
The shape below is **proposed** and must be **approved at C0** before Nick writes the
fixtures. Approval = an explicit user decision; do not treat this as agreed until then.

`examples/fixtures/known_topology.json` — known-topology *input* (not the output report):
```json
{
  "_demo_fixture": "Synthetic known-topology INPUT. Fictional packages; not a real dependency graph.",
  "packages": [
    { "id": "synth-a", "name": "synth-a", "version": "0.0.0" },
    { "id": "synth-b", "name": "synth-b", "version": "0.0.0" },
    { "id": "synth-c", "name": "synth-c", "version": "0.0.0" }
  ],
  "edges": [
    { "id": "e1", "source": "synth-a", "target": "synth-b", "weight": 1.0 },
    { "id": "e2", "source": "synth-b", "target": "synth-c", "weight": 1.0 }
  ]
}
```

`examples/fixtures/cve_fixture.json` — synthetic advisory *input*:
```json
{
  "_demo_fixture": "Synthetic advisory INPUT. Fictional advisories; not real CVEs.",
  "advisories": [
    {
      "id": "SYNTH-2026-0001",
      "package_id": "synth-a",
      "title": "Synthetic advisory A",
      "description": "Synthetic example advisory for synth-a. Not a real vulnerability."
    },
    {
      "id": "SYNTH-2026-0002",
      "package_id": "synth-b",
      "title": "Synthetic advisory B",
      "description": "Synthetic example advisory for synth-b. Not a real vulnerability."
    },
    {
      "id": "SYNTH-2026-0003",
      "package_id": "synth-c",
      "title": "Synthetic advisory C",
      "description": "Synthetic example advisory for synth-c. Not a real vulnerability."
    }
  ]
}
```

**Rules for the proposed shape:**
- **Packages** `packages[]`: each has `id` (unique string), `name`, `version`. The
  *output* report uses a *separate* `packages` shape (see the spec) — these two
  `packages` arrays are **distinct** (input vs output); do not conflate them.
- **Edges** `edges[]`: each has `id`, `source`, `target` (each references a package
  `id` in `packages[]`), and `weight` (number; unit weight `1.0`). Three packages,
  two directed unit-weight edges (`a→b`, `b→c`) is the intended chain.
- **Advisories** `advisories[]`: each has `id` (form `SYNTH-2026-XXXX`, all unique),
  `package_id` (references a package `id` in the topology), `title`, `description`.
  Three advisories, one per package (synth-a, synth-b, synth-c).
- **Required:** `_demo_fixture` (synthetic label), and, per item above, the fields
  listed. **Uniqueness:** package `id`s unique; edge `id`s unique; advisory `id`s
  unique. **Invalid references:** an edge `source`/`target` or an advisory
  `package_id` must name an existing package `id`; otherwise the loader must reject
  it (do not invent the package).
- **No real identifiers:** no real CVE numbers, package versions, or advisory IDs.

> **Not a loader promise:** nothing in the tree currently accepts this shape. `load_known_topo_json()`
> is *proposed* (W1-DE-01.L, Vale) and does not exist yet. This contract only defines what Nick's
> input fixtures *should* look like once the shape is approved.

## DECISIONS — Severity mapping, topology, PHEI, model backend, and GUI (2026-11-03)

### Severity (OSV authoritative)
- **OSV is the authoritative source** for vulnerability findings and supplied severity data.
- When OSV provides a usable CVSS score, map deterministically:
  - `Low`: 0.1–3.9
  - `Medium`: 4.0–6.9
  - `High`: 7.0–10.0
- If severity is missing or unusable, label it **Unknown**; do **not** infer it with an LLM.
- Preserve the source score, CVSS version/vector, and provenance where available.
- `deps.dev` may add package/dependency context or cross-check package metadata. It **must not** invent or override OSV severity.

### Dependency edges and PHEI
- An edge records that one package depends on another; nodes are packages, edges are their dependency relationships.
- **Prefer the project's resolved lockfile or package-manager dependency tree** as the source of actual edges.
- `deps.dev` may enrich or cross-check dependency information, but its graph can vary by environment/options. **Do not** silently treat it as the project's authoritative resolved graph.
- **Never infer edges from an LLM or from a flat package list.**
- **PHEI is a separate topology-based impact score with a transparent, deterministic 0–100 normalization.** It is computed on the known dependency graph using:
  1. **Reachable dependents**: for each vulnerable package, count how many other packages transitively depend on it (direct + indirect). This is the "impact multiplicity."
  2. **Recorded importance/criticality**: if the graph carries a `node_risks` dict (CVE-severity per node) or a separate `importance` field on nodes, use those as weighted factors. If no importance data exists, use unweighted reachable-dep counts only.
  3. **Normalization**: `raw_score = Σ(reachable_dependents[node] × importance[node])` over all vulnerable nodes in the graph; `PHEI = min(100, raw_score / max(1, total_vulnerable_nodes) × 10)`. This yields a 0–100 score. If the graph has no known edges, PHEI is **unavailable** (do not fabricate a score).
- PHEI is distinct from per-finding Low/Medium/High severity. It requires a known dependency graph and the approved scoring rule above.
- If trustworthy topology or an approved PHEI scoring rule is absent, **report topology-based PHEI as unavailable**; do not fabricate a score.

### Model backend — **OpenAI/ChatGPT, Claude, or a custom endpoint** (user-selected)
||- **OpenAI/ChatGPT, Claude, or a custom endpoint configured by URL/IP and port (credentials if required)** are valid for AI explanations in the demo. The user selects and configures the provider.
|- Keep deterministic explanation fallback available when no provider is configured or the endpoint is unreachable.
|- The `src/explanation/` layer's deterministic explainer is the default; the optional local-model client targets any `/v1/chat/completions` endpoint via `OPENAI_BASE_URL` / `OPENAI_API_KEY` (no credentials committed).
|- **No remote endpoint is approved by default.** Model use requires explicit opt-in (`--model ON` + `OPENAI_BASE_URL` pointing to a configured endpoint).

### GUI — settled: standalone app for Windows/Linux
- **Deliver a standalone GUI for Windows and Linux.** Docker is **dismissed/out of scope**.
- The stdlib `http.server` dashboard (`src/web/`) is the appropriate approach: a self-contained Python script that serves `dashboard.html` on loopback (127.0.0.1), works on any OS with Python 3.10+, requires no third-party deps, and is a single `python -m src.web` command.
- The dashboard is **read-only**: it serves a report and its page; it does not re-run scans, edit manifests, or imply a fix was verified.
- For the Dec 9 demo, the stdlib dashboard is sufficient. A full Flask+D3 interactive graph is deferred.

### Bounded dependency fixes
- The agent may propose bounded dependency fixes when a known fixed version exists, but must show rationale, diff, and verification results and obtain explicit approval before modifying scanned project files.
- Source-code fixes are **suggestions only** for the initial demo.
- If evidence is inadequate or verification fails, stop without applying the fix.

## Phase 1: Parser (Multi-format Manifest Support) — December-critical → T-DE-01
Owner: Vale. Depends: shared `DependencyGraph` IR (T-DE-03 schema).
- [x] Parse `requirements.txt` (`package==version`) — `src/parser/parser.py:7–57`
- [x] Parse `pyproject.toml` (`[project] dependencies`) — `src/parser/parser.py:78–111`
- [x] `build_mock_graph()` test helper — `src/parser/parser.py:113–130`
- [x] Add `package.json` (JSON) parser via `json` module — `src/parser/parser.py:parse_package_json` (W9, Nick)
- [ ] Add `go.mod` / `go.sum` parser — **W10 blocker for ≥4 target**
- [ ] Add `Cargo.toml` / `Cargo.lock` parser
- [ ] Add `Gemfile` / `package-lock.json` parsers
- [ ] Normalize all formats into shared `DependencyGraph` IR
- [x] Tests: `tests/test_parser.py` (mock graph + file read)
- **Status: 3/4 minimum formats** (requirements.txt, pyproject.toml, package.json). go.mod is the remaining blocker.

## Phase 2: Engine (Real CVE Lookups + PHEI Reconciliation) — December-critical → T-DE-02
Owner: Vale. Depends: parser (T-DE-01), reporter schema (T-DE-03).
|- [x] PHEI path-max scoring implemented in `src/engine/risk_analyzer.py`
  (replaces the old global-sum; resolves the path-max vs global-sum divergence)
|- [x] Wire NVD API client into the graph so `get_cve_severity(node_key)` returns real data
  (2026-11-03: `risk_analyzer.py` patched — `get_cve_severity(node_key)` calls `_get_nvd_client()` →
  `NVDClient.query_nvd_api()`, falls back to `MOCK_CVE_DB` on `None`/error;
  `MOCK_CVE_DB` restricted to explicit test/demo paths only)
|- [x] OSV API fallback for ecosystems not in NVD (npm, PyPI, Go, Rust)
  (2026-11-03: `nvd_client.py` has `query_osv_api()`; `get_cve_severity` tries NVD first,
  falls back to OSV; real OSV scan on repo root returned 0 findings — clean)
|- [x] Severity normalization (NVD CVSS ↔ OSV severity ↔ PHEI scale)
  (2026-11-03: NVD returns CVSS score as `severity_score`; OSV returns `severity` enum;
  unknown severity stays `None` — no fabricated categorical labels)
|- [x] Rate-limiting / retry / exponential backoff for API clients
  (2026-11-03: `nvd_client.py` `RateLimiter` + `CachedResponse`; 5 req/30s no key, 50/30s with key)
|- [x] Update `tests/test_risk_analyzer.py` with mocked API responses
  (2026-11-03: `tests/test_risk_analyzer_nvd_integration.py` — 12 focused tests, all passing,
  injected client, clean scan, NVD→OSV fallback, rate-limit, cache, single-node, no edges, etc.)
|- [x] Run PHEI end-to-end on a **real** project (2026-11-03: real OSV-Scanner scan on repo root
  returned 0 findings — clean scan; normalizer produces dashboard-compatible JSON with
  `risk.status: "unavailable"`, `risk.score: null` for inventory-only input; 12 focused offline
  tests pass; full suite 272 tests pass)

## Phase 3: Reporter & Agent Layer — December-critical → T-DE-03
Owner: Vale. Depends: engine (T-DE-02).
- [x] Structured output schema: `RiskReport` dataclass + `src/reporter/interface.py`
  (v0.1 contract: `docs/specs/scan-result-v0.1.md`; inventory serializer implemented,
  dependency-graph serializer **unimplemented**)
- [ ] Agree graph construction + scoring semantics; export graph adjacency for dashboard
- [ ] Generate dependency risk-path summaries using the agreed scoring contract
- [x] Produce plain-language risk narratives per component
- [x] **AI layer (`src/agent/`):** pluggable model backend (local endpoint or API key),
  grounded in the structured report + before/after risk diff. **Investigation loop
  implemented and tested** (2026-10-03; 45 passing tests in `tests/test_agent.py`)
  **plus a remediation stage** (uncommitted in the working tree): `build_remediation_plan`
  emits one item per baseline finding using only normalized scanner evidence — scanner-provided
  fixed versions verbatim (never invented), no numeric CVSS score or high/low label (unknown
  severity stays unknown), and a plain recommended action that names a fixed version
  only when the scanner supplies one; `verify_remediation` reconciles the plan against a
  user-supplied after scan (no network) and makes **no resolution claim** with no after
  scan (`status == "not_run"`); malformed/missing/unusable after reports fail closed to
  `not_run`. The system does **not** edit manifests, install packages, execute project code,
  or claim a fix worked without an after-scan.  An opt-in deps.dev
  enrichment layer (`tests/test_enrichment.py`, 26 passing)
  adds the `package_context` tool. Bounded tool loop over normalized OSV-Scanner output,
  conditional allowlisted tool selection, append-only `EvidenceTrail`, deterministic
  grounded policy when no model
  (or when the model is out of band), and `compare_scans` before/after delta. The
  **W9 real-project OSV-Scanner scan (Vale)**: `osv-scanner scan . --experimental-exclude tests examples docs` returned **0 findings** (clean scan; no known CVEs in project deps). Normalizer produces dashboard-compatible JSON (`risk.status: "unavailable"`, `risk.score: null` for inventory-only). 15 focused offline tests pass. `src/agent/normalizer.py` (445 lines) remains the older agent-format normalizer; `src/web/osv_normalizer.py` is the dashboard-format normalizer. No single canonical normalizer yet — two exist with different schemas. **NVD/OSV wiring now complete (2026-11-03): `risk_analyzer.py` patched — `get_cve_severity(node_key)` calls `NVDClient.query_nvd_api()`, then `query_osv_api()`; MOCK_CVE_DB removed from production path (audit 2026-11-03). Full suite: 275 tests pass.**
  loop is **not** "OSV-Scanner + LLM summary": every claim is backed by a real field
  from the OSV-Scanner output and every tool call is recorded.  A **real** model backend (**OpenAI/ChatGPT, Claude, or a custom endpoint**, user-configured — pending decision, see TASKS.md pending-decisions /
  `docs/STATUS.md`) is **not yet wired** (`used_llm=False` in current runs).
- [x] Deterministic plain-language fallback when no model is configured / generation fails
- [x] Tests: `tests/test_agent.py` (45) + `tests/test_remediation.py` (24, remediation
  planning + after-scan verification, uncommitted) + `tests/test_report_generator.py` (8)
  (`tests/test_reporter.py` still to be added alongside the Mode B serializer)

## Phase 4: Dashboard — December-critical (the visible deliverable) → T-DE-04
Owner: Team. Depends: engine (T-DE-02) + reporter (T-DE-03).
- [x] `src/web/` stdlib dashboard (read-only, 127.0.0.1, no third-party deps): `__init__.py`, `__main__.py`, `server.py`, `dashboard.html`
- [x] `src/web/osv_normalizer.py` (6,851 bytes, untracked): normalizes OSV JSON for dashboard (corrected to dashboard contract)
- [ ] Severity filter (numeric `severity_score` ≥ 7.0 threshold; null → Unknown)
- [ ] Search bar (pending — no repository evidence of implementation as of 2026-11-06)
- [ ] Interactive graph visualization (deferred to W12)
- [ ] Real-time risk score display with trend history (deferred)
- [ ] Filter by ecosystem, severity threshold, node criticality (deferred)

## Phase 5: Standalone GUI (Windows/Linux) — December deliverable → T-DE-05
Owner: Team. Depends: dashboard (T-DE-04).
- [ ] Finalize `src/web/dashboard.html` (read-only stdlib `http.server` + vanilla JS, no framework)
- [ ] Ensure `python -m src.web --report <report.json> --port 8000` works on Windows and Linux
- [ ] Add `--model ON/OFF` flag for **OpenAI/ChatGPT, Claude, or a custom endpoint** explanation toggle (deterministic fallback when OFF)
- [ ] Verify dashboard renders: findings table, risk status, remediation plan (fixed versions verbatim), `not_run` state
- [ ] No Docker, no third-party deps, no API keys required
- [ ] Single-command launch: `python -m src.web --report examples/fixtures/sample_risk_report.json --port 8000`

## Complete Demo Flow (T-DE-02 + T-DE-03, W10–W13)
**Owners:** Vale (scanner/reporter), Christian (dashboard), Aliyan (demo validation)
**Due:** Dec 8 rehearsal, Dec 9 presentation

1. Scan a controlled vulnerable project (fixture with known CVEs, clearly labeled as non-real).
2. Show OSV findings and severity scores on the dashboard.
3. Generate grounded AI explanation and fix recommendation (user-selectable endpoint: OpenAI/ChatGPT, Claude, or custom).
4. Require visible human approval before applying any patch.
5. Apply only the approved patch; run a second scan.
6. Report only verified results (no unverified claims).

**Systemic risk vs. PHEI:** Systemic risk (CVE severity × topology) and PHEI (topology-only path-max × impact-multiplicity) are **separate results**. Risk is unavailable when topology or scoring evidence is missing.

**Clean repo scan vs. controlled demo:** The repo-root OSV-Scanner scan (0 findings) is a **clean-repository scan**, not a demo. The December demo uses a **controlled vulnerable project** (fixture with known CVEs) — never present the fixture's findings as real project findings. The two are distinct and must not be conflated.

## Status

### Current baseline (published baseline `83b10fb`, 2026-10-19)
- **Date:** 2026-11-09. **Branch:** `feat/inventory-report`. **HEAD (local):** `11937e4a9a9ea60eeea64c510d35855e170cfe31` (W10 handoffs, 2026-11-09). **Published tip:** `origin/feat/inventory-report` = `11937e4a9a9ea60eeea64c510d35855e170cfe31`.
- **Agent layer (`src/agent/`):**
- **Explanation + dashboard (committed 83b10fb):**  `src/explanation/` (3 files:
  `__init__.py`, `deterministic.py`, `local_model.py`) — a grounded deterministic
  explainer plus an optional **OpenAI/ChatGPT, Claude, or a custom** local-model client (env-only
  `OPENAI_BASE_URL` / `OPENAI_API_KEY`, stdlib `urllib`, per-finding deterministic
  fallback on any failure, bounded `max_calls` cap, no credentials committed).
  `src/web/` (4 files: `__init__.py`, `__main__.py`, `server.py`,
  `dashboard.html`): a minimal *read-only* stdlib `http.server` dashboard (no
  third-party deps) serving `dashboard.html` at `/` and the report at
  `/report.json`, rendering findings, risk limitations, the remediation plan,
  and the verification state **including `not_run`** (no resolution claim).
  Tests: `tests/test_explanation.py` (20), `tests/test_explanation_http.py` (7),
  `tests/test_dashboard.py` (10). All **committed** in 83b10fb and pushed to
  `origin/feat/inventory-report`.
- **Prior baseline (historical):** `a873a90` (2026-10-17), `1b4a8d9` (2026-10-03),
  `b4fc87c` (2026-10-02), `f1c59a8` (agent/enrichment/pipeline implementation),
  `6129e14` (remediation stage, last implementation commit before 83b10fb).
||- **Working tree:** tracked files **unmodified** at HEAD (`11937e4a9a9ea60eeea64c510d35855e170cfe31`).
|- **Test count:** 248 passed, 29 subtests — reported historical result (date 2026-10-19
  not independently verifiable from repository evidence; no test output file present).
  Full suite: 241 passed, 29 subtests, 2 warnings (re-run 2026-10-10): 53 reporter, 45 agent,
  26 enrichment, 23 pipeline, **24 remediation**, 11 NVD integration, 10 parser, 8
  report generator, 5 risk analyzer, 23 explanation, 7 explanation-HTTP, 13
  dashboard (23 explanation, 7 explanation-HTTP, 13 dashboard). The T-DE-02
  NVD integration suite currently passes (11).
  > **Unverified:** The aggregate totals "248 passed" and "241 passed" are **unverified**.
  > The per-module breakdown (53+45+26+23+24+11+10+8+5+23+7+13 = 248) does not
  > establish a passing-test total — it is a function-count listing, not a run result.
  > No test output file exists on disk to confirm either figure.


### Implementation state (published HEAD `11937e4a9a9ea60eeea64c510d35855e170cfe31`; 2026-11-09)
|- **Parser (T-DE-01):** `requirements.txt` + `pyproject.toml` (W3, merged) — 5 new test methods, 62 lines added. `parse_pyproject_toml()` reads `[project].dependencies` and `[project.optional-dependencies]` into a `DependencyGraph` with `edge_availability = "unavailable"`. `parse_package_json()` added (W9, committed `1ad2a7b`). **Status: 3/4 minimum formats (requirements.txt, pyproject.toml, package.json). Remaining to reach the ≥4 target: go.mod (W10 blocker).**
- **Engine (T-DE-02):** PHEI path-max scoring implemented
  (`calculate_path_weight` / `calculate_impact_multiplicity` / `calculate_phei`) +
  `UnavailableTopologyError` guard. NVD/OSV client code present
  (`src/engine/nvd_client.py`) — **NVD/OSV wiring closed (2026-11-03):** `get_cve_severity(node_key)` calls `NVDClient.query_nvd_api()` then `query_osv_api()`; MOCK_CVE_DB removed from production path. Real OSV-Scanner scan on repo root returned **0 findings** (clean). Rate-limiting / retry / exponential backoff implemented (5 req/30s no key, 50/30s with key).
- **Reporter (T-DE-03):** `RiskReport` dataclass + `src/reporter/interface.py` +
  `report_generator.py` present. Inventory serializer implemented; **dependency-graph
  serializer unimplemented (W10 deliverable)**. The **read-only stdlib dashboard** (`src/web/`) is
  **committed** (83b10fb) — a stdlib `http.server` + `dashboard.html`, serving the
  report and its page; the full Flask+D3 dashboard (T-DE-04) is still not started.
|- **Agent (T-DE-03 AI layer):** implemented + tested — new `src/agent/` package
  (bounded tool loop, `EvidenceTrail`, allowlisted tools, deterministic grounded policy
  with no model, `compare_scans`). **45 passing tests** (`tests/test_agent.py`).
  Plus **remediation** (`build_remediation_plan` / `verify_remediation`; committed in
  `6129e14`): `build_remediation_plan` (pure; one item per finding; fixed versions
  verbatim; severity left `None` / evidence-only) + `verify_remediation` (user-supplied
  after scan; no after scan → `not_run`, no resolution claim; unusable after report
  fails closed to `not_run`). **24 passing tests** (`tests/test_remediation.py`).
  A **real** model backend (**OpenAI/ChatGPT, Claude, or a custom endpoint**, user-configured) is **not yet wired** (pending decision);
  current runs use the deterministic policy (`used_llm=False`). The **explanation layer**
  (`src/explanation/`, **committed** 83b10fb) provides a grounded deterministic
  explainer plus an optional **OpenAI/ChatGPT, Claude, or a custom** local-model client (env-only config,
  per-finding deterministic fallback) — tested by `tests/test_explanation.py` (23) and
  `tests/test_explanation_http.py` (7).

> Test counts are **historical** unless re-run. The "pytest 79 passed" figure dates to
> the `5b8a1f7` baseline and has been **superseded**: the full suite now runs
> **241 passed, 29 subtests, 2 warnings** (re-run 2026-10-10): 53 reporter, 45 agent,
> 26 enrichment, 23 pipeline, **24 remediation**, 11 NVD integration, 10 parser, 8
> report generator, 5 risk analyzer, 23 explanation, 7 explanation-HTTP, 13
> dashboard (23 explanation, 7 explanation-HTTP, 13 dashboard). The T-DE-02
> NVD integration suite currently passes (11).

## Unresolved technical contradictions (do not guess)
- Dashboard stack: **settled** — stdlib `src/web/` (read-only, 127.0.0.1, no third-party deps) is the December deliverable. Flask+D3 deferred to W12. The `src/web/osv_normalizer.py` (6,851 bytes, untracked) normalizes OSV JSON for the dashboard contract.
- Search bar: pending — no repository evidence of implementation as of 2026-11-06. W9 plan step 3 marked "pending: search bar not yet implemented."
- Severity filter: plan expects numeric `severity_score` threshold (≥ 7.0 matches; below 7.0 = Unknown; null = Unknown).
- go.mod indirect deps: unresolved — direct only or transitive? TASKS.md §DECISIONS.
- **OSV severity mapping:** resolved — TASKS.md §DECISIONS (Low: 0.1–3.9, Medium: 4.0–6.9, High: 7.0–10.0).
- Professor recommendations (agent handoffs with context blocks, evidence-grounded solutions, user approval before code changes, ML/model support, architecture diagrams) are **proposed design work pending team/sponsor agreement**; they are not implemented. The current remediation behavior is read-only (no manifest edits, no package installs, no execution of project code; no resolution claim without an after-scan).