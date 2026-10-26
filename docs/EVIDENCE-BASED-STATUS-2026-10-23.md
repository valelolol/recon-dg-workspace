# RECON-DG Evidence-Based Project Status Report

**Date:** 2026-10-23 (CDT)
**Branch:** `feat/inventory-report`
**HEAD:** `8154770` — "docs: reconcile documentation to verified implementation state (W2/W7 scanner-reporter workflow, src.web CLI, OSV-Scanner external)"
**Remote tip:** `origin/feat/inventory-report` = `8154770` (matched — fully pushed)
**Last implementation commit:** `83b10fb` (2026-10-19, "feat: add opt-in explanations and read-only dashboard")
**Last implementation commit before that:** `6129e14` (2026-10-10, "feat(agent): add evidence-grounded remediation verification")
**Working tree:** untracked (2 files): `docs/EVIDENCE-BASED-STATUS-2026-10-23.md` (this report, intentionally untracked) + `docs/REVIEW-DECISIONS.md` (intentionally preserved).

---

## 1. Completed (verified by source files + commit history)

### T-DE-01: Parser (partial)
- **`requirements.txt` parser** — `src/parser/parser.py:7–57` (72 lines total). Verified: function `parse_requirements()` exists, reads a file, builds a `DependencyGraph` with `edge_availability="unavailable"`.
- **`build_mock_graph()` test helper** — `src/parser/parser.py:54–72`. Verified: exists.
- **`tests/test_parser.py`** — 10 tests. Verified: exists (5,627 bytes).
- **NOT done:** `parse_package_json()`, `parse_pyproject_toml()`, `parse_go_mod()`, `parse_Cargo_toml()`, `parse_Gemfile()` — **none exist in the source tree.** Only 1 of ~6 manifest formats implemented.
- **`src/parser/__init__.py`** — 0 bytes (empty). No public API surface exported.
| **`examples/scan-results/` — 2 synthetic demo fixtures (not real scan output; see TASKS.md line 22 synthetic-data rule):**
  - `dependency-graph-demo.json` (76 lines): labeled `_demo_fixture: "Demonstration fixture — synthetic dependency graph scan result. Uses fictional package names; not a production output."` Fictional packages (`synth-utils`, `synth-network`), advisory `SYNTH-2026-0042` from `synth-advisory-db`. `topology_status: "known"`, 1 synthetic finding.
  - `inventory-only.json` (52 lines): labeled `_demo_fixture: "Demonstration fixture — inventory scan result. Synthetic data; not a production output."` `topology_status: "unavailable"`, `vulnerability_lookup.status: "not_run"`, `findings: []`. Warning: "Vulnerability lookup was not requested for this demonstration."
  - Both created in commit `4af2d8e` ("Define scan result v0.1 contract and **demonstration fixtures**"). **Not real OSV-Scanner output.**

### T-DE-02: Engine (partial)
- **PHEI path-max scoring** — `src/engine/risk_analyzer.py` (216 lines). Verified: `calculate_path_weight()`, `calculate_impact_multiplicity()`, `calculate_phei()` exist; `UnavailableTopologyError` guard present.
- **NVD/OSV client** — `src/engine/nvd_client.py` (415 lines). Verified: `NVDClient`, `RateLimiter`, `CachedResponse` classes exist. **The authoritative scanner is the external OSV-Scanner** (ROADMAP.md "Security and privacy gates" heading, line 146); NVD/OSV API calls are enrichment. No evidence of a live OSV-Scanner scan on disk.
- **`tests/test_risk_analyzer.py`** — 5 tests. Verified: exists.
- **`tests/test_nvd_integration.py`** — 11 tests. Verified: exists (10,937 bytes).
- **NOT done:** OSV-Scanner scan output wired into the graph for `get_cve_severity(node_key)`; severity normalization (NVD CVSS ↔ OSV ↔ PHEI).

### T-DE-03: Reporter & Agent Layer (substantially complete)
- **`RiskReport` dataclass + schema** — `src/reporter/interface.py` (328 lines). Verified: `RiskReport` dataclass + `RiskLevel` enum exist.
- **`report_generator.py`** — `generate_report()` wired to `calculate_phei` (path-max). Verified: 122 lines.
- **Inventory serializer (Mode A)** — `src/reporter/inventory.py` (324 lines). Verified: exists.
- **Dependency-graph serializer (Mode B)** — **unimplemented** (per TASKS.md Phase 3, line 237).
- **Agent layer (`src/agent/`) — implemented + tested** (published in `f1c59a8`, remediation in `6129e14`):
  - `agent.py` (1,013 lines): bounded evidence-grounded investigation loop, `EvidenceTrail`, allowlisted tool set, deterministic grounded policy when no model, `compare_scans`.
  - `normalizer.py` (445 lines): normalizes OSV-Scanner JSON → `DependencyGraph` + `Finding` objects.
  - `scan_runner.py` (305 lines): thin OSV-Scanner subprocess wrapper; `construct_command()`, `run_scan()`, `run_scan_from_json()`.
  - `pipeline.py` (396 lines): end-to-end glue (`investigate()`, `investigate_from_json()`).
  - `__init__.py` (46 lines): re-exports `Agent`, `EvidenceTrail`, `Finding`, `compare_scans`, `normalize_scan`, `osv_json_to_graph`, `run_scan`, `run_scan_from_json`, `investigate`, `investigate_from_json`, `ScanResult` + `__version__ = "0.1.0"`.
  - **Total: 2,205 lines across 5 files.**
  - **Remediation stage** (`6129e14`): `build_remediation_plan` (pure, one item per finding, fixed versions verbatim, severity `None`), `verify_remediation` (reconciles against user-supplied after scan; no after scan → `not_run`, no resolution claim).
- **`tests/test_agent.py`** — 45 tests. Verified: exists (36,950 bytes).
- **`tests/test_remediation.py`** — 24 tests. Verified: exists (21,434 bytes).
- **`tests/test_pipeline.py`** — 23 tests. Verified: exists (36,449 bytes).
- **Explanation layer (`src/explanation/`, committed `83b10fb`):**
  - `deterministic.py` (124 lines): grounded deterministic explainer (default).
  - `local_model.py` (321 lines): optional OpenAI-compatible `/v1/chat/completions` client via stdlib `urllib`.
  - `__init__.py` (128 lines): `add_explanations(report, use_model=True)`.
  - `tests/test_explanation.py` — 23 tests. Verified: exists (19,694 bytes).
  - `tests/test_explanation_http.py` — 7 tests. Verified: exists (11,206 bytes).
  - **Total: 573 lines across 3 files.**
- **`tests/test_report_generator.py`** — 8 tests. Verified: exists (9,475 bytes).
- **`tests/test_inventory_reporter.py`** — 53 tests. Verified: exists (21,526 bytes).
- **`tests/test_enrichment.py`** — 26 tests. Verified: exists (14,294 bytes).
- **`tests/data/osv-scanner.json`** — real OSV-Scanner shape fixture (6,236 bytes). Verified: exists.
- **`tests/fixtures/requirements-before.txt`** — real manifest fixture (368 bytes). Verified: exists.
- **NOT done:** Real model backend (llama.cpp vs. user API key) **not wired** (pending decision); current runs use deterministic policy (`used_llm=False`).

### T-DE-04: Dashboard (partial)
- **stdlib `src.web/` dashboard** — **committed** (`83b10fb`, read-only):
  - `server.py` (175 lines): minimal `http.server` dashboard on `127.0.0.1:8000`.
  - `dashboard.html` (263 lines): renders findings, risk limitations, remediation plan, verification state (including `not_run` red card).
  - `__init__.py` (27 lines), `__main__.py` (10 lines).
  - **Total: 475 lines across 4 files.**
  - `tests/test_dashboard.py` (13 tests, 17,532 bytes).
- **Flask+D3 dashboard (T-DE-04)** — **not started**. `src/dashboard/` does not exist.
- **`tests/test_dashboard.py`** — 13 tests. Verified: exists.

### T-DE-05: Docker (not started)
- **`Dockerfile`** — does not exist.
- **`docker-compose.yml`** — does not exist.
- **`.dockerignore`** — does not exist.

### Documentation (all committed)
- `docs/ROADMAP.md` — December roadmap (184 lines). Verified: exists.
- `docs/STATUS.md` — status document (158 lines). Verified: exists.
- `docs/weekly-handoffs/W1–W7.md` — all 7 handoffs. Verified: all exist.
- `docs/demo-presentation-outline.md` — presentation outline (90 lines). Verified: exists.
- `docs/specs/scan-result-v0.1.md` — scan-result contract. Verified: exists.
- `docs/specs/design_spec.md` — PHEI design spec (35 lines). Verified: exists.
- `docs/TEAM_ONBOARDING.md` — onboarding guide. Verified: exists (14,376 bytes).
- `docs/WEEKLY.md` — historical (M-DE-CORE). Verified: exists.
- `docs/REVIEW-DECISIONS.md` — **untracked** (intentionally preserved). Verified: exists.
- `TASKS.md` — task register (364 lines). Verified: exists.

---

## 2. In Progress

### T-DE-01: Parser (multi-format)
- **Current state:** 1 of ~6 manifest formats done (`requirements.txt`).
- **Blocked by:** `examples/fixtures/` directory does not exist (no input fixtures for testing other parsers). Note: `examples/scan-results/` exists with 2 synthetic demo fixtures (`dependency-graph-demo.json`, `inventory-only.json`) — labeled as synthetic in their own `_demo_fixture` fields (commit `4af2d8e`); they are **not** real OSV-Scanner output and **not** input fixtures for the multi-format parser.
- **Evidence:** `src/parser/parser.py` is 72 lines (only `parse_requirements` + `build_mock_graph`); no other parser functions exist.

### T-DE-02: Engine (OSV-Scanner → report workflow — unverified)
- **Current state:** OSV-Scanner scanner (`scan_runner.py`, 305 lines) and NVD/OSV enrichment client (`nvd_client.py`, 415 lines) both exist. The gap is a **missing integration** connecting a manifest scan by the authoritative external OSV-Scanner to generation of a dashboard-compatible report — neither component has been run end-to-end against a real project.
- **Operational concern:** NVD rate limits (5 req/30s without key) are an operational concern, not a blocker — the active roadmap (ROADMAP.md "Security and privacy gates" heading, line 142) designates OSV-Scanner as the authoritative scanner. No real scan output on disk to validate against.
- **Evidence:** `src/engine/nvd_client.py` exists with `NVDClient`/`RateLimiter`/`CachedResponse` classes but no evidence of a live OSV-Scanner scan (no `report.json` output file, no scan log).

### T-DE-03: Reporter (dependency-graph serializer)
- **Current state:** Inventory serializer (Mode A) implemented; dependency-graph serializer (Mode B) **unimplemented**.
- **Blocked by:** no `examples/fixtures/known_topology.json` input fixture (directory doesn't exist).

### T-DE-03: Agent (real model backend wiring)
- **Current state:** `src/explanation/local_model.py` targets `/v1/chat/completions` via env-only `OPENAI_BASE_URL`/`OPENAI_API_KEY`. **Not yet wired to a real endpoint** (llama.cpp vs. user API key — pending decision).
- **Evidence:** `src/explanation/local_model.py` (321 lines) exists; `--model` defaults to `OFF`; current runs use deterministic policy (`used_llm=False`).

---

## 3. Blocked / Pending Decisions

### Decision 1: Model backend (llama.cpp vs. user API key)
- **Status:** pending — not wired.
- **Impact:** blocks W5 (AI explanations demo), W7 (demo validation with `--model ON`).
- **Evidence:** `src/explanation/local_model.py` (321 lines) exists but `--model` defaults to `OFF`; no `OPENAI_BASE_URL`/`OPENAI_API_KEY` set in any committed file.
- **Privacy note:** `--model ON` sends finding data + API key to the configured endpoint over HTTP or HTTPS (open privacy decision — whether the endpoint is encrypted is not decided).

### Decision 2: Dashboard stack (stdlib vs. Flask+D3)
- **Status:** stdlib dashboard committed (`83b10fb`); Flask+D3 not started.
- **Impact:** blocks T-DE-04 (interactive graph, per-node paths, filters, trend history).
- **Evidence:** `src/web/` (4 files) is the stdlib dashboard; `src/dashboard/` does not exist.

### Decision 3: NVD API rate limits for demo
- **Status:** open.
- **Impact:** blocks T-DE-02 (OSV-Scanner → report workflow — unverified).
- **Evidence:** 5 req/30s without API key; 50 req/30s with key. No API key in repo.

### Decision 4: Demo scope (which manifest format to use)
- **Status:** open.
- **Impact:** blocks W7 (demo validation) and W4 (dashboard demo).
- **Evidence:** only `requirements.txt` parser exists; `examples/fixtures/` directory does not exist.

---

## 4. Planned / Not Started

### T-DE-04: Flask+D3 Dashboard
- **Status:** not started.
- **Evidence:** `src/dashboard/` does not exist; TASKS.md Phase 4 (line 267) lists 5 subtasks: create `src/dashboard/` (Flask + D3), REST endpoints (`/risk`, `/graph`, `/paths/<node>`), interactive graph visualization (D3.js / Cytoscape.js), real-time risk score display with trend history, filter by ecosystem/severity/node criticality — none implemented.

### T-DE-05: Docker Packaging
- **Status:** not started.
- **Evidence:** no `Dockerfile`, no `docker-compose.yml`, no `.dockerignore` in the repo.

### W7: Demo Validation (proposed, no registered task ID)
- **Status:** proposed handoff to Aliyan; no registered task ID in TASKS.md.
- **Evidence:** `docs/weekly-handoffs/W7-demo-validation.md` (119 lines) exists but is a **proposed** handoff — "team confirmation required, no registered task ID."
- **Deliverable:** `docs/demo-validation/validation-report.md` + `docs/demo-validation/demo-script.md` — neither directory exists.

---

## 5. Risk Assessment

| Risk | Severity | Evidence |
|------|----------|----------|
| Demo cannot show real PHEI score (no verified OSV-Scanner → report workflow) | **High** | OSV-Scanner scanner and NVD/OSV enrichment client both exist but have never been run end-to-end; no **real** scan output on disk (only synthetic demo fixtures in `examples/scan-results/`) |
| Demo cannot show real dependency graph (no `known_topology.json` fixture) | **High** | `examples/fixtures/` directory does not exist |
| AI explanation demo blocked (pending model decision) | **Medium** | `--model` defaults OFF; no `OPENAI_BASE_URL` set |
| Dashboard demo limited to read-only stdlib (no interactive graph) | **Medium** | Flask+D3 not started; only stdlib `http.server` dashboard |
| Parser covers only 1 of ~6 formats | **Medium** | `requirements.txt` only; no `package.json`/`pyproject.toml`/`go.mod` parsers |
| Test counts unverified | **Low** | "248 passed" / "241 passed" are historical claims with no test output file on disk |
| W7 has no registered task ID | **Low** | Proposed handoff exists but no TASKS.md entry |

---

## 6. Next Bounded Tasks

1. **Create `examples/fixtures/`** with `known_topology.json` and `cve_fixture.json` (T-DE-01 → T-DE-03 → T-DE-02 pipeline). Per TASKS.md line 22, synthetic demo fixtures are acceptable for demo, but **implement and verify the OSV-Scanner → dashboard-compatible report workflow** (connect the existing OSV-Scanner scanner to the existing reporter) is the critical-path blocker for a defensible December demo.
2. **Verify the OSV-Scanner → report workflow** end-to-end on a real project manifest (T-DE-02). The scanner (`scan_runner.py`) and reporter (`report_generator.py`) components exist; they need a verified end-to-end run to validate the pipeline.
3. **Resolve model backend decision** (llama.cpp vs. user API key) — blocks W5 and W7 demo validation.
4. **Team decision: stdlib vs. Flask+D3 dashboard** — blocks T-DE-04.
5. **Register W7 task** in TASKS.md (no task ID currently exists).

---

## 7. Evidence Summary

| Claim | Evidence |
|-------|----------|
| Branch `feat/inventory-report` | `git branch` — HEAD; `origin/feat/inventory-report` = `8154770` |
| HEAD = `8154770` | `git rev-parse HEAD` |
| Remote tip = `8154770` | `git rev-parse origin/feat/inventory-report` |
| Working tree untracked (2 files) | `git status --short` (this report + `docs/REVIEW-DECISIONS.md`) |
| Parser = 1 of ~6 formats | `src/parser/parser.py` is 72 lines, only `parse_requirements()` + `build_mock_graph()` |
| PHEI implemented | `src/engine/risk_analyzer.py:calculate_phei()` (216 lines) |
| OSV-Scanner scanner + NVD/OSV enrichment client exist | `src/agent/scan_runner.py` (305 lines) + `src/engine/nvd_client.py` (415 lines): `NVDClient`, `RateLimiter`, `CachedResponse` |
| Agent layer implemented | `src/agent/` (5 files, 2,205 lines); `tests/test_agent.py` (45 tests) |
| Remediation stage implemented | `src/agent/agent.py:build_remediation_plan()` + `verify_remediation()` (committed `6129e14`); `tests/test_remediation.py` (24 tests) |
| Explanation layer committed | `src/explanation/` (3 files, 573 lines); `tests/test_explanation.py` (23) + `tests/test_explanation_http.py` (7) |
| Dashboard committed | `src/web/` (4 files, 475 lines); `tests/test_dashboard.py` (13 tests) |
| Docker not started | No `Dockerfile`/`docker-compose.yml`/`.dockerignore` in repo |
| `examples/fixtures/` missing | `ls: cannot access 'examples/fixtures/'` |
| Test counts unverified | No `pytest` output file on disk; "248 passed" is a historical claim |
| W7 no task ID | No TASKS.md entry for W7; `docs/weekly-handoffs/W7-demo-validation.md` says "no registered task ID" |

---

*Report generated from live repository state at `/home/vale/projects/recon-dg-workspace` on 2026-10-23. All file paths and line numbers are from direct reads of the working tree.*
