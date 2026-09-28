# TASKS.md — Predictive Risk Mapping Agent

## Project Scope (December deliverable)

recon-dg is a **dependency risk mapper**. One command must, for a given project:

1. **Scan** → build a dependency graph (which third-party packages are used + how they
   connect).
2. **Check** → look up known CVEs for each package (NVD + OSV).
3. **Score systemic risk** → not "this package has a flaw," but whether low-severity
   flaws combine along critical dependency paths into a real threat (PHEI path-max).
4. **Display** → a clear dashboard showing the graph, per-package risk, and the top
   risk paths.
5. **Explain** → an AI backend that turns each finding into plain-language explanations
   and helps developers prioritize what to fix.

### The two scanner tracks — do NOT conflate them
- **Core (December deliverable):** dependency/CVE assessment over the graph —
  `src/parser`, `src/models`, `src/engine`, `src/reporter`, `src/agent`, dashboard.
- **Supporting sub-track (Week 1):** source-code static analysis via Bandit —
  `examples/source-audit-week1/`, `src/scanner/`. It finds vulns *inside the code you
  scan* (a useful extra signal and a good pipeline/harness exercise). It is **not**
  the December deliverable and must stay **separate** from dependency findings.

### December-critical path (in order)
1. Parser: enough manifest formats to scan a real project.
2. Engine: wire NVD/OSV into the graph so **real** CVE data flows into PHEI.
3. Reporter: structured report schema + deterministic fallback.
4. Dashboard: web app (graph + risks + per-package risk).
5. AI explanations: `src/agent/` pluggable model layer (plain-language + prioritization).
6. Docker: portable image + local-dev compose.

## Current status (2026-09-28, branch `feat/inventory-report`)

- **Parser:** `requirements.txt` done (1 of ~6 manifest formats).
- **Engine:** PHEI path-max scoring implemented (`calculate_path_weight` /
  `calculate_impact_multiplicity` / `calculate_phei`) + `UnavailableTopologyError` guard.
  NVD/OSV client code present (`src/engine/nvd_client.py`) but **not yet run end-to-end**
  against a real project; `tests/test_nvd_integration.py` still failing (7 of 79).
- **Reporter:** `RiskReport` dataclass + `src/reporter/interface.py` + `report_generator.py`
  present. **No dashboard yet.**
- **Agent (AI explanations):** empty — not started.
- **Source-audit (Bandit) sub-track:** `multi_check_wrapper.py` runs and detects the eval
  finding but mislabels `rule_id` (`"blacklist"` instead of `B307`) and has a char-count
  bug (`"1474 results"`); `scan_demo.py` crashes (`NameError: venv_path`);
  `test_harness.py` does not run. Being corrected: **Nick** = rule mapping +
  `docs/security-checks.md`; **Christian** = harness (path, `-ll` flag, B704→B301, cover
  5 rules) + new shell/B602 & SQL/B608 example pairs. This is the supporting track,
  **not** the December deliverable.

## Phase 1: Parser (Multi-format Manifest Support) — December-critical
- [x] Parse `requirements.txt` (`package==version`) — `src/parser/parser.py:7–57`
- [x] `build_mock_graph()` test helper — `src/parser/parser.py:59–75`
- [ ] Add `package.json` (JSON) parser via `json` module
- [ ] Add `pyproject.toml` / `setup.cfg` parser via `tomllib`
- [ ] Add `go.mod` / `Gopfile.lock` parser
- [ ] Add `Cargo.toml` / `Cargo.lock` parser
- [ ] Add `Gemfile` / `package-lock.json` parsers
- [ ] Normalize all formats into shared `DependencyGraph` IR
- [x] Tests: `tests/test_parser.py` (mock graph + file read)

## Phase 2: Engine (Real CVE Lookups + PHEI Reconciliation) — December-critical
- [x] PHEI path-max scoring implemented in `src/engine/risk_analyzer.py`
  (replaces the old global-sum; resolves the path-max vs global-sum divergence)
- [ ] Wire NVD API client into the graph so `get_cve_severity(node_key)` returns real data
- [ ] OSV API fallback for ecosystems not in NVD (npm, PyPI, Go, Rust)
- [ ] Severity normalization (NVD CVSS ↔ OSV severity ↔ PHEI scale)
- [ ] Rate-limiting / retry / exponential backoff for API clients
- [ ] Update `tests/test_risk_analyzer.py` with mocked API responses
- [ ] Run PHEI end-to-end on a **real** project (currently only code, unverified)

## Phase 3: Reporter & Agent Layer — December-critical
- [x] Structured output schema: `RiskReport` dataclass + `src/reporter/interface.py`
- [ ] Agree graph construction + scoring semantics; export graph adjacency for dashboard
- [ ] Generate dependency risk-path summaries using the agreed scoring contract
- [ ] Produce plain-language risk narratives per component
- [ ] **AI layer (`src/agent/`):** pluggable model backend (local endpoint or API key),
  grounded in the structured report + before/after risk diff
- [ ] Deterministic plain-language fallback when no model is configured / generation fails
- [ ] Tests: `tests/test_reporter.py`, `tests/test_agent.py`

## Phase 4: Dashboard — December-critical (the visible deliverable)
- [ ] Create `src/dashboard/` — lightweight web app (Flask + D3 recommended for speed)
- [ ] REST endpoints: `/risk`, `/graph`, `/paths/<node>`
- [ ] Interactive graph visualization (D3.js / Cytoscape.js)
- [ ] Real-time risk score display with trend history
- [ ] Filter by ecosystem, severity threshold, node criticality

## Phase 5: Docker Packaging — December deliverable
- [ ] Write `Dockerfile` — multi-stage build (builder → runtime)
- [ ] Write `docker-compose.yml` for local dev stack (app + optional DB)
- [ ] Add `.dockerignore` and `requirements.txt` for image
- [ ] Test containerized run against sample manifests
- [ ] Document `docker compose up` deployment steps

## Supporting sub-track: Source-Audit / Bandit (Week 1, NOT the December core)
Kept separate from dependency findings. See `examples/source-audit-week1/` and
`src/scanner/bandit_config.py`. Month-1 scope:
- **Nick** — `bandit_config.py` rule mapping + `docs/security-checks.md`:
  correct shell→B602, deserialization→B301, B704=markupsafe XSS (not deser); write
  per-check expectations (catches / doesn't catch / false-positives / one-line fix).
- **Christian** — `tests/test_harness.py` + example pairs + results table:
  fix path / `-ll` flag / B704→B301; assert on `test_id` (never `test_name`="blacklist");
  add shell/B602 + SQL/B608 pairs; cover all 5 rules + unsupported-rule→error; build
  the evidence table; prove the 3 Month-1 checks (vuln→finding, safe→none, unsupported→error).
- Shared contract: rule ID is in `test_id`; exit codes 0=clean / 1=findings / >=2=error
  (no rc=5); never turn an error into "0 vulns."
