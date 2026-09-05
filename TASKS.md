# TASKS.md — Predictive Vulnerability Mapping Agent

## Phase 1: Parser (Multi-format Manifest Support)
- [x] Parse `requirements.txt` (package==version) — `src/parser/parser.py:7–57`
- [x] `build_mock_graph()` test helper — `src/parser/parser.py:59–75`
- [ ] Add `package.json` (JSON) parser via `json` module
- [ ] Add `pyproject.toml` / `setup.cfg` parser via `tomllib`
- [ ] Add `go.mod` / `Gopfile.lock` parser
- [ ] Add `Cargo.toml` / `Cargo.lock` parser
- [ ] Add `Gemfile` / `package-lock.json` parsers
- [ ] Normalize all formats into shared `DependencyGraph` IR
- [x] Tests: `tests/test_parser.py` (mock graph + file read)

## Phase 2: Engine (Real CVE Lookups + PHEI Reconciliation)
- [ ] Replace `MOCK_CVE_DB` in `src/engine/risk_analyzer.py` with NVD API client
- [ ] Add OSV API fallback for ecosystems not in NVD (npm, PyPI, Go, Rust)
- [ ] Implement severity normalization (NVD CVSS ↔ OSV severity ↔ PHEI scale)
- [ ] Reconcile scoring formula: resolve path-max vs global-sum divergence noted in `ARCHITECTURE.md`
- [ ] Add `get_cve_severity(node_key)` → real API call with caching
- [ ] Add rate-limiting / retry / exponential backoff for API clients
- [ ] Update `tests/test_risk_analyzer.py` with mocked API responses

## Phase 3: Reporter (Rewrite from Scratch)
- [ ] Design structured output schema (JSON + human-readable text)
- [ ] Generate predicted exploitation pathway summaries (top-N paths by risk)
- [ ] Produce plain-language risk narratives per component
- [ ] Export graph adjacency for dashboard/visualization integration
- [ ] Add `src/reporter/__init__.py` (currently empty) with `generate_report(graph, score, paths)`
- [ ] Add `tests/test_reporter.py` with assertions on output format

## Phase 4: Dashboard
- [ ] Create `src/dashboard/` — lightweight web app (Flask/FastAPI + React/Vue)
- [ ] REST endpoints: `/risk`, `/graph`, `/paths/<node>`
- [ ] Interactive graph visualization (D3.js / Cytoscape.js)
- [ ] Real-time risk score display with trend history
- [ ] Filter by ecosystem, severity threshold, node criticality

## Phase 5: Docker Packaging
- [ ] Write `Dockerfile` — multi-stage build (builder → runtime)
- [ ] Write `docker-compose.yml` for local dev stack (app + optional DB)
- [ ] Add `.dockerignore` and `requirements.txt` for image
- [ ] Test containerized run against sample manifests
- [ ] Document `docker compose up` deployment steps
