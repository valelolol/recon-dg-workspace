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

**Constraint:** inventory-only input must not produce invented dependency edges. Risk
scoring requires an explicitly "known" topology; with inventory-only input the edges
array stays empty and risk is unavailable.

### The two scanner tracks — do NOT conflate them
- **Core (December deliverable):** dependency/CVE assessment over the graph —
  `src/parser`, `src/models`, `src/engine`, `src/reporter`, `src/agent`, dashboard.
- **Supporting sub-track (Week 1):** source-code static analysis via Bandit —
  `examples/source-audit-week1/`, `src/scanner/`. It finds vulns *inside the code you*
  *scan* (a useful extra signal and a good pipeline/harness exercise). It is **not**
  the December deliverable and must stay **separate** from dependency findings.

### December-critical path (in order)
1. Parser: enough manifest formats to scan a real project.
2. Engine: wire NVD/OSV into the graph so **real** CVE data flows into PHEI.
3. Reporter: structured report schema + deterministic fallback.
4. Dashboard: web app (graph + risks + per-package risk).
5. AI explanations: `src/agent/` pluggable model layer (plain-language + prioritization).
6. Docker: portable image + local-dev compose.

## Task register

Stable IDs used by `docs/STATUS.md`, `docs/WEEKLY.md`, and the handoffs. "Unverified"
means a completion claim that is not yet backed by a run command or a passing test in
the tree — treat it as not done until verified.

| Task ID | Title | Track | Owner | Status | Depends on |
|---------|-------|-------|-------|--------|-----------|
| T-DE-01 | Parser: multi-format manifest support | Core | Vale | In progress | v0.1 contract (done) |
| T-DE-02 | Engine: real CVE lookups + PHEI reconciliation | Core | Vale | In progress | T-DE-01, T-DE-03 |
| T-DE-03 | Reporter schema + deterministic fallback | Core | Vale | In progress | T-DE-01, T-DE-02 |
| T-DE-04 | Dashboard: graph + risk + per-package view | Core | Team | Not started | T-DE-02, T-DE-03 |
| T-DE-05 | Docker packaging + local compose | Core | Team | Not started | T-DE-04 |
| T-SA-01 | Scanner pipeline (Bandit) → correct report | Supporting | Vale | In progress (unverified) | shared contract (done) |
| T-SA-02 | Check config + security-checks docs | Supporting | Nick | In progress (unverified) | shared contract (done) |
| T-SA-03 | Harness + example pairs + results table | Supporting | Christian | In progress (unverified) | T-SA-01, T-SA-02 |

Handoffs: **T-SA-02** → `HANDOFF_NICK.md`. **T-SA-03** → `HANDOFF_CHRISTIAN.md`.
Shared contract lives in `examples/source-audit-week1/RECON-DG_MONTH1_ROADMAP.md`
§"Shared contract".

## Supporting sub-track: Source-Audit / Bandit (Week 1, NOT the December core)

Kept separate from dependency findings. See `examples/source-audit-week1/` and
`src/scanner/bandit_config.py`. Month-1 scope:

- **T-SA-01 Vale** — scanner: one command `python scan_demo.py <input> <output.json>`
  writes valid JSON; each finding has `rule_id` (from `test_id`, never `test_name`),
  `filename`, `line_number`, 1-line evidence, severity, confidence, `fix_suggestion`.
  Move the working wrapper into `src/scanner/`. Move the working logic into the canonical
  module rather than leaving it only in `examples/`.
  - [ ] Fix the `NameError` in `scan_demo.py` (`venv_path` defined once at top of `main()`).
  - [ ] Rewrite the Bandit command: drop `-r .` and `-ll`; use
    `[bandit, "-f", "json", "-t", check_id, str(source_path)]`.
  - [ ] Exit-code semantics: `rc=1` = findings, `rc=0` = clean, `rc>=2` = error.
  - [ ] Read `test_id`, not `test_name`, into `Finding.rule_id`.
  - [ ] Add the evidence snippet from the finding's `line_range`.
  - [ ] Run all four checks (B307, B301, B602, B608); aggregate into one report.
  - [ ] Verify against the eval pair (B307 found / safe pair clean) and the pickle
    pair (B301 found / safe pair clean); confirm `rule_id` = `"B307"`/`"B301"`.
  - Evidence: **unverified** — `scan_demo.py` currently crashes (`NameError: venv_path`);
    `multi_check_wrapper.py` runs and catches the eval finding but writes
    `rule_id="blacklist"` and uses rc=5. Claims below are *not* from a fresh run this
    session.

- **T-SA-02 Nick** — `bandit_config.py` rule mapping + `docs/security-checks.md`:
  correct shell→B602, deserialization→B301, B704=markupsafe XSS (not deser); write
  per-check expectations (catches / doesn't catch / false-positives / one-line fix).
  Handoff: `HANDOFF_NICK.md`.
  - [ ] B608 block: SQL **only** → `[\"B608:sql-injection\"]`; rename to
    \"SQL Injection\" (shell is a separate check, B602).
  - [ ] B704 block: this is **markupsafe XSS**, not deserialization. Delete it (3
    categories) or replace with the real `B704:markupsafe-unsafe` entry (4th category).
  - [ ] B602 block: keep the rules; rename `name` to \"Shell Command Injection\".
  - [ ] B301 block: correct — keep.
  - [ ] `CVE_EXAMPLES`: move the deser CVEs from the B704 key to B301.
  - [ ] `MITIGATION_PATTERNS`: fix the B704 key the same way.
  - [ ] `docs/security-checks.md`: Category 2 Shell `B608 → B602` (Bandit rule →
    `B602:subprocess-popen-no-shell-false`); Category 3 Deserialization `B704 → B301`
    (Bandit rule → `B301:python-unsafe-deserialization`); fix the summary table.
  - [ ] Record Bandit/Python version and the "rc=5 doesn't exist / rc=1=findings"
    contract in `docs/limitations.md`.
  - Evidence: **unverified** — config and docs still carry the backwards mapping; not
    run this session.

- **T-SA-03 Christian** — `tests/test_harness.py` + example pairs + results table:
  fix path / `-ll` flag / B704→B301; assert on `test_id` (never `test_name`); add
  shell/B602 + SQL/B608 pairs; cover all 5 rules + unsupported-rule→error; build the
  evidence table; prove the 3 Month-1 checks (vuln→finding, safe→none, unsupported→error).
  Handoff: `HANDOFF_CHRISTIAN.md`.
  - [ ] Fix examples path: `Path(__file__).parent.parent / \"examples\" /
    \"source-audit-week1\"`.
  - [ ] Fix `run_scanner`: drop `-ll`, drop `check=True`, read `test_id`, handle
    exit codes per the contract (rc≥2 → raise error).
  - [ ] Write `status` key and call `_calculate_status`.
  - [ ] Register 8 cases (4 rules × vulnerable/secure): B307, B301, B602, B608.
  - [ ] Add `vulnerable_example_shell.py`/`safer_example_shell.py` (B602) and
    `vulnerable_example_sql.py`/`safer_example_sql.py` (B608).
  - [ ] Run harness; table shows TP/FP/FN/TN and accuracy; `test_results.json` has
    per-row `status`; rc≥2 reported as error, never as \"0 vulns.\"
  - Evidence: **unverified** — harness does not run (wrong examples path + invalid
    `-ll` + expects B704 for pickle).

### Shared source-audit contract (single source of truth)
- **Rule = JSON `test_id`.** `test_name` is *always* the literal string `"blacklist"`.
  Never read the rule from `test_name`.
- **Exit codes — `rc=5` does NOT exist:** `0`=clean (missing file → rc=0 with `errors`
  populated) · `1`=**findings** · `2`=internal error · `3`=unknown.
- **Any rc ≥ 2 = error state — report it; NEVER turn it into "0 vulnerabilities."**
- **CLI shape (bare rule IDs only; no `-ll`):**
  `bandit -f json -t B602 /path/to/file.py`  (`-ll` is invalid; `-c` is `--config-file`
  (INI), not a rule.)
- **Canonical rule table (Bandit 1.9.4, verified):** B307=eval/exec, B301=pickle
  deserialization, B602=shell command injection, B608=SQL injection,
  B704=markupsafe XSS (NOT deserialization).

## Phase 1: Parser (Multi-format Manifest Support) — December-critical → T-DE-01
Owner: Vale. Depends: shared `DependencyGraph` IR (T-DE-03 schema).
- [x] Parse `requirements.txt` (`package==version`) — `src/parser/parser.py:7–57`
- [x] `build_mock_graph()` test helper — `src/parser/parser.py:59–75`
- [ ] Add `package.json` (JSON) parser via `json` module
- [ ] Add `pyproject.toml` / `setup.cfg` parser via `tomllib`
- [ ] Add `go.mod` / `Gopfile.lock` parser
- [ ] Add `Cargo.toml` / `Cargo.lock` parser
- [ ] Add `Gemfile` / `package-lock.json` parsers
- [ ] Normalize all formats into shared `DependencyGraph` IR
- [x] Tests: `tests/test_parser.py` (mock graph + file read)

## Phase 2: Engine (Real CVE Lookups + PHEI Reconciliation) — December-critical → T-DE-02
Owner: Vale. Depends: parser (T-DE-01), reporter schema (T-DE-03).
- [x] PHEI path-max scoring implemented in `src/engine/risk_analyzer.py`
  (replaces the old global-sum; resolves the path-max vs global-sum divergence)
- [ ] Wire NVD API client into the graph so `get_cve_severity(node_key)` returns real data
- [ ] OSV API fallback for ecosystems not in NVD (npm, PyPI, Go, Rust)
- [ ] Severity normalization (NVD CVSS ↔ OSV severity ↔ PHEI scale)
- [ ] Rate-limiting / retry / exponential backoff for API clients
- [ ] Update `tests/test_risk_analyzer.py` with mocked API responses
- [ ] Run PHEI end-to-end on a **real** project (currently only code, unverified)

## Phase 3: Reporter & Agent Layer — December-critical → T-DE-03
Owner: Vale. Depends: engine (T-DE-02).
- [x] Structured output schema: `RiskReport` dataclass + `src/reporter/interface.py`
  (v0.1 contract: `docs/specs/scan-result-v0.1.md`; inventory serializer implemented,
  dependency-graph serializer **unimplemented**)
- [ ] Agree graph construction + scoring semantics; export graph adjacency for dashboard
- [ ] Generate dependency risk-path summaries using the agreed scoring contract
- [ ] Produce plain-language risk narratives per component
- [ ] **AI layer (`src/agent/`):** pluggable model backend (local endpoint or API key),
  grounded in the structured report + before/after risk diff — **not started**
- [ ] Deterministic plain-language fallback when no model is configured / generation fails
- [ ] Tests: `tests/test_reporter.py`, `tests/test_agent.py`

## Phase 4: Dashboard — December-critical (the visible deliverable) → T-DE-04
Owner: Team. Depends: engine (T-DE-02) + reporter (T-DE-03).
- [ ] Create `src/dashboard/` — lightweight web app (Flask + D3 recommended for speed)
- [ ] REST endpoints: `/risk`, `/graph`, `/paths/<node>`
- [ ] Interactive graph visualization (D3.js / Cytoscape.js)
- [ ] Real-time risk score display with trend history
- [ ] Filter by ecosystem, severity threshold, node criticality

## Phase 5: Docker Packaging — December deliverable → T-DE-05
Owner: Team. Depends: dashboard (T-DE-04).
- [ ] Write `Dockerfile` — multi-stage build (builder → runtime)
- [ ] Write `docker-compose.yml` for local dev stack (app + optional DB)
- [ ] Add `.dockerignore` and `requirements.txt` for image
- [ ] Test containerized run against sample manifests
- [ ] Document `docker compose up` deployment steps

## Current status (2026-09-28, branch `feat/inventory-report`, HEAD c548f32)

- **Parser (T-DE-01):** `requirements.txt` done (1 of ~6 manifest formats).
- **Engine (T-DE-02):** PHEI path-max scoring implemented
  (`calculate_path_weight` / `calculate_impact_multiplicity` / `calculate_phei`) +
  `UnavailableTopologyError` guard. NVD/OSV client code present
  (`src/engine/nvd_client.py`) but **not yet run end-to-end** against a real project;
  `tests/test_nvd_integration.py` was reported failing earlier in this session
  (see `docs/STATUS.md` for the unverified count).
- **Reporter (T-DE-03):** `RiskReport` dataclass + `src/reporter/interface.py` +
  `report_generator.py` present. Inventory serializer implemented; **dependency-graph
  serializer unimplemented**; **no dashboard yet**.
- **Agent (T-DE-03 AI layer):** empty — not started.
- **Source-audit (T-SA-01/02/03):** `multi_check_wrapper.py` runs and detects the eval
  finding but mislabels `rule_id` (`"blacklist"` instead of `B307`) and has a char-count
  bug (`"1474 results"`); `scan_demo.py` crashes (`NameError: venv_path`);
  `test_harness.py` does not run. Corrections in flight — **Nick** = rule mapping +
  `docs/security-checks.md` (T-SA-02); **Christian** = harness (path, `-ll` flag,
  B704→B301, cover 5 rules) + new shell/B602 & SQL/B608 example pairs (T-SA-03).
  This is the supporting track, **not** the December deliverable.

> Test counts are **historical/unverified** unless re-run: an earlier note recorded
> "pytest 79 passed"; the T-DE-02 NVD integration suite was reported failing in the
> same window. Do not quote these as current without re-running.

## Unresolved technical contradictions (do not guess)
1. **Exit-code claim:** `examples/source-audit-week1/README.md` states B307 findings
   produce "exit code 5". The shared contract (and Bandit 1.9.4) says rc=5 does not
   exist; rc=1 = findings. Which semantics the *scanner* itself (not Bandit) will use is
   not decided. **Unresolved.**
2. **Test-count discrepancy:** WEEK1 doc says "79 passed"; TASKS status says
   "7 of 79" failing; an earlier note says 68 pass / 7 fail. No test run this session
   can confirm. **Unverified.**
3. **Dashboard stack:** Flask+D3 (recommended in TASKS/ARCHITECTURE) vs. other options.
   **Unresolved — needs user decision (see docs/WEEKLY.md).**
