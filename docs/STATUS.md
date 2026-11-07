# STATUS — Recon-DG

**Date:** 2026-11-06 (CST)
**Host:** vale-llm
**Branch:** `feat/inventory-report`
**Published baseline:** `83b10fb` ("feat: add opt-in explanations and read-only dashboard", 2026-10-19) — the current live tip of `feat/inventory-report`, pushed to `origin/feat/inventory-report`.
**Current HEAD (local):** `b2d0fee72f` (W9 planning docs pushed to origin, 2026-11-06; uncommitted edits in working tree preserved).
**Published tip:** `origin/feat/inventory-report` = `b2d0fee72f`.

`6129e14` ("feat(agent): add evidence-grounded remediation verification", 2026-10-10)
is the last commit that changed implementation code before the explanation/dashboard slice.
The published baseline **includes** the `src/agent/` investigation layer, the **remediation
stage** (`build_remediation_plan` / `verify_remediation`, published in `6129e14`), `src/enrichment/`,
`tests/data/osv-scanner.json`, `tests/test_agent.py`,
`tests/test_report_generator.py`, `tests/test_enrichment.py`,
`tests/test_pipeline.py`, and `tests/test_remediation.py`.

The explanation + dashboard layer (`src/explanation/` ×3, `src/web/` ×4, 3 test files)
is **committed in 83b10fb** and pushed — not untracked.

*Historical prior states (label only, not the current state):* `f1c59a8`
("Implement evidence-grounded agent and scanner pipeline" — added the
agent/enrichment/pipeline implementation; now superseded by `6129e14` which commits
the remediation stage); `1b4a8d9` (docs-only); `b4fc87c` (docs-only) and the other
docs-only publishes did not change implementation code; `c548f32` added NVD/reporter/
scanner scaffolding.

*This session (2026-10-19):* reconciled docs against accepted scope; updated README.md,
TASKS.md, and docs/STATUS.md to reflect the published commit 83b10fb (explanation +
dashboard committed and pushed). The full suite now runs **248 passed, 29 subtests**
(2026-10-19 — reported historical result, date not independently verifiable from
repository evidence). **Working tree:** tracked files unmodified at HEAD.

## Scope

RECON-DG identifies project dependencies, checks known vulnerabilities (NVD + OSV),
uses actual dependency relationships when available, and helps developers prioritize
findings via deterministic PHEI risk analysis. The December prototype includes a clear
dashboard and AI explanations grounded in the findings. Inventory-only input must not
produce invented dependency edges; risk scoring requires explicitly "known" topology.

## Current state (HEAD `83b10fb` + committed explanation + dashboard)

- **Agent layer (`src/agent/`) — implemented (published in `f1c59a8`) and tested:** a
  package (`agent.py`, `normalizer.py`, `scan_runner.py`, `__init__.py`) runs a bounded,
  evidence-grounded investigation over normalized OSV-Scanner output (45 passing
  tests in `tests/test_agent.py`; tested against the checked-in
  `tests/data/osv-scanner.json` fixture). It is *not* "OSV-Scanner with an LLM
  summary": a pluggable `llm` hook may steer tool selection but is restricted to an
  allowlisted tool set (`findings`, `get_finding`, `package_info`, `package_context`,
  `high_severity`, `risk_score`, `summary`, `stop`) and every call is recorded in an
  append-only `EvidenceTrail`; out-of-band choices fall back to a grounded deterministic
  policy (recorded). On the flat fixture (5 findings, 4 packages, 0 edges) a run reports
  `risk.status == "unavailable"` and `risk.score is None` with *"No score is
  fabricated; this is an inventory-only result."* A **real** model backend (any OpenAI-compatible endpoint, user-configured) is a pending decision — not yet wired.
- **Remediation stage (`src/agent/`) — implemented and published in `6129e14`:** a pure
  `build_remediation_plan` (one item per baseline finding; scanner-provided fixed
  versions verbatim, never "latest"/"best"; `severity_score` left `None` — no numeric
  CVSS score or high/low category; scheme types + vector strings preserved as evidence;
  a plain recommended action) plus `verify_remediation` (reconciles the plan against a
  user-supplied after scan, no network; no after scan → `status == "not_run"` with
  no resolution claim; same version persists as `unchanged`, key absent → `resolved`,
  same advisory at a different version → `regressed`; unusable after report fails
  closed to `not_run`). Verified by 24 passing tests in `tests/test_remediation.py`.
- **Explanation layer (`src/explanation/`, committed 83b10fb):** a grounded
  deterministic explainer (default; `explain_finding` / `explain_findings`) that cites
  only facts already on the finding and never fabricates a numeric CVSS score, version,
  or CVE. Plus an optional OpenAI-compatible local-model client
  (`src/explanation/local_model.py`) targeting a single `/v1/chat/completions` endpoint
  via stdlib `urllib`, configured only by `OPENAI_BASE_URL` / `OPENAI_API_KEY` (no
  credentials or endpoint secrets committed). `add_explanations` is additive: it adds
  `report["ai_explanations"]` (one `{"text", "source"}` entry per finding) and
  `report["explanation_source"]` (counts model vs deterministic; never echoes the key/
  endpoint). Deterministic fallback is guaranteed and labelled per finding on any
  failure (no config, network/timeout, non-2xx, malformed body, empty completion,
  `max_calls` cap). Verified by `tests/test_explanation.py` (23) +
  `tests/test_explanation_http.py` (7, a real local `/v1/chat/completions` server
  driven by real `urllib` requests — no injected transport seam).
- **Read-only dashboard (`src/web/`, committed 83b10fb):** a minimal read-only stdlib
  `http.server` dashboard (no third-party deps) serving `dashboard.html` at `/` and the
  structured report at `/report.json` on local loopback. It does **not** re-run scans,
  edit manifests, or imply a fix was verified. It renders findings, the risk
  limitations (`risk.status == "unavailable"` → "no score is fabricated"), the
  remediation plan (scanner-provided fixed versions verbatim), and the after-scan
  verification state **including `not_run`** (a red card with a zero count summary
  and no resolution claim). Additive labelled explanations are rendered alongside
  findings when `use_model=True`. Verified by `tests/test_dashboard.py` (13, real
  loopback GETs).
- **Model activation:** `--model` defaults to **OFF** (deterministic only). Only the
  exact value `--model ON` (case-insensitive) enables the optional local-model backend.
  The backend targets any `/v1/chat/completions` endpoint via
  `OPENAI_BASE_URL` / `OPENAI_API_KEY` env vars. **No remote endpoint is approved
  by default.** When **ON** and the endpoint is configured, the dashboard sends
  **finding data** (package name, version, vulnerability ID, aliases, severity
  score, severity vector, severity types, published date, affected range, fixed versions,
  recommended action) to the configured endpoint. Whether the configured endpoint is
  unencrypted HTTP or encrypted HTTPS is an **open privacy decision** — the endpoint
  receives the API key and finding data in either case. Model use is **not approved
  by default**; it requires explicit opt-in. Deterministic fallback is guaranteed
  and labelled `source` per finding.

## Implementation state (published HEAD `83b10fb`; explanation + dashboard committed)

- **Parser (T-DE-01):** `requirements.txt` + `pyproject.toml` (PR #4, merged 5d1101d, 2026-11-02). `parse_pyproject_toml()` added with fixture `tests/fixtures/pyproject_with_deps.toml` and **5 new test methods** (`tests/test_parser.py`). `parse_package_json()` added (W9, committed `1ad2a7b`). The repo-root `pyproject.toml` declares no dependencies (confirmed by `test_repo_pyproject_has_no_dependencies`). **Status: 3/4 minimum formats (requirements.txt, pyproject.toml, package.json). Remaining to reach the ≥4 target: go.mod (W10 blocker).**
|- **Engine (T-DE-02):** PHEI path-max scoring implemented
  (`calculate_path_weight` / `calculate_impact_multiplicity` / `calculate_phei`) +
  `UnavailableTopologyError` guard. NVD/OSV client code present
  (`src/engine/nvd_client.py`) and **wired into the graph** (`risk_analyzer.py` patched:
  `get_cve_severity(node_key)` calls `NVDClient.query_nvd_api()`, then `query_osv_api()`;
  **no MOCK_CVE_DB fallback in production — removed 2026-11-03 per audit**.
  Real OSV-Scanner scan on repo root returned 0 findings (clean). 15 focused offline tests
  pass (`tests/test_risk_analyzer_nvd_integration.py`). Full suite: 275 tests pass.
  **Audit note (2026-11-03):** `get_cve_severity` production path with no injected/default
  client returns `{}` (never MOCK_CVE_DB). Three new tests (13–15) prove API failure
  cannot produce mock findings.
||**- Reporter (T-DE-03):** `RiskReport` dataclass + `src/reporter/interface.py` +
||  `report_generator.py` present. Inventory serializer implemented; **dependency-graph
||  serializer unimplemented**.
||
||**⚠️ W9 audit finding (2026-11-03, T-DE-02):** NVD/OSV client wiring **exists** and is covered by 15 focused offline tests (`tests/test_risk_analyzer_nvd_integration.py`). A clean real-project OSV-Scanner scan was run (0 findings, clean). **However, live CVE data has NOT been demonstrated flowing into the PHEI score on a real project.** The `get_cve_severity()` function is wired to `NVDClient.query_nvd_api()` → `query_osv_api()` and **no MOCK_CVE_DB fallback exists in production** (removed 2026-11-03). But `calculate_phei()` (risk_analyzer.py:186-190) computes `path_weight * impact_multiplicity` **without using `node_risks`** (the CVE-severity dict computed at lines 146-154). CVE severity is used in `calculate_systemic_risk()` (lines 224-258) but **not** in `calculate_phei()`. PHEI is **topology-only by design** (ROADMAP §7 resolved); severity is handled by `calculate_systemic_risk()`, not by `calculate_phei()`. T-DE-02 remains **partial** — the end-to-end demo must show live CVE data flowing into `calculate_systemic_risk()`.
||  The **read-only stdlib dashboard** (`src/web/`) is
||  **committed** (83b10fb) — a stdlib `http.server` + `dashboard.html`, serving the
|  report and its page; the full Flask+D3 dashboard (T-DE-04) is still not started.
|  **Scan-to-report integration met (2026-11-03):** `src/web/osv_normalizer.py` corrected
|  to match the dashboard contract (`vulnerability_id`, `package_name`, `numeric severity_score`,
|  no `risk_level` label; aliases merged per group). Real OSV-Scanner scan on the repo root
|  (2026-11-03) returned **0 findings** (clean scan; no known CVEs in project deps).
|  Normalizer produces dashboard-compatible JSON with `risk.status: "unavailable"`,
|  `risk.score: null` for inventory-only input. 12 focused offline tests added
|  (`tests/test_osv_normalizer.py`). `src/agent/normalizer.py` (445 lines) remains the
|  older agent-format normalizer; `src/web/osv_normalizer.py` is the dashboard-format
|  normalizer. No single canonical normalizer yet — two exist with different schemas.
- **Agent (T-DE-03 AI layer):** implemented + tested — new `src/agent/` package
  (bounded tool loop, `EvidenceTrail`, allowlisted tools, deterministic grounded policy
  with no model, `compare_scans`). **45 passing tests** (`tests/test_agent.py`).
  Plus **remediation** (`build_remediation_plan` / `verify_remediation`; committed in
  `6129e14`): `build_remediation_plan` (pure; one item per finding; fixed versions
  verbatim; severity left `None` / evidence-only) + `verify_remediation` (user-supplied
  after scan; no after scan → `not_run`, no resolution claim; unusable after report
  fails closed to `not_run`). **24 passing tests** (`tests/test_remediation.py`). A real model
  backend (any OpenAI-compatible endpoint, user-configured) is **not yet wired** (pending decision);
  current runs use the deterministic policy (`used_llm=False`). The **explanation layer**
  (`src/explanation/`, **committed** 83b10fb) provides a grounded deterministic
  explainer plus an optional OpenAI-compatible local-model client (env-only config,
  per-finding deterministic fallback) — tested by `tests/test_explanation.py` (23) and
  `tests/test_explanation_http.py` (7).

## Open decisions (not yet resolved)

1. **Full interactive dashboard (T-DE-04):** Flask+D3 graph, per-node `/paths/<node>`,
   filters, trend history — **not started**. The stdlib dashboard (committed 83b10fb)
   is read-only and dependency-free.
2. **Dependency-graph serializer (T-DE-03):** unimplemented; inventory-only input
   produces no risk score (by design, `risk.status == "unavailable"`).
3. **Real NVD/OSV end-to-end scan:** NVD/OSV client code present but not yet run
   against a real project.
4. **Edge-weight function (ROADMAP §7):** Resolved. Systemic risk is topology-only (path-max × impact-multiplicity, capped at 10.0). Severity is handled by `calculate_systemic_risk()`. No fabricated edge weights.

## Prior published baselines (historical)

- `7e8d4c4` (2026-09-28): docs-scope + templates + PHEI engine + handoffs.
- `24c99b6` (docs-only): reconciled docs against accepted scope.
- `6129e14` (2026-10-10): evidence-grounded remediation verification.
- `f1c59a8`: agent/enrichment/pipeline implementation (superseded by `6129e14`).
- `1b4a8d9` (docs-only): last-implementation baseline to c548f32.
- `b4fc87c` (docs-only): correct Aliyan handoff schema/path.
- `c548f32`: NVD/reporter/scanner scaffolding.
- `e455881` (2026-10-20): docs: fix test_inventory_reporter.py count (3 docs-only commits ahead of published baseline `83b10fb`).

## W1-DE-03.T progress (2026-11-02, Christian)

- `tests/test_e2e_risk.py` and `docs/E2E_EXPECTED_RESULTS.md` added. Verification: `python -m pytest tests/test_e2e_risk.py -v` -> 6 passed, 7 skipped (Windows, Python 3.15).
- **Still blocked:** the 7 skipped tests need `examples/fixtures/sample_risk_report.json`, `load_known_topo_json()`,
  known-topology support in `serialize_inventory`, and `examples/fixtures/known_topology.json`. None exist on any branch.

## W9 plan and handoffs (2026-11-03)

- **Weekly plan:** `docs/weekly-plan/W9-2026-11-03-to-2026-11-09.md`
  - Goal: Parser at 3/4 formats; NVD/OSV wiring closed (2026-11-03); dashboard validation; W10 handoffs
  - Deliverables: W10 handoffs for Nick (go.mod), Christian (dashboard validation), Aliyan (demo script/search/filter), Vale (end-to-end CVE-to-PHEI demo on controlled data)
- **Historical handoffs (W1–W7):** removed from the repository (see the rule in `docs/weekly-handoff-template.md` that old handoff files must not be archived in the repo). The M-DE-CORE week (Sep 28–Oct 4, 2026) is documented in `docs/WEEKLY.md` (historical) and `docs/ROADMAP.md` §47.

## W9 reconciliation (2026-11-03)

- **Nick's W9 parser deliverable (W9-Nick.md):** ✅ **3/4 minimum formats reached.** `parse_pyproject_toml()` (PR #4, merged `5d1101d`) + `parse_package_json()` (W9, committed `1ad2a7b`). The repo-root `pyproject.toml` declares **no** dependencies (confirmed by `test_repo_pyproject_has_no_dependencies`). **Status: 3/4 minimum formats (requirements.txt, pyproject.toml, package.json). Remaining to reach the ≥4 target: go.mod. Any additional formats listed in the task register are further scope, not part of the minimum-four count.**
- **Christian's W9 dashboard validation (W9-Christian.md):** ⏳ **Pending.** PR #5 merged as `423511f` (2026-11-02). `tests/test_e2e_risk.py` (6 passed, 7 skipped) + `docs/E2E_EXPECTED_RESULTS.md`. The 7 skipped tests require `examples/fixtures/sample_risk_report.json`, `load_known_topo_json()`, and `examples/fixtures/known_topology.json` — none exist. Skips are **not** passes. Christian's W9 scan-JSON test assignment (empty input, malformed input, unknown-topology) is **pending** until those three cases are present and verified. **Note: PR #5 is the historical W1-DE-03.T E2E skeleton only — it is NOT a completion of Christian's current W9 handoff (offline scan-JSON → normalized-report tests) unless those specific acceptance criteria are independently verified in the repo.**
|- **Vale's W9 real-project OSV-Scanner scan (W9-Vale.md):** ✅ **Delivered (2026-11-03).** `src/web/osv_normalizer.py` corrected to dashboard contract. Real OSV-Scanner scan on the repo root (`osv-scanner scan . --experimental-exclude tests examples docs`) returned **0 findings** (clean scan; no known CVEs in project deps). Normalizer produces dashboard-compatible JSON (`risk.status: "unavailable"`, `risk.score: null` for inventory-only). 15 focused offline tests pass. `src/agent/normalizer.py` (445 lines) remains the older agent-format normalizer; `src/web/osv_normalizer.py` is the dashboard-format normalizer. No single canonical normalizer yet — two exist with different schemas. **NVD/OSV wiring complete (2026-11-03): `risk_analyzer.py` patched — `get_cve_severity(node_key)` calls `NVDClient.query_nvd_api()`, then `query_osv_api()`; MOCK_CVE_DB removed from production path (audit 2026-11-03). Full suite: 275 tests pass.**
  **W10 deliverable (Vale):** end-to-end CVE-to-PHEI demo on controlled data. `calculate_phei()` (risk_analyzer.py:186-190) computes `path_weight * impact_multiplicity` **without using `node_risks`** (the CVE-severity dict). CVE severity IS used in `calculate_systemic_risk()` (lines 224-258) but **not** in `calculate_phei()`. The agreed PHEI target is **topology-only and separate from systemic risk** (ROADMAP §7 resolved); severity is handled by `calculate_systemic_risk()`, not by `calculate_phei()`. T-DE-02 remains **partial** — W10 must demonstrate the end-to-end: real scan → real CVE data → `calculate_systemic_risk()` on a controlled project.
- **Aliyan's W9 bounded dashboard search/filter (W9-Aliyan.md):** ⏳ **W10 deliverable (moved from W9).** No repository evidence of search bar or severity_score threshold filter in `src/web/dashboard.html`. No new files or edits to `dashboard.html` exist.
- **Christian's W9 dashboard validation (W9-Christian.md):** ⏳ **W10 deliverable (moved from W9).** PR #5 merged as `423511f` (2026-11-02). `tests/test_e2e_risk.py` (6 passed, 7 skipped) + `docs/E2E_EXPECTED_RESULTS.md`. The 7 skipped tests require `examples/fixtures/sample_risk_report.json`, `load_known_topo_json()`, and `examples/fixtures/known_topology.json` — none exist. Skips are **not** passes. Christian's W9 scan-JSON test assignment (empty input, malformed input, unknown-topology) is **pending** until those three cases are present and verified. **Note: PR #5 is the historical W1-DE-03.T E2E skeleton only — it is NOT a completion of Christian's current W9 handoff (offline scan-JSON → normalized-report tests) unless those specific acceptance criteria are independently verified in the repo.**
- **Nick's W9 parser deliverable (W9-Nick.md):** ✅ **3/4 minimum formats reached.** `parse_pyproject_toml()` (PR #4, merged `5d1101d`) + `parse_package_json()` (W9, committed `1ad2a7b`). The repo-root `pyproject.toml` declares **no** dependencies (confirmed by `test_repo_pyproject_has_no_dependencies`). **Status: 3/4 minimum formats (requirements.txt, pyproject.toml, package.json). Remaining to reach the ≥4 target: go.mod (W10 deliverable).**

- **Edge-weight function (ROADMAP §7):** Resolved. Systemic risk is topology-only (path-max × impact-multiplicity, capped at 10.0). Severity is handled by `calculate_systemic_risk()`. No fabricated edge weights.
- **Post-demo next steps:** What comes after the December deliverable? — Not yet decided.
- **AI backend:** any OpenAI-compatible endpoint (user-selected); deterministic fallback when no provider configured.

## Critical dependency correction

The dependency-graph serializer (T-DE-03 Mode B) is **unimplemented** and **must be scheduled before** the W11 end-to-end CVE-to-PHEI demo. The W9 plan already noted this gap; W10 delivers the serializer; W11 demonstrates it. Without the serializer, the W10 CVE-to-PHEI demo milestone is impossible. T-DE-03 is corrected from "Done" to "Partial" in TASKS.md (2026-11-03).
