# STATUS — Recon-DG

**Date:** 2026-10-17 (CDT)
**Host:** vale-laptop
**Branch:** `feat/inventory-report`
**Published baseline:** `6cd2e46` (\"docs: remove stale M-DE-CORE present-tense claims, label demo work historical\", 2026-10-17) — the current live tip of `feat/inventory-report`.
`6129e14` (\"feat(agent): add evidence-grounded remediation verification\", 2026-10-10)
is the last commit that changed implementation code. `24c99b6` is a docs-only commit.
The published baseline **includes** the `src/agent/` investigation layer, the **remediation
stage** (`build_remediation_plan` / `verify_remediation`), `src/enrichment/`,
`tests/data/osv-scanner.json`, `tests/test_agent.py`,
`tests/test_report_generator.py`, `tests/test_enrichment.py`,
`tests/test_pipeline.py`, and `tests/test_remediation.py`. The working tree ahead
of that tip also contains a **provisional, uncommitted explanation + dashboard
layer** (see \"Current state\" below): 10 untracked files (`src/explanation/` ×3,
`src/web/` ×4, `tests/test_dashboard.py`, `tests/test_explanation.py`,
`tests/test_explanation_http.py`) that are **unpublished** — not staged, not committed,
not pushed.
*Historical prior states (label only, not the current state):* `f1c59a8`
(\"Implement evidence-grounded agent and scanner pipeline\" — added the
agent/enrichment/pipeline implementation; now superseded by `6129e14` which commits
the remediation stage); `1b4a8d9` (docs-only); `b4fc87c` (docs-only) and the other
docs-only publishes did not change implementation code; `c548f32` added NVD/reporter/
scanner scaffolding. The executed verifications below (PHEI == 6.0, the older
\"pytest 205 passed\" count) were run at the historical point before `6129e14` and
remain *historical* unless re-run.
**This session (2026-10-17):** reconciled docs against accepted scope; resolved dashboard-stack contradiction (README already stated stdlib http.server). No new implementation work was done this session — the uncommitted files (`src/explanation/` ×3, `src/web/` ×4, 3 test files) were authored in the prior session and verified here. The full suite now runs **241 passed, 29 subtests, 0 warnings** (re-run 2026-10-17). **Working tree is dirty and uncommitted** (this session intentionally stops before staging/commit/push per the repo's completion routine).

## Scope

RECON-DG identifies project dependencies, checks known vulnerabilities (NVD + OSV),
uses actual dependency relationships when available, and helps developers prioritize
findings via deterministic PHEI risk analysis. The December prototype includes a clear
dashboard and AI explanations grounded in the findings. Inventory-only input must not
produce invented dependency edges; risk scoring requires explicitly \"known\" topology.

## Current state (HEAD `6cd2e46` + uncommitted provisional explanation + dashboard layer)

- **Agent layer (`src/agent/`) — implemented (published in `f1c59a8`) and tested:** a
  package (`agent.py`, `normalizer.py`, `scan_runner.py`, `__init__.py`) runs a bounded,
  evidence-grounded investigation over normalized OSV-Scanner output (45 passing
  tests in `tests/test_agent.py`; tested against the checked-in
  `tests/data/osv-scanner.json` fixture). It is *not* \"OSV-Scanner with an LLM
  summary\": a pluggable `llm` hook may steer tool selection but is restricted to an
  allowlisted tool set (`findings`, `get_finding`, `package_info`, `package_context`,
  `high_severity`, `risk_score`, `summary`, `stop`) and every call is recorded in an
  append-only `EvidenceTrail`; out-of-band choices fall back to a grounded deterministic
  policy (recorded). On the flat fixture (5 findings, 4 packages, 0 edges) a run reports
  `risk.status == \"unavailable\"` and `risk.score is None` with *\"No score is
  fabricated; this is an inventory-only result.\"* A **real** model backend (llama.cpp
  vs. user API key) is a pending decision — not yet wired.
- **Remediation stage (`src/agent/`) — implemented and published in `6129e14`:** a pure
  `build_remediation_plan` (one item per baseline finding; scanner-provided fixed
  versions verbatim, never \"latest\"/\"best\"; `severity_score` left `None` — no numeric
  CVSS score or high/low category; scheme types + vector strings preserved as evidence;
  a plain recommended action) plus `verify_remediation` (reconciles the plan against a
  user-supplied after scan, no network; no after scan → `status == \"not_run\"` with
  no resolution claim; same version persists as `unchanged`, key absent → `resolved`,
  same advisory at a different version → `regressed`; unusable after report fails
  closed to `not_run`). Verified by 24 passing tests in `tests/test_remediation.py`.
- **Provisional explanation layer (`src/explanation/`, uncommitted):** a grounded
  deterministic explainer (default; `explain_finding` / `explain_findings`) that cites
  only facts already on the finding and never fabricates a numeric CVSS score, version,
  or CVE. Plus an optional OpenAI-compatible local-model client
  (`src/explanation/local_model.py`) targeting a single `/v1/chat/completions` endpoint
  via stdlib `urllib`, configured only by `OPENAI_BASE_URL` / `OPENAI_API_KEY` (no
  credentials or endpoint secrets committed). `add_explanations` is additive: it adds
  `report[\"ai_explanations\"]` (one `{\"text\", \"source\"}` entry per finding) and
  `report[\"explanation_source\"]` (counts model vs deterministic; never echoes the key/
  endpoint). Deterministic fallback is guaranteed and labelled per finding on any
  failure (no config, network/timeout, non-2xx, malformed body, empty completion,
  `max_calls` cap). Verified by `tests/test_explanation.py` (20) +
  `tests/test_explanation_http.py` (7, a real local `/v1/chat/completions` server
  driven by real `urllib` requests — no injected transport seam).
- **Provisional dashboard (`src/web/`, uncommitted):** a minimal read-only stdlib
  `http.server` dashboard (no third-party deps) serving `dashboard.html` at `/` and the
  structured report at `/report.json` on local loopback. It does **not** re-run scans,
  edit manifests, or imply a fix was verified. It renders findings, the risk
  limitations (`risk.status == \"unavailable\"` → \"no score is fabricated\"), the
  remediation plan (scanner-provided fixed versions verbatim), and the after-scan
  verification state **including `not_run`** (a red card with a zero count summary and
  no resolution claim). Verified by `tests/test_dashboard.py` (9, real loopback HTTP
  GETs to `/` and `/report.json`).
- **Onboarding / handoffs:** rewritten for complete beginners on individual machines
  (Windows PowerShell and Linux/macOS routes in `docs/TEAM_ONBOARDING.md`).
  `README.md` and `docs/WEEKLY.md` direct readers to the shared onboarding and the
  M-DE-CORE handoffs first (historical demo track; Sep 28–Oct 4, 2026).
- **M-DE-CORE plan:** committed in `TASKS.md` (Mode B field mapping + proposed
  input-fixture contract, §C0-prereq). The **implementation** it assigns (known-topology
  loader, Mode B serializer, `src/cli.py`, viewer, reference output, E2E test) is
  **not in the tree yet**. The agent layer (above) *is* in the tree — it is a separate,
  already-built deliverable, not part of the M-DE-CORE demo plan (historical; not yet built).
- **PHEI return value:** `calculate_phei` returns **only the scalar score** (6.0 for the
  3-node unit chain); **no** path field is emitted, rendered, or asserted. The numeric
  result is the \"maximum path score,\" not an argmax path. No `top_risk_path`.
- **Missing reference sample:** `examples/fixtures/` (and `sample_risk_report.json`) do
  **not** exist in the tree. The reference `report.json` is **not** checked in. This is a
  prerequisite for Christian's E2E assertion and Aliyan's viewer — see the handoffs.

## Evidence-supported implementation progress (implementation state at HEAD `6cd2e46`
plus uncommitted remediation work, 2026-10-10)

- **Agent (`src/agent/`, published in `f1c59a8`):** bounded, evidence-grounded
  investigation loop. `normalizer` turns OSV-Scanner JSON into a `DependencyGraph` +
  `Finding` objects (including the scanner-provided `fixed_versions` extraction);
  `scan_runner` builds/executes the OSV-Scanner CLI via injection (no real binary
  required); `agent` runs the tool loop, records an `EvidenceTrail`, and exposes
  `compare_scans`. **Verified** (`tests/test_agent.py`, 45 passed): deterministic with
  no model; an LLM hook can only pick allowlisted tools and its out-of-band/invalid
  choices fall back to the grounded policy (recorded); risk is `unavailable`/`None` on
  a flat graph (no fabricated score).
- **Remediation (`src/agent/`, uncommitted in the working tree):** `build_remediation_plan`
  + `verify_remediation` (see the \"Current state\" and \"Verified\" sections). Verified by
  24 passing tests in `tests/test_remediation.py`.
- **Parser (T-DE-01):** `requirements.txt` done + `build_mock_graph()` (3-node unit
  chain A→B→C, edge weights 1.0). Known-topology loader **not yet built**
  (W1-DE-01.L, Vale).
- **Engine (T-DE-02):** PHEI path-max implemented and verified. `calculate_phei` returns
  **6.0** for the 3-node unit chain and is invariant to CVE severity. `report_generator.generate_report`
  now calls the canonical `calculate_phei` (path-max), **not** the legacy global-sum
  `calculate_systemic_risk` (W1-DE-02.R, done 2026-10-03; `calculate_systemic_risk` kept
  in place as legacy). Unavailable topology yields an \"unavailable\" risk status instead of
  a fabricated numeric score. NVD/OSV client present but not yet wired into PHEI.
- **Reporter (T-DE-03):** inventory serializer (`serialize_inventory`) works; it **rejects
  any graph with edges** (requires `edge_availability == \"unavailable\"`). The before/after
  **report generator** is implemented (no more stub). Mode B
  `serialize_dependency_graph` **not started**. No `src/cli.py` and no `src/dashboard/` yet.

## Blockers (as of HEAD `6cd2e46` + uncommitted remediation work)

- Mode B (dependency-graph serializer) does not exist yet — required to emit the 6.0 report
  (W1-DE-03.R).
- **No reference `report.json` / `examples/fixtures/`** — required for Christian's byte-identity
  E2E assertion and Aliyan's viewer. Must be produced by Vale (W1-DE-03.R).
- `httpx` is imported by `nvd_client.py` but undeclared in any manifest (separate fix;
  not needed for the core path this week).
- No live NVD/OSV end-to-end run this session (findings are synthetic fixtures).
- Dashboard framework and Docker are not started (out of scope this week). The AI
  layer's *investigation loop* (`src/agent/`) is implemented and tested (45 passing
  tests, deterministic policy, no real model); wiring a **real** model
  backend (llama.cpp endpoint vs. user API key) is a pending decision, not yet done.

## Pending decisions (unchanged)

1. **Severity in the score.** The design spec leaves the edge-weight function `w_uv`
   undefined. Current PHEI is topology-only — CVE severity is **unspecified**
   (`findings[].severity` is `null` per v0.1) and does **not** enter the score. Decide
   whether/how severity would enter `w_uv` once a severity standard is agreed.
   **Open, assigned to Vale.** Do not call the current 6.0 a complete vulnerability-risk
   score.
2. **AI backend:** local model (llama.cpp) vs. user-provided API key?
3. **Dashboard stack:** Flask + D3.js (recommended) vs. FastAPI + React? (Full T-DE-04
   dashboard out of scope this week; only a provisional static-viewer spike is proposed.)

## Next bounded task (historical M-DE-CORE plan; not yet executed)

- **M-DE-CORE checkpoint (historical, not yet executed).** Sign the Mode B field-mapping contract and the **proposed
  input-fixture contract** (TASKS.md §C0-prereq — approval required before Nick authors
  fixtures), then Vale implements the known-topology loader (W1-DE-01.L) + Mode B
  serializer (W1-DE-03.R) to emit the 6.0 reference `report.json`. Only after that
  can Christian's E2E byte-assertion and Aliyan's viewer be run against a real sample.
- **What the pending C0 fixture-contract decision does and does not block.** C0 (the
  shared contract + the proposed input-fixture contract, `TASKS.md` §C0-prereq) gates
  exactly two things: **(a)** Nick authoring the two M-DE-CORE fixtures, and **(b)**
  anything that **consumes** those approved fixtures — Vale's end-to-end CLI run +
  generated reference sample, Christian's running E2E assertions, and Aliyan's viewer run
  against real data. C0 does **not** gate (i) drafting/writing Vale's loader / Mode B
  serializer / CLI against the proposed shape, (ii) drafting Christian's test scaffolding
  + expected-results doc, or (iii) reviewing or sharing the handoffs.
- **Beginner onboarding doc committed:** `docs/TEAM_ONBOARDING.md` is **committed** in the
  repo and ships with the published handoffs (confirmed by `git ls-files`); all four
  M-DE-CORE handoffs, `README.md`, and `docs/WEEKLY.md` link to it.

## Verified / Proposed / Unverified

- **Verified (executed, 2026-10-17, working tree with uncommitted remediation work):**
  - Full pytest suite: **241 passed, 29 subtests, 0 warnings**
    (reported test result; `.venv/bin/python -m pytest tests/ -q`). Per-file:
    test_inventory_reporter 53, test_agent 45, test_enrichment 26,
    test_pipeline 22, **test_remediation 24**, test_nvd_integration 11,
    test_parser 10, test_report_generator 8, test_risk_analyzer 5,
    test_explanation 20, test_explanation_http 7, test_dashboard 9.
  - **Remediation (`src/agent/`, uncommitted):** 24 passing tests in
    `tests/test_remediation.py`. `build_remediation_plan` emits one item per baseline
    finding using only normalized scanner evidence (fixed versions verbatim, `severity_score`
    left `None`, evidence-only severity, no numeric score or high/low category);
    `verify_remediation` returns `not_run` with no resolution claim when no after scan is
    supplied, and reconciles a user-supplied after scan (same-version persists as
    `unchanged`, absent = `resolved`, same advisory at a different version = `regressed`,
    new after-scan findings reported as `new_count` not attributed to the plan).
  - **Agent (`src/agent/`):** 45 passing tests in `tests/test_agent.py`. A deterministic
    (no-model) run over the flat fixture (`tests/data/osv-scanner.json`: 5 findings,
    4 packages, 0 edges) completes in 7 turns (`findings`, `get_finding` ×3, `risk_score`,
    `summary`, `stop`) and reports `risk.status == \"unavailable\"`, `risk.score is None`,
    with *\"No score is fabricated; this is an inventory-only result.\"*
  - **Enrichment (`src/enrichment/`):** stdlib-only deps.dev client (`DepsDevClient` +
    `build_package_context`; no network attempted at import time), 26 passing tests in
    `tests/test_enrichment.py`. It surfaces the opt-in `package_context` agent tool:
    published, resolved, labelled `generic_published`, additive (never erases
    OSV-Scanner findings), never fed to PHEI scoring, with a hard call limit and
    per-coordinate cache.
  - `generate_report` (before/after) routes through `calculate_phei` (path-max), not
    the legacy global-sum `calculate_systemic_risk` (8 passing tests,
    `tests/test_report_generator.py`); unavailable topology → \"unavailable\" (no
    fabricated score); the dead `generate_report_mock` (fabricated placeholder) was
    removed.
  - `calculate_phei` == 6.0 on a **one-off synthetic** 3-node unit chain A→B→C
    (2 unit-weight edges × 3 nodes = 6.0). PHEI is invariant to CVE severity.
  - The historical \"pytest 79 passed\" / PHEI==6.0 runs date to baseline `5b8a1f7`
    and are superseded by the 241-passed count above (reported result).
- **Proposed (M-DE-CORE demo, not yet in repo):** known-topology loader, Mode B serializer,
  `src/cli.py`, `src/dashboard/view.py`, the two input fixtures,
  `examples/fixtures/sample_risk_report.json`, `tests/test_e2e_risk.py`,
  `docs/E2E_EXPECTED_RESULTS.md`. **No out-of-spec fields are emitted this week:**
  v0.1 defines no risk-path field, so `top_risk_path` is **deferred to a separate
  schema decision** (not emitted, rendered, or asserted). All emitted fields are
  spec-defined v0.1 fields; the known-topology input is a JSON file, so it uses
  `input.type = file`, `input.format = \"synthetic-graph\"` (both spec-supported; the
  committed demo uses `synthetic-graph`). Emitted (spec-backed): `findings[].id`,
  `findings[].advisory_source` (`synthetic-fixture`), `findings[].severity = null`.
  `vulnerability_lookup.matched` = distinct package IDs with at least one finding.
  Deferred: `packages[].risk_score` (node-level PHEI undefined). `risk.status` uses the
  spec enum `available`/`unavailable`.
- **Unverified / pending:** that the new Mode B serializer emits 6.0 end-to-end
  (not yet built); severity-in-score (open, Vale);
  that the reference sample (once produced) byte-matches Christian's determinism check (run twice with identical scan_id and created_at, then compare outputs).

> Test counts in this file are **historical** unless re-run and re-recorded. No completion
> percentages are reported.
