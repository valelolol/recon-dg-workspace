# STATUS — Recon-DG

**Date:** 2026-10-19 (CDT)
**Host:** vale-llm
**Branch:** `feat/inventory-report`
**Published baseline:** `83b10fb` ("feat: add opt-in explanations and read-only dashboard", 2026-10-19) — the current live tip of `feat/inventory-report`, pushed to `origin/feat/inventory-report`.

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

**This session (2026-10-19):** reconciled docs against accepted scope; updated README.md,
TASKS.md, and docs/STATUS.md to reflect the published commit 83b10fb (explanation +
dashboard committed and pushed). The full suite now runs **248 passed, 29 subtests**
(2026-10-19). **Working tree is clean.**

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
  fabricated; this is an inventory-only result."* A **real** model backend (llama.cpp
  vs. user API key) is a pending decision — not yet wired.
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
  `max_calls` cap). Verified by `tests/test_explanation.py` (20) +
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
  findings when `use_model=True`. Verified by `tests/test_dashboard.py` (10, real
  loopback GETs).
- **Model activation:** `--model` defaults to **OFF** (deterministic only). Only the
  exact value `--model ON` (case-insensitive) enables the optional local-model backend.
  When **ON** and `OPENAI_BASE_URL` / `OPENAI_API_KEY` are configured, the dashboard
  sends **finding data** (package name, version, vulnerability ID, aliases, severity
  score, severity vector, severity types, published date, affected range, fixed versions,
  recommended action) to the configured endpoint. Whether the configured endpoint is
  unencrypted HTTP or encrypted HTTPS is an **open privacy decision** — the endpoint
  receives the API key and finding data in either case. Model use is **not approved
  by default**; it requires explicit opt-in.

## Implementation state (published HEAD `83b10fb`; explanation + dashboard committed)

- **Parser (T-DE-01):** `requirements.txt` done (1 of ~6 manifest formats).
- **Engine (T-DE-02):** PHEI path-max scoring implemented
  (`calculate_path_weight` / `calculate_impact_multiplicity` / `calculate_phei`) +
  `UnavailableTopologyError` guard. NVD/OSV client code present
  (`src/engine/nvd_client.py`) but **not yet run end-to-end** against a real project.
- **Reporter (T-DE-03):** `RiskReport` dataclass + `src/reporter/interface.py` +
  `report_generator.py` present. Inventory serializer implemented; **dependency-graph
  serializer unimplemented**. The **read-only stdlib dashboard** (`src/web/`) is
  **committed** (83b10fb) — a stdlib `http.server` + `dashboard.html`, serving the
  report and its page; the full Flask+D3 dashboard (T-DE-04) is still not started.
- **Agent (T-DE-03 AI layer):** implemented + tested — new `src/agent/` package
  (bounded tool loop, `EvidenceTrail`, allowlisted tools, deterministic grounded policy
  with no model, `compare_scans`). **45 passing tests** (`tests/test_agent.py`).
  Plus **remediation** (`build_remediation_plan` / `verify_remediation`; committed in
  `6129e14`): `build_remediation_plan` (pure; one item per finding; fixed versions
  verbatim; severity left `None` / evidence-only) + `verify_remediation` (user-supplied
  after scan; no after scan → `not_run`, no resolution claim; unusable after report
  fails closed to `not_run`). **24 passing tests** (`tests/test_remediation.py`). A real model
  backend (llama.cpp vs. user API key) is **not yet wired** (pending decision);
  current runs use the deterministic policy (`used_llm=False`). The **explanation layer**
  (`src/explanation/`, **committed** 83b10fb) provides a grounded deterministic
  explainer plus an optional OpenAI-compatible local-model client (env-only config,
  per-finding deterministic fallback) — tested by `tests/test_explanation.py` (20) and
  `tests/test_explanation_http.py` (7).

## Open decisions (not yet resolved)

1. **Model backend (llama.cpp vs. user API key):** pending — not wired. The optional
   local-model client (`src/explanation/local_model.py`) targets a single
   `/v1/chat/completions` endpoint via env-only `OPENAI_BASE_URL`/`OPENAI_API_KEY`
   (no credentials committed). `--model` defaults to **OFF**; only exact `--model ON`
   enables it. Whether the configured endpoint is HTTP or HTTPS is an **open privacy
   decision** — the endpoint receives the API key and finding data in either case.
2. **Full interactive dashboard (T-DE-04):** Flask+D3 graph, per-node `/paths/<node>`,
   filters, trend history — **not started**. The stdlib dashboard (committed 83b10fb)
   is read-only and dependency-free.
3. **Dependency-graph serializer (T-DE-03):** unimplemented; inventory-only input
   produces no risk score (by design, `risk.status == "unavailable"`).
4. **Real NVD/OSV end-to-end scan:** NVD/OSV client code present but not yet run
   against a real project.

## Prior published baselines (historical)

- `7e8d4c4` (2026-09-28): docs-scope + templates + PHEI engine + handoffs.
- `24c99b6` (docs-only): reconciled docs against accepted scope.
- `6129e14` (2026-10-10): evidence-grounded remediation verification.
- `f1c59a8`: agent/enrichment/pipeline implementation (superseded by `6129e14`).
- `1b4a8d9` (docs-only): last-implementation baseline to c548f32.
- `b4fc87c` (docs-only): correct Aliyan handoff schema/path.
- `c548f32`: NVD/reporter/scanner scaffolding.

## Verification

- **Test suite:** 248 passed, 29 subtests (2026-10-19).
- **Remote tip:** `origin/feat/inventory-report` = `83b10fb` (matches).
- **Untracked files:** none (the explanation/dashboard files are committed in 83b10fb).
