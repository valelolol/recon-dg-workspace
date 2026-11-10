# December Demo Roadmap — RECON-DG

> **Branch:** `feat/inventory-report`
> **HEAD:** `11937e4a9a9ea60eeea64c510d35855e170cfe31` (2026-11-09)
> **Published baseline:** `83b10fb` (2026-10-19)
> **Untracked:** `docs/REVIEW-DECISIONS.md` (intentionally preserved)

---

## Product scope (one command)

> One command takes a project and:
> 1. **Scans** it into a dependency graph (third-party packages + connections).
> 2. **Checks** each package for known CVEs via **OSV-Scanner** (the project's external vulnerability scanner — the project does *not* build a scanner).
> 3. **Scores** systemic risk — whether low-severity flaws combine along critical dependency paths into a real threat (PHEI path-max).
> 4. **Displays** the results in a dashboard.
> 5. **Explains** each finding in plain language via an AI backend.

**Constraint:** inventory-only input must not produce invented dependency edges. Risk scoring requires explicitly "known" topology.

**Synthetic data rule:** synthetic graph/advisory data is only for clearly labeled offline tests or a separate demo. It is **never** scanner evidence. Real scanner output (OSV-Scanner JSON) is the only valid input for the agent and PHEI scoring.

---

## Implementation-state inventory (as of HEAD `11937e4a9a9ea60eeea64c510d35855e170cfe31`)

| Module | Status | Evidence |
|--------|--------|----------|
| `src/parser` | **Partial — 3/4 minimum formats** — `requirements.txt`, `pyproject.toml`, `package.json` (W9 Nick). `go.mod` is the remaining blocker for ≥4 target. | `src/parser/parser.py:11,78,parse_package_json` |
| `src/engine/risk_analyzer` | **Implemented** — PHEI path-max (`calculate_path_weight`, `calculate_impact_multiplicity`, `calculate_phei`) + `UnavailableTopologyError` guard. | `src/engine/__init__.py`, `src/engine/risk_analyzer.py` |
| `src/engine/nvd_client` | **Partial** — NVD/OSV API enrichment fallback client present but **not yet run end-to-end** against a real project. | `src/engine/__init__.py`, `src/engine/nvd_client.py` |
| `src/reporter` | **Partial** — `RiskReport` dataclass + `interface.py` + `report_generator.py` present. Inventory serializer implemented; **dependency-graph serializer unimplemented**. | `src/reporter/__init__.py`, `src/reporter/interface.py`, `src/reporter/report_generator.py`, `src/reporter/inventory.py` |
| `src/agent` | **Implemented** — bounded tool loop, `EvidenceTrail`, allowlisted tools, deterministic grounded policy (no model). **45 passing tests** (`tests/test_agent.py`). | `src/agent/__init__.py`, `src/agent/agent.py`, `src/agent/normalizer.py`, `src/agent/pipeline.py`, `src/agent/scan_runner.py` |
| `src/agent` remediation | **Implemented** — `build_remediation_plan` (pure, fixed versions verbatim, severity `None`) + `verify_remediation` (user-supplied after scan; no after scan → `not_run`). **24 passing tests** (`tests/test_remediation.py`). | `src/agent/agent.py` |
| `src/explanation` | **Implemented** — grounded deterministic explainer (default) + optional **OpenAI/ChatGPT, Claude, or a custom** local-model client (`src/explanation/local_model.py`). Model defaults **OFF** (`--model ON` required). Per-finding deterministic fallback. | `src/explanation/__init__.py`, `src/explanation/deterministic.py`, `src/explanation/local_model.py`; `tests/test_explanation.py` (23), `tests/test_explanation_http.py` (7) |
|| `src/web` (dashboard) | **Implemented** — stdlib `http.server` + `dashboard.html` (no third-party deps). Read-only; serves report + page. **Not** Flask+D3. `src/web/osv_normalizer.py` (6,851 bytes) corrected to dashboard contract (2026-11-03). **Note:** two normalizers exist: `src/web/osv_normalizer.py` (dashboard format) and `src/agent/normalizer.py` (445 lines, older agent format). No single canonical normalizer yet. | `src/web/__init__.py`, `src/web/__main__.py`, `src/web/server.py`, `src/web/dashboard.html`, `src/web/osv_normalizer.py`; `tests/test_dashboard.py` (13), `tests/test_osv_normalizer.py` (12) |
| `src/enrichment` | **Implemented** — deps.dev enrichment layer (stdlib-only, `package_context` tool, additive only, never fed to PHEI). **26 passing tests** (`tests/test_enrichment.py`). | `src/enrichment/__init__.py`, `src/enrichment/deps_dev.py` |
| `src/models/dependency_graph` | **Implemented** — `DependencyNode` + `DependencyGraph` (NetworkX DiGraph). | `src/models/__init__.py`, `src/models/dependency_graph.py` |
| `tests/` | **Partial** — 12 test files; full suite historically ~241–248 passed (historical counts; verify before demo). | See `tests/` directory |

**Test counts are historical unless re-run.** The "pytest 248 passed" figure is historical (2026-10-19; date not independently verifiable from repository evidence).

---

## Week-by-week milestones (ordered by dependency)

> Week numbers are sequential relative to the start of the December build cycle. No calendar dates are assumed; the team selects the start week.

### W1 — Multi-format manifest parser (T-DE-01) — **W9 in progress (3/4)**

**Milestone:** Parser supports ≥4 manifest formats (`requirements.txt`, `pyproject.toml`, `package.json`, `go.mod`) → shared `DependencyGraph` IR.

**Why first:** Every downstream step (engine, reporter, dashboard) depends on a real graph.

**Current state (W9):** 3/4 minimum formats implemented (requirements.txt, pyproject.toml, package.json). `go.mod` is the remaining blocker for the ≥4 target. See archived W9-Nick.md for W9 deliverable.

**Deliverable:** `src/parser/parser.py` with `parse_package_json()`, `parse_pyproject_toml()`, `parse_go_mod()` (in addition to existing `parse_requirements()`), all normalizing to `DependencyGraph` with correct `edge_availability` (inventory-only → `"unavailable"`).

**Verification:** `python -m pytest tests/test_parser.py -q`

**W9 handoff (archived):** `docs/weekly-handoffs/W9-Nick.md`

### W2 — Engine wiring: real OSV + PHEI on known topology (T-DE-02) — **PHEI partial**

**Milestone:** OSV client wired into the graph; real CVE data flows into PHEI on a graph with `edge_availability = "known"`. Inventory-only input (no edges) reports risk as unavailable — no score fabricated.

**⚠️ PHEI gap (agreed direction):** The agreed PHEI target is a **topology-based 0–100 impact score using reachable dependents and existing importance/criticality, separate from OSV severity**. The current `calculate_phei()` (risk_analyzer.py:124–200) uses `get_cve_severity()` (NVD/OSV severity) as node risk values (lines 147–154), mixing severity into the score. **This contradicts the agreed topology-only direction.** PHEI is **partial/unavailable** pending topology data (reachable dependents, importance/criticality). The severity-to-PHEI mapping is **not an open decision** — topology-only is the agreed direction. If trustworthy topology or approved rule absent → report unavailable; do not fabricate.

**Why second:** Depends on W1 (real graph needed for real lookups).

**Deliverable:** `src/engine/nvd_client.py` calls the real NVD/OSV API enrichment fallback (with rate-limiting, exponential backoff). `calculate_phei` runs on real graph data with known topology. Inventory-only input → `UnavailableTopologyError` → risk status `"unavailable"`.

**Verification:** `python -m pytest tests/test_nvd_integration.py tests/test_risk_analyzer.py -q`

**W9 handoff (archived):** `docs/weekly-handoffs/W9-Vale.md`

### W3 — Inventory report schema + evidence-grounded suggestions (T-DE-03) — **Mode B unimplemented**

**Milestone:** `src/reporter/` includes an inventory-only serializer (Mode A) that emits the `RiskReport` schema with findings, OSV evidence, and remediation plan. PHEI is **not** required for inventory-only input — risk status is `"unavailable"` when topology is unknown.

**Why third:** Depends on W2 (engine must produce real data first).

**Deliverable:** `src/reporter/report_generator.py` with Mode A serializer: emits `RiskReport` with `findings[]`, `evidence[]` (OSV data), `risk` (status `"unavailable"` for inventory-only), `remediation_plan[]`. Suggested fixes are evidence-grounded using project functions or cited OWASP guidance.

**Verification:** `python -m pytest tests/test_report_generator.py tests/test_inventory_reporter.py -q`

**Mode B (dependency-graph serializer):** Unimplemented. This is a **W3 deliverable** that has been missed; rescheduled to W10 (see W10 plan). Mode B must emit `findings[]`, `evidence[]`, `risk`, `remediation_plan[]` with no fabricated data. No out-of-spec extension emitted this week; a risk-path field is deferred to a separate schema decision. See `docs/weekly-plan/W10-2026-11-09-to-2026-11-15.md`.

**W9 handoff (archived):** `docs/weekly-handoffs/W9-Vale.md` (PHEI gap documentation)

### W4 — Dashboard (optional / decision-dependent) (T-DE-04)

**Milestone:** Interactive visualization of findings and remediation plan. The committed stdlib `src.web` dashboard (committed 83b10fb) serves as the default demo fallback. Flask+D3 is an optional enhancement — team to decide if it's needed for the demo.

**Why fourth:** Depends on W3 (needs a structured report to render).

**Deliverable:** `src/web/` dashboard extended with findings table, remediation plan display, and `not_run` state (red card, zero count summary). **Optional:** `src/dashboard/` with Flask routes, D3.js graph (local copy, no CDN), per-node path display, severity/threshold filters.

**Verification:** `python -m src.web` starts the stdlib dashboard; `python -m pytest tests/test_dashboard.py -q` extends to cover new endpoints.

> **Decision-dependent:** Flask+D3 requires team agreement on third-party deps and demo value. The stdlib dashboard is sufficient for the December demo.

### W5 — Wire the configured model endpoint (resolved — user-selected provider)

**Milestone:** The opt-in explanation layer (already implemented, defaults `--model OFF`) is wired to the team's chosen endpoint (**OpenAI/ChatGPT, Claude, or a custom endpoint**). Deterministic grounded fallback remains active when the model is unavailable.

**Why fifth:** Depends on W3 (needs findings to explain).

**Deliverable:** `src/agent/` wired to the chosen endpoint. `--model ON` enables the layer; `--model OFF` (default) uses the deterministic grounded explainer. All model output is additive only (never modifies findings).

**Verification:** `python -m src.agent --model OFF` is **unavailable** — the `src/agent` layer has no `--model` CLI flag. `--model` is a `src.web` dashboard flag (serves an existing report only; requires `OPENAI_BASE_URL` + `OPENAI_API_KEY` for `--model ON`). The agent layer is already implemented (bounded tool loop, `EvidenceTrail`, deterministic grounded policy) but its endpoint wiring (**OpenAI/ChatGPT, Claude, or a custom endpoint**, user-configured) is pending.

> **Decision settled:** The user selects **ChatGPT (OpenAI), Claude, or a custom endpoint** (URL/IP/port with credentials if required). The current client supports a generic **OpenAI/ChatGPT, Claude, or a custom** `/v1/chat/completions` endpoint; provider-selection UI and native Claude integration are **implementation gaps**, not unresolved decisions. Endpoint selection/configuration is implementation work, not a pending decision. The agent layer is **already implemented** — only the endpoint wiring is pending.

### W6 — Docker packaging — **dismissed / out of scope** (2026-11-03)

**Decision:** Docker is **dismissed** for the December deliverable. The standalone stdlib dashboard (`src/web/`) and agent are sufficient for the Dec 9 presentation on any Python 3.10+ machine (Windows/Linux). A portable container is a future enhancement, not a December requirement.

> **Rationale:** The Dec 9 demo runs on the user's local machine. A Docker image adds complexity (multi-stage build, image size, dependency resolution) without demo value over `python -m src.web`. The team agreed to keep the product deployable as a single `python -m src.web` command.

### W7 — Dashboard/report usability and demo validation (resolved — Aliyan, W12 deliverable)

**Milestone:** Independently testable usability validation of the dashboard and report output for the December demo.

**Why seventh:** Depends on W3 (needs a structured report to validate) + W4 (needs a dashboard to validate).

**Deliverable:** `docs/demo-validation/` with a checklist: (1) real scan runs (not synthetic), (2) PHEI score shown (not `None`), (3) patch workflow demonstrated (show, don't tell), (4) AI explanation shown (if `--model ON`), (5) unavailable topology demonstrated (contrast with available), (6) `--model OFF` demonstrated (deterministic fallback). Deliverable is an independently testable validation report, not a code change.

**Verification:** `python -m src.web` starts the stdlib dashboard; run the demo-validation checklist.

> **Owner:** Aliyan (resolved, W12 deliverable). This is a usability/demo-validation task, not a code task. **W12 plan:** `docs/weekly-plan/W12-2026-11-23-to-2026-11-29.md` §Demo validation.

### W8 — Historical milestone: W9 planning docs pushed to origin (2026-11-06)

> **This is a historical milestone — not a deliverable week.** It records the last committed state before the W9–W13 plan cycle.

**What was delivered:** The W9 planning docs (`docs/weekly-plan/W9-2026-11-02-to-2026-11-08.md`), all four W9 handoffs (`docs/weekly-handoffs/W9-*.md`, now archived), and the STATUS.md/ROADMAP.md/TASKS.md reconciliation were pushed to origin at commit `88f2b2c12e979000aaaa604955e205010f76c133` (2026-11-06). This is the published baseline for the W9–W13 cycle. The W10 handoffs (untracked) build on this baseline.

**Published tip:** `origin/feat/inventory-report` = `11937e4a9a9ea60eeea64c510d35855e170cfe31`.

**Why W8:** Documents the last committed state before the active W9–W13 planning cycle began. All subsequent weeks (W9–W13) build on this baseline.

---

### W9 — Dependency-graph serializer (T-DE-03 Mode B) — **W10 deliverable**

> **Moved from W9 to W10:** The dependency-graph serializer (Mode B) was originally planned for W9 but deferred to W10 because it is unimplemented and blocks the W11 CVE→systemic-risk demo.

**Milestone:** `src/reporter/report_generator.py` Mode B serializer: emits `findings[]`, `evidence[]`, `risk`, `remediation_plan[]` with no fabricated data. No out-of-spec extension emitted this week; a risk-path field is deferred to a separate schema decision.

**Why ninth:** Depends on W3 (needs a structured report to serialize).

**Deliverable:** `src/reporter/report_generator.py` Mode B serializer. Parses the `DependencyGraph` (NetworkX DiGraph) output from `src/parser/parser.py` and emits the `RiskReport` schema.

**Verification:** `python -m pytest tests/test_report_generator.py -q` (Mode B tests).

**W10 plan:** `docs/weekly-plan/W10-2026-11-09-to-2026-11-15.md`

**W9 handoff (archived):** `docs/weekly-handoffs/W9-Vale.md` (Mode B deliverable moved to W10)

### W10 — Dependency-graph serializer (T-DE-03 Mode B) — **W10 deliverable**

**Four active handoffs, one per team member.** No archived W1–W8 or M-DE-CORE handoffs restored.

**December timeline:** Dec 4 (Fri) team demo, Dec 7 (Mon) team demo, Dec 8 (Tue) rehearsal/buffer, Dec 9 (Wed) presentation.

> **Interim-demo scope:** The Dec 9 presentation is an interim demonstration of progress toward the larger RECON-DG project — not a declaration that the full project is complete. The December deliverable is a working prototype (scan → graph → OSV findings → systemic risk → dashboard → AI explanation → bounded fix → human approval → rescan → verified results), not a finished application.

> **Dec 4 milestone:** Team demo — `python -m src.web` serves the report dashboard; real scan evidence is present (Mode B or Mode A).

> **Dec 7 milestone:** Team demo — full pipeline (scan → report → dashboard → explanation) runs end-to-end on a controlled project.

> **Dec 8 milestone:** Rehearsal — the full demo script (≤10 steps, each with expected output) is dry-run on a controlled project; feedback logged in `docs/demo-validation/dec-8-rehearsal.md`.

> **Dec 9 milestone:** Presentation — the December deliverable demo delivered to faculty/sponsor.

|| Member | Handoff file | Focus |
|--------|-------------|-------|
| Nick | `docs/weekly-handoffs/W10-Nick.md` | Parser: `parse_go_mod()` (3/4 → 4/4) |
| Vale | `docs/weekly-handoffs/W10-Vale.md` | Engine + reporter: Mode B serializer (dependency-graph serializer) |
| Christian | `docs/weekly-handoffs/W10-Christian.md` | Dashboard validation tests (empty/malformed input, unknown-topology) |
| Aliyan | `docs/weekly-handoffs/W10-Aliyan.md` | Demo validation: `docs/demo-validation/` directory + rehearsal checklist + demo script |

**W10 plan:** `docs/weekly-plan/W10-2026-11-09-to-2026-11-15.md`

---

## Open coordination questions (for team to decide)

| # | Question | Status |
|---|----------|--------|
| 2 | **"integrations across different stories"** — phrase appears in TASKS.md without a defined meaning. | **Flagged for clarification** — do not assign an assumed meaning. |

---

## Implementation notes (not blockers)

| Item | Status |
|------|--------|
| Communication channel (Slack, Discord, email, etc.) | Team to decide; not blocking current work |
| Review policy (who reviews, when, acceptance criteria) | Team to decide; not blocking current work |
| Open privacy decision: `OPENAI_BASE_URL` endpoint HTTP vs HTTPS | Implementation note — endpoint receives API key and finding data in either case. Documented in `src/explanation/local_model.py` and `docs/STATUS.md`. |

---

## Security and privacy gates

| Gate | Requirement |
|------|-------------|
| **OSV-Scanner authoritative** | OSV-Scanner is the only valid scanner evidence. No other tool replaces its output. |
| **deps.dev optional/additive** | deps.dev may provide package context but must never replace OSV-Scanner findings or establish dependency topology. |
| **Model opt-in** | `--model` defaults to **OFF**. Only exact `--model ON` (case-insensitive) enables the local-model backend. |
| **Bounded agent** | Agent has a `max_turns` hard cap + natural stopping rule. Every tool call recorded in `EvidenceTrail`. |
| **Deterministic fallback** | If the model is unavailable or returns out-of-band, the agent falls back to a grounded deterministic policy. |
| **No fabricated edges** | Inventory-only input produces `edge_availability == "unavailable"`; no edges invented. |
| **No PHEI without topology** | `calculate_phei` raises `UnavailableTopologyError` when topology is not `"known"`. |
| **User-approval patch** | Agent proposes a patch; the user sees exact changes and applies only after explicit approval. |
| **After-scan verification** | A vulnerability is claimed resolved only when a usable user-provided after-scan supports that conclusion. |
| **No model training/fine-tuning** | Out of scope. |
| **No faculty/sponsor approval in runtime** | The patch-approval checkpoint is the *user's* approval, not a faculty gate. |

---

## Historical (not on the active critical path)

| Item | Status |
|------|--------|
| M-DE-CORE demo week (Sep 28–Oct 4, 2026) | Historical; not current track. See `docs/WEEKLY.md` (historical). |
| Mode B (historical/demo-only) | Historical/demo-only. Not in the tree. Not prerequisites. |
| C0 contract checkpoint | Historical/demo-only. |
| `HANDOFF_*_MDECORE.md` files | Historical assignments; not current team agreements. |

---

## Team roster (for team confirmation)

| Member | Proposed role |
|--------|---------------|
| Vale | Scanner pipeline + engine + reporter (W1–W3) |
| Nick | Parser (W1) |
| Christian | Dashboard (W4) + Docker packaging (W6, proposed, optional) |
| Aliyan | Dashboard/report usability + demo validation (W7 → W12, resolved) |

> All proposed owner assignments are **for team confirmation**. Historical handoff assignments (M-DE-CORE) are not current agreements.

---

*This document is the current December roadmap. For historical context, see `docs/WEEKLY.md` and `docs/REVIEW-DECISIONS.md`.*
