# December Demo Roadmap — RECON-DG

> **Branch:** `feat/inventory-report`
> **HEAD:** `dfd115c5d1c5d556b0c8f2b37d3f968b643a0666` (2026-10-20)
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

## Implementation-state inventory (as of HEAD `dfd115c`)

| Module | Status | Evidence |
|--------|--------|----------|
| `src/parser` | **Partial** — `requirements.txt` only (1 of ~6 manifest formats). | `src/parser/parser.py:7–51` |
| `src/engine/risk_analyzer` | **Implemented** — PHEI path-max (`calculate_path_weight`, `calculate_impact_multiplicity`, `calculate_phei`) + `UnavailableTopologyError` guard. | `src/engine/risk_analyzer.py` |
| `src/engine/nvd_client` | **Partial** — NVD/OSV API enrichment fallback client present but **not yet run end-to-end** against a real project. | `src/engine/nvd_client.py` |
| `src/reporter` | **Partial** — `RiskReport` dataclass + `interface.py` + `report_generator.py` present. Inventory serializer implemented; **dependency-graph serializer unimplemented**. | `src/reporter/interface.py`, `src/reporter/report_generator.py`, `src/reporter/inventory.py` |
| `src/agent` | **Implemented** — bounded tool loop, `EvidenceTrail`, allowlisted tools, deterministic grounded policy (no model). **45 passing tests** (`tests/test_agent.py`). | `src/agent/agent.py`, `src/agent/normalizer.py`, `src/agent/pipeline.py`, `src/agent/scan_runner.py` |
| `src/agent` remediation | **Implemented** — `build_remediation_plan` (pure, fixed versions verbatim, severity `None`) + `verify_remediation` (user-supplied after scan; no after scan → `not_run`). **24 passing tests** (`tests/test_remediation.py`). | `src/agent/agent.py` |
| `src/explanation` | **Implemented** — grounded deterministic explainer (default) + optional OpenAI-compatible local-model client (`src/explanation/local_model.py`). Model defaults **OFF** (`--model ON` required). Per-finding deterministic fallback. | `src/explanation/deterministic.py`, `src/explanation/local_model.py`; `tests/test_explanation.py` (20), `tests/test_explanation_http.py` (7) |
| `src/web` (dashboard) | **Implemented** — stdlib `http.server` + `dashboard.html` (no third-party deps). Read-only; serves report + page. **Not** Flask+D3. | `src/web/server.py`, `src/web/__main__.py`, `src/web/dashboard.html`; `tests/test_dashboard.py` (10) |
| `src/enrichment` | **Implemented** — deps.dev enrichment layer (stdlib-only, `package_context` tool, additive only, never fed to PHEI). **26 passing tests** (`tests/test_enrichment.py`). | `src/enrichment/deps_dev.py` |
| `src/models/dependency_graph` | **Implemented** — `DependencyNode` + `DependencyGraph` (NetworkX DiGraph). | `src/models/dependency_graph.py` |
| `tests/` | **Partial** — 12 test files; full suite historically ~241–248 passed (historical counts; verify before demo). | See `tests/` directory |

**Test counts are historical unless re-run.** The "pytest 248 passed" figure is historical (2026-10-19; date not independently verifiable from repository evidence).

---

## Week-by-week milestones (ordered by dependency)

> Week numbers are sequential relative to the start of the December build cycle. No calendar dates are assumed; the team selects the start week.

### W1 — Multi-format manifest parser (T-DE-01)

**Milestone:** Parser supports ≥4 manifest formats (`requirements.txt`, `package.json`, `pyproject.toml`, `go.mod`) → shared `DependencyGraph` IR.

**Why first:** Every downstream step (engine, reporter, dashboard) depends on a real graph.

**Deliverable:** `src/parser/parser.py` with `parse_package_json()`, `parse_pyproject_toml()`, `parse_go_mod()` (in addition to existing `parse_requirements()`), all normalizing to `DependencyGraph` with correct `edge_availability` (inventory-only → `"unavailable"`).

**Verification:** `python -m pytest tests/test_parser.py -q`

### W2 — Engine wiring: real OSV + PHEI on known topology (T-DE-02)

**Milestone:** OSV client wired into the graph; real CVE data flows into PHEI on a graph with `edge_availability = "known"`. Inventory-only input (no edges) reports risk as unavailable — no score fabricated.

**Why second:** Depends on W1 (real graph needed for real lookups).

**Deliverable:** `src/engine/nvd_client.py` calls the real NVD/OSV API enrichment fallback (with rate-limiting, exponential backoff). `calculate_phei` runs on real graph data with known topology. Inventory-only input → `UnavailableTopologyError` → risk status `"unavailable"`.

**Verification:** `python -m pytest tests/test_nvd_integration.py tests/test_risk_analyzer.py -q`

### W3 — Inventory report schema + evidence-grounded suggestions (T-DE-03)

**Milestone:** `src/reporter/` includes an inventory-only serializer (Mode A) that emits the `RiskReport` schema with findings, OSV evidence, and remediation plan. PHEI is **not** required for inventory-only input — risk status is `"unavailable"` when topology is unknown.

**Why third:** Depends on W2 (engine must produce real data first).

**Deliverable:** `src/reporter/report_generator.py` with Mode A serializer: emits `RiskReport` with `findings[]`, `evidence[]` (OSV data), `risk` (status `"unavailable"` for inventory-only), `remediation_plan[]`. Suggested fixes are evidence-grounded using project functions or cited OWASP guidance.

**Verification:** `python -m pytest tests/test_report_generator.py tests/test_inventory_reporter.py -q`

### W4 — Dashboard (optional / decision-dependent) (T-DE-04)

**Milestone:** Interactive visualization of findings and remediation plan. The committed stdlib `src.web` dashboard (committed 83b10fb) serves as the default demo fallback. Flask+D3 is an optional enhancement — team to decide if it's needed for the demo.

**Why fourth:** Depends on W3 (needs a structured report to render).

**Deliverable:** `src/web/` dashboard extended with findings table, remediation plan display, and `not_run` state (red card, zero count summary). **Optional:** `src/dashboard/` with Flask routes, D3.js graph (local copy, no CDN), per-node path display, severity/threshold filters.

**Verification:** `python -m src.web` starts the stdlib dashboard; `python -m pytest tests/test_dashboard.py -q` extends to cover new endpoints.

> **Decision-dependent:** Flask+D3 requires team agreement on third-party deps and demo value. The stdlib dashboard is sufficient for the December demo.

### W5 — Wire the configured model endpoint (proposed; no registered task ID)

**Milestone:** The opt-in explanation layer (already implemented, defaults `--model OFF`) is wired to the team's chosen endpoint (llama.cpp local model or user API key). Deterministic grounded fallback remains active when the model is unavailable.

**Why fifth:** Depends on W3 (needs findings to explain).

**Deliverable:** `src/agent/` wired to the chosen endpoint. `--model ON` enables the layer; `--model OFF` (default) uses the deterministic grounded explainer. All model output is additive only (never modifies findings).

**Verification:** `python -m src.agent --model OFF` (deterministic fallback); `python -m src.agent --model ON` (configured endpoint).

> **Decision-dependent:** Team to decide llama.cpp vs. user API key. The agent layer is **already implemented** — only the endpoint wiring is pending.

### W6 — Docker packaging (optional / decision-dependent) (T-DE-05)

**Milestone:** Portable Docker image + local-dev compose. The stdlib dashboard and agent are sufficient for the December demo; Docker is an optional enhancement.

**Why sixth:** Depends on W4 (dashboard must be runnable before containerizing).

**Deliverable:** `Dockerfile` (multi-stage: builder → runtime), `docker-compose.yml`, `.dockerignore`, `requirements.txt` for image.

**Verification:** `docker compose up` against a sample manifest

> **Decision-dependent:** Docker is optional for the December demo. The stdlib dashboard + agent can run on any Python 3.10+ machine.

### W7 — Dashboard/report usability and demo validation (proposed — team confirmation required, no registered task ID)

**Milestone:** Independently testable usability validation of the dashboard and report output for the December demo.

**Why seventh:** Depends on W3 (needs a structured report to validate) + W4 (needs a dashboard to validate).

**Deliverable:** `docs/demo-validation/` with a checklist: (1) real scan runs (not synthetic), (2) PHEI score shown (not `None`), (3) patch workflow demonstrated (show, don't tell), (4) AI explanation shown (if `--model ON`), (5) unavailable topology demonstrated (contrast with available), (6) `--model OFF` demonstrated (deterministic fallback). Deliverable is an independently testable validation report, not a code change.

**Verification:** `python -m src.web` starts the stdlib dashboard; run the demo-validation checklist.

> **Owner:** Aliyan (for team confirmation). This is a usability/demo-validation task, not a code task.

---

## Open coordination questions (for team to decide)

| # | Question | Status |
|---|----------|--------|
| 1 | **Demo date and meeting cadence** | Unconfirmed — no date or cadence recorded in repo files. Team to decide. |
| 2 | **Communication channel** (Slack, Discord, email, etc.) | Unconfirmed. Team to decide. |
| 3 | **Review policy** (who reviews, when, acceptance criteria) | Unconfirmed. Team to decide. |
| 4 | **Model backend: llama.cpp vs. user API key** | Pending decision (see W5). |
| 5 | **Open privacy decision:** whether the configured `OPENAI_BASE_URL` endpoint is HTTP or HTTPS — the endpoint receives the API key and finding data in either case. | Open — documented in `src/explanation/local_model.py` and `docs/STATUS.md`. |
| 6 | **"integrations across different stories"** — phrase appears in TASKS.md without a defined meaning. | **Flagged for clarification** — do not assign an assumed meaning. |

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
| Aliyan | Dashboard/report usability + demo validation (W7, proposed) |

> All proposed owner assignments are **for team confirmation**. Historical handoff assignments (M-DE-CORE) are not current agreements.

---

*This document is the current December roadmap. For historical context, see `docs/WEEKLY.md` and `docs/REVIEW-DECISIONS.md`.*
