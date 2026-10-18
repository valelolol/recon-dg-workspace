# RECON-DG — Dependency Risk Mapper

**Scope:** recon-dg is a **dependency risk mapper**. One command takes a project and:
(1) scans it into a dependency graph (which third-party packages are used and how
they connect), (2) checks each package for known CVEs via **OSV-Scanner** (the
project's external vulnerability scanner — the project does *not* build a scanner
from scratch), (3) scores *systemic* risk — whether low-severity flaws combine
along critical dependency paths into a real threat (PHEI path-max) — (4) displays
the results in a dashboard, and (5) explains each finding in plain language via an
AI backend.

**Intended full pipeline (the December deliverable — *planned; not all of it is
implemented yet*):** the (1)–(5) steps above are the full intended pipeline.

**What works this week (M-DE-CORE):** the Mode A **inventory serializer**
(`src/reporter/inventory.py`), the **PHEI** path-max function
(`calculate_phei` in `src/engine/risk_analyzer.py`), the before/after
**report generator** (`src/reporter/report_generator.py`), and a new **agent
layer** (`src/agent/`) that runs a bounded, evidence-grounded investigation over
a normalized OSV-Scanner scan (see "Agent layer" below). The **Mode B**
dependency-graph serializer and the synthetic reference `report.json` are still
*planned* deliverables, not yet working features. Earlier verification results
(e.g., PHEI == 6.0 on a synthetic 3-node unit chain, and the "pytest 79 passed"
count) are **historical** — they date to an earlier commit. Re-running the full suite this week gives **241 passed, 29 subtests, 2
warnings** (re-run 2026-10-10): 53 reporter, 45 agent, 26 enrichment, 23
pipeline, 24 remediation, 11 NVD integration, 10 parser, 8 report generator,
5 risk analyzer, 20 explanation, 7 explanation-HTTP, 9 dashboard.
A **provisional** stdlib-only dashboard (`src/web/`) and a **provisional**
explanation layer (`src/explanation/` — a grounded deterministic explainer plus
an optional OpenAI-compatible local-model client) are now in the tree (uncommitted)
and verified by real loopback HTTP tests. The **full Flask+D3** dashboard and a
*real* local model remain **planned** and not yet running. Steps (2) live
NVD/OSV, (4) the full dashboard, and (5) a real AI model backend are still
planned; the agent below runs fully without a model via a deterministic policy.

**Core track (December deliverable):** dependency inventory → OSV-Scanner scan →
deterministic risk analysis → reporting → dashboard → AI explanations.
*As of this week the inventory serializer, the PHEI function, the report
generator, and the agent layer (`src/agent/`) are in the tree and tested; the
Mode B serializer + synthetic `report.json`, live NVD/OSV, the dashboard, and a
real AI model backend are not yet implemented.*

## Getting started (read this first)

- **`docs/TEAM_ONBOARDING.md`** — how to clone the repo and set up **your own computer**
  (Git + Python checks, a personal branch, a virtual environment, and how to validate
  your JSON fixtures). It defines the ten terms you will meet and gives separate
  PowerShell / terminal routes.
- **`docs/WEEKLY.md`** — historical M-DE-CORE demo-track focus, acceptance criteria,
  and the handoff list for that week (now complete); current project status is in
  **`docs/STATUS.md`**.
- **`TASKS.md`** — the task register (stable IDs), phase plans, and the shared
- **`docs/STATUS.md`** — the current state (date, branch/HEAD, working-tree state).

**Synthetic data rule:** synthetic graph/advisory data is only for clearly labeled offline tests or a separate demo. It is **never** scanner evidence. Real scanner output (OSV-Scanner JSON) is the only valid input for the agent and PHEI scoring.

## Agent layer

`src/agent/` is the *agentic* heart of the dependency-risk mapper. It is deliberately **not**
"OSV-Scanner with an LLM summary." The product's differentiator is a **bounded,
evidence-grounded workflow**: detect → investigate with allowlisted tools → explain
evidence and uncertainty → propose human-reviewed remediation → verify against a
user-supplied after-scan. The agent:

- operates on the **real** OSV-Scanner output, normalized into the repo's
  `DependencyGraph` + first-class `Finding` objects (`src/agent/normalizer.py`);
- runs a **bounded** loop — a `max_turns` hard cap *plus* a natural stopping rule
  (all high-severity findings investigated, risk computed, summary emitted);
- makes a **conditional** tool choice each turn, deciding from its own state
  (which findings exist, which are high-severity, whether topology is known);
- records **every** tool call — tool name, arguments, and the structured
  observation — into an append-only **`EvidenceTrail`**. That trail is the
  observable artifact a reviewer, dashboard, or downstream AI reads to audit *why*
  each conclusion was drawn;
- **never invents data.** Every claim about a finding is backed by a field from the
  OSV-Scanner output (id, advisory, CVSS, affected range, published date).

A pluggable ``llm`` callable may steer tool selection (the product's AI backend),
but it can only pick from an **allowlisted** tool set and must return valid
arguments; if it returns anything out of band, the agent falls back to a
grounded deterministic policy and records that fallback in the trail. This keeps
the agent fully functional with **no model** (deterministic policy) while a real
model can steer it when one is available — and keeps the *evidence* grounded
either way.

| Tool | Args | Observation |
|------|------|-------------|
| `findings` | — | all findings (count + ids) |
| `get_finding` | `vulnerability_id` | one `Finding` as dict |
| `package_info` | `package_name`, `version` | vulnerabilities for a package node |
| `package_context` | `package_name`, `version` (opt `ecosystem`, `vulnerability_id`) | deps.dev published context, labelled `generic_published`; strictly additive, review-only — **never** replaces OSV-Scanner findings or feeds PHEI scoring |
| `high_severity` | `threshold` | high-severity findings only; **unknown severity stays unknown** — the system does not invent numeric CVSS scores or high/low labels |
| `risk_score` | — | PHEI path-max, or "unavailable" — PHEI is available only when trustworthy project dependency topology exists; otherwise it is unavailable. Do not fabricate edges or paths. |
| `summary` | — | plain-language narrative |
| `stop` | `reason` | terminal |

`compare_scans(before, after)` produces the before/after delta (new / resolved /
unchanged findings + the PHEI risk delta, skipped when topology is unavailable).

The agent layer also carries a **remediation** stage, wired through the pipeline
(`src/agent/pipeline.py`, `investigate` / `investigate_from_json` with an optional
`after_scan_report`):

- **`build_remediation_plan(scan)`** — a *pure* function (no manifest edits, no
  installs, no network, no scoring) that emits one item per baseline finding.  Each
  item preserves the advisory ID + aliases, the package, the installed version, the
  affected range, the scanner-provided **fixed versions verbatim** (never
  "latest"/"best" and never invented), an explicit `has_fixed_version` flag, and the
  severity *evidence only* (`severity_score` left `None`; scheme types + vector
  strings preserved).  It never computes or implies a numeric CVSS score or a
  high/low category.  A plain recommended action names the scanner's fixed version
  when one exists and otherwise says a specific target cannot be asserted.
- **`verify_remediation(before_scan, plan, after_scan=None)`** — reconciles that
  plan against a **user-supplied** after scan (no network; the caller supplies the
  scan).  With **no after scan** it returns `status == "not_run"` and makes **no
  resolution claim** and asserts no fix.  With an after scan it classifies each
  plan item on the `(package, version, vulnerability_id)` key: same version in the
  after scan = `unchanged` (never counted as fixed); key absent = `resolved`; same
  advisory at a *different* version = `regressed`.  Findings new in the after scan
  that were not in the plan are counted via the existing comparison and reported as
  `new_count`, **not** attributed to the plan.  Risk/PHEI is preserved from the
  comparison and is left `unavailable` when topology is unavailable — no edges or
  scores are invented.  Verification appends a step to the caller's `EvidenceTrail`
  (and always carries its own auditable `evidence`) so that "verification ran
  (or was requested but had no after scan)" is on the record.
- A **malformed, missing, or unusable** after report fails closed to
  `status == "not_run"` and makes no resolution claim; the baseline investigation is
  always preserved.

**Status.** Implemented and tested (45 passing tests in `tests/test_agent.py`
plus 24 in `tests/test_remediation.py`),
plus an opt-in **deps.dev enrichment** layer (`src/enrichment/`, stdlib-only,
26 passing tests in `tests/test_enrichment.py`) that exposes a new
`package_context` tool (published, resolved, labelled `generic_published`;
additive, never fed to PHEI scoring). It runs fully **without** a model via the
deterministic policy. On the checked-in flat fixture (`tests/data/osv-scanner.json`:
5 findings, 4 packages, 0 edges) a 7-turn run reports `risk.status == "unavailable"`,
`risk.score is None`, with the message *"No score is fabricated; this is an
inventory-only result"* — no invented edges, no invented score, consistent with
the inventory-only contract. Wiring a **real** model backend (local llama.cpp
endpoint vs. user-provided API key) is a pending decision (see `TASKS.md`) and is
not yet implemented. Full suite: **241 passed, 29 subtests, 2 warnings**.

## Provisional dashboard & explanation layer (in the tree; uncommitted)

The December deliverable includes a dashboard (step 4) and AI explanations (step
5). Two **provisional, uncommitted** implementations are now in the tree and
verified by real loopback-HTTP tests — these are toward the December target, not
the final deliverable:

- **Dashboard (`src/web/`) — stdlib-only `http.server`, no third-party deps.**
  `python -m src.web [--report FILE] [--port N] [--host HOST] [--model ON/OFF]`
  serves a self-contained `dashboard.html` at `/` and the structured report at
  `/report.json` on local loopback (binds `127.0.0.1` by default). It is
  read-only: it serves a report and its page; it **does not** re-run scans,
  edit manifests, or imply a fix was verified. It renders the findings, the
  risk *limitations* (`risk.status == "unavailable"` → "no score is fabricated"),
  the remediation plan (scanner-provided fixed versions verbatim), and the
  after-scan verification state **including `not_run`** (a red card with a zero
  count summary and no resolution claim). Verified by `tests/test_dashboard.py`
  (9 passing tests, real HTTP GETs to `/` and `/report.json`).
  **Deviation from the recommended stack:** this is *not* Flask + D3. Flask is
  not installed in this environment and is not declared in any manifest; per the
  no-install constraint the dashboard is implemented as a dependency-free
  stdlib `http.server` + self-contained vanilla-JS page (no D3). The full
  interactive Flask+D3 dashboard (graph, per-node `/paths/<node>`, filters, trend
  history) is still **T-DE-04** and not started. To move to Flask+D3 the smallest
  safe change is: add `flask>=2.3,<3` to `requirements-dev.txt` (dev only), port
  the two handlers (`/` and `/report.json`) into Flask routes, and load D3.js
  from a local copy (no external CDN) — a follow-up T-DE-04 task, not part of
  this slice.

- **Explanation layer (`src/explanation/`) — deterministic + optional local model.**
  The **default** is a grounded deterministic explainer
  (`src/explanation/deterministic.py`) that cites only facts already on the
  finding and never fabricates a numeric CVSS score, version, or CVE. The
  **optional** backend (`src/explanation/local_model.py`) targets a single
  OpenAI-compatible `/v1/chat/completions` endpoint via stdlib `urllib`,
  configured only by the `OPENAI_BASE_URL` / `OPENAI_API_KEY` environment
  variables (no credentials or endpoint secrets are committed). Model output is
  *optional explanatory text only*: `add_explanations(report, use_model=True)`
  adds an additive `report["ai_explanations"]` (one `{"text", "source"}` entry
  aligned with `report["findings"]`) and an `explanation_source` summary that
  counts model vs deterministic entries and **never echoes the API key or
  endpoint**. Deterministic fallback is guaranteed and labelled `source` per
  finding — on *any* per-finding failure (no config, network/timeout, non-2xx
  status, malformed body, empty or non-string completion) that finding falls
  back to the grounded deterministic text; the request is bounded by a hard
  `max_calls` cap. Findings, severity, fixed versions, risk, remediation, and
  verification are **never modified** by this layer. Verified by
  `tests/test_explanation.py` (20), `tests/test_explanation_http.py` (7, a real
  local `/v1/chat/completions` server driven by real `urllib` requests — no
  injected transport seam), and the dashboard tests above.

> These provisional modules are **uncommitted** and are a bounded step toward the
> December dashboard + AI deliverable; the full Flask+D3 dashboard (T-DE-04) and
> a *real* model backend (pending decision) remain open.

## Key documents

- [docs/TEAM_ONBOARDING.md](docs/TEAM_ONBOARDING.md) — beginner setup on your own machine (read first)
- [AGENTS.md](AGENTS.md) — startup/completion routine, evidence rules, routing
- [TASKS.md](TASKS.md) — task register, phase plans
- [docs/STATUS.md](docs/STATUS.md) — current state (date, branch/HEAD, working tree)
- [docs/WEEKLY.md](docs/WEEKLY.md) — weekly focus and acceptance criteria
|- **Current handoffs (M-DE-CORE, for reference):**
  - `HANDOFF_NICK_MDECORE.md` — Nick · fixtures + limitations note (T-DE-01/02)
  - `HANDOFF_CHRISTIAN_MDECORE.md` — Christian · offline tests + expected results (T-DE-02/03)
  - `HANDOFF_VALE_MDECORE.md` — Vale · loader, PHEI/report integration, reference output (T-DE-01/02/03)
  - `HANDOFF_ALIYAN_MDECORE.md` — Aliyan (provisional) · static viewer spike (T-DE-04)
- [docs/WEEKLY.md](docs/WEEKLY.md) — historical weekly focus and acceptance criteria

> **Read the handoff list above (for reference).** `docs/WEEKLY.md` is now historical;
> the `HANDOFF_*_MDECORE.md` files are this week's (complete) handoffs.
