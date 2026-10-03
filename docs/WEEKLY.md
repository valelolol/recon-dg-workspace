# WEEKLY — September 28 – October 4, 2026

## Focus
Move the **core** T-DE-01/02/03 path from "PHEI implemented" to "a small, demonstrable core
dependency-risk report" using clearly-labeled synthetic fixtures and **no live API calls**.
The Bandit sub-track (T-SA-01/02/03) stays **non-gating this week** (course requirement
UNKNOWN — pending confirmation). No completion percentages are quoted; status is per task ID.
The docs reviewed in this session (2026-10-01, reviewed at HEAD `1524425`; published at
HEAD `6323285`; corrected/baseline-updated at HEAD `b4fc87c`, 2026-10-02) are the
*documentation-only*
state: handoffs rewritten for complete beginners, README/TASKS/STATUS reconciled. No code,
fixture, manifest, or test changed.

## Baseline (for the reader)
- **Branch:** `feat/inventory-report`. **HEAD:** `b4fc87c` ("docs: correct Aliyan handoff
  schema/path and baseline dates", 2026-10-02, docs-only). **Live remote**
  `origin/feat/inventory-report` == `b4fc87c` (verified via `git ls-remote`).
- *Historical prior HEAD (label only):* `6323285` ("docs: publish current team handoffs and
  clean up obsolete guidance", 2026-10-02) and `1524425` ("Publish reviewed M-DE-CORE plan
  and four handoffs", 2026-10-01) — both docs-only commits that published the plan and the
  four handoffs; implementation code was unchanged by them.
- The *implementation* code state is as of `c548f32` (the last commit that changed
  implementation code — it added the NVD/reporter/scanner scaffolding); the later commits
  `f2303ee`, `5b8a1f7`, `1524425`, `6323285`, and `b4fc87c` are docs-only and did not
  alter it. The executed verifications below (PHEI == 6.0, pytest 79 passed) date to
  `5b8a1f7` and remain *historical* unless re-run.

## Intended deliverable & acceptance criteria (M-DE-CORE)
| Task ID | Owner | Deliverable | Acceptance criteria |
|---------|-------|-------------|---------------------|
| T-DE-01/02/03 | Vale + Nick | `report.json` (Mode A + Mode B) + reference sample | One command, no live API. Mode A: existing fields/behavior preserved and existing tests pass. Mode B: `analysis_mode: dependency_graph`, `topology_status: known`, **`risk.score: 6.0`**, `method: phei`, `risk.status: available` (spec enum `available`/`unavailable`, not `complete`), `input.format == "synthetic-graph"`, 3 synthetic findings with `id`, `advisory_source` = `synthetic-fixture`, `severity: null`, synthetic `warnings`, **no path field** (v0.1 defines none). Byte-equality asserted only where `scan_id`/`created_at` are fixed. |
| T-DE-04 | Aliyan (provisional) | `src/dashboard/view.py` → `report.html` (provisional static spike) | Renders packages/edges/numeric score/findings from `report.json`; **no LOW/MED/HIGH/CRITICAL labels**; data-driven; no framework. Full Phase 4 T-DE-04 dashboard scope (Flask+D3, endpoints, interactive graph) is preserved and out of scope this week. **Prerequisite:** a reference `report.json` must exist (Vale, W1-DE-03.R) — without it Aliyan can only build a static viewer skeleton + a hand-authored synthetic sample (labeled synthetic). |
| T-DE-02/03 | Christian | `tests/test_e2e_risk.py` + `docs/E2E_EXPECTED_RESULTS.md` | 3 scenarios pass offline, deterministic (run twice with the same fixed scan_id and created_at and compare outputs); asserts the 6.0 reference. **Prerequisite:** reference `report.json` (Vale). Without it, Christian can only write the test harness skeleton + expected-results doc. |
| T-SA-01/02/03 | — | (unchanged) | **Non-gating this week; course requirement UNKNOWN.** |

**Defer:** the older T-DE-02 goal of *real* NVD/OSV lookups is deferred this week in favor
of synthetic fixtures and no live API.

## Delivery order (after checkpoint C0)
> The C0 gate holds **Nick's fixture authoring and the downstream *fixture-consuming*
> steps** (reference sample, E2E assertion, viewer run against real data). It does
> **not** block Vale *writing* the loader/serializer/CLI against the proposed shape,
> Christian *drafting* the harness, or presenting/reviewing the handoffs — those are
> already written and can be shared for review now.

1. **C0:** everyone signs the Mode B field mapping **and** the **proposed input-fixture
   contract** (TASKS.md §C0-prereq — approval *required* before Nick authors fixtures).
2. **Nick (fixtures)** — needs input-contract approval. Authors the two synthetic inputs.
3. **Vale (loader → report → reference sample)** — `load_known_topo_json()`, Mode B
   serializer, `sample_risk_report.json` (the 6.0 reference). This is the gating output.
4. **Christian (E2E + expected results)** — runs against the *checked-in* reference sample;
   run twice with identical fixed scan_id and created_at, then compare outputs.
5. **Aliyan (provisional static viewer)** — runs against the checked-in reference sample;
   first checkpoint to assess fit for the Phase 4 dashboard.
6. **Supporting Bandit (Nick/Christian)** — runs in parallel, **non-gating**: rule config +
   docs (T-SA-02), harness + pairs + table (T-SA-03).
Nothing waits on a finished CLI; the reference sample is the single shared artifact the
later three roles depend on.

## Blockers (as of Oct 2, HEAD `6323285`)
- **No reference `report.json` / `examples/fixtures/` in the tree.** This is the single
  gating prerequisite for Christian's byte-assertion and Aliyan's viewer. Must be produced
  by Vale (W1-DE-03.R). Without it, their "first checkpoints" are static-only.
- `tests/test_harness.py` does not run correctly: wrong examples path (exits before
  scanning); the `-ll` flag (a *valid* Bandit severity filter that omits low-severity
  findings); and the pickle pair expects B704 (must be B301).
- Dashboard, AI layer, and Docker not started (T-DE-04 / T-DE-03 AI-layer item / T-DE-05).
- Mode B serializer missing (required for the 6.0 report).
- `httpx` undeclared in any manifest (not needed for the core path).
- **Historical** (not re-run this session): `tests/test_nvd_integration.py` previously
  failing.

## Handoffs (beginner-friendly, one manageable assignment each)
Active this week (M-DE-CORE core deliverable):
- **Vale (M-DE-CORE loader/serializer/integration):** `HANDOFF_VALE_MDECORE.md`.
- **Nick (M-DE-CORE fixtures):** `HANDOFF_NICK_MDECORE.md`.
- **Christian (M-DE-CORE E2E + expected results):** `HANDOFF_CHRISTIAN_MDECORE.md`.
- **Aliyan (M-DE-CORE T-DE-04 viewer, provisional):** `HANDOFF_ALIYAN_MDECORE.md`.

Supporting (Bandit source-audit sub-track, **parked / non-gating this week** — NOT the December deliverable; preserved, ownership unchanged):
- Nick (T-SA-02, rule config + docs) and Christian (T-SA-03, harness + pairs + table): no
  active handoff files this week. Task descriptions are in `TASKS.md` (T-SA-02 / T-SA-03) and
  the shared contract in `examples/source-audit-week1/RECON-DG_MONTH1_ROADMAP.md`.

Beginners: start at `docs/TEAM_ONBOARDING.md` for OS-specific setup, then the handoff
matching your task ID.

## Shared contract (checkpoint C0 — everyone signs before parallel work)
- Output contract = existing v0.1 JSON. **All emitted fields are spec-defined; no out-of-spec
  field is emitted this week** (v0.1 has no risk-path field — `top_risk_path` is deferred
  to a separate schema decision).
- `input.type = file`, `input.format = "synthetic-graph"` (a free string the spec lists
  as valid; `file` is a spec-supported type because the known-topology input is a JSON
  file).
- `vulnerability_lookup` = `{status, total_packages, checked_package_ids, matched}`.
  `matched` = distinct package IDs with at least one finding. `advisory_source` is **not**
  in the lookup — it is set on each finding instead (`synthetic-fixture`).
- `findings[].id` (required) and `findings[].advisory_source` are present;
  `findings[].severity` is `null` (unspecified; v0.1 defines no severity values yet) and
  does not affect the score. No level labels this week.
- `calculate_phei` returns **only the scalar maximum-path score** (6.0 here); its numeric
  behavior, 10.0 cap, and topology guard are unchanged; no path-returning API and no
  `top_risk_path` this week; severity contributes nothing (open `w_uv`).

## Proposed goals (PROPOSED — require user approval; **unapproved** as of this review)
These are **proposal labels, not registered task IDs** in the `TASKS.md` register;
each maps to an existing registered task and stays unapproved until the user accepts it:
- **P-DE-04 → T-DE-04 (Dashboard):** spike the dashboard (Flask + D3.js vs FastAPI +
  React) on a static sample graph; deliver a click-through prototype, not production UI.
  This week's static view is a step toward this; the full Phase 4 T-DE-04 scope (REST
  endpoints, interactive graph, real-time score display, filters) is preserved and
  out of scope.
- **P-DE-05 → T-DE-05 (Docker):** draft the Dockerfile + `docker-compose.yml` skeleton
  against a pinned `requirements.txt`; verify `docker compose up` builds locally.
- **P-DE-03-AI → T-DE-03 (AI-layer item):** define the agent contract (local llama.cpp
  endpoint vs user API key, grounded explanations + deterministic fallback) and write the
  prompt-design doc.

## Friday outcomes (to fill)
- T-SA-01: [ ] / [ ] scanner reports correct `rule_id` on the eval + pickle pairs.
- T-SA-02: [ ] / [ ] config + docs show only the canonical mapping (verified by the
  commands in `docs/security-checks.md` / the T-SA-02 section of `TASKS.md`).
- T-SA-03: [ ] / [ ] harness table shows TP/FP/FN/TN; 8 cases (4 rules × vulnerable/secure).
- T-DE-01/02/03 (M-DE-CORE): [ ] / [ ] `report.json` Mode B score == 6.0, method phei,
  3 findings, no path field, synthetic warnings; Mode A fields/behavior preserved and
  existing tests pass.
- T-DE-04 (M-DE-CORE): [ ] / [ ] `report.html` renders numeric score + findings, no level
  labels, data-driven (Aliyan provisional).
- T-DE-02/03 (M-DE-CORE): [ ] / [ ] E2E: 3 scenarios pass offline; run twice with
  the same fixed scan_id and created_at and compare outputs (Christian).
- Unresolved: [ ] dashboard stack decision · [ ] AI backend decision ·
  [ ] severity-in-score (`w_uv`) decision · [ ] Bandit course-requirement confirmation ·
  [ ] reference `report.json` produced (gates Christian + Aliyan) ·
  [ ] input-fixture contract approved at C0 (gates Nick).
