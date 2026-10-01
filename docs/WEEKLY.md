# WEEKLY — September 28 – October 4, 2026

## Focus
Move the **core** T-DE-01/02/03 path from "PHEI implemented" to "a small, demonstrable core
dependency-risk report" using clearly-labeled synthetic fixtures and **no live API calls**.
The Bandit sub-track (T-SA-01/02/03) stays **non-gating this week** (course requirement
UNKNOWN — pending confirmation). No completion percentages are quoted; status is per task ID.

## Intended deliverable & acceptance criteria (M-DE-CORE)
| Task ID | Owner | Deliverable | Acceptance criteria |
|---------|-------|-------------|---------------------|
| T-DE-01/02/03 | Vale + Nick | `report.json` (Mode A + Mode B) + reference sample | One command, no live API. Mode A: existing fields/behavior preserved and existing tests pass. Mode B: `analysis_mode: dependency_graph`, `topology_status: known`, **`risk.score: 6.0`**, `method: phei`, `risk.status: available` (spec enum `available`/`unavailable`, not `complete`), `input.format == "synthetic-graph"`, 3 synthetic findings with `id`, `advisory_source` = `synthetic-fixture`, `severity: null`, synthetic `warnings`, **no path field** (v0.1 defines none). Byte-equality asserted only where scan_id/created_at are fixed. |
| T-DE-04 | Aliyan (provisional) | `src/dashboard/view.py` → `report.html` (provisional static spike) | Renders packages/edges/numeric score/findings from `report.json`; **no LOW/MED/HIGH/CRITICAL labels**; data-driven; no framework. Full Phase 4 T-DE-04 dashboard scope (Flask+D3, endpoints, interactive graph) is preserved and out of scope this week. |
| T-DE-02/03 | Christian | `tests/test_e2e_risk.py` + `docs/E2E_EXPECTED_RESULTS.md` | 3 scenarios pass offline, deterministic, byte-identical on fixed seed; asserts the 6.0 reference. |
| T-SA-01/02/03 | — | (unchanged) | **Non-gating this week; course requirement UNKNOWN.** |

**Defer:** the older T-DE-02 goal of *real* NVD/OSV lookups is deferred this week in favor
of synthetic fixtures and no live API.

## Blockers (as of Oct 1)
- `tests/test_nvd_integration.py` previously failing (68/79, historical — not re-run).
- `test_harness.py` does not run correctly: wrong examples path (exits before scanning);
  the `-ll` flag (a *valid* Bandit severity filter that omits low-severity findings); and
  the pickle pair expects B704 (must be B301).
- Dashboard, AI layer, and Docker not started (T-DE-04 / T-DE-03 AI-layer item / T-DE-05).
- Mode B serializer missing (required for the 6.0 report).
- `httpx` undeclared in any manifest (not needed for the core path).

## Handoffs (beginner-friendly, one manageable assignment each)
- **Nick (T-SA-02, non-gating this week):** active `HANDOFF_NICK.md` (unchanged).
- **Christian (T-SA-03, non-gating this week):** active `HANDOFF_CHRISTIAN.md`
  (unchanged).
- **Nick (M-DE-CORE fixtures):** `HANDOFF_NICK_MDECORE.md`.
- **Christian (M-DE-CORE tests):** `HANDOFF_CHRISTIAN_MDECORE.md`.
- **Aliyan (M-DE-CORE T-DE-04, provisional):** `HANDOFF_ALIYAN_MDECORE.md`.
- **Vale (M-DE-CORE T-DE-01/02/03 integration):** `HANDOFF_VALE_MDECORE.md`.

## Shared contract (checkpoint C0 — everyone signs before parallel work)
- Output contract = existing v0.1 JSON. **All emitted fields are spec-defined; no out-of-spec
  field is emitted this week** (v0.1 has no risk-path field — `top_risk_path` is deferred
  to a separate schema decision).
- `input.type = file`, `input.format = "synthetic-graph"` (a free string the spec lists
  as valid; `file` is a spec-supported type because the known-topology input is a JSON
  file).
- `vulnerability_lookup` = `{status, total_packages, checked_package_ids, matched}`. `matched`
  = distinct package IDs with at least one finding. `advisory_source` is **not** in the lookup
  — it is set on each finding instead (`synthetic-fixture`).
- `findings[].id` (required) and `findings[].advisory_source` are present; `findings[].severity`
  is `null` (unspecified; v0.1 defines no severity values yet) and does not affect the score.
  No level labels this week.

## Parallel order (after checkpoint C0)
- C0 (sign the contract above) → then in parallel: Nick (fixtures) · Vale (loader →
  report integration → reference output) · Christian (tests + expected results) · Aliyan
  (provisional static viewer, early checkpoint to assess fit). Tests and the viewer run
  against the **checked-in** reference sample; nothing waits on a finished CLI.

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
  handoff commands in `HANDOFF_NICK.md`).
- T-SA-03: [ ] / [ ] harness table shows TP/FP/FN/TN; 4 pairs present.
- T-DE-01/02/03 (M-DE-CORE): [ ] / [ ] `report.json` Mode B score == 6.0, method phei,
  3 synthetic findings, no path field, synthetic warnings; Mode A fields/behavior
  preserved and existing tests pass.
- T-DE-04 (M-DE-CORE): [ ] / [ ] `report.html` renders numeric score + findings, no level
  labels, data-driven (Aliyan provisional).
- T-DE-02/03 (M-DE-CORE): [ ] / [ ] E2E: 3 scenarios pass offline, byte-identical on
  fixed seed (Christian).
- Unresolved: [ ] dashboard stack decision · [ ] AI backend decision ·
  [ ] severity-in-score (`w_uv`) decision · [ ] Bandit course-requirement confirmation.
