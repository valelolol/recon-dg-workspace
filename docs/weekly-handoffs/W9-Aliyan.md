# W9 Handoff — Aliyan (Demo Validation)
# 2026-11-03 to 2026-11-09

## Goal
W10 deliverable (moved from W9): Create the Dec 8 rehearsal checklist and the ≥10-step demo script for the December 9 presentation. Verify the dashboard search bar + severity filter.

## Evidence
- **No repository evidence of search bar or severity_score threshold filter in `src/web/dashboard.html` as of 2026-11-06.** The W9 plan expected this; it has not been delivered.
- `docs/fixtures/report-fixture-demo.json` (committed in `1ad2a7b8`) uses `severity` (not `severity_score`); normalizer expects `severity_score`. **Mismatch documented by Christian.**
- Dec 8 rehearsal: one place only — `docs/weekly-plan/W9-2026-11-03-to-2026-11-09.md` §Dec 8 Rehearsal.
- `docs/demo-validation/` directory does not exist yet.
- `ai_explanations` carries deterministic explanations (from `src/explanation/deterministic.py`, 5,311 bytes); `src/explanation/local_model.py` (14,362 bytes) is the optional local-model client.
- `--model ON` still requires `OPENAI_API_KEY` env var (not baked into any output).
- **Findings schema confirmed:** `severity_score` (float | null), `package_name`, `vulnerability_id`, `aliases`, `ecosystem`, `published`, `vulnerability_spec`, `fixed_versions`, plus `ai_explanations`.

## Deliverable by Friday
- `docs/demo-validation/` directory with:
  - `dec-8-rehearsal.md` (the Dec 8 rehearsal checklist, single source of truth).
  - `demo-script.md` (≤10 steps, each with expected output).
- Verify: search bar filters by package name; severity filter uses numeric threshold; `--model OFF` demonstrates deterministic fallback.
- `src/web/dashboard.html` improved: search bar + severity filter dropdown (no new Python files).

## Acceptance
- `docs/demo-validation/dec-8-rehearsal.md` exists with ≥6 checkpoints.
- `docs/demo-validation/demo-script.md` has ≤10 steps, each with expected output.
- `docs/demo-validation/` checklist ≥80% pass on the committed stdlib dashboard.
- `git diff --check` clean on dashboard edits.

## Dependencies
- Nick's parser deliverable (≥3 formats) and Vale's scan output are prerequisites for the demo script.
- Christian's dashboard validation tests are a prerequisite for the demo checklist.

## Notes
- Dec 8 rehearsal is in W9 plan only; do not duplicate in ROADMAP or TASKS.md.
- Do NOT restore any archived W1–W8 handoff files.
|- **Questions/blockers:** Should demo include live patch-and-rescan sequence or just show patch proposal? Does demo need to cover all ecosystems (npm, PyPI, Go, Rust) or just one? Is demo script for 10-minute or 30-minute slot? Should validation report be committed to `docs/demo-validation/` or kept as local artifact? **Demo AI explanation: local llama.cpp with deterministic fallback; no required API key or remote inference.** (see W5)
