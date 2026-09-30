# WEEKLY — September 28 – October 4, 2026

## Focus
Move the source-audit sub-track (T-SA-01/02/03) from "runs in pieces" to "measured and
correct", and unblock the December-critical core path (T-DE-02: real CVE lookups).
No completion percentages are quoted; status is per task ID.

## Intended deliverables & acceptance criteria
| Task ID | Owner | Deliverable | Acceptance criteria |
|---------|-------|-------------|---------------------|
| T-SA-01 | Vale | Scanner in `src/scanner/` — one command → valid JSON | Each finding: `rule_id` from `test_id` (never `test_name`), `filename`, `line_number`, 1-line evidence, severity, confidence, `fix_suggestion`; rc=1=findings, rc=0=clean, rc>=2=error. |
| T-SA-02 | Nick | `bandit_config.py` + `docs/security-checks.md` | Only the canonical mapping (B307 eval / B301 deser / B602 shell / B608 SQL / B704=markupsafe-XSS); every `rules` list a valid bare-rule `-t` filter; per-check expectations + limitations documented. |
| T-SA-03 | Christian | `tests/test_harness.py` + 4 example pairs + results table | Harness runs to completion (no `KeyError`, no skipped examples); 8 cases (4 rules × vulnerable/secure); table shows TP/FP/FN/TN + accuracy; `test_results.json` has per-row `status`; rc>=2 = error, never "0 vulns". |
| T-DE-02 | Vale | NVD/OSV wired into the graph | `get_cve_severity(node_key)` returns real data for a real project; `tests/test_nvd_integration.py` re-run and the **actual** result recorded (current counts are historical). |

## Blockers (as of Sep 30)
- `tests/test_nvd_integration.py` previously failing (68/79, historical — not re-run).
- `test_harness.py` does not run correctly: wrong examples path (exits before scanning); the `-ll` flag (a *valid* Bandit severity filter that omits low-severity findings); and the pickle pair expects B704 (must be B301).
- Dashboard, AI layer, and Docker not started (T-DE-04 / T-DE-03 AI-layer item / T-DE-05).

## Handoffs (beginner-friendly, one manageable assignment each)
- **Nick (T-SA-02):** `HANDOFF_NICK.md` — rule configuration + detection-limit documentation.
- **Christian (T-SA-03):** `HANDOFF_CHRISTIAN.md` — harness + example pairs + results table.

## Vale's prerequisites (teammates cannot start until these are done)
- **T-SA-01 (scanner, Vale):** emit a correct `rule_id` (from `test_id`, never `test_name`) and honor the rc=1=findings / rc≥2=error contract on the eval (B307) + pickle (B301) pairs. Per TASKS.md the current state is that `scan_demo.py` crashes (`NameError: venv_path`).
- **Shared contract:** both handoffs cite `examples/source-audit-week1/RECON-DG_MONTH1_ROADMAP.md` §"Shared contract" as the single source of truth.
- **Needs verification by Vale:** `.venv` state (Bandit 1.9.4 + pytest). Neither teammate should install anything until you confirm — both handoffs flag this as an open prerequisite.

## Proposed goals (PROPOSED — require user approval; **unapproved** as of this review)
These are **proposal labels, not registered task IDs** in the `TASKS.md` register;
each maps to an existing registered task and stays unapproved until the user accepts it:
- **P-DE-04 → T-DE-04 (Dashboard):** spike the dashboard (Flask + D3.js vs FastAPI +
  React) on a static sample graph; deliver a click-through prototype, not production UI.
- **P-DE-05 → T-DE-05 (Docker):** draft the Dockerfile + `docker-compose.yml` skeleton
  against a pinned `requirements.txt`; verify `docker compose up` builds locally.
- **P-DE-03-AI → T-DE-03 (AI-layer item):** define the agent contract (local llama.cpp
  endpoint vs user API key, grounded explanations + deterministic fallback) and write
  the prompt-design doc.

## Friday outcomes (to fill)
- T-SA-01: [ ] / [ ] scanner reports correct `rule_id` on the eval + pickle pairs.
- T-SA-02: [ ] / [ ] config + docs show only the canonical mapping (verified by the
  handoff commands in `HANDOFF_NICK.md`).
- T-SA-03: [ ] / [ ] harness table shows TP/FP/FN/TN; 4 pairs present.
- T-DE-02: [ ] / [ ] NVD/OSV end-to-end run result (actual pass/fail count).
- Unresolved: [ ] dashboard stack decision · [ ] AI backend decision.
