# HANDOFF_ALIYAN_MDECORE.md — Aliyan (provisional) · T-DE-04
Static viewer spike. (M-DE-CORE week)

Goal: A self-contained static viewer (HTML, no framework) that reads `report.json`
and shows packages, edges, the numeric PHEI score, and findings. This is a
PROVISIONAL step toward the full T-DE-04 dashboard (Phase 4), NOT the full app.
The full December T-DE-04 dashboard scope (Flask/D3 or FastAPI/React, graph + risk +
per-package view) is preserved and untouched by this week's work.

## Your file (edit only this)
- `src/dashboard/view.py` (new)

## Setup (beginner-friendly)
1. `cd /home/vale/projects/recon-dg-workspace`
2. `git checkout feat/inventory-report && git pull`
3. `git switch -c feat/mdecore-aliyan-viewer feat/inventory-report`
4. `python -m venv .venv && source .venv/bin/activate`
5. No new dependencies — pure Python + standard library.
6. Re-read the contract: `docs/specs/scan-result-v0.1.md` and the M-DE-CORE field
   mapping in `TASKS.md`. You will only render fields that exist there.

## Steps
1. **(W1-DE-04.V) Create `src/dashboard/view.py`.** CLI:
   `python src/dashboard/view.py <report.json> [-o report.html]`
   It reads the JSON and writes a single self-contained `report.html` (inline CSS,
   no JS library, no Flask, no D3).
2. Render, from `report.json`, exactly: the packages (id/name/version), the edges
   (source → target), the risk (numeric score + `risk.status`), and the findings (id,
   advisory_source, advisory_id, title, description) — `findings[].severity` is `null`
   (unspecified) so render it as "unspecified"/blank, not a level. **Render only fields
   defined by the v0.1 spec; there is no path field (`top_risk_path`) in v0.1 and none
   is present in `report.json`, so render nothing for a path.**
3. **CRITICAL:** display the NUMERIC score and the existing `risk.status` ONLY.
   Do NOT render LOW/MEDIUM/HIGH/CRITICAL labels — level thresholds are a deferred
   decision and the spec has no such field.
4. Show the synthetic warnings (they tell a reader the data is a fixture and the
   score is topology-based).

## Verify
- `python src/dashboard/view.py examples/fixtures/sample_risk_report.json -o /tmp/a.html`
- Run the same command again → `/tmp/b.html`; `diff /tmp/a.html /tmp/b.html` →
  identical (fixed seed).
- Grep `report.html` for `Low:` / `Medium:` / `High:` / `Critical:` — the score is
  shown as a number (6.0) with status, not a level word.
- Open `report.html` in a browser: packages, edges, score 6.0, and findings all visible.

## Acceptance
- Renders the v0.1 fields it shows from `report.json`.
- No framework, no D3/Flask.
- No severity level labels; numeric score + status only.
- Runs on the checked-in sample and on a second sample (data-driven).

## Branch & PR
```
git add src/dashboard/view.py
git commit -m "W1-DE-04.V: provisional static viewer for M-DE-CORE"
git push origin feat/mdecore-aliyan-viewer
```
Open a PR to `feat/inventory-report`; list W1-DE-04.V, paste the two diffs proving
determinism, and note it is PROVISIONAL (the full T-DE-04 dashboard remains the
Phase 4 deliverable).

## If blocked — send Vale (or your teammate) EXACTLY this, in under ~20 lines
- The exact command + full error/output.
- Whether the field you're trying to render is missing from `report.json` (a Vale
  issue) or the HTML rendering is wrong (yours).
- If it's a fit question: say "this is more/less than I expected" and what
  specifically. (T-DE-04 ownership is provisional — Vale may absorb `view.py` if it
  isn't a fit. That is a normal decision, not a failure.)
- One sentence on what you tried.

## Connects
You render the reference `report.json` Vale emits. If a field you need isn't there,
that's a contract question for Vale — don't invent it.
