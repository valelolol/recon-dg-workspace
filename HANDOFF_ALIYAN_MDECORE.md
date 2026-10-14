# HANDOFF — Aliyan (provisional): M-DE-CORE static viewer spike → T-DE-04 (Flask+D3)

## Your assignment

Build a **provisional static viewer** (`src/dashboard/view.py`) that renders `report.json` as `report.html`. This is a spike toward the full Phase 4 dashboard (T-DE-04: Flask+D3). It is **not** the final dashboard.

## What to produce

### 1. `src/dashboard/view.py`

A Python script: `python src/dashboard/view.py <report.json> report.html` that:
- Reads a `report.json` (the 6.0 reference from Vale).
- Renders a static HTML page showing:
  - The risk score (numeric, **no** LOW/MED/HIGH/CRITICAL labels)
  - Packages and edges (simple list/table)
  - Findings (list with advisory_id, severity, description)
  - The synthetic warning
- Is **data-driven** (no hardcoded values — reads from the JSON).
- Uses **no framework** (pure HTML/CSS/JS, or a minimal template).

### 2. `report.html` (generated output)

The rendered HTML from the reference `sample_risk_report.json`. Must show:
- Numeric score 6.0
- No level labels (no LOW/MED/HIGH/CRITICAL)
- Data-driven rendering (not hardcoded)

## Acceptance criteria

- `python src/dashboard/view.py examples/fixtures/sample_risk_report.json report.html` produces valid HTML.
- The page renders the score, findings, and warnings from the JSON.
- **No** LOW/MED/HIGH/CRITICAL labels appear.
- No framework dependencies (no Flask, no React).
- The viewer can run against any valid `report.json` (not just the 6.0 reference).

## Where to start

1. `cd /home/vale/projects/recon-dg-workspace && git checkout feat/inventory-report`
2. `git switch -c aliyan-viewer`
3. Read `docs/STATUS.md` §Verified/Proposed/Unverified for current state.
4. Read `docs/WEEKLY.md` for this week's focus.
5. Build the viewer against Vale's reference sample.
6. Commit and push.

## Prerequisites (from Vale)

- A reference `examples/fixtures/sample_risk_report.json` must exist (Vale, W1-DE-03.R). Without it, you can only build a static viewer skeleton + a hand-authored synthetic sample (labeled synthetic).

## Key documents to read first

- `docs/TEAM_ONBOARDING.md` — your OS-specific setup.
- `TASKS.md` §C0-prereq — the Mode B field mapping (what fields your viewer must render).
- `docs/STATUS.md` — current implementation state.
- `docs/WEEKLY.md` — this week's focus and acceptance criteria.

## Notes

- This is a **provisional** spike. The full Phase 4 T-DE-04 dashboard (Flask+D3, REST endpoints, interactive graph, real-time score display) is preserved and out of scope this week.
- The `src/web/` module (uncommitted stdlib dashboard) is a separate provisional implementation.
- No framework is needed for this spike — a simple HTML template is sufficient.