|# W8: Dashboard validation (Docker = W9) (T-DE-04)

> **For:** Christian — beginner-friendly, reusable handoff.
> **Branch:** `feat/inventory-report`
> **Workspace:** `/home/vale/projects/recon-dg-workspace`
> **Template:** `docs/weekly-handoff-template.md`
> **PR target:** `feat/inventory-report` (confirmed by `docs/TEAM_ONBOARDING.md:279`; do NOT target `main`)
> **HEAD:** `e455881`

---

## Goal and demo value

One sentence: Write offline tests for the actual scan JSON → normalized report path, including empty/malformed input and unknown-topology behavior. No Docker this week.

## Proposed accountable owner

Christian (proposed — team confirmation required)

## Prerequisites

- W8 handoff (Vale): first real `report.json` from a live scan
- `src/web/` — existing stdlib `http.server` dashboard (committed 83b10fb; `server.py` 7,892 bytes, `dashboard.html` 11,939 bytes)
- `src/web/__main__.py` — CLI entry point (`python -m src.web`)
- `src/web/server.py` — `build_server()`, `prepare_report()`, `main()` (stdlib `http.server`)
- `tests/test_dashboard.py` — existing tests (confirmed: file exists; verify count by inspection, do not assert specific number)
- Aliyan's W8 demo-validation checklist (for coordination)
- Severity threshold: inclusive ≥ (confirmed by `dashboard.html` line 106: `report.severity_threshold` is a float; filter is "at or above")

## Input / Output contract

|| Direction | Artifact | Format |
|-----------|----------|--------|
| Input | `report.json` from Vale's real scan | Structured JSON with findings, edges, PHEI score |
| Output | `src/web/` (existing stdlib dashboard) | Read-only `http.server` serving `dashboard.html` at `/` and `/report.json` |
| Output | `tests/test_dashboard.py` | Extended tests for real report rendering |
| Output | **Docker = W9** | No Dockerfile in W8 |

## Deliverable (one bounded item)

Offline tests for the actual scan JSON → normalized report path (including empty/malformed input and unknown-topology behavior). **No Docker this week.**

## Acceptance criteria

- [ ] Offline tests for the actual scan JSON → normalized report path pass (empty/malformed input and unknown-topology behavior)
- [ ] Remediation plan displays scanner-provided fixed versions verbatim
- [ ] `not_run` state renders (red card, zero count summary)
- [ ] **No Docker this week**

## Verification commands / evidence

```bash
cd /home/vale/projects/recon-dg-workspace
python -m pytest tests/test_dashboard.py -q
```

For live demo (serving the real report):

```bash
python -m src.web --report report.json --host 127.0.0.1 --port 8000 --model OFF
# Open http://127.0.0.1:8000 in browser
```

## Security / privacy controls

- Dashboard is **read-only**: serves report and page; does NOT re-run scans
- `--model` defaults to **OFF**; only `--model ON` enables AI
- No credentials committed in dashboard code
- No Docker in W8

## Fallback

|| Unavailable service | Fallback behavior |
|---------------------|-------------------|
| Flask not installed | Use existing stdlib dashboard (committed 83b10fb) |
| D3.js local copy missing | Use stdlib dashboard (no D3 dependency) |
| Report file missing | Serve empty report with "no data" message |

## Stop conditions

- If the dashboard crashes on startup (missing deps, syntax error), stop and report the error.
- If the real report fails to render, stop and report the traceback.

## Questions / blockers

- Demo date confirmed? (see weekly plan)
- Flask+D3 optional: team decision needed (see W4 handoff)

---

*Handoff v2 — 2026-10-27. Owner: Christian (proposed — team confirmation required). Corrected: Docker = W9; dashboard files verified (server.py 7,892 bytes, dashboard.html 11,939 bytes); test count not asserted without verification.*
