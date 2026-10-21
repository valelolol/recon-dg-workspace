# W4: Dashboard (optional / decision-dependent) (T-DE-04)

## Goal and demo value

Interactive visualization of findings and remediation plan. The committed stdlib `src.web` dashboard (committed 83b10fb) serves as the default demo fallback. Flask+D3 is an optional enhancement — team to decide if it's needed for the demo.

## Proposed accountable owner

Christian (for team confirmation)

## Prerequisites

- W3 deliverable: `generate_report()` produces a complete `RiskReport` with real data
- `src/web/` exists with the stdlib `http.server` dashboard (committed 83b10fb) — serves as a reference for the report format
- `src/models/dependency_graph.py` has `get_nodes_list()` and `get_edges_list()` for serialization
- `tests/test_dashboard.py` (10 tests) exists — extend for Flask endpoints

## Input / Output contract

| Direction | Artifact | Format |
|-----------|----------|--------|
| Input | `RiskReport` from W3 | Structured JSON with findings, edges, PHEI score, remediation plan |
| Output | `src/dashboard/` (new directory) | Flask app with routes `/risk`, `/graph`, `/paths/<node>` |
| Output | `src/dashboard/static/graph.html` | D3.js interactive graph (local copy, no CDN) |
| Output | `src/dashboard/static/dashboard.html` | Main page with filters, trend display |
| Output | `tests/test_dashboard.py` | Extended tests for Flask endpoints |

## Deliverable (one bounded item)

`src/web/` dashboard extended with findings table, remediation plan display, and `not_run` state (red card, zero count summary). **Optional:** `src/dashboard/` with Flask routes (`/risk`, `/graph`, `/paths/<node>`), D3.js graph (local copy, no CDN), per-node path display, severity/threshold filters.

## Acceptance criteria

- [ ] `python -m src.web` starts the stdlib dashboard on `127.0.0.1:8000`
- [ ] Dashboard renders findings table + risk summary
- [ ] `python -m pytest tests/test_dashboard.py -q` passes (stdlib dashboard)
- [ ] **Optional (Flask+D3):** `python -m src.dashboard` starts Flask server on `127.0.0.1:5000`
- [ ] **Optional (Flask+D3):** GET `/graph` returns graph adjacency as JSON
- [ ] **Optional (Flask+D3):** D3.js graph renders nodes as circles, edges as arrows, color-coded by risk
- [ ] **Optional (Flask+D3):** Filters work: ecosystem, severity threshold, node criticality
- [ ] No third-party deps beyond `flask>=2.3,<3` (dev only, in `requirements-dev.txt`)

## Verification commands / evidence

```bash
cd /home/vale/projects/recon-dg-workspace
python -m pytest tests/test_dashboard.py -q
```

For live demo:
```bash
python -m src.dashboard --report <path-to-report.json> --port 5000
# Open http://127.0.0.1:5000 in browser
```

## Security / privacy controls

- Dashboard is **read-only**: it serves a report and its page; it does NOT re-run scans, edit manifests, or imply a fix was verified
- D3.js loaded from local copy (no external CDN) — no network dependency at runtime
- `--model` flag defaults to **OFF**; only `--model ON` enables AI explanations
- When `--model ON`, finding data sent to the configured endpoint is documented (see open privacy decision)
- No credentials committed in dashboard code

## Fallback

| Unavailable service | Fallback behavior |
|---------------------|-------------------|
| Flask not installed | Use the existing stdlib `src.web` dashboard (committed 83b10fb) as the default demo fallback |
| D3.js local copy missing | Use the stdlib dashboard (no D3.js dependency) |
| Report file missing | Serve empty report with "no data" message |

## Stop conditions

- If the Flask app crashes on startup (missing deps, syntax error), stop and report the error before proceeding.
- If the D3.js graph fails to render (missing nodes, invalid data), stop and report the data format issue.
- "integrations across different stories" — unclear phrase in TASKS.md; needs clarification.

## Questions / blockers

- **Team decision:** Should the demo use the existing stdlib dashboard (already committed, read-only) or the new Flask+D3 dashboard (not started)? Flask+D3 is optional — the stdlib dashboard is sufficient for the December demo.
- D3.js local copy: where to download it? (github.com/d3/d3/releases) — only needed if Flask+D3 is chosen.
- Should the dashboard include trend history (historical scans)? This is a W4+ feature.
- Should the dashboard show the remediation plan with the `not_run` state (red card, zero count summary)?

---

*Handoff v1 — 2026-10-20. Owner: Christian (for team confirmation).*
