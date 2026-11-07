# W9 Handoff — Christian (Dashboard Validation)
# 2026-11-03 to 2026-11-09

## Goal
W10 deliverable (moved from W9): Extend `tests/test_dashboard.py` for real report rendering: empty input, malformed input, unknown-topology behavior. Verify the untracked `src/web/osv_normalizer.py` against the dashboard contract.

## Evidence
- `src/web/dashboard.html` serves at `/` via `python -m src.web`. CSS vars: `--bg:#0f1216`, `--card:#161b22`, `--accent:#4da3ff`, `--ok:#3fb96f`, `--warn:#ffb52a`, `--bad:#ff5e62`, `--det:#7c8b9e`.
- `src/web/osv_normalizer.py` (untracked, 6,851 bytes) normalizes OSV JSON for the dashboard. **Not yet integrated** — no evidence of integration in committed code.
- `docs/fixtures/report-fixture-demo.json` (committed in `1ad2a7b8`) has fields: `findings[]` (id, package, version, ecosystem, severity, advisory_ids, aliases, risk_level, recommendation), `ai_explanations[]`, `risk.status/score`.
- **Schema mismatch**: `report-fixture-demo.json` uses `id`/`package`/`severity`; normalizer expects `vulnerability_id`/`package_name`/`severity_score`. **Not resolved.**
- `tests/test_dashboard.py` (13 tests) exists but covers only the stdlib dashboard, not the normalizer path.
- **Historical W1-DE-03.T Mode B E2E skeleton (PR #5, merged `5d1101d`, 2026-11-02):** `tests/test_e2e_risk.py` (6 passed, 7 skipped) + `docs/E2E_EXPECTED_RESULTS.md`. The 7 skipped tests require `examples/fixtures/sample_risk_report.json`, `load_known_topo_json()`, and `examples/fixtures/known_topology.json` — none exist. Skips are **not** passes. The three W9 scan-JSON cases (empty input, malformed input, unknown-topology) are **pending** until present and verified. **This is the historical W1-DE-03.T skeleton only — it is NOT a completion of the current W9 handoff (offline scan-JSON → normalized-report tests) unless those specific acceptance criteria are independently verified in the repo.**
- `severity_threshold` is a float (confirmed by `dashboard.html` line 106: `report.severity_threshold` is a float; filter is "at or above").

## Deliverable by Friday
- `tests/test_dashboard.py` extended: ≥3 new tests for empty input, malformed input, unknown-topology rendering.
- Verify `src/web/osv_normalizer.py` output against dashboard expectations; document the schema gap.
- One test: `python -m src.web --report <real-report.json> --port 8000` renders findings table (insertion order, no sort).

## Acceptance
- `python -m pytest tests/test_dashboard.py -q` passes (all existing + new).
- Schema gap documented in `docs/STATUS.md`.
- No fabricated findings in tests.

## Dependencies
- Vale's W9 scan output (real report.json) is a prerequisite for the integration test.
- W10 dashboard validation tests depend on this.

## Notes
- Do NOT restore any archived W1–W8 handoff files.
- Flask/D3 is deferred; stdlib dashboard is sufficient for Dec 9.
- **Fallback:** Flask not installed → use existing stdlib dashboard (committed `83b10fb`). D3.js local copy missing → use stdlib dashboard (no D3 dependency). Report file missing → serve empty report with "no data" message.
- **Stop conditions:** If dashboard crashes on startup, stop and report error. If real report fails to render, stop and report traceback.
- **Questions/blockers:** Demo date confirmed? Flask+D3 optional: team decision needed (see W4 handoff).
