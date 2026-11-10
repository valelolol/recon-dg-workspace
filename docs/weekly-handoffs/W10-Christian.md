# W10 Handoff — Christian (Dashboard Validation)

## Goal and demo value

**Interim-demo scope:** The Dec 9 presentation is an interim demonstration of progress toward the larger RECON-DG project — not a declaration that the full project is complete. The December deliverable is a working prototype (scan → graph → OSV findings → systemic risk → dashboard → AI explanation → bounded fix → human approval → rescan → verified results), not a finished application.

**Demo opportunities before presentation:** Dec 4 (Fri) and Dec 7 (Mon) are scheduled as internal team demos to validate the pipeline end-to-end before the Dec 9 presentation. Dec 8 (Tue) is a rehearsal/buffer day.

**One sentence:** Extend `tests/test_dashboard.py` with ≥3 new tests for real report rendering: empty input, malformed input, and unknown-topology behavior — the dashboard validation layer for the W10 Mode B serializer output.

## Proposed accountable owner

Christian.

## Prerequisites

- `src/web/dashboard.html` serves at `/` via `python -m src.web`. CSS vars: `--bg:#0f1216`, `--card:#161b22`, `--accent:#4da3ff`, `--ok:#3fb96f`, `--warn:#ffb52a`, `--bad:#ff5e62`, `--det:#7c8b9e`.
- `src/web/osv_normalizer.py` (6,851 bytes) normalizes OSV JSON for the dashboard contract. **Not yet integrated** — no evidence of integration in committed code (published tip `11937e4a9a9ea60eeea64c510d35855e170cfe31`).
- `docs/fixtures/report-fixture-demo.json` (committed in `1ad2a7b8`) has fields: `findings[]` (id, package, version, ecosystem, severity, advisory_ids, aliases, risk_level, recommendation), `ai_explanations[]`, `risk.status/score`.
- **Schema mismatch**: `report-fixture-demo.json` uses `id`/`package`/`severity`; normalizer expects `vulnerability_id`/`package_name`/`severity_score`. **Not resolved.**
- `tests/test_dashboard.py` (13 tests) exists but covers only the stdlib dashboard, not the normalizer path.
- `severity_threshold` is a float (confirmed by `dashboard.html` line 106: `report.severity_threshold` is a float; filter is "at or above").
- TASKS.md §T-DE-04: Dashboard — **Not started** (Flask+D3 deferred; stdlib dashboard sufficient for Dec 9).
- Historical W1-DE-03.T Mode B E2E skeleton (PR #5, merged `5d1101d`, 2026-11-02): `tests/test_e2e_risk.py` (6 passed, 7 skipped) + `docs/E2E_EXPECTED_RESULTS.md`. The 7 skipped tests require `examples/fixtures/sample_risk_report.json`, `load_known_topo_json()`, and `examples/fixtures/known_topology.json` — none exist. Skips are **not** passes.

## Input / Output contract

| Direction | Artifact | Format |
|-----------|----------|--------|
| Input | `tests/test_dashboard.py` (13 tests) | Python test module |
| Output | `tests/test_dashboard.py` extended (≥16 tests) | Python test module with 3+ new tests for empty/malformed/unknown-topology |

## Deliverable (one bounded item)

`tests/test_dashboard.py` extended: ≥3 new tests for empty input, malformed input, and unknown-topology rendering. Verify `src/web/osv_normalizer.py` output against dashboard expectations; document the schema gap.

## Acceptance criteria

- [ ] `python -m pytest tests/test_dashboard.py -q` passes (all existing + new)
- [ ] Schema gap documented in `docs/STATUS.md`
- [ ] No fabricated findings in tests
- [ ] `git diff --check` clean
- [ ] One test: `python -m src.web --report <real-report.json> --port 8000` renders findings table (insertion order, no sort)

## Verification commands / evidence

```bash
# Run dashboard tests
python -m pytest tests/test_dashboard.py -q

# Expected: all tests pass (no new failures)

# Verify normalizer output against dashboard contract
python -c "from src.web.osv_normalizer import normalize; print(normalize.__doc__)"
```

## Security / privacy controls

- No fabricated findings in tests.
- Empty input → "no data" message (not a crash).
- Malformed input → graceful error (not a crash).
- Unknown-topology → `risk.status == "unavailable"` rendered as red card.
- Flask/D3 deferred; stdlib dashboard is sufficient for Dec 9.

## Fallback

| Unavailable service | Fallback behavior |
|---------------------|-------------------|
| Flask not installed | Use existing stdlib dashboard (committed `83b10fb`) |
| D3.js local copy missing | Use stdlib dashboard (no D3 dependency) |
| Report file missing | Serve empty report with "no data" message |

## Stop conditions

- If dashboard crashes on startup, stop and report error.
- If real report fails to render, stop and report traceback.

## Questions / blockers

- Demo date confirmed? Dec 9 is the presentation (interim demo of progress, not full completion); Dec 4 and Dec 7 demos are planned.
- Flask+D3 optional: team decision needed (see ROADMAP §W4).
- Schema mismatch between `report-fixture-demo.json` and normalizer: resolved or deferred?
- No Aliyan task this week — no natural task for Aliyan in dashboard validation.

---

*W10 handoff v1 — 2026-11-09. Owner: Christian (proposed). For team confirmation.*
