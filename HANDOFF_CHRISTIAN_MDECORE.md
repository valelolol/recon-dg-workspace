# HANDOFF_CHRISTIAN_MDECORE.md — Christian · T-DE-02/03
Offline tests + expected results. (M-DE-CORE week)

Goal: Pin the demo's behavior as offline, deterministic tests plus an expected-results
table — the acceptance gate for the whole week.

## Your files (edit only these)
- `tests/test_e2e_risk.py` (new)
- `docs/E2E_EXPECTED_RESULTS.md` (new)

## Setup (beginner-friendly)
1. `cd /home/vale/projects/recon-dg-workspace`
2. `git checkout feat/inventory-report && git pull`
3. `git switch -c feat/mdecore-christian-tests feat/inventory-report`
4. `python -m venv .venv && source .venv/bin/activate`
5. `pip install -r requirements.txt`
6. You can start against a hand sample (a `sample_risk_report.json` Vale gives you, or
   one you write from the TASKS.md field mapping). You do NOT need the final CLI.

## Steps
1. **(W1-DE-03.T) `docs/E2E_EXPECTED_RESULTS.md`** — a table, columns:
   `Scenario | Input | Expected (offline, deterministic)`:
   - **1 Mode A inventory:** `requirements.txt` → `analysis_mode: inventory`,
     `topology_status: unavailable`, `edges: []`, risk unavailable. (Preserves existing
     behavior; no byte equality required beyond the fixed seed.)
   - **2 Mode B topology:** `examples/fixtures/known_topology.json` → `input.type: file`,
     `analysis_mode: dependency_graph`, `topology_status: known`, `risk.score == 6.0`,
     `method: phei`, `risk.status: available` (spec enum; not `complete`), **no path
     field** (v0.1 defines none).
   - **3 Mode B findings:** + `cve_fixture.json` → `vulnerability_lookup.status: complete`,
     `matched == 3` (distinct package IDs with at least one finding; one finding each
     on synth-a/b/c), each finding has `id`, `advisory_source` = `synthetic-fixture`,
     `advisory_id` `SYNTH-2026-*`, `severity: null`, description marked synthetic,
     `warnings` present.
   - **4 Determinism:** identical `scan_id`/`created_at` → byte-identical output.
2. Compute the expected PHEI by hand/script and confirm it is **6.0**: 2 edges × 1.0 =
   path weight 2.0; × 3 nodes = 6.0, on the known-topology fixture.
3. **`tests/test_e2e_risk.py`** — 3 scenarios. Use a FIXED `scan_id` and `created_at`
   (set an env var or monkeypatch the clock) so output is byte-identifiable. Disable
   network (tests must pass with no API). Assert the expected table.
   - Assert the **score**: for scenario 2,
     `report["risk"]["score"] == 6.0` **and** `report["risk"]["method"] == "phei"`.
     Assert the output contains **no path field** (`"top_risk_path" not in report`) —
     v0.1 defines no risk-path field.
4. Keep the existing test files (`test_parser.py`, `test_risk_analyzer.py`,
   `test_inventory_reporter.py`, `test_nvd_integration.py`). Do NOT touch
   `tests/test_harness.py` (it collects 0 tests and is out of scope this week).

## Verify
- `python -m pytest tests/test_e2e_risk.py -q` (all 3 scenarios pass, offline).
- Run the suite twice with the same fixed seed; diff the two `report.json` outputs —
  they must be byte-identical.
- `python -m pytest -q` (the existing suite stays green).

## Acceptance
- 3 scenarios pass offline (no network).
- Byte-identical on a fixed seed.
- The test asserts the 6.0 reference **and** that no path field is present
  (v0.1 defines none).

## Branch & PR
```
git add tests/test_e2e_risk.py docs/E2E_EXPECTED_RESULTS.md
git commit -m "W1-DE-03.T: offline E2E for M-DE-CORE (6.0, no path field) + expected results"
git push origin feat/mdecore-christian-tests
```
Open a PR to `feat/inventory-report`; list W1-DE-03.T and paste the `pytest -q` summary.

## If blocked — send Vale's teammate (or the relevant teammate) EXACTLY this, in under ~20 lines
- Which scenario (1/2/3/4) is failing.
- The exact `pytest -q` output for that scenario.
- Whether the mismatch is in the expected value (a table bug), the actual output (a
  Vale/Nick issue), or the test harness.
- One sentence on what you tried.

## Connects
Your table is the acceptance gate. If your expected value disagrees with what Vale
actually emits, stop and sync — do not change the expected table to match a bug.
