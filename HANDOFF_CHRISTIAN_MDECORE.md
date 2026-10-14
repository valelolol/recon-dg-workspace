# HANDOFF — Christian: M-DE-CORE E2E tests + expected results

## Your assignment

Write an **offline, deterministic** end-to-end test that asserts the Mode B `report.json` output matches a fixed reference. This test runs without any network calls.

## What to produce

### 1. `tests/test_e2e_risk.py`

A pytest test module that:
- Loads the **checked-in** reference `examples/fixtures/sample_risk_report.json` (Vale produces this).
- Runs the pipeline: `load_known_topo_json()` → `calculate_phei()` → `generate_report()` → serialize to JSON.
- Asserts the output matches the reference sample **byte-for-byte** where `scan_id` and `created_at` are fixed (use a deterministic `scan_id` and `created_at` in the test input).
- Asserts `risk.score == 6.0`, `method == "phei"`, `risk.status == "available"`.
- Asserts **no `top_risk_path` field** is emitted (v0.1 defines none).
- Asserts `findings[].severity` is `null` for all findings.
- Asserts `warnings[]` contains the synthetic-labeled warning.
- Runs **twice** with the same fixed `scan_id`/`created_at` and compares outputs to prove determinism.

### 2. `docs/E2E_EXPECTED_RESULTS.md`

A short doc listing:
- The three test scenarios (Mode A inventory, Mode B graph, determinism check).
- Expected results for each (what assertions pass).
- Notes on what is **not** tested (no real NVD/OSV, no live API).

## Acceptance criteria

- `python -m pytest tests/test_e2e_risk.py -v` passes **offline** (no network).
- Running the test twice with the same fixed inputs produces **identical** output (byte-identity).
- The test asserts the 6.0 reference score and the absence of a path field.
- The expected-results doc is consistent with the test assertions.

## Where to start

1. `cd /home/vale/projects/recon-dg-workspace && git checkout feat/inventory-report`
2. `git switch -c christian-e2e`
3. Read `TASKS.md` §C0-prereq for the field mapping.
4. Read `docs/STATUS.md` §Verified/Proposed/Unverified for the current state.
5. Write the test against the reference sample Vale will produce (note: the reference may not exist yet — write the test to load it from `examples/fixtures/sample_risk_report.json` and note the prerequisite).
6. Commit and push.

## Prerequisites (from Vale)

- A reference `examples/fixtures/sample_risk_report.json` with `risk.score == 6.0` must exist before your test can assert byte-identity.
- Without it, you can write the test skeleton + expected-results doc and note the dependency.

## Key documents to read first

- `docs/TEAM_ONBOARDING.md` — your OS-specific setup.
- `TASKS.md` §C0-prereq — the Mode B field mapping.
- `docs/STATUS.md` — current implementation state.
- `docs/WEEKLY.md` — this week's focus.

## Notes

- The test must be **deterministic**: use fixed `scan_id` and `created_at` values.
- No `TestCase`/`TestHarness` classes (they break pytest collection). Use plain `def test_...` functions.
- The `test_harness.py` file was removed (Bandit track). Your test is the E2E test for the core track.