# HANDOFF_CHRISTIAN_MDECORE.md — Christian · M-DE-CORE harness (T-DE-03)
**Role this week:** a small test harness that checks the demo's *inputs* and *determinism*
against a **reference** `report.json` that Vale will generate. You do **not** need the scanner,
the CLI, a model, a GPU, or live network access.

> **Read once before touching anything:** your work is *testing*, and you test against a
> **reference** produced by Vale (a *future* file, not yet in the repo — see "What exists now"
> below). You do **not** need Vale's machine or any server. All setup is local.
>
> **One-time setup:** open a terminal and follow `docs/TEAM_ONBOARDING.md` until you have a
> local clone in a folder you chose, Git + Python working, and a working venv active. Use only
> the route that matches your machine. Then create your personal branch (step 0).
>
> ## Terms
> - **test harness:** a fixed program (a pytest file) that runs the demo against known inputs
>   and checks whether the output is what it should be.
> - **assertion:** a statement like `assert a == b` — if it's false, the test fails.
> - **reference (golden) file:** a known-good output produced by a trusted run, used as the
>   thing to compare against.
> - **deterministic:** same input → byte-identical output every time.

**What you own (draft now; run once the dependencies land):**
- `tests/test_e2e_risk.py` (new) — the test scaffolding + assertions.
- `docs/E2E_EXPECTED_RESULTS.md` (new) — the expected-results document (draftable today;
  it records the expected 6.0 reference and the no-path-field expectation; it is a
  *document*, not a runnable test).

**Do not change** code files, fixtures, `requirements.txt`, or the scoring formula.

## 0. Personal branch
Confirm clean + integration branch (`git status`, `git branch`) as in the Nick handoff §0
(note about a dirty tree applies here too). Then:

```bash
git switch -c feat/mdecore-christian-harness feat/inventory-report
```

## 1. What exists now — read this carefully
- **Now:** the graph model (`src/models/dependency_graph.py`), the PHEI engine
  (`src/engine/risk_analyzer.py`, function `calculate_phei`), the reporter
  (`src/reporter/report_generator.py`), and the v0.1 output spec
  (`docs/specs/scan-result-v0.1.md`) all exist.
- **Not yet (future, owned by Vale):** `src/parser/parser.py` (a loader for the two
  synthetic fixtures), `src/cli.py`, and the generated reference file
  `examples/fixtures/sample_risk_report.json`. **None of these exist yet.**
- **Therefore:** you cannot write a harness that *runs the full pipeline* today, and your
  **fixture-dependent tests cannot be green yet**, because Nick's two fixtures and Vale's
  reference do not exist yet. What you **can** do today is **draft** the test scaffolding
  (`tests/test_e2e_risk.py`) and the expected-results document (`docs/E2E_EXPECTED_RESULTS.md`),
  writing the assertions and the skip-guard for the reference now. But the **fixture-dependent
  tests (scenarios 1 and 2, which load `examples/fixtures/known_topology.json`) cannot pass
  until Nick's fixture is committed**, and the **reference-dependent test (scenario 3) cannot
  pass until Vale's reference exists**. Until both land, the harness is *drafted*, not *green*
  — do **not** report it as passing or runnable-to-green today.

## 2. The three scenarios (functional) + one determinism check (not a 4th "scenario")
Your handoff says "three functional scenarios, plus determinism as an additional check applied to
them." Here they are. **A random seed alone does not make output deterministic** — UUIDs,
timestamps, dictionary ordering, and JSON whitespace can all differ between runs. Do **not**
invent a seed env var or CLI flag to "fix" this; the codebase has no such thing today. The
determinism check below is the correct way to assert stability.

| # | Name | What it asserts | Status (today) |
|---|------|----------------|----------------|
| 1 | **Topology validity** | Nick's `known_topology.json` parses; 3 unique package ids; exactly 2 directed unit-weight edges; each edge's `source`/`target` reference a real package id; no self-loops. | **Blocked — needs Nick's fixture** (write the assertions now). |
| 2 | **PHEI score is the expected scalar** | Build the graph in-memory from the fixture; call `calculate_phei`; assert the returned value **equals 6.0** (the maximum path score) and is a scalar (a number, not a list). Do **not** assert any path field — `calculate_phei` returns **only** the scalar score per the approved contract. | **Blocked — needs Nick's fixture** (write the assertions now). |
| 3 | **Output schema** | If/when Vale's reference `report.json` lands, load it and assert it matches the v0.1 schema: `input.type == "file"`, `input.format == "synthetic-graph"`, `risk.score == 6.0`, `risk.method == "phei"`, 3 findings each with `id` + `advisory_source == "synthetic-fixture"` + `severity: null`, and **no** `top_risk_path` field. | **Blocked on Vale's reference** — write the assertions now, mark the test with a clear "skips until reference exists" guard so it doesn't run yet. |
| 4 | **Determinism (applied to scenario 2, and 3 when available)** | Run the PHEI engine twice on the same topology; assert the two returned scores are byte-identical (and equal 6.0). When scenario 3's reference exists, run the schema check twice and assert both pass identically. This is a **check**, not a fourth functional scenario. | **Blocked** — on the fixture for the scenario-2 half and on the reference for the scenario-3 half. |

## 3. Steps
1. **Scenario 1 test.** Load `examples/fixtures/known_topology.json` with the standard-library
   `json` module (no new deps). Assert the 3/2/unique/edge-reference conditions listed in the
   table. *Expected today:* the test **fails with the fixture missing** (the file does not exist
   yet); it **passes once Nick commits `known_topology.json`**.
2. **Scenario 2 test.** In a small helper (no new file), build a `DependencyGraph` from the
   fixture's packages+edges (mirror what `calculate_phei` expects), call `calculate_phei(graph)`,
   and `assert result == 6.0`. Also `assert isinstance(result, (int, float))`. *Expected today:*
   **fails with the fixture missing**; the engine itself is fine — this passes only once Nick
   commits the fixture.
3. **Scenario 3 test (blocked on reference).** Write the schema assertions from the table
   (load `examples/fixtures/sample_risk_report.json`, compare fields). Wrap it so it
   **skips** (pytest `pytest.skip`) when the file doesn't exist yet, with a comment
   "blocked: awaiting Vale's reference sample." *Expected:* skips cleanly today, passes once
   Vale's reference lands.
4. **Scenario 4 (determinism).** For scenario 2: run the engine twice; `assert run1 == run2`.
   Add the same double-run for scenario 3 (skipped until reference). *Expected:* the
   scenario-2 half **fails with the fixture missing**; it passes once Nick's fixture is present.
   The scenario-3 half skips until the reference exists.

> **Do not claim `pytest` produces `report.json`.** The harness does not run the pipeline.
> The reference `report.json` will be produced by Vale's CLI (a future file) — when it exists,
> scenario 3 *compares against* it. The harness itself never generates it.

## 4. Verification commands (what is expected today vs. after the dependencies land)
From the repo root, venv active. `python` = the venv Python (TEAM_ONBOARDING.md §7).

**Today (no fixtures, no reference in the tree):** the two fixture-dependent scenarios and the
one-liner will **not** pass because `examples/fixtures/known_topology.json` does not exist.
The reference-dependent scenario 3 **skips**. This is the expected, correct state for a
harness that is *drafted*, not *green*.

```bash
# Runs your test file. EXPECTED TODAY: scenario 3 + the ref half of 4 SKIP; scenarios 1, 2 and
# the scenario-2 half of 4 FAIL because Nick's known_topology.json does not exist yet.
# (That failure is a missing-dependency signal, not a test-authoring bug. Do not "fix" it by
# inventing the fixture — that is Nick's W1-DE-01.F.)
python -m pytest tests/test_e2e_risk.py -v

# AFTER Nick's fixture is committed: the fixture-dependent scenarios + the one-liner should
# pass / print 6.0. Then the reference-dependent parts still skip until Vale's sample lands.
```

- **Expected (pytest, today):** `SKIP` for scenario 3 and the reference-dependent half of 4
  (correct — "waiting on reference"); `FAIL` for the fixture-dependent parts (correct — Nick's
  fixture not yet committed). A `FAIL` here is **not** a failure of your test code — it is the
  missing-dependency signal the handoff expects. **Do not** present a failing harness as passing.
- **Expected (one-liner):** `6.0` — only once the fixture exists.
- **Do not** run `bandit`, the full test suite, or any live advisory service — none of it is
  in scope for this task.

## Acceptance
- `tests/test_e2e_risk.py` exists, runs, and shows the expected PASS/SKIP pattern above.
- Scenario 2 asserts a **scalar** `6.0`; it asserts **no path field** and **no severity in the
  score**.
- Scenario 3 is written and guarded to skip until Vale's reference exists (do not create a fake
  reference — a hand-authored sample may support *contract* work, but it must be labeled synthetic
  and manually authored; testing it alone is not an end-to-end pipeline test).
- Determinism is the **additional check** on scenarios 2/3, not a fourth functional scenario.

## How to submit (only when your work is ready — your action, not mine)
```bash
git diff
git add tests/test_e2e_risk.py
git commit -m "W1-DE-03: M-DE-CORE harness (3 scenarios + determinism check)"
git push origin feat/mdecore-christian-harness
```
Open a **PR targeting `feat/inventory-report`**; paste the pytest PASS/SKIP output and note that
the reference-dependent parts skip until Vale's sample exists. **No credentials or tokens in the PR.**

## If blocked, send **Vale** exactly this, under ~20 lines
1. Which scenario/test you're on + branch.
2. Exact command + full error output (copy-paste).
3. Whether it's a **fixture** problem (Nick's file) or a **reference** problem (Vale's file
   that isn't here yet) — name the missing file explicitly.
4. One sentence on what you tried. **Never** include any secret.

## How this connects
You test the pieces Vale produces. If a reference field is missing from Vale's future sample,
send that field name to Vale — don't invent it in your assertions.
