# HANDOFF — Christian (test harness + example pairs + results table)

**Task:** T-SA-03 · **Repo:** `valelolol/recon-dg-workspace` · **Branch:** `feat/inventory-report` (already pushed — pull first)

## 1. What you're doing and why it matters

recon-dg is a **dependency risk mapper** (December: graph → CVE check → PHEI risk score → dashboard + AI). Your source-audit **harness** is a *supporting sub-track*: it must **measure the scanner honestly** — and it currently doesn't, because it skips the examples, swallows findings, and mislabels rules. Your job is to make it report what it actually did, and to add the example pairs it needs to be testable.

**Shared contract (source of truth):**
- **Rule = JSON `test_id`.** The `test_id` field carries the rule ID (e.g. `B608`). `test_name`'s value **varies** by rule/version — **never** read the rule from it.
- **Exit codes — `rc=5` does not exist:** `0` = no findings · `1` = findings · `2` = internal error · `3` = unknown. `rc ≥ 2` is an **error state** — never "0 vulns." `rc=1` is a *normal* run that found something; it is **not** an error.
- **A "clean" scan is a composite condition.** A case is clean **only when all of these hold together:** the process succeeded (rc in {0, 1}), the output is valid JSON, `results == []`, and `errors == []`. Anything else is an **error** — in particular a missing file (Bandit returns `rc=0` but with `errors` populated), malformed JSON, or any `rc ≥ 2`. An error is **not** clean, **not** a finding, and must **never** be scored as TN or FN.
- **CLI shape for a single rule check:** `bandit -f json -t B602 /path/to/file.py`. We **drop `-ll`** from the harness. **`-ll` is a valid Bandit flag** — it just filters to **medium-or-higher** severity. We drop it so **low-severity findings are not silently omitted.**

## 2. Files you own and prerequisites

**You can start now, independently.** You own (strictly): `tests/test_harness.py`, the **example pair** files in `examples/source-audit-week1/`, and the results table/JSON (`test_results.json`). You do **not** touch Nick's config/docs or Vale's scanner engine.

You do **not** need Vale's T‑SA‑01 work to begin. Vale's scanner wrapper is only required for the **final integration** (wiring this harness into the real scanner). For this task you verify Bandit directly via its CLI — that is all the harness needs to be correct and testable today.

Prerequisites:
- A Python venv with pytest and Bandit. **Needs Vale verification:** I have not confirmed `.venv` — ask before installing.
- The shared contract in `examples/source-audit-week1/RECON-DG_MONTH1_ROADMAP.md`.

Jargon: *harness* = a fixed script that runs the scanner against known examples and scores the outcome; *example pair* = a vulnerable file + a safer version that should scan clean (your ground truth); *TP/FP/FN/TN* = true/false positive/negative.

## 3. First checkpoint to send Vale

**Do not presume the pytest result.** Run it and send the *actual* outcome — pass, fail, or "collected 0 tests" — plus the output that shows which. The file may already be passing if it is ahead of this handoff, or more broken than expected; either way, report exactly what you see.

The commands below are **Linux examples**. If you are on Windows (or unsure of your OS/env), tell me for equivalents (shortly: `dir` for `ls`; `.venv\Scripts\python` for `.venv/bin/python`).

```bash
# Linux
ls examples/source-audit-week1/
.venv/bin/python -m pytest tests/test_harness.py -q -s
```
```bash
# Windows
dir examples\source-audit-week1
.venv\Scripts\python -m pytest tests\test_harness.py -q -s
```

Send: the directory listing, and the full pytest output with a one-line summary of what happened (passed / failed / 0 collected).

## 4. Steps (with expected outcomes)

**Before editing, locate these by symbol (not line number) in the current `tests/test_harness.py`:** the examples-path definition, the `run_scanner` function, and the `_calculate_status` function.

1. **Fix the examples path.** Locate the examples-path definition (currently points at `tests/examples/source-audit-week1/`, which does not exist); change it to the repo-root `examples/source-audit-week1/`. Expected: no "Examples directory not found" error.
2. **Fix `run_scanner`.**
   - Drop the `-ll` flag (valid flag, but it filters to medium+ severity → it would omit low-severity findings; we want every finding).
   - Drop `check=True` (it turns `rc=1` — "findings found" — into a raised exception, so every vulnerable example is currently counted clean).
   - Read the rule from `test_id`, never `test_name`.
   - Report execution failures as `error`: `rc ≥ 2`, a missing file (populated `errors`), malformed JSON, **or** an unsupported rule id (e.g. `B999`). An unsupported rule is **not** a finding and not a clean pass.
   - Apply the strict clean definition (§1): clean = rc in {0,1} + valid JSON + `results==[]` + `errors==[]`.
   - Expected: a vulnerable file returns `{rule_id: count}` keyed by the correct `test_id`; any execution failure raises/records as an error, never "clean."
3. **Write the `status` key** into each result and call `_calculate_status()` (currently defined but never invoked). Expected: the results table prints with no `KeyError`.
4. **Fix the pickle pair's expected rule:** B704 → B301 (B704 is markupsafe XSS, **not** deserialization; the pickle examples expect `{"B301": 1}` / `{"B301": 0}`). Expected: example 3 matches B301.
5. **Create the missing pairs** in `examples/source-audit-week1/`: `vulnerable_example_shell.py` + `safer_example_shell.py` (B602) and `vulnerable_example_sql.py` + `safer_example_sql.py` (B608); register all **8 cases** (4 rules × vulnerable/secure): B307, B301, B602, B608. Expected: the harness covers all four rules, and the results table shows exactly these 8 rows.
6. **Run and verify raw.** For each rule, run Bandit directly and confirm the finding's `test_id` (and that `errors` is empty). **A finding produces a *nonzero* exit status (`rc=1`) — that is normal, not a failure.** So inspect the JSON `test_id` and `errors`, not the shell exit code.
   ```bash
   .venv/bin/bandit -f json -t B602 examples/source-audit-week1/vulnerable_example_shell.py
   #   expect: rc=1, test_id: B602, errors: []
   #   (likewise for B608 / B301 / B307)
   ```
   If a new pair doesn't fire the expected rule, make the pattern clearly unsafe — the expected rule is the contract. Expected: 4 vulnerable → correct rule; 4 secure → clean.
7. **Commit + push** (see §6), then send the results table + `test_results.json` to Nick and Vale. Expected: the table shows TP/FP/FN/TN, accuracy (over the 8 cases only), and a separate error count; JSON has per-row `status`; every execution failure is `error`, never "0 vulns."

## 5. Completion checklist

- [ ] Harness runs to completion (no KeyError, no skipped examples)
- [ ] **8 cases** registered: B307/B301/B602/B608 × (vulnerable, secure)
- [ ] Results table: TP/FP/FN/TN + accuracy (over the 8 cases, **errors excluded**), plus a separate error count
- [ ] 4 vulnerable → correct rule (TP); 4 secure → clean (TN); any execution failure → `error` (never TN/FN)
- [ ] `rc≥2`, missing file, malformed JSON, and unsupported rule all reported as `error`, never "0 vulns."
- [ ] `test_results.json` has per-row `status` for each of the 8 cases (TP/FP/FN/TN); execution errors are reported separately as `error`
- [ ] Commit pushed; PR open

## 6. Submitting (verified repo details)

Verified with `git remote -v`: remote `git@github.com:valelolol/recon-dg-workspace.git` → https://github.com/valelolol/recon-dg-workspace. Current branch: `feat/inventory-report`.

1. `git fetch origin && git checkout feat/inventory-report && git pull`
2. `git checkout -b feature/tsa03-christian-harness`
3. `git add tests/test_harness.py examples/source-audit-week1/*.py` (only your files)
4. `git commit -m "fix(harness): fix examples path; drop -ll (keep low severity); read test_id; status key; add shell+SQL pairs"`
5. `git push origin feature/tsa03-christian-harness`
6. Open a PR targeting `feat/inventory-report` from the GitHub page (or `gh pr create` if the gh CLI is authenticated), mention Nick + Vale in the description.

## 7. If blocked, send Vale

The exact error output, the command, your branch, and the file you were on. Examples: venv missing pytest/Bandit → paste `python -m pip list`; a new pair doesn't fire the expected rule → paste the raw Bandit JSON (and note its exit status — a finding is *expected* to be nonzero); unsure whether a failure is your harness or Vale's scanner → send both the raw `bandit -f json -t <rule> file.py` output and the pytest output. Don't guess which side is at fault.

---

*(Removed: the stale "line numbers L66–102 / L269–270" note. Locate `run_scanner`, `_calculate_status`, and the examples path by symbol in the current file, not by line.)*
