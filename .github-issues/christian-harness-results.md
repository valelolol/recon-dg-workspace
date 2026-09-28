# GitHub Issue: Test Harness + Example Pairs + Results Table

**Assignee:** Christian
**Labels:** `testing`, `test-harness`, `priority-high`

> **Project scope:** recon-dg is a **dependency risk mapper**; the source-code
> scanner (Bandit) is a supporting sub-track. The **harness is what proves the work
> runs**: it takes a scanner's output and measures it against known-good examples.
> Without a working harness, nothing Vale or Nick build is proven.
>
> **Why this exists:** the current harness won't even run. Fix it, extend it to all
> five rules, and produce the evidence table that says "we verified this."

---

## Shared contract (do not break — single source of truth)

- Rule ID is in **`test_id`**; `test_name` is always `"blacklist"` — **assert on
  `test_id`, never `test_name`.**
- Exit codes: `0` clean · `1` findings · `>=2` error. **No rc=5.**
- CLI: `bandit -f json -t <bare_rule_id> <file>` — bare rule IDs, **no `-ll`**.

Canonical table (wins over every other doc):

| Rule | Category |
|---|---|
| B307 | eval / exec |
| B301 | unsafe-deserialization (pickle) |
| B602 | shell command injection |
| B608 | SQL injection |
| B704 | markupsafe XSS (**NOT** deserialization) |

> ⚠️ **The docs and current harness currently say shell→B608 / deser→B704 — that is
> backwards.** The table above is ground truth. Any doc or test that disagrees must be
> changed to match it.

---

## Scope — what Christian owns (nothing else)

- `tests/test_harness.py` — the harness.
- `examples/source-audit-week1/` — the example pairs.
- The results table (Month-1 README / handoff doc).
- Does **NOT** touch the scanner engine (`src/scanner/`) or the check config
  (`bandit_config.py`). Consume their output via CLI and assert on it.

---

## The three bugs in the current harness

| # | Bug | Fix |
|---|---|---|
| 1 | Points at the wrong examples directory (`tests/examples/…`) | `Path(__file__).parent.parent / "examples" / "source-audit-week1"` |
| 2 | Passes the invalid `-ll` flag to Bandit | Remove `-ll`; use `-t <rule_id>` (or `-l` if you need a severity floor) |
| 3 | Expects `B704` for the pickle example | Change to **`B301`** |

---

## Step-by-step

1. **Fix the examples path** (bug 1).
2. **Fix the Bandit invocation** (bug 2): drop `-ll`, handle `rc` correctly
   (1 = findings, 0 = clean, >=2 = error). Optionally use the venv `bandit` path
   explicitly so it doesn't depend on PATH.
3. **Correct the expected rules** (bug 3): pickle pair must expect **B301**, not B704.
4. **Add the two missing example pairs** (we only have B307 + B301):
   - **Shell (B602):**
     - `shell_vulnerable.py`: `import os; def run_cmd(x): os.system(f"ls {x}")`
     - `shell_safe.py`: `import subprocess; def run_cmd(x): subprocess.run(["ls", x])`
   - **SQL (B608):**
     - `sql_vulnerable.py`: `cur.execute(f"SELECT * FROM users WHERE id = {user_id}")`
     - `sql_safe.py`: `cur.execute("SELECT * FROM users WHERE id = ?", (user_id,))`
   - If a form doesn't fire, run `bandit -f json -t B602` (resp. `B608`) on it and
     tweak the fixture until the rule fires. The goal is a **reliable fixture**, not a
     specific code shape.
5. **Extend the harness to all five rules.** Each rule: run against its vulnerable
   example (expect a finding) and its safe example (expect none). Assert on `test_id`.
   Cover B307, B301, B602, B608, **and an unsupported rule (expect the error state)**.
6. **Fix the TP/FP/FN logic** (`print_results_table` / `save_results`): there are
   leftover/ mis-scoped variables (`rule`, `count`) in the current loops.
7. **Build the results table** (one row per rule, plus the unsupported row):
   `| Example | Rule | Expected | Got | Status |`
8. **Document false positives / false negatives** you observe.

### Results table (fill in with real output)

| Example | Rule | Expected | Got | Status |
|---|---|---|---|---|
| `vulnerable_example.py` | B307 | 1 | ? | ? |
| `safer_example.py` | B307 | 0 | ? | ? |
| `vulnerable_example_3.py` | B301 | 1+ | ? | ? |
| `safer_example_3.py` | B301 | 0 | ? | ? |
| `shell_vulnerable.py` | B602 | 1 | ? | ? |
| `shell_safe.py` | B602 | 0 | ? | ? |
| `sql_vulnerable.py` | B608 | 1 | ? | ? |
| `sql_safe.py` | B608 | 0 | ? | ? |
| `shell_vulnerable.py` | NONEXISTS | error | ? | ERROR (not 0) |

---

## Prove the three Month-1 checks and record the output

```bash
# 1. vulnerable -> finding
python -m src.scanner examples/source-audit-week1/shell_vulnerable.py
# 2. secure -> none
python -m src.scanner examples/source-audit-week1/shell_safe.py
# 3. unsupported -> error (NEVER a fake "0 vulns")
python -m src.scanner --rule NONEXISTS examples/source-audit-week1/shell_vulnerable.py
```

---

## VERIFY before you commit
```bash
python -m pytest -q     # must be GREEN, 0 failures
git diff                # harness fix + 2 example pairs + results table only
```

## DONE when
- `tests/test_harness.py` runs green and covers all five rules + the unsupported case.
- Shell (B602) + SQL (B608) pairs exist in `examples/source-audit-week1/`.
- The results table is filled and matches the pytest output.
- The three Month-1 checks are documented as passing.
- Committed to `feat/inventory-report`:
  `feat(harness): shell+SQL pairs, fix path/flag/B704, cover all 5 rules`

**Gotchas:** the three classic bugs (wrong path, invalid `-ll`, B704-for-pickle) — fix
all three. Assert on `test_id`, never `test_name`. rc=5 doesn't exist. Never turn a
scan error into "0 vulns". Don't write the scanner engine or the config.
