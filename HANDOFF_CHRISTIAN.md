# HANDOFF — Christian (Test Harness + Example Pairs + Results Table)

**Repo:** `recon-dg-workspace` · **Branch:** `feat/inventory-report` (already pushed — pull first)
**Your ownership (strict):** `tests/test_harness.py`, the **example pair files**, and the
**results table/JSON**. You do NOT touch Nick's config/docs or Vale's scanner engine.

## The big picture (why this matters)

recon-dg is a **dependency risk mapper** (scan a project → build dependency graph → check
packages for known CVEs → score systemic risk → dashboard + AI explanations). The
**source-code audit** you're on is a *supporting sub-track*: it proves the scan → label →
measure discipline. Your job is a harness that **measures the scanner honestly** — and right
now it does not, because of several real bugs (all verified by reading the code + running
Bandit, not the docs).

## The shared contract (read first — source of truth)

- **Rule = JSON `test_id`.** `test_name` is *always* the literal string `"blacklist"`.
  It does NOT hold the rule. Never read the rule from `test_name`.
- **Exit codes — `rc=5` does NOT exist:** `0`=clean · `1`=**findings** · `2`=internal error ·
  `3`=unknown.
- **Any rc ≥ 2 = error state — report it as an error, NEVER treat it as clean/"0 vulns."**
  (rc=1 is a *successful* run that found issues — it is NOT an error.)
- **CLI shape (bare rule IDs only; no `-ll`):**
  `bandit -f json -t B602 /path/to/file.py`  (`-ll` is invalid; `-c` is `--config-file`.)

## Verified current state of `tests/test_harness.py` — the bugs

I read the whole file and ran the tools. Here is exactly what is wrong (line numbers from
the current file). **Do not trust the README/doc claims — these are the live facts:**

1. **Wrong examples path — L269–270.**
   `current_dir = Path(__file__).parent` → that's `tests/`.
   `examples_dir = current_dir / "examples" / "source-audit-week1"` → resolves to
   **`tests/examples/source-audit-week1`** — which does **not** exist. The examples live at
   the repo root: **`examples/source-audit-week1/`**.
   → The harness finds no examples and skips everything.

2. **`check=True` silently swallows findings — L69–98 (the `subprocess.run` in
   `run_scanner`).** This is the *biggest* bug. With `check=True`, any **non-zero** exit code
   raises `subprocess.CalledProcessError`. But Bandit exits **rc=1 when it finds issues**
   — which is a *success* (findings present), **not** an error. So for every vulnerable file:
   rc=1 → `CalledProcessError` → caught → `return {}` → the harness sees **0 findings**
   → **every vulnerable example becomes a FALSE NEGATIVE.**
   Fix: drop `check=True` and read `returncode` yourself (see step 2 below).

3. **Invalid `-ll` flag — L73.** `"-ll"` is not a valid Bandit flag. Bandit will error on
   it. Remove it.

4. **Reading `test_name` instead of `test_id` — L89.**
   `rule_id = issue.get("test_name", "unknown")` → `test_name` is always `"blacklist"`,
   so every finding is counted under the key `"blacklist"`, never `B307`/`B301`/B602/
   B608. Fix: `issue.get("test_id", "unknown")`.

5. **`status` key is never written — L116–122 (the `result` dict).**
   The dict gets `file`, `description`, `expected`, `actual`, `timestamp` — **no `status`.**
   But `print_results_table` does `status = result["status"]` (L182) → **`KeyError`**.

6. **`_calculate_status()` is defined but never called — L128 (def only).**
   There is no call site anywhere. It must be invoked in `run_all_tests` (L103) and its
   return stored as `result["status"]`.

7. **Wrong expected rule for example 3 — L55 and L60.**
   `vulnerable_example_3.py` (pickle deserialization) expects `{"B704": 1}` and `safer_example_3.py`
   expects `{"B704": 0}`. **Wrong.** The pickle example is **B301**, not B704. B704 is
   markupsafe XSS. Change both to `B301`.

8. **Missing shell (B602) and SQL (B608) example pairs.**
   The examples dir currently has only:
   - `vulnerable_example.py` + `safer_example.py` → B307 (eval) ✅
   - `vulnerable_example_3.py` + `safer_example_3.py` → B301 (pickle) ✅ (rule fixed in step 7)
   
   You need to **create** the two new pairs (B602 shell, B608 SQL) and register them as
   test cases.

9. **`bandit` invoked from PATH — L71.** `[ "bandit", "-f", "json", "-ll", str(filepath) ]`.
   When run under pytest in the venv, `bandit` is on PATH. To be robust and not depend on
   PATH, use the venv's python: `[sys.executable, "-m", "bandit", "-f", "json", str(filepath)]`.
   (Import `sys` — it's already there, L17.)

## Step-by-step

### Step 1 — Fix the examples path (L269–270)
```python
current_dir = Path(__file__).parent
examples_dir = current_dir / ".." / "examples" / "source-audit-week1"
# i.e. resolve to repo-root / examples/source-audit-week1/
```
Better (explicit, no `..`): `examples_dir = Path(__file__).parent.parent / "examples" / "source-audit-week1"`.
Verify it exists: after `main()`, the "Examples directory not found" error should go away.

### Step 2 — Fix `run_scanner` (L66–102): drop `-ll`, drop `check=True`, read `test_id`,
handle exit codes per the contract
```python
def run_scanner(self, filepath: Path) -> Dict[str, int]:
    """Run Bandit on a file. Returns rule_id -> count.
    rc=0 -> clean, rc=1 -> findings (SUCCESS), rc>=2 -> scan error (raise)."""
    import sys
    result = subprocess.run(
        [sys.executable, "-m", "bandit", "-f", "json", str(filepath)],
        capture_output=True, text=True, timeout=60
        # NO check=True — rc=1 is a normal "found issues" outcome
    )
    rc = result.returncode
    if rc >= 2:
        # internal error / unknown. This is an ERROR state, not a clean result.
        raise RuntimeError(f"Bandit scan error (rc={rc}) for {filepath}: "
                           f"{result.stderr}")
    # rc in (0, 1): both are valid runs (clean vs findings). Parse stdout.
    if not result.stdout.strip():
        return {}
    findings = json.loads(result.stdout)
    rule_counts: Dict[str, int] = {}
    for issue in findings.get("results", []):
        rule_id = issue.get("test_id", "unknown")   # <- test_id, NEVER test_name
        rule_counts[rule_id] = rule_counts.get(rule_id, 0) + 1
    return rule_counts
```

### Step 3 — Call `_calculate_status` and write `status` (in `run_all_tests`, L103–126)
After computing `actual_findings`:
```python
status = self._calculate_status(test_case.expected_findings, actual_findings)
result = {
    "file": test_case.filename,
    "description": test_case.description,
    "expected": {k: v for k, v in test_case.expected_findings.items()},
    "actual": actual_findings,
    "status": status,          # <- the key that was missing
    "timestamp": datetime.now().isoformat()
}
```

### Step 4 — Fix expected rules (L44–63) and register all 4 categories
The `load_test_cases` list should end up with **8 cases** (4 rules × vulnerable/secure):
```python
self.test_cases = [
    # B307 — dynamic execution (existing, correct)
    TestCase("vulnerable_example.py", {"B307": 1}, "Unsafe eval (example 1)"),
    TestCase("safer_example.py",     {"B307": 0}, "Secure (example 1)"),
    # B301 — deserialization (FIXED: was B704, must be B301)
    TestCase("vulnerable_example_3.py", {"B301": 1}, "Unsafe deserialization (example 3)"),
    TestCase("safer_example_3.py",      {"B301": 0}, "Secure (example 3)"),
    # B602 — shell command injection (NEW pair)
    TestCase("vulnerable_example_shell.py", {"B602": 1}, "Shell command injection (shell pair)"),
    TestCase("safer_example_shell.py",      {"B602": 0}, "Secure shell (shell pair)"),
    # B608 — SQL injection (NEW pair)
    TestCase("vulnerable_example_sql.py", {"B608": 1}, "SQL injection (sql pair)"),
    TestCase("safer_example_sql.py",      {"B608": 0}, "Secure SQL (sql pair)"),
]
```

### Step 5 — Create the two new example pairs
Write these into `examples/source-audit-week1/`:

**`vulnerable_example_shell.py`** (should fire **B602**):
```python
import os
import subprocess

user_input = "rm -rf /"   # attacker-controlled

# VULNERABLE — os.system with user input
os.system("ls " + user_input)

# VULNERABLE — subprocess with shell=True + f-string
subprocess.call(f"cat {user_input}", shell=True)
```

**`safer_example_shell.py`** (should fire **nothing**):
```python
import subprocess

user_input = "report.txt"

# SECURE — list args, no shell
subprocess.call(["ls", user_input], shell=False)
```

**`vulnerable_example_sql.py`** (should fire **B608**):
```python
user_input = "' OR 1=1"

# VULNERABLE — string concatenation
query = "SELECT * FROM users WHERE id = " + user_input

# VULNERABLE — f-string interpolation
query2 = f"DELETE FROM logs WHERE user = '{user_input}'"
```

**`safer_example_sql.py`** (should fire **nothing**):
```python
user_input = "42"

# SECURE — parameterized query
query = "SELECT * FROM users WHERE id = ?"
params = (user_input,)
```

### Step 6 — Run it and verify with the tool (non-negotiable)
From the repo root:
```bash
cd /home/vale/projects/recon-dg-workspace
.venv/bin/python -m pytest tests/test_harness.py -q -s   # -s for the table output
```
Then sanity-check each rule raw, to confirm the expected rule IDs are correct:
```bash
.venv/bin/bandit -f json -l -t B307 examples/source-audit-week1/vulnerable_example.py     # -> B307
.venv/bin/bandit -f json -l -t B301 examples/source-audit-week1/vulnerable_example_3.py    # -> B301
.venv/bin/bandit -f json -l -t B602 examples/source-audit-week1/vulnerable_example_shell.py # -> B602
.venv/bin/bandit -f json -l -t B608 examples/source-audit-week1/vulnerable_example_sql.py   # -> B608
```
If any new pair does NOT fire the expected rule, **adjust the example** (make the pattern
obviously unsafe) until it does — the expected rule is the contract.

**Definition of done for the harness:**
- It runs to completion (no `KeyError`, no skipped examples).
- The results table shows **TP/FP/FN/TN** and an accuracy %.
- All 4 vulnerable examples → correct rule → ✓ True Pos.
- All 4 secure examples → no finding → ✓ True Neg.
- A scan that errors (rc ≥ 2) is reported as an **error**, never as "0 vulns".
- `test_results.json` is written with the correct `status` per row.

### Step 7 — Deliverable + commit
Commit to `feat/inventory-report`:
```bash
git commit -m "feat(harness): run real examples, fix path/-ll/test_id/status, add shell+SQL pairs"
git push
```
Then hand the results table + the 4-pair results to Nick (his config/docs must agree)
and Vale (his scanner must emit the right `test_id`).

## What the three of us agree on (end state)

| Person | Owns | Done when |
|--------|------|-----------|
| Vale | scanner engine + report + NVD/OSV + B307/B301 example pairs | scanner emits correct `test_id` (not `blacklist`), rc=1=findings |
| **Nick** | `bandit_config.py` + `docs/security-checks.md` + `docs/limitations.md` | config/docs only B602=shell, B301=deser, B608=SQL (B704=markupsafe-XSS, NOT deser) |
| **Christian (you)** | `tests/test_harness.py` + example pairs + results table | harness runs, 4 rules covered (B307/B301/B602/B608), table+JSON correct, rc≥2=error |

**Acceptance gate for the source-audit sub-track (3 checks):**
1. Vulnerable example → finding (correct rule ID).
2. Secure example → nothing.
3. Unsupported/failed check → **error** (never a fake "0 vulns").
