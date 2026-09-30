# WEEK 1 HANDOFF — Nick & Christian
**Project:** RECON-DG source-code security audit prototype
**Repo:** https://github.com/valelolol/recon-dg-workspace
**Branch to work on:** `feat/inventory-report`
**Engine:** Bandit 1.9.4 (already installed in `.venv`) · Python 3.14.4

> **You're seeing this for the first time?** Skip straight to your section.
> The whole thing reads top-to-bottom in ~5 minutes.

---

## 1. What this project is (30 seconds)

We're building a **source-code security audit prototype**. One command takes a project directory, runs a static-analysis engine (Bandit) over the Python code, and emits a JSON report showing:
- what's vulnerable
- where (file + line)
- evidence (a code snippet)
- a suggested fix

A separate **test harness** then runs the scanner against deliberately vulnerable and safe example files and measures accuracy (true positives, false positives, false negatives).

**Two constraints that matter the whole time:**
1. **Read code only — never run the submitted application.**
2. **Source-code findings (Bandit) stay separate from dependency findings.** Don't mix them.

The pipeline is a chain of three hands:

```
vulnerable/secure examples (Christian)
        ↓  expected findings
security checks + Bandit config   (Nick)
        ↓
scanner → JSON report             (Vale / you)
        ↓
test harness measures accuracy    (Christian)
```

---

## 2. The repo layout you'll care about

```
examples/source-audit-week1/      ← your example pairs live here
    vulnerable_example.py         eval()  → should trigger B307
    safer_example.py              int()   → should be clean
    vulnerable_example_3.py       pickle  → should trigger B301
    safer_example_3.py            json    → should be clean
    scan_demo.py                  Vale's scanner (currently BROKEN)
    multi_check_wrapper.py        Vale's working multi-check scanner
tests/
    test_harness.py               Christian's harness (currently BROKEN)
src/scanner/
    bandit_config.py              Nick's check config (currently WRONG)
src/engine/
    nvd_client.py                 dependency/CVE side (NOT your work)
```

**Get started:**
```bash
git clone https://github.com/valelolol/recon-dg-workspace.git
cd recon-dg-workspace
git checkout feat/inventory-report
source .venv/bin/activate          # Bandit is already in here
bandit --version                   # should say bandit 1.9.4
```

---

## 3. ⚠️ CRITICAL — the rule mapping is inconsistent in the repo

**Read this before touching anything.** The roadmap and the existing code in the repo currently disagree with each other about which Bandit rule means what. Bandit 1.9.4's real behavior is the single source of truth — everything below was verified by running Bandit 1.9.4 directly, not by reading a doc.

### The correct rule → category map (Bandit 1.9.4, verified)

| Category | Rule ID | Typical code | Bandit severity/conf |
|---|---|---|---|
| Unsafe code execution (eval/exec) | **B307** | `eval(user_input)` | MEDIUM / HIGH |
| Unsafe deserialization (**pickle**) | **B301** | `pickle.loads(user_input)` | MEDIUM / HIGH |
| Shell command injection (subprocess `shell=True`) | **B602** | `subprocess.run(cmd, shell=True)` | HIGH / HIGH |
| SQL injection | **B608** | `"SELECT ... WHERE id = '" + input` | — |
| markupsafe XSS | **B704** | `autoescape=False` | LOW / HIGH |

**Where the repo is currently wrong:**
- The roadmap says *Deserialization → B704* and *Shell → B608*. **That's backwards.** Pickle is **B301**; shell is **B602**.
- `src/scanner/bandit_config.py` labels **both** B301 and B704 as "Unsafe Deserialization" and lists SQL/shell under B608 — the B704 entry is mislabeled (B704 is markupsafe XSS, not deserialization).
- Christian's harness expects the pickle pair to produce **B704** — Bandit 1.9.4 actually emits **B301** for pickle.

**Until we all standardize on the table above, the harness will report false negatives no matter how good the scanner is** — because expected and actual will disagree. Pick one mapping, and use it everywhere. I recommend the verified table above (pickle = **B301**).

### The correct Bandit JSON shape (verified output)

```json
{
  "errors": [],                 // non-empty only if the input can't be read
  "generated_at": "...",
  "metrics": { ... },
  "results": [
    {
      "test_id": "B307",                    // ← THE REAL RULE ID (use this!)
      "test_name": "blacklist",             // ← ALWAYS the plugin label "blacklist"
      "issue_severity": "MEDIUM",
      "issue_confidence": "HIGH",
      "line_number": 15,
      "filename": "vulnerable_example.py",
      "code": "<1-line snippet>",
      "issue_text": "Use of eval with user input..."
    }
  ]
}
```

**Two traps that bite everyone today:**
1. **`test_name` is ALWAYS `"blacklist"` — never the rule ID.** The rule ID is `test_id`. If you read `test_name` into your `rule_id` field you'll write `"rule_id": "blacklist"`. **Read `test_id`.**
2. **Exit code `1` means findings were found.** `0` = clean / no findings, `2` = internal error, `3` = unknown. (A missing input file gives `rc=0` with `errors` populated.) There is **no rc=5**. If your script treats `rc==5` as "findings," every real scan reports as failure.

### The correct command (verified)

```bash
bandit -f json -t B307 examples/source-audit-week1/vulnerable_example.py
```
- `-t` takes **bare rule IDs** (`B307`, `B301`, `B602`, `B608`) — not `B307:use-of-eval`.
- `-l` = minimum severity (valid). **`-ll` is NOT a valid flag** (Bandit rejects it).
- When scanning a single file, **don't** pass `-r .` (that scans the whole tree).

---

## 4. YOUR SECTION

Pick the one you're responsible for, skip the other.

---
### NICK — security checks
**Your job:** make the check configuration correct and document, per check, exactly what it detects and its known limitations.

**Where you start:** `src/scanner/bandit_config.py`

**Steps:**
1. **Fix the rule mapping** in `SECURITY_CHECKS` (see §3):
   - Pickle deserialization → **B301** (remove the "Unsafe Deserialization" label on B704; B704 is markupsafe **XSS** — relabel it or drop it).
   - Shell command injection → **B602** (subprocess `shell=True`).
   - SQL injection → **B608**.
2. **Fix the `rules` lists.** They currently contain strings like `"B608:sql-injection"`. Those are **not** valid Bandit `-t` filters. Use bare rule IDs only (`B307`, `B301`, `B602`, `B608`) and verify each one actually runs:
   ```bash
   bandit -f json -t B307 examples/source-audit-week1/vulnerable_example.py
   bandit -f json -t B301 examples/source-audit-week1/vulnerable_example_3.py
   ```
3. **Write detection expectations per check.** For each rule, document: the exact finding pattern expected (severity/confidence), the code that triggers it, and the false-positive/false-negative cases you've observed.
4. **Write known-limitations notes per check.** Bandit is static and has no taint/data-flow analysis, so e.g. it catches `shell=True` via the hardcoded flag but *not* dynamically assembled argument strings. Say what each check misses.

**What you deliver to Vale:** a corrected `src/scanner/bandit_config.py` where every `check_id` is a valid `-t` filter and the mapping matches the §3 table, **plus** a short written doc of detection expectations + limitations per check.

---
### CHRISTIAN — harness & results
**Your job:** make the harness actually run, complete the example pairs, and measure accuracy against the correct rule set.

**Where you start:** `tests/test_harness.py` + `examples/source-audit-week1/`

**Steps:**
1. **Fix the examples path.** `Path(__file__).parent` is `tests/`, so your `examples_dir` resolves to `tests/examples/…` (wrong — it exits with "Examples directory not found"). Change it to `Path(__file__).parent.parent / "examples" / "source-audit-week1"`.
2. **Fix the Bandit invocation.** Your `run_scanner` uses `-ll`, which Bandit **rejects** (rc=1) — and uses the bare `bandit` in PATH. Use the venv path and the valid flag:
   ```python
   [bandit, "-f", "json", "-l", str(filepath)]   # no -ll
   ```
   (Drop `check=True` or handle rc explicitly — rc=1 is findings, not an error.)
3. **Correct the expected rules to §3.** The pickle pair (`vulnerable_example_3.py`) must expect **B301**, not B704.
4. **Add the two missing example pairs** so all three roadmap categories are covered. Right now only eval (B307) and pickle (B301) exist. Add:
   - **Shell (B602):** `vulnerable_shell_example.py` (subprocess `shell=True`) + `safer_shell_example.py` (list args, `shell=False`).
   - **SQL (B608):** `vulnerable_sql_example.py` (string-built query with user input) + `safer_sql_example.py` (parameterized query).
   - **Rule of thumb:** each vulnerable file must contain *exactly* the pattern the rule flags, and each safe pair must be the documented-safe alternative. Keep them small (5–15 lines) so the evidence snippet is meaningful.
5. **Fix the TP/FP/FN counting.** `print_results_table` and `save_results` have a buggy loop (a leftover `rule` variable and `count` read from the wrong scope) — recount against the expected-vs-actual dicts directly.
6. **Run the harness** and produce the results table: each row = file / rule / expected / actual / status, plus a summary of TP / FP / FN / TN and accuracy.
7. **Document false positives & false negatives** you actually observe (this is a required deliverable, not optional).

**What you deliver to Vale:** a harness that runs to completion (no "examples not found," no invalid-flag errors), all three example pairs in place, and the measured results table with TP/FP/FN counts + a limitations note.

---
### VALE (me) — what I'm delivering, so you know where you connect
I own the scanner. By end of week I give you both:
- A working scanner: `python scan_demo.py <input> <output.json>` → JSON with correct `rule_id` (from `test_id`), `filename`, `line_number`, 1-line evidence snippet, severity, confidence, fix suggestion.
- Exit codes: 0 = clean, 1 = findings found, 2 = validation error, 3 = tool/internal error.
- Source-code findings kept separate from dependency findings.

**How we connect:** Nick's corrected rule set drives what checks my scanner runs; Christian's expected-findings (corrected to the §3 table) is what my report is scored against. If we all use the §3 table, the harness and the scanner agree.

---

## 5. End-of-week: what I need from you (handoff checklist)

**From Nick (by Friday):**
- [ ] `src/scanner/bandit_config.py` corrected (rule map + bare-rule `rules` lists).
- [ ] Per-check detection expectations + known limitations documented.

**From Christian (by Friday):**
- [ ] `tests/test_harness.py` runs end-to-end (correct path, valid flags, correct B301 for pickle).
- [ ] Three example pairs exist (B307 eval, B301 pickle, + B602 shell or B608 SQL).
- [ ] Results table with TP / FP / FN / TN counts + accuracy.
- [ ] False positives / false negatives documented.

**From both of you:**
- [ ] **Everyone using the §3 rule table** — no `test_name`→`rule_id`, no `rc==5`, no `-ll`, no B704-for-pickle.

**From me (Vale):**
- [ ] Scanner produces the correct JSON (see §4).
- [ ] One-command scan of an example project works.

---

## 6. Verification (run these, they should all pass by Friday)

```bash
source .venv/bin/activate
# 1. Bandit is installed
bandit --version
# 2. Rule mapping is right
bandit -f json -t B301 examples/source-audit-week1/vulnerable_example_3.py   # should find pickle (B301)
bandit -f json -t B307 examples/source-audit-week1/vulnerable_example.py     # should find eval  (B307)
# 3. Full test suite
python -m pytest tests/ -q            # 79 passed at time of writing
# 4. Harness runs and prints a real results table
python tests/test_harness.py
```

**Definition of done for the week:** one command scans an example and writes a correct report; every finding carries file + line + correct rule ID + evidence + fix; all three categories have a vulnerable/safe pair; the harness measures and documents accuracy; source-code findings are separate from dependency findings; limitations are written down.

**Out of scope this week:** dashboard, multi-language, LLM-generated explanations.
