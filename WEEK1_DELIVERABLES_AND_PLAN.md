# Week 1 — Deliverables & Step-by-Step Plan
**Project:** RECON-DG source-code security audit prototype
**Repo:** `recon-dg-workspace` · branch `feat/inventory-report`
**Engine:** Bandit 1.9.4 (verified installed in `.venv`) · Python 3.14.4
**Last verified:** pytest **79 passed** / 2 benign warnings

> **Why this doc:** the roadmap, Nick's config, and Christian's harness each contain a
> rule-mapping error that makes them disagree with Bandit 1.9.4. Until the team agrees
> on the *one* ground-truth rule set below, the harness will report false negatives
> no matter how good the scanner is. Read §2 before touching any code.

---

## 1. The pipeline (what we're building)

```
input .py file/dir
   └─► scanner (Bandit)          Nick: which checks?
        └─► raw JSON (Bandit)     Vale: normalize into Finding schema
             └─► structured report Vale: file, line, rule, evidence, fix
                  └─► test harness   Christian: expected vs actual → TP/FP/FN
```

Three people, three deliverables:

| Partner | Owns | This week's deliverable |
|---------|------|-------------------------|
| **Vale** (you) | Scanner pipeline | One command that scans an example and writes a correct JSON report (file, line, rule ID, evidence, fix). Works against the three rules. |
| **Nick** | Security checks | Correct check configuration + per-check detection expectations + known-limitations notes. |
| **Christian** | Harness & results | Working harness + complete vulnerable/secure example pairs + measured results table. |

---

## 2. Bandit 1.9.4 ground truth (single source of truth)

**Everything downstream must match this. The roadmap's rule table is wrong.**

### 2.1 JSON shape (verified output)
```json
{
  "errors": [],                       // populated if input can't be read
  "generated_at": "...",
  "metrics": { ... },
  "results": [ { "test_id", "test_name", ... } ]
}
```
**Per-result keys (verified):** `code, col_offset, end_col_offset, filename,
issue_confidence, issue_cwe, issue_severity, issue_text, line_number,
line_range, more_info, test_id, test_name`.

> ⚠️ **`test_name` is ALWAYS the plugin label `"blacklist"` — never the rule ID.**
> The real rule ID is `test_id`. Every current script reads `test_name` into `rule_id`,
> so it writes `"rule_id": "blacklist"`. **Fix: read `test_id`.**

### 2.2 Exit codes (verified)
| rc | Meaning |
|----|---------|
| 0 | Clean / no findings (also: missing file → rc=0 with `errors` populated) |
| 1 | **Findings found** |
| 2 | Internal error |
| 3 | Unknown |

> ⚠️ Current scripts treat `rc == 5` as "findings" — Bandit has **no rc=5**.
> This makes every real scan report as `"failure"`. **Fix: `rc == 1` = findings.**

### 2.3 Correct rule → category mapping (roadmap table is wrong)
| Category | Correct rule | Notes |
|----------|-------------|-------|
| eval / exec unsafe code execution | **B307** | MEDIUM / HIGH |
| **pickle** unsafe deserialization | **B301** | MEDIUM / HIGH |
| **shell** command injection (subprocess `shell=True`) | **B602** | HIGH / HIGH |
| SQL injection | **B608** | — |
| markupsafe XSS | B704 | *Not* deserialization |

> ⚠️ The roadmap says *SQL → B608, Shell → B608, Deserialization → B704*.
> The **real** 1.9.4 mapping is the table above. Nick's `bandit_config.py` and
> Christian's harness both label pickle as B704 — Bandit 1.9.4 emits **B301** for pickle.
> **Decision needed:** standardize on B301 (pickle), or deliberately add a B704
> (markupsafe) pair if the team wants to cover that rule. Until fixed, the pickle pair
> will always be a false negative.

### 2.4 CLI that works (verified)
```bash
.venv/bin/bandit -f json -t B307 examples/source-audit-week1/vulnerable_example.py
```
- `-t` takes **bare rule IDs** (`B307`, `B301`, `B602`, `B608`) — not `B307:use-of-eval`.
- `-l` = min severity (valid). **`-ll` is INVALID (rc=1)** — Christian's harness uses it.
- Do **NOT** use `-r .` when scanning a specific file; it scans the whole tree.

---

## 3. Current state — what's done vs broken (verified by running)

| Artifact | Partner | Status |
|----------|---------|--------|
| Bandit install | Vale | ✅ Done (1.9.4 in `.venv`) |
| `multi_check_wrapper.py` | Vale | ⚠️ Runs all 3 checks & catches the eval finding, **but** writes `rule_id="blacklist"` (reads `test_name`) and uses rc=5 |
| `scan_demo.py` | Vale | ❌ **Crashes** — `NameError: name 'venv_path' is not defined` (line ~239). Also uses `-r .` + rc=5 + `-ll`-style errors |
| `scan_demo_fixed.py` | Vale | ❌ Doesn't crash but produces a `"failure"` report with 0 findings (bad Bandit args + rc=5) |
| `bandit_config.py` | Nick | ⚠️ Rule IDs present but B704 mislabeled as deserialization; `rules` strings use `B608:sql-injection` format (not valid `-t` values) |
| `test_harness.py` | Christian | ❌ Won't run: wrong examples path + uses invalid `-ll` + expects B704 for pickle (should be B301) |
| Example pairs | Christian | ⚠️ Only 2 pairs (B307 eval, B301 pickle). **Missing shell (B602) & SQL (B608) pairs** needed to cover all 3 roadmap categories |
| `src/scanner/` (canonical module) | Team | ⚠️ Contains only `bandit_config.py` — no scanner code yet (the working wrapper lives in `examples/`) |

---

## 4. Step-by-step — Vale (scanner pipeline)

**Goal:** one command `python scan_demo.py <input> <output.json>` that writes a correct
report against B307 / B301 / B602 / B608, plus move the working logic into `src/scanner/`.

1. **Fix the `NameError` in `scan_demo.py`.** `venv_path` is only defined inside
   `run_bandit_scan()`. Define it once at the top of `main()` (as `scan_demo_fixed.py` does) or pass it in.
2. **Rewrite the Bandit command.** Drop `-r .` and `-ll`; use:
   `[bandit, "-f", "json", "-t", check_id, str(source_path)]`.
3. **Fix exit-code semantics.** Treat `rc == 1` as findings, `rc == 0` as clean,
   otherwise as error. Set `scan_status = "success" if rc in (0,1) else "failure"`.
   Stop treating rc=5 as a finding condition.
4. **Read `test_id`, not `test_name`,** into `Finding.rule_id`. (Both `test_name` and
   `test_id` exist; only `test_id` is the rule ID.)
5. **Add evidence snippet.** Use the finding's `line_range` to pull the 1-line code
   around each finding (roadmap requirement: "1-line code snippet around each finding").
6. **Keep fix suggestions** (already present in `multi_check_wrapper.py` — reuse `generate_fix_suggestion`).
7. **Run all four checks** (B307, B301, B602, B608) and aggregate findings into one report.
8. **Move the working code into `src/scanner/`** (the canonical module) rather than
   leaving it only in `examples/`.
9. **Verify:** scan the eval pair (B307 found, safe pair clean) AND the pickle pair
   (B301 found, safe pair clean). Confirm `rule_id` = `"B307"`/`"B301"`, not `"blacklist"`.

**Deliverable definition-of-done:**
- `python src/scanner/<scanner>.py <input> <output.json>` exits 0 and writes valid JSON.
- Each finding has: `rule_id` (B3xx/B6xx), `filename`, `line_number`, evidence snippet,
  `severity`, `confidence`, `fix_suggestion`.
- Findings are **source-code** findings; dependency findings remain separate (roadmap constraint).

---

## 5. Step-by-step — Nick (security checks)

**Goal:** a correct, testable check configuration + detection expectations.

1. **Fix the rule mapping** in `src/scanner/bandit_config.py`:
   - pickle deserialization → **B301** (not B704)
   - shell command injection → **B602** (subprocess `shell=True`)
   - SQL injection → **B608**
   - B704 → relabel as **markupsafe XSS**, or remove from the pickle category.
2. **Correct the `rules` lists.** They currently use `B307:python-unsafe-eval` format,
   which is **not** a valid Bandit `-t` filter. Use bare rule IDs (B307, B301, B602, B608)
   — verify each against `bandit -f json -t <rule> <file>`.
3. **Write detection expectations per check:** for each rule, the exact finding pattern
   expected (severity/confidence), the code that triggers it, and the false-positive /
   false-negative cases you've observed.
4. **Write known-limitations notes** per check (what Bandit misses — e.g., no taint/data-
   flow, so `shell=True` only caught via the hardcoded flag, not dynamic argument assembly).

**Deliverable definition-of-done:** a config where every `check_id` is a valid `-t`
filter, the rule→category mapping matches §2.3, and each check has documented detection
expectations + limitations.

---

## 6. Step-by-step — Christian (harness & results)

**Goal:** a harness that actually runs and a measured results table.

1. **Fix the examples path.** `examples_dir = current_dir / "examples" / "source-audit-week1"`
   resolves to `tests/examples/…` (wrong). Change `current_dir` to `Path(__file__).parent.parent`.
2. **Fix the Bandit invocation.** Replace the invalid `-ll` with `-l` (or omit). Drop
   `check=True` or handle rc properly. Use the same clean command as Vale (§4 step 2).
   Optionally use the venv `bandit` path explicitly so it doesn't depend on PATH.
3. **Correct expected rules to match §2.3.** The pickle pair must expect **B301**, not B704.
4. **Add the missing example pairs** (roadmap needs 3 categories):
   - **Shell (B602):** `vulnerable_shell_example.py` (subprocess `shell=True`) /
     `safer_shell_example.py` (list args, `shell=False`).
   - **SQL (B608):** `vulnerable_sql_example.py` (string-built query w/ user input) /
     `safer_sql_example.py` (parameterized query).
5. **Fix the TP/FP/FN logic** in `print_results_table` / `save_results` (currently buggy:
   leftover `rule` variable, `count` read from the wrong loop).
6. **Run the harness** and produce the table: each row = file / rule / expected / actual /
   status, plus summary TP / FP / FN / TN and accuracy.
7. **Document false positives & false negatives** you observe (roadmap requirement).

**Deliverable definition-of-done:** harness runs to completion (no `examples not found`,
no invalid-flag errors), all 3 categories have a matching pair, and the results table
shows correct detections with TP/FP/FN counts and a limitations note.

---

## 7. Cross-cutting items the team must resolve

| # | Item | Why it matters |
|---|------|----------------|
| 1 | **Rule-mapping disagreement** (B704 vs B301 for pickle; B608 vs B602 for shell) | Harness compares expected vs actual. If Nick's config, the examples, and the scanner disagree, the harness reports false negatives even with a perfect scanner. |
| 2 | **Example coverage** — only 2 pairs exist | The 3 roadmap categories need 3 pairs; SQL (B608) and shell (B602) pairs are missing. |
| 3 | **`src/scanner/` is a stub** | The working wrapper lives in `examples/`. Week 2 (structured reporting) needs the code in the canonical module. |
| 4 | **Separation of concerns** | Source-code findings (Bandit) must stay separate from dependency findings (inventory/NVD). Keep two report shapes. |

---

## 8. Week 1 Definition of Done (success criteria)

- ✅ One command scans an example project and writes a correct JSON report.
- ✅ Each finding carries: file, line, **correct** rule ID, evidence snippet, fix suggestion.
- ✅ All 3 categories (B307, B301, B602 or B608, B608) have a vulnerable/secure pair.
- ✅ Harness runs and reports TP/FP/FN against a shared rule set.
- ✅ False positives/negatives + limitations documented.
- ✅ Source-code findings ≠ dependency findings.

**Out of scope this week:** dashboard, multi-language, LLM explanations (Phase 2+).
