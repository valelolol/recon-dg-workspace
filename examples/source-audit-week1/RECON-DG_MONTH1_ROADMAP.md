# RECON-DG Month 1 — Source-Audit Sub-Track
## Source-Code Security Audit Prototype (supporting the dependency risk mapper)

> **Parent scope (December deliverable):** recon-dg is a **dependency risk mapper** —
> it scans a project's dependency graph, checks each package for known CVEs
> (NVD + OSV), scores *systemic* risk (low-severity flaws combining along critical
> paths, PHEI path-max), and displays the results in a dashboard with an AI backend
> explaining each finding in plain language.
>
> This document covers the **source-code audit sub-track** (the Bandit scanner + test
> harness). It is a supporting piece that must label findings correctly so the report's
> "fix suggestion" and "limitations" text are trustworthy. It is **not** the December
> deliverable itself.

## Objective

Build a source-code security audit prototype with a test harness:

**Scanner:** Examines Python code and reports potential security weaknesses with evidence.

**Test Harness:** Runs the scanner against deliberately vulnerable and secure examples
to measure accuracy (TP/FP/FN).

**Deliverable:** One command scans a project directory and produces a report showing:
- Vulnerabilities
- File locations
- Evidence snippets
- Suggested fixes

**Constraint:** Inspect code without running the submitted application. Keep
dependency findings **separate** from source-code findings.

---

## Team Roles

| Person | Ownership | First Deliverable |
|--------|-----------|-------------------|
| **Vale (you)** | Scanner pipeline: accept project directory, invoke analysis, collect findings, generate a consistent report | One command that scans the example project and saves results |
| **Nick** | Security checks: define vulnerability categories, select/configure the analysis engine, document checks | Correct check config + per-check detection expectations + limitations |
| **Christian** | Test harness & results: build vulnerable/secure examples, compare expected vs. actual, present results | Automated results table with correct detections, false positives, and missed vulnerabilities |

---

## Shared contract (single source of truth — read before touching code)

The scanner drives Bandit via the CLI and reads its JSON. Two things are easy to swap
and are the #1 bug source in this repo:

| Field | Meaning |
|-------|---------|
| **`test_id`** | The actual rule ID (e.g. `B602`). **This is the rule.** Read this. |
| **`test_name`** | **Not** a reliable rule ID — its value varies by rule/version (e.g. `blacklist` for B307/B301, `subprocess_popen_with_shell_equals_true` for B602, `hardcoded_sql_expressions` for B608). Never read the rule from it. |

**Bandit exit codes (rc=5 does NOT exist):**

| rc | Meaning |
|----|---------|
| 0 | Clean, no findings (also: missing file → rc=0 with `errors` populated) |
| 1 | **Findings found** |
| 2 | Internal error |
| 3 | Unknown / unrecognized |

**Any rc >= 2 = scan error → report it as an error state. Never turn it into "0 vulnerabilities."**

**CLI shape (bare rule IDs only):**

```bash
bandit -f json -t B602 /path/to/file.py
```

No severity flag is used. (`-l`/`-ll`/`-lll` *are* valid Bandit flags — they
report low / medium-or-higher / high-or-higher severity **floors**. They are
omitted here so **low-severity findings are not silently omitted**, e.g. B608 is
LOW-confidence/MEDIUM-severity and would vanish under `-ll`.)

## Canonical rule table (wins over every other doc)

| Rule | Category | What it catches |
|------|----------|-----------------|
| B307 | eval / exec | `eval()`, `exec()` |
| B301 | unsafe-deserialization | `pickle.loads` / `pickle.load` |
| B602 | shell command injection | `subprocess` calls with `shell=True` (NOT `os.system` — that is B605) |
| B608 | SQL injection | raw `cursor.execute()` string concat |
| B704 | markupsafe XSS | **(NOT deserialization!)** |

> ⚠️ Earlier drafts of this doc listed *Shell → B608* and *Deserialization → B704*.
> That was **backwards** and is wrong for Bandit 1.9.4. The table above is ground
> truth. Bandit 1.9.4 emits **B301** for pickle and **B602** for `shell=True`;
> `os.system` is **B605**, not B602.

> **Four tested rules, eight cases (T-SA-03).** The harness tests **B307, B301,
> B602 and B608** — each as a vulnerable and a secure example (4 × 2 = **8 cases**).
> **B704** (markupsafe XSS) is the fifth rule in this table but is **not** one of
> the four tested in the eight-case harness; do not describe the harness as "5 rules."

---

## Team Roles (detailed ownership)

- **Vale:** `src/scanner/`, the Bandit wrapper, and the `RiskReport` output. Owns making the scanner emit `rule_id` = the real `test_id`.
- **Nick:** `src/scanner/bandit_config.py` + `docs/security-checks.md` + `docs/limitations.md` (config only — does **not** touch the scanner engine or the harness).
- **Christian:** `tests/test_harness.py` + the example pairs + the results table.

---

## Timeline

| Week | Goal | Completion Evidence |
|------|------|---------------------|
| **Week 1** | Choose Python + Bandit, correct the 3 categories, ground-truth contract | Correct config + detection expectations + paired vulnerable/secure examples |
| **Week 2** | Connect scanner to structured reporting | One command produces findings with file, line, **correct rule ID**, and explanation |
| **Week 3** | Run the test harness and investigate incorrect results | Recorded false positives/negatives; regression cases for fixes |
| **Week 4** | Demonstrate complete audit workflow | Repeatable scan, readable report, measured results, documented limitations |

---

## End-of-Month Demonstration

The demo must show three things:

1. **Vulnerable example produces the expected finding** — Bandit detects it.
2. **Secure counterpart avoids the finding** — same pattern, safe implementation, no detection.
3. **Unsupported/failed check reports clearly** — as an error, never as "secure" or "0 vulns."

---

## Current Status (verified by running — Week 1)

### Bandit environment
- ✅ **Bandit 1.9.4** installed in `.venv` (the old "Bandit not installed" blocker is resolved).
- ✅ Python 3.14.4.

### Example pairs
- ✅ `vulnerable_example.py` (B307 eval) + `safer_example.py` — working.
- ✅ `vulnerable_example_3.py` (pickle) + `safer_example_3.py` — present.
- ⏳ **Missing:** shell pair (B602) and SQL pair (B608) — Christian to add (see his task).

### Scanner (Vale's)
- ⚠️ `multi_check_wrapper.py` runs and catches the eval finding, **but** writes
  `rule_id="blacklist"` (reads `test_name` instead of `test_id`) and uses rc=5.
- ⚠️ `scan_demo.py` **crashes** — `NameError: name 'venv_path' is not defined`.

### Check config + docs (Nick's)
- ⚠️ `bandit_config.py` / `docs/security-checks.md` still carry the **backwards**
  mapping (Shell→B608, Deser→B704). Correct to B602 / B301.

### Harness (Christian's)
- ⚠️ `tests/test_harness.py` does **not run** correctly — wrong examples path (exits
  before scanning); it also passes the *valid* `-ll` severity flag (which would
  omit low-severity findings, e.g. B608) and it expects B704 for the pickle
  example (must be B301).

---

## Workload Distribution (Month 1)

| Person | Hours | Activities |
|--------|-------|------------|
| Vale | ~26h | Bandit setup, multi-check wrapper, evidence extraction, schema normalization, dependency-engine wiring, demo prep |
| Nick | ~20h | Correct check config, document 3 categories with detection expectations, tune to reduce false positives, limitations notes |
| Christian | ~28h | Write examples (incl. B602/B608 pairs), build & fix test harness, run tests, document results, demo slides |

---

## Success Criteria (source-audit sub-track, end of Month 1)

1. ✅ **Scanner:** one command scans an example project and writes a correct JSON report.
2. ✅ **Findings:** each carries file, line, **correct** rule ID, evidence snippet, fix suggestion.
3. ✅ **Tested:** known false positives/negatives documented; harness reports TP/FP/FN.
4. ✅ **Separated:** source-code findings ≠ dependency findings.
5. ✅ **Transparent:** limitations clearly documented.

**NOT included in the source-audit month-1 demo:** the dashboard UI, multi-language
support, and the AI/LLM explanation layer. (Those belong to the **parent project's
December deliverable** — the dashboard + AI explanations are Phase 4/3, separate work.)

---

## Next Steps (Immediate)

1. **All three:** agree on the shared contract in the section above — `test_id`
   (never `test_name`), exit codes (no rc=5), and the CLI shape (bare rule IDs,
   **no** severity flag so low-severity findings are measured).
2. **Nick:** correct the config + docs mapping (B602 / B301), verify by hand.
3. **Christian:** add the B602 (shell) and B608 (SQL) pairs; fix the harness; run the 3 checks.
4. **Vale:** fix the scanner (`rule_id`, rc, evidence); move it into `src/scanner/`; then wire the dependency engine (NVD/OSV + PHEI) toward the December deliverable.

---

## Notes

- Use the existing static-analysis engine (Bandit) — don't build a parser / data-flow
  analysis from scratch.
- Evidence extraction: include a 1-line code snippet around each finding.
- Limitations document: track false positives, false negatives, tool constraints.
- Meeting demo: step-by-step scan → results → test harness → limitations.
- **This sub-track feeds the dependency risk mapper.** Its job is to prove that
  findings are scanned, labeled, and measured correctly — the discipline carries
  directly into proving the CVE pipeline and the dashboard later.
