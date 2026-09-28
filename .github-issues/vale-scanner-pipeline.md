# GitHub Issue: Scanner Pipeline (Source-Audit + Dependency Engine)

**Assignee:** Vale
**Labels:** `implementation`, `priority-high`

> **Project scope (December deliverable):** recon-dg is a **dependency risk
> mapper** — scan a project's dependency graph, check each package for known CVEs
> (NVD + OSV), score *systemic* risk (low-severity flaws combining along critical
> paths, PHEI path-max), and display results in a dashboard with an AI backend
> explaining each finding in plain language.
>
> **Where this issue fits:** the *scanner* is the front half of the pipeline
> (scan → parse → structured findings). The source-code (Bandit) sub-track and the
> dependency/CVE engine are two separate findings streams that must NOT be mixed.
> This month's work keeps both moving toward the dependency-risk deliverable.

---

## Shared contract (do not break — single source of truth)

| Fact | Value |
|---|---|
| Rule ID field in Bandit JSON | **`test_id`** (e.g. `B307`) |
| `test_name` field | Always the literal `"blacklist"` — **NEVER** the rule. Read `test_id`. |
| Exit codes | `0` clean · `1` **findings** · `2` internal error · `3` unknown. **No rc=5.** |
| `rc >= 2` | **Error state** — report as error, NEVER "0 vulns". |
| CLI shape | `bandit -f json -t <bare_rule_id> <file>` — bare rule IDs, **no `-ll`**. |

Canonical rule → category (Bandit 1.9.4):

| Rule | Category |
|---|---|
| B307 | eval / exec unsafe code execution |
| B301 | unsafe deserialization (pickle) |
| B602 | shell command injection (subprocess `shell=True`) |
| B608 | SQL injection |
| B704 | markupsafe XSS (NOT deserialization) |

---

## Scope — what Vale owns

1. **Source-audit scanner (this month, Week 1 — fix the pipeline):**
   - One command that scans a file and writes a correct JSON report:
     `file, line, rule_id, evidence snippet, severity, confidence, fix_suggestion`.
   - Move working logic from `examples/source-audit-week1/` into the canonical
     `src/scanner/` module.
   - Keep findings **source-code-only** (do NOT mix with dependency findings).
2. **Dependency engine (feeds the December deliverable):**
   - Finish parser coverage (`package.json`, `pyproject.toml`, `go.mod`, `Cargo.toml`).
   - Wire the NVD/OSV client into the graph so real CVE data flows into PHEI scoring.
   - Produce the structured `RiskReport` that the dashboard + AI layer consume.

---

## Current state (verified by running)

| Artifact | Status |
|---|---|
| `examples/source-audit-week1/scan_demo.py` | ❌ **Crashes** — `NameError: venv_path is not defined`; also uses `-r .`, `-ll`, rc=5 |
| `examples/source-audit-week1/multi_check_wrapper.py` | ⚠️ Runs, catches the eval finding, **but** writes `rule_id="blacklist"` (reads `test_name`) and uses rc=5; char-count bug ("1474 results") |
| `src/scanner/` | ⚠️ Contains only `bandit_config.py` — no scanner code yet |
| Parser | ⚠️ `requirements.txt` only (1 of ~6 formats) |
| `src/engine/nvd_client.py` | ⚠️ Code present, not yet wired into a real project run |
| PHEI in `src/engine/risk_analyzer.py` | ✅ Path-max implemented |

---

## Step-by-step

### A. Fix the source-audit scanner
1. Fix the `NameError` in `scan_demo.py` — `venv_path` is defined inside `run_bandit_scan()`. Define it once at the top of `main()` (as `scan_demo_fixed.py` does) or pass it in.
2. Rewrite the Bandit command. Drop `-r .` and `-ll`; use:
   `[bandit, "-f", "json", "-t", check_id, str(source_path)]` (venv `bandit` path).
3. Fix exit-code semantics: `rc==1` findings, `rc==0` clean, otherwise error.
   `scan_status = "success" if rc in (0,1) else "failure"`. Stop treating rc=5 as findings.
4. **Read `test_id`, not `test_name`,** into `Finding.rule_id`.
5. Add the evidence snippet: use `line_range` to pull the 1-line code around each finding.
6. Keep `fix_suggestion` (reuse `generate_fix_suggestion`).
7. Run all checks (B307, B301, B602, B608) and aggregate into one report.
8. Move the working code into `src/scanner/` (canonical module), not just `examples/`.
9. Verify: scan the eval pair (B307 found, safe pair clean) AND the pickle pair
   (B301 found, safe pair clean). Confirm `rule_id` = `"B307"`/`"B301"`, **not** `"blacklist"`.

### B. Dependency engine (toward December)
- [ ] Complete parser formats (package.json, pyproject.toml, go.mod, Cargo.toml)
- [ ] Wire NVD/OSV into `get_cve_severity()` so the graph holds real CVE data
- [ ] Run PHEI end-to-end on a **real** project (currently code only, unverified)
- [ ] Expose the structured `RiskReport` for the dashboard + AI

---

## Deliverable — definition of done

- `python src/scanner/<scanner>.py <input> <output.json>` exits 0, writes valid JSON.
- Each finding carries: `rule_id` (B3xx/B6xx), `filename`, `line_number`, evidence
  snippet, `severity`, `confidence`, `fix_suggestion`.
- `rule_id` is a real Bandit rule (never `"blacklist"`).
- Findings are **source-code** findings; dependency findings remain a separate report shape.

**Out of scope this month:** the dashboard UI and the AI explanation layer are Phase 4/3
separate work — this issue only delivers the scan/parse/report engine they consume.
