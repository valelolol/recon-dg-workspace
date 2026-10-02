Source Audit Pipeline Demo — Week 1
=====================================

> **HISTORICAL / NON-OPERATIONAL — do not run this as a live pipeline.**
> These Week 1 demo files (`scan_demo.py`, `multi_check_wrapper.py`) are legacy
> prototypes kept only to show the *pipeline shape* (input → engine → findings →
> JSON report). They are **not operational** and must not be relied on or copied:
> `scan_demo.py` crashes (`NameError: venv_path` is not defined), and
> `multi_check_wrapper.py` mislabels the rule ID (`test_name` → `"blacklist"` instead of
> `test_id`) and used a nonexistent `rc=5`.
>
> **Canonical shared contract (single source of truth) — read before touching any
> scanner/config/harness code:** `RECON-DG_MONTH1_ROADMAP.md` §"Shared contract",
> restated in `README.md` / `docs/STATUS.md`:
> - Rule = JSON **`test_id`**, never `test_name`.
> - Bandit exit codes: `0`=clean, `1`=**findings**, `2`=internal error, `3`=unknown;
>   **`rc=5` does not exist**. Any `rc >= 2` is an **error state** — never "0 vulnerabilities."
> - CLI: `bandit -f json -t <bare_rule_id> <file.py>` (bare rule IDs, no severity flag).

Pipeline Overview
-----------------
This demonstration implements the source-audit pipeline for the RECON-DG
supporting sub-track (Bandit static analysis of Python source code). It is
distinct from the dependency risk mapper, which is the December deliverable
(dependency inventory → known-CVE lookup → PHEI systemic-risk scoring →
dashboard + AI explanations):

    input file → analysis engine (Bandit) → structured findings → JSON report

The pipeline demonstrates:
- Safe file inspection (read-only, no execution of submitted code)
- Input validation and symlink protection
- Static analysis via Bandit's B307 rule (use of eval/exec)
- Normalized JSON output with consistent schema
- Clear distinction between "issues found" and "scan failure"

Team Roles
----------
- **You (Scan Pipeline Developer)**: Connect input → analysis → findings → report
- **Nick (Security)**: Defines security checks (B307: eval/exec, etc.)
- **Christian (Validation/Presentation)**: Validates output format and presents results

This demo implements your role: orchestrating the pipeline flow and producing structured output.

Files
-----
- vulnerable_example.py: Code using eval() — should trigger B307 finding
- safer_example.py: Code using int() safely — should have no B307 finding
- scan_demo.py: CLI wrapper implementing the pipeline
- README.md: This file

Prerequisites
-------------
Bandit must be installed in the environment:

    pip install bandit

To verify:

    bandit --version

Running the Demo
----------------
1. Activate the virtual environment:

       source .venv/bin/activate

2. Verify Bandit is available:

       bandit --version

3. Scan the vulnerable example (should find B307):

       python scan_demo.py vulnerable_example.py vuln_report.json

4. Scan the safer example (should have no B307 finding):

       python scan_demo.py safer_example.py safe_report.json

5. Test error handling (nonexistent file):

       python scan_demo.py nonexistent.py report.json
       # Expect: error message, exit code 2

Generated Reports
-----------------
Each scan produces a JSON report in the following schema:

{
  "schema_version": "1.0",
  "input_filename": "/path/to/file.py",
  "engine_name": "bandit",
  "checks_requested": ["B307:use-of-eval"],
  "scan_status": "success",
  "findings": [
    {
      "rule_id": "B307",
      "filename": "vulnerable_example.py",
      "line_number": 7,
      "severity": "High",
      "confidence": "Medium",
      "explanation": "Use of eval with user input can lead to arbitrary code execution"
    }
  ],
  "errors": []
}

Exit Codes — Bandit (canonical contract)
----------------------------------------
- `0` — clean, no findings. A **missing file** also returns `rc=0` with `errors`
  populated — so `rc=0` alone is **not** proof of success ("clean" is composite:
  `rc=0` + valid JSON + empty `results` + empty `errors`).
- `1` — **findings found** (e.g., the B307 eval/exec finding below).
- `2` — internal error.
- `3` — unknown / unrecognized.
- **`rc=5` does not exist.** Any `rc >= 2` is an *error state* — report it as an
  error, never turn it into "0 vulnerabilities."

(These are **Bandit's** exit codes, which the legacy wrapper mirrors. The wrapper's
*internal* report-status strings (`validation_failed`, `tool_unavailable`) are a
separate, non-operational prototype detail.)

What This Demonstrates
----------------------
This is ONE static check (B307: use of eval/exec). It demonstrates:

1. Pipeline orchestration: reading input, running analysis, normalizing output
2. Input validation: checking file existence, preventing output/input conflicts
3. Structured reporting: consistent schema, deterministic output
4. Error handling: clear distinction between "no issues" and "scan failed"

This does NOT represent comprehensive vulnerability detection. Real-world usage
would integrate multiple checks (Nick's domain) and validate results (Christian's domain).
