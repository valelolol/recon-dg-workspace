Source Audit Pipeline Demo — Week 1
=====================================

Pipeline Overview
-----------------
This demonstration implements the core scan-pipeline workflow for RECON-DG:

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

Exit Codes
----------
- 0: Scan completed successfully with no findings
- 1: Tool unavailable or internal error
- 2: Input validation error (file not found, output conflicts with input)

What This Demonstrates
----------------------
This is ONE static check (B307: use of eval/exec). It demonstrates:

1. Pipeline orchestration: reading input, running analysis, normalizing output
2. Input validation: checking file existence, preventing output/input conflicts
3. Structured reporting: consistent schema, deterministic output
4. Error handling: clear distinction between "no issues" and "scan failed"
5. Exit code semantics: B307 findings produce exit code 5, not failure

This does NOT represent comprehensive vulnerability detection. Real-world usage
would integrate multiple checks (Nick's domain) and validate results (Christian's domain).
