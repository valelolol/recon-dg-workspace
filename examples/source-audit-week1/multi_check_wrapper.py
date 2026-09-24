#!/usr/bin/env python3
"""
Multi-Check Scanner Wrapper — Week 1
=====================================
A comprehensive scanner implementing Bandit checks:
- B307: Use of __import__, eval(), exec(), open(), pickle
- B602: Use of subprocess with shell=True
- B301: Use of possibly insecure serialization (pickle, marshal, shelve)

Usage:
    python multi_check_wrapper.py <input_file> <output_json>

Author: Vale (RECON-DG Team)
"""

import argparse
import json
import os
import subprocess
import sys
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Optional


@dataclass
class Finding:
    """Bandit finding normalized to a consistent schema."""
    rule_id: str
    filename: str
    line_number: int
    severity: str
    confidence: str
    explanation: str
    fix_suggestion: str = ""


@dataclass
class ScanReport:
    """Structured scan report with schema version."""
    schema_version: str = "1.0"
    input_filename: str = ""
    engine_name: str = "bandit"
    checks_requested: list = None
    scan_status: str = "success"
    findings: list = None
    errors: list = None

    def __post_init__(self):
        if self.checks_requested is None:
            self.checks_requested = []
        if self.findings is None:
            self.findings = []
        if self.errors is None:
            self.errors = []

    def to_dict(self):
        """Convert to dictionary for JSON serialization."""
        return asdict(self)


def validate_input_path(path: str) -> bool:
    """Validate that input file exists and is readable."""
    path = Path(path)
    if not path.exists():
        raise ValueError(f"Input file does not exist: {path}")
    if not path.is_file():
        raise ValueError(f"Input path is not a file: {path}")
    if not path.is_absolute() and path.is_symlink():
        resolved = path.resolve()
        if not resolved.is_file():
            raise ValueError(f"Input symlink target is not a file: {path}")
    return True


def validate_output_path(output_path: str, input_path: str) -> bool:
    """Validate output path and reject conflicts with input."""
    output = Path(output_path)
    input_file = Path(input_path)

    if output.resolve() == input_file.resolve():
        raise ValueError(
            f"Output path must not be the same as input file: {input_path}"
        )

    if output.is_symlink() and output.resolve() == input_file.resolve():
        raise ValueError(
            f"Output symlink must not point to input file: {input_path}"
        )

    if input_file.resolve() in output.parents and output.is_symlink():
        raise ValueError(
            f"Output symlink cannot reference input via parent: {input_path}"
        )

    if output.exists() and not output.is_dir():
        pass  # Overwrite allowed

    return True


def run_bandit_check(source_path: str, check_id: str) -> tuple[int, subprocess.CompletedProcess]:
    """
    Run a single Bandit check.

    Args:
        source_path: Path to source file
        check_id: Bandit check ID (e.g., B307, B602, B301)

    Returns:
        tuple: (exit_code, completed_process)
    """
    venv_path = os.path.join(os.getcwd(), ".venv")
    cmd = [
        os.path.join(venv_path, "bin", "bandit"),
        "-f", "json",
        "-l",
        f"-t", check_id,
        str(source_path)
    ]

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=60
    )
    return result.returncode, result


def parse_bandit_output(output_text: str) -> list[Finding]:
    """
    Parse Bandit's JSON output and normalize to our Finding schema.
    """
    findings = []

    try:
        data = json.loads(output_text)
    except json.JSONDecodeError as e:
        raise ValueError(f"Failed to parse Bandit JSON output: {e}")

    for issue in data.get("results", []):
        # Generate fix suggestion based on the issue type
        fix_suggestion = generate_fix_suggestion(issue)

        finding = Finding(
            rule_id=issue.get("test_name", "unknown"),
            filename=issue.get("filename", "unknown"),
            line_number=issue.get("line_number", 0),
            severity=issue.get("issue_severity", "unknown"),
            confidence=issue.get("issue_confidence", "unknown"),
            explanation=issue.get("issue_text", "No explanation provided"),
            fix_suggestion=fix_suggestion
        )
        findings.append(finding)

    return findings


def generate_fix_suggestion(issue: dict) -> str:
    """
    Generate a fix suggestion based on the issue type.
    """
    test_name = issue.get("test_name", "")
    issue_text = issue.get("issue_text", "").lower()

    if "B307" in test_name or "import" in issue_text or "eval" in issue_text:
        return (
            "Replace dynamic code execution with safer alternatives:\n"
            "- Use `importlib.import_module()` instead of `__import__()`\n"
            "- Use `ast.literal_eval()` instead of `eval()` for safe expression parsing\n"
            "- Use `subprocess.run()` instead of `exec()` for code execution"
        )

    elif "B602" in test_name or "shell" in issue_text or "subprocess" in issue_text:
        return (
            "Avoid shell=True with subprocess:\n"
            "- Pass command and arguments as a list instead of a shell string\n"
            "- Use `subprocess.run(['cmd', 'arg1', 'arg2'])` instead of `shell=True`\n"
            "- Quote arguments properly if shell execution is required"
        )

    elif "B301" in test_name or "pickle" in issue_text or "deserialise" in issue_text:
        return (
            "Avoid insecure deserialization:\n"
            "- Use JSON instead of pickle for data serialization\n"
            "- Use `marshal.loads()` only for internal Python objects\n"
            "- Use `shelve.open()` with caution and validate data sources\n"
            "- Implement input validation before deserializing untrusted data"
        )

    elif "B608" in test_name or "sql" in issue_text or "injection" in issue_text:
        return (
            "Prevent SQL injection:\n"
            "- Use parameterized queries or prepared statements\n"
            "- Use ORM frameworks like SQLAlchemy with proper binding\n"
            "- Validate and sanitize all user inputs\n"
            "- Never concatenate user input into SQL queries"
        )

    elif "B704" in test_name or "xss" in issue_text or "escape" in issue_text:
        return (
            "Prevent XSS attacks:\n"
            "- Escape user input before rendering in HTML\n"
            "- Use frameworks' built-in escape functions\n"
            "- Implement Content Security Policy (CSP)\n"
            "- Use HTTPS to prevent MITM attacks"
        )

    else:
        return (
            f"Review the finding at line {issue.get('line_number', 'N/A')}.\n"
            f"Severity: {issue.get('issue_severity', 'Unknown')}\n"
            f"See: https://bandit.readthedocs.io/en/latest/plugins/{test_name.replace('_', '-').lower()}.html"
        )


def generate_report(
    source_path: str,
    output_path: str,
    findings: list[Finding],
    errors: list[str],
    exit_code: int
) -> None:
    """Generate the structured JSON report."""
    report = ScanReport(
        schema_version="1.0",
        input_filename=str(Path(source_path).resolve()),
        engine_name="bandit",
        checks_requested=["B307", "B602", "B301"],
        scan_status="success" if exit_code == 0 or exit_code == 5 else "failure",
        findings=[asdict(f) for f in findings],
        errors=errors
    )

    output_dir = Path(output_path).parent
    output_dir.mkdir(parents=True, exist_ok=True)

    report_path = Path(output_path)
    with open(report_path, "w") as f:
        json.dump(report.to_dict(), f, indent=2)

    print(f"Report written to: {report_path.resolve()}")


def scan_file(source_path: str, checks: list[str]) -> tuple[list[Finding], list[str], int]:
    """
    Run multiple Bandit checks on a file.

    Args:
        source_path: Path to source file
        checks: List of Bandit check IDs to run

    Returns:
        tuple: (findings, errors, exit_code)
    """
    all_findings = []
    all_errors = []
    exit_codes = []

    for check_id in checks:
        print(f"\nRunning check: {check_id}")
        exit_code, result = run_bandit_check(source_path, check_id)
        exit_codes.append(exit_code)

        if exit_code == 0:
            print(f"  ✓ No findings for {check_id}")
        else:
            print(f"  Found {len(result.stdout)} results")
            try:
                findings = parse_bandit_output(result.stdout)
                all_findings.extend(findings)
            except ValueError as e:
                all_errors.append(str(e))

    # Use exit code 5 if findings were found, otherwise 0
    final_exit_code = 5 if all_findings else 0

    return all_findings, all_errors, final_exit_code


def main():
    parser = argparse.ArgumentParser(
        description="Multi-Check Scanner Wrapper — Week 1",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    python multi_check_wrapper.py vulnerable_example.py report.json
    python multi_check_wrapper.py safer_example.py safe_report.json
        """
    )
    parser.add_argument(
        "input_file",
        help="Path to Python source file to analyze"
    )
    parser.add_argument(
        "output_file",
        help="Path to output JSON report"
    )
    parser.add_argument(
        "--checks",
        nargs="+",
        default=["B307", "B602", "B301"],
        help="Bandit checks to run (default: B307, B602, B301)"
    )

    args = parser.parse_args()

    # Validate inputs
    try:
        validate_input_path(args.input_file)
        validate_output_path(args.output_file, args.input_file)
    except ValueError as e:
        print(f"Input validation error: {e}", file=sys.stderr)
        report = ScanReport(
            schema_version="1.0",
            input_filename=args.input_file,
            engine_name="bandit",
            checks_requested=args.checks,
            scan_status="validation_failed",
            errors=[str(e)]
        )
        output_dir = Path(args.output_file).parent
        output_dir.mkdir(parents=True, exist_ok=True)
        report_path = Path(args.output_file)
        with open(report_path, "w") as f:
            json.dump(report.to_dict(), f, indent=2)
        print(f"Report written (validation failed): {report_path.resolve()}")
        sys.exit(2)

    # Check if Bandit is available
    try:
        venv_path = os.path.join(os.getcwd(), ".venv")
        bandit_check = subprocess.run(
            [os.path.join(venv_path, "bin", "bandit"), "--version"],
            capture_output=True,
            text=True,
            timeout=10
        )
        if bandit_check.returncode != 0:
            raise RuntimeError("bandit command not found in venv")
    except FileNotFoundError:
        print(
            "ERROR: Bandit is not installed in this environment.\n",
            "Install with: pip install bandit\n",
            file=sys.stderr
        )
        raise
    except Exception as e:
        print(f"Failed to check Bandit: {e}", file=sys.stderr)
        raise

    # Run the scan
    try:
        findings, errors, exit_code = scan_file(args.input_file, args.checks)
    except subprocess.TimeoutExpired:
        print("Scan timed out after 60 seconds", file=sys.stderr)
        errors = ["Scan timed out"]
        findings = []
    except Exception as e:
        print(f"Scan execution failed: {e}", file=sys.stderr)
        errors = [str(e)]
        findings = []
    else:
        errors = []

    # Generate report
    generate_report(args.input_file, args.output_file, findings, errors, exit_code)

    # Summary
    print(f"\n{'='*50}")
    print("Scan Summary:")
    print(f"{'='*50}")
    print(f"Total findings: {len(findings)}")
    print(f"High severity: {sum(1 for f in findings if f.severity == 'HIGH')}")
    print(f"Medium severity: {sum(1 for f in findings if f.severity == 'MEDIUM')}")
    print(f"Low severity: {sum(1 for f in findings if f.severity == 'LOW')}")
    if findings:
        print(f"\nRule IDs: {', '.join(f.rule_id for f in findings)}")
        print(f"\nFiles scanned: {len(set(f.filename for f in findings))}")


if __name__ == "__main__":
    main()
