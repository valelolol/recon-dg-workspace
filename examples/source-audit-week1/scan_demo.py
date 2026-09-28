#!/usr/bin/env python3
"""
Source Audit Pipeline Demo — Week 1
=====================================
A static analysis wrapper demonstrating the pipeline:
input file → analysis engine (Bandit) → structured findings → JSON report.

Usage:
    python scan_demo.py <input_file> <output_json>

This demonstrates one static check (B307: use of eval/exec).
It is NOT comprehensive vulnerability detection.

Author: Scan Pipeline Developer (RECON-DG)
"""

import argparse
import json
import os
import subprocess
import sys
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Optional
from sys import argv


@dataclass
class Finding:
    """Bandit finding normalized to a consistent schema."""
    rule_id: str
    filename: str
    line_number: int
    severity: str
    confidence: str
    explanation: str


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
        # Resolve symlink and verify it points to a file
        resolved = path.resolve()
        if not resolved.is_file():
            raise ValueError(f"Input symlink target is not a file: {path}")
    return True


def validate_output_path(output_path: str, input_path: str) -> bool:
    """Validate output path and reject conflicts with input."""
    output = Path(output_path)
    input_file = Path(input_path)

    # Reject if output refers to input file directly
    if output.resolve() == input_file.resolve():
        raise ValueError(
            f"Output path must not be the same as input file: {input_path}"
        )

    # Reject if output is a symlink to input file
    if output.is_symlink() and output.resolve() == input_file.resolve():
        raise ValueError(
            f"Output symlink must not point to input file: {input_path}"
        )

    # Reject if output path contains symlink alias of input
    if input_file.resolve() in output.parents and output.is_symlink():
        raise ValueError(
            f"Output symlink cannot reference input via parent: {input_path}"
        )

    # If output exists, it must be a directory or we'll overwrite it
    if output.exists() and not output.is_dir():
        pass  # Overwrite allowed

    return True


def run_bandit_scan(source_path: str) -> tuple[int, subprocess.CompletedProcess]:
    """
    Run Bandit with B307 check on the source file.
    
    Returns:
        tuple: (exit_code, completed_process)
    """
    # Use venv from current directory
    venv_path = os.path.join(os.getcwd(), ".venv")
    cmd = [
        os.path.join(venv_path, "bin", "bandit"),
        "-r", ".",  # Scan current directory, not recursive
        "-f", "json",  # JSON output
        "-l",  # Low severity minimum
        "-t", "B307",  # Filter for eval/exec usage (test/rule filter)
        str(source_path)
    ]

    result: subprocess.CompletedProcess = subprocess.run(
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
        finding = Finding(
            rule_id=issue.get("test_name", "unknown"),
            filename=issue.get("filename", "unknown"),
            line_number=issue.get("line_number", 0),
            severity=issue.get("issue_severity", "unknown"),
            confidence=issue.get("issue_confidence", "unknown"),
            explanation=issue.get("issue_text", "No explanation provided")
        )
        findings.append(finding)

    return findings


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
        checks_requested=["B307:use-of-eval"],
        scan_status="success" if exit_code == 0 or exit_code == 5 else "failure",
        findings=[asdict(f) for f in findings],
        errors=errors
    )

    # Ensure output directory exists
    output_dir = Path(output_path).parent
    output_dir.mkdir(parents=True, exist_ok=True)

    # Write report
    report_path = Path(output_path)
    with open(report_path, "w") as f:
        json.dump(report.to_dict(), f, indent=2)

    print(f"Report written to: {report_path.resolve()}")


    # Use venv bandit executable
    import os
    venv_path = os.path.join(os.getcwd(), ".venv")
def main():
    parser = argparse.ArgumentParser(
        description="Source Audit Pipeline Demo — Week 1",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    python scan_demo.py vulnerable_example.py report.json
    python scan_demo.py safer_example.py safe_report.json
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

    args = parser.parse_args()

    # Validate inputs
    try:
        validate_input_path(args.input_file)
        validate_output_path(args.output_file, args.input_file)
    except ValueError as e:
        print(f"Input validation error: {e}", file=sys.stderr)
        # Still generate a report indicating validation failure
        report = ScanReport(
            schema_version="1.0",
            input_filename=args.input_file,
            engine_name="bandit",
            checks_requested=["B307:use-of-eval"],
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

    # Check if Bandit is available in venv
    try:
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
            "ERROR: Bandit is not installed in this environment.\n"
            "Install with: pip install bandit\n",
            file=sys.stderr
        )
        raise
    except Exception as e:
        print(f"Failed to check Bandit: {e}", file=sys.stderr)
        raise
        # Still generate a report indicating the tool is unavailable
        report = ScanReport(
            schema_version="1.0",
            input_filename=args.input_file,
            engine_name="bandit",
            checks_requested=["B307:use-of-eval"],
            scan_status="tool_unavailable",
            errors=["Bandit not installed in environment"]
        )
        output_dir = Path(args.output_file).parent
        output_dir.mkdir(parents=True, exist_ok=True)
        report_path = Path(args.output_file)
        with open(report_path, "w") as f:
            json.dump(report.to_dict(), f, indent=2)
        print(f"Report written (tool unavailable): {report_path.resolve()}")
        sys.exit(1)
    except Exception as e:
        print(f"Failed to check Bandit: {e}", file=sys.stderr)
        sys.exit(2)

    # Run the scan
    try:
        exit_code, result = run_bandit_scan(args.input_file)
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

    # Parse results
    findings = []
    if result.returncode == 0:
        try:
            findings = parse_bandit_output(result.stdout)
        except ValueError as e:
            errors.append(str(e))
    elif result.returncode == 5:
        # Bandit exit code 5 means issues were found
        if result.stdout.strip():
            try:
                findings = parse_bandit_output(result.stdout)
            except ValueError as e:
                errors.append(str(e))
    else:
        # Other errors
        if result.stderr.strip():
            errors.append(result.stderr)

    # Generate report
    generate_report(args.input_file, args.output_file, findings, errors, exit_code)

    # Summary
    print(f"\nScan complete: {len(findings)} findings")
    if findings:
        print("Rule IDs:", ", ".join(f.rule_id for f in findings))


if __name__ == "__main__":
    main()
