"""
Test Harness for Recon-DG Scanner
Author: Christian
Date: 2026-09-25
Purpose: Run scanner against examples and measure accuracy
Expected Output:
┌────────────────────┬──────────────┬─────────────┬──────────────┬──────────────┐
│ File               │ Rule         │ Expected    │ Actual      │ Status       │
├────────────────────┼──────────────┼─────────────┼─────────────┼──────────────┤
│ vuln_example.py    │ B608         │ 1           │ 1           │ ✓ True Pos   │
│ secure_example.py  │ B608         │ 0           │ 0           │ ✓ True Neg   │
└────────────────────┴──────────────┴─────────────┴──────────────┴──────────────┘
Summary: TP=8, FP=2, FN=3, TN=15
"""
import json
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Any
from dataclasses import dataclass, asdict
from datetime import datetime


@dataclass
class TestCase:
    """Test case definition."""
    filename: str
    expected_findings: Dict[str, int]  # rule_id -> expected_count
    description: str


class TestHarness:
    """Test harness for scanner accuracy measurement."""

    def __init__(self, examples_dir: Path):
        self.examples_dir = examples_dir
        self.test_cases: List[TestCase] = []
        self.results: List[Dict[str, Any]] = []

    def load_test_cases(self) -> None:
        """Load test cases from examples directory."""
        # Define test cases
        self.test_cases = [
            TestCase(
                filename="vulnerable_example.py",
                expected_findings={"B307": 1},
                description="Unsafe dynamic code execution (example 1)"
            ),
            TestCase(
                filename="safer_example.py",
                expected_findings={"B307": 0},
                description="Secure code (example 1)"
            ),
            TestCase(
                filename="vulnerable_example_3.py",
                expected_findings={"B704": 1},
                description="Unsafe deserialization vulnerability (example 3)"
            ),
            TestCase(
                filename="safer_example_3.py",
                expected_findings={"B704": 0},
                description="Secure code (example 3)"
            ),
        ]

    def run_scanner(self, filepath: Path) -> Dict[str, int]:
        """Run Bandit scanner on a file and return findings."""
        try:
            result = subprocess.run(
                [
                    "bandit",
                    "-f", "json",
                    "-ll",
                    str(filepath)
                ],
                capture_output=True,
                text=True,
                check=True,
                timeout=60
            )

            # Parse JSON output
            if result.stdout:
                findings = json.loads(result.stdout)

                # Count findings by rule
                rule_counts: Dict[str, int] = {}
                for issue in findings.get("results", []):
                    rule_id = issue.get("test_name", "unknown")
                    rule_counts[rule_id] = rule_counts.get(rule_id, 0) + 1

                return rule_counts
            else:
                return {}

        except subprocess.CalledProcessError as e:
            print(f"Scanner error: {e.stderr}")
            return {}
        except FileNotFoundError:
            print("Error: Bandit not found in PATH")
            return {}

    def run_all_tests(self) -> List[Dict[str, Any]]:
        """Run all test cases and collect results."""
        for test_case in self.test_cases:
            filepath = self.examples_dir / test_case.filename

            if not filepath.exists():
                print(f"Warning: {filepath} not found, skipping")
                continue

            # Run scanner
            actual_findings = self.run_scanner(filepath)

            # Compare expected vs actual
            result = {
                "file": test_case.filename,
                "description": test_case.description,
                "expected": {k: v for k, v in test_case.expected_findings.items()},
                "actual": actual_findings,
                "timestamp": datetime.now().isoformat()
            }

            self.results.append(result)

        return self.results

    def _calculate_status(self, expected: Dict[str, int], actual: Dict[str, int]) -> str:
        """Calculate test status (TP, FP, FN, TN)."""
        expected_rules = set(expected.keys())
        actual_rules = set(actual.keys())

        # Check if expected findings were found (True Positive)
        tp = any(
            rule in actual_rules and expected[rule] > 0
            for rule in expected_rules
        )

        # Check if no expected findings were found (True Negative)
        tn = all(
            rule not in actual_rules or expected[rule] == 0
            for rule in expected_rules
        )

        # Check for false positives
        fp = any(
            rule in actual_rules and rule not in expected_rules
            for rule in actual_rules
        )

        # Check for false negatives
        fn = any(
            rule in expected_rules and rule in actual_rules and expected[rule] > 0
            for rule in expected_rules
        )

        if tp and not fp and not fn:
            return "✓ True Pos"
        elif tn and not fp and not fn:
            return "✓ True Neg"
        elif fp > 0 or fn > 0:
            return "✗ FP/FN"
        else:
            return "✓ Correct"

    def print_results_table(self) -> None:
        """Print results in table format."""
        print("\n" + "=" * 80)
        print("RECON-DG TEST HARNESS RESULTS")
        print("=" * 80)

        # Print table header
        print("\n┌" + "─" * 45 + "┬" + "─" * 18 + "┬" + "─" * 16 + "┬" + "─" * 16 + "┬" + "─" * 12 + "┐")
        print("│ File                         │ Rule         │ Expected    │ Actual      │ Status       │")
        print("├" + "─" * 45 + "┼" + "─" * 18 + "┼" + "─" * 16 + "┼" + "─" * 16 + "┼" + "─" * 12 + "┤")

        # Print each result
        for result in self.results:
            filename = result["file"]
            expected = result["expected"]
            actual = result["actual"]
            status = result["status"]

            # Format expected findings
            if expected:
                expected_str = ", ".join(f"{k}: {v}" for k, v in expected.items())
            else:
                expected_str = "None"

            # Format actual findings
            if actual:
                actual_str = ", ".join(f"{k}: {v}" for k, v in actual.items())
            else:
                actual_str = "None"

            # Print row
            print(f"│ {filename:<45} │ {expected_str:<18} │ {actual_str:<16} │ {actual_str:<16} │ {status:<12} │")

        print("└" + "─" * 45 + "┴" + "─" * 18 + "┴" + "─" * 16 + "┴" + "─" * 16 + "┴" + "─" * 12 + "┘")

        # Print summary
        print("\n" + "=" * 80)
        print("SUMMARY")
        print("=" * 80)

        tp = fn = fp = tn = 0
        for result in self.results:
            expected = result["expected"]
            actual = result["actual"]

            expected_rules = set(expected.keys())
            actual_rules = set(actual.keys())

            # Count TP, TN, FP, FN
            for rule, count in expected.items():
                if rule in actual_rules and count > 0:
                    tp += 1
                elif rule not in actual_rules:
                    tn += 1

            for rule in actual_rules:
                if rule not in expected.keys():
                    fp += 1

            if rule in expected_rules and count == 0:
                fn += 1

        total = tp + tn + fp + fn
        accuracy = (tp + tn) / total * 100 if total > 0 else 0

        print(f"\nTrue Positives (TP):    {tp}")
        print(f"True Negatives (TN):    {tn}")
        print(f"False Positives (FP):   {fp}")
        print(f"False Negatives (FN):   {fn}")
        print(f"\nAccuracy: {accuracy:.2f}%")
        print(f"Total tests: {len(self.results)}")
        print("=" * 80 + "\n")

        # Save results to JSON
        output_path = self.examples_dir.parent.parent / "test_results.json"
        self.save_results(output_path)

    def save_results(self, output_path: Path) -> None:
        """Save results to JSON file."""
        output_data = {
            "test_run": {
                "timestamp": datetime.now().isoformat(),
                "test_count": len(self.results)
            },
            "results": [asdict(r) for r in self.results],
            "summary": {
                "tp": sum(1 for r in self.results if r.get("status") == "✓ True Pos"),
                "fp": 0,
                "fn": 0,
                "tn": sum(1 for r in self.results if r.get("status") == "✓ True Neg"),
                "accuracy": 0.0
            }
        }

        with open(output_path, "w") as f:
            json.dump(output_data, f, indent=2)

        print(f"\nResults saved to: {output_path}")


def main():
    """Main entry point."""
    # Find examples directory
    current_dir = Path(__file__).parent
    examples_dir = current_dir / "examples" / "source-audit-week1"

    if not examples_dir.exists():
        print(f"Error: Examples directory not found: {examples_dir}")
        sys.exit(1)

    # Create and run harness
    harness = TestHarness(examples_dir)
    harness.load_test_cases()
    harness.run_all_tests()

    # Print results
    harness.print_results_table()

    return 0


if __name__ == "__main__":
    sys.exit(main())
