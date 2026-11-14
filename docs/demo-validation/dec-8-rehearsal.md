
# RECON-DG — December 8 Rehearsal Checklist

**Owner:** Aliyan Javed  
**Week:** 10 — Demo Validation  
**Rehearsal date:** December 8, 2026  
**Presentation date:** December 9, 2026  
**Status:** Not yet executed

## 1. Purpose

Validate that the RECON-DG prototype is ready for the December 9 interim presentation.

The demonstration covers the security analysis workflow from dependency scanning through vulnerability findings, risk analysis, dashboard visualization, AI-assisted explanations, human approval, and verification.

This is an interim prototype demonstration, not a claim that the complete application is finished.

## 2. Prerequisites

- RECON-DG repository is available.
- Python and required project dependencies are installed.
- The committed standard-library dashboard can be generated and opened.
- A controlled demonstration project or clearly labeled synthetic fixture is available.
- Demo findings include the fields required by the dashboard, including `severity_score`.
- API credentials, if needed, are configured through environment variables.
- No credentials or secrets appear in demonstration output.

## 3. Rehearsal Checkpoints

Record PASS, FAIL, or BLOCKED for each checkpoint after testing.

| ID | Checkpoint | Expected result | Status |
|----|------------|-----------------|--------|
| C01 | Scan a controlled project | Dependency inventory is generated successfully | NOT RUN |
| C02 | Display OSV vulnerability findings | Findings include evidence-backed identifiers, affected packages, and available severity values | NOT RUN |
| C03 | Generate dependency graph | Graph represents actual dependency relationships without fabricated edges | NOT RUN |
| C04 | Display systemic risk | Calculated risk is shown when available; otherwise an explicit unavailable state is shown | NOT RUN |
| C05 | Open the standard-library dashboard | Dashboard renders the committed report without errors | NOT RUN |
| C06 | Test package search and severity filtering | Package search and numeric severity thresholds filter displayed findings correctly | NOT RUN |
| C07 | Demonstrate deterministic AI fallback | With `--model OFF`, deterministic explanations are available without external AI credentials | NOT RUN |
| C08 | Demonstrate optional AI explanation | Configured provider produces an explanation, or the unavailable service is clearly disclosed | NOT RUN |
| C09 | Demonstrate bounded fix and human approval | A bounded fix proposal is shown; no patch is applied without explicit approval | NOT RUN |
| C10 | Verify rescan and results | A rescan shows verified changes, or unsupported functionality is clearly identified as pending | NOT RUN |

## 4. Validation Rules

- Use only real, evidence-backed vulnerability identifiers for real projects.
- Label all synthetic fixtures as **SYNTHETIC / DEMO ONLY**.
- Never present fixture findings as real-project findings.
- Never fabricate dependency edges, severity scores, or scan results.
- Do not expose API keys or other credentials.
- Do not automatically apply patches without explicit human approval.
- Do not claim that a fix succeeded unless a rescan verifies the result.
- If an external AI service is unavailable, demonstrate the deterministic fallback.
- If systemic risk cannot be calculated, display its unavailable state rather than inventing a score.

## 5. Pass/Fail Calculation

Acceptance target: at least 80% of checkpoints must PASS.

Total checkpoints: 10

Passing checkpoints: TBD

Failing checkpoints: TBD

Blocked checkpoints: TBD

Pass rate = (PASS checkpoints / 10) × 100

Minimum passing checkpoints required: 8

**Overall result:** PENDING

Blocked and failed checkpoints do not count as passing.

## 6. Fallback Procedures

| Problem | Fallback |
|---------|----------|
| Controlled vulnerable project unavailable | Use a clearly labeled synthetic fixture |
| Dashboard fails to render | Inspect the generated report JSON and document the failure |
| Systemic risk cannot be calculated | Show the unavailable result without inventing a score |
| External AI service unavailable | Demonstrate deterministic explanations using `--model OFF` |
| Patch-and-rescan workflow unavailable | Show the bounded patch proposal and mark live verification as pending |
| Docker unavailable | Continue without Docker; it is outside Week 10 scope |

## 7. Rehearsal Evidence

Record the following after executing the checklist:

- Git commit or branch tested:
- Python version:
- Dashboard report used:
- Fixture or controlled project:
- Commands executed:
- Screenshots or output evidence:
- Failed or blocked checkpoints:
- Issues requiring team attention:

## 8. Final Decision

- [ ] At least 8 of 10 checkpoints PASS.
- [ ] Demo script has no more than 10 steps.
- [ ] Every demo step includes an expected output.
- [ ] Synthetic fixtures are clearly labeled.
- [ ] No credentials are exposed.
- [ ] Unverified functionality is identified as pending.
- [ ] The team has reviewed outstanding blockers.

**Rehearsal decision:** PENDING

**Notes:** Complete this section after actual validation. Do not mark checkpoints as passing before they have been tested.

## Week 10 Validation Results — November 13, 2026

**Tester:** Aliyan Javed
**Branch:** feat/aliyan-w10-demo-validation
**Test environment:** Windows, Python 3.13
**Test data:** SYNTHETIC / DEMO ONLY

### Automated Tests

- Dashboard pytest suite: PASS (13/13)
- Git whitespace check: PASS (`git diff --check`)

### Manual Dashboard Validation

| Test | Result | Evidence |
|---|---|---|
| Dashboard launches locally | PASS | Served at 127.0.0.1:8765 |
| Demonstration report loads | PASS | 89 fixture findings |
| Package names display | PASS | pyyaml, urllib3, requests |
| Package search | PASS | Searching pyyaml displays matching findings |
| Numeric severity filter | PASS | 9+ displayed 18 of 89 findings |
| Unknown-only filter | PASS | Known-severity findings hidden |
| Filtered findings counter | PASS | Heading updates to 18 of 89 |
| Deterministic explanations | PASS | Displayed with --model OFF |
| Systemic risk status | PASS | Unreported when no score is supplied |

### Fixture Compatibility Issue

The committed demonstration fixture uses `package`, while the
dashboard expects `package_name`.

A temporary local report named `w10-demo-report.json` was created
with the required package_name fields.

The original fixture was not modified.

### Remaining Validation

- Live dependency scanning: NOT TESTED
- Complete dependency graph accuracy: NOT TESTED
- Optional external AI provider: NOT TESTED
- Human approval workflow: NOT TESTED
- Patch-and-rescan verification: NOT TESTED

**December 8 final rehearsal:** PENDING

These preliminary tests do not constitute final rehearsal acceptance.
