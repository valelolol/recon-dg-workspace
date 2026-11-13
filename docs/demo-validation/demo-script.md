
# RECON-DG — December 9 Interim Demo Script

**Owner:** Aliyan Javed  
**Week:** 10 — Demo Validation  
**Presentation:** December 9, 2026  
**Status:** Draft — pending rehearsal validation

## Purpose

Demonstrate the progress of the RECON-DG cybersecurity prototype through dependency scanning, OSV vulnerability findings, dependency graph analysis, systemic risk, dashboard visualization, AI-assisted explanations, bounded fix proposals, human approval, and verification.

This is an interim demonstration, not a completed production application.

**Target duration:** Approximately 10 minutes for this demonstration segment, subject to team confirmation.

## Demonstration Steps

### Step 1 — Introduce RECON-DG

**Action:** Explain the project and the security problems it addresses.

**Expected output:** Audience understands that RECON-DG analyzes software dependencies and helps identify and explain security risks.

### Step 2 — Scan a Controlled Project

**Action:** Run the supported dependency scanner against a controlled demonstration project.

**Expected output:** A dependency inventory is generated containing packages and supported version information.

**Fallback:** Use a clearly labeled synthetic demonstration fixture if a controlled project is unavailable.

### Step 3 — Show OSV Vulnerability Findings

**Action:** Present the vulnerability findings generated from the scan.

**Expected output:** Evidence-backed vulnerability identifiers, affected packages, and available severity information are displayed.

**Important:** Never present synthetic fixture findings as real scan results.

### Step 4 — Show Dependency Graph

**Action:** Display the generated dependency relationships.

**Expected output:** The graph shows actual relationships supported by the dependency inventory, without fabricated edges.

### Step 5 — Explain Systemic Risk

**Action:** Show the available systemic risk analysis.

**Expected output:** Supported risk results are displayed. If the graph or required data is insufficient, the system clearly reports that risk is unavailable.

### Step 6 — Demonstrate the Dashboard

**Action:** Open the committed standard-library dashboard. Test package-name search and severity filtering.

**Expected output:** The dashboard displays findings, filters packages by name, and applies numeric severity thresholds correctly.

### Step 7 — Demonstrate Security Explanations

**Action:** Show deterministic explanations with `--model OFF`. If configured and available, demonstrate an optional user-selected AI provider.

**Expected output:** Deterministic explanations remain available without external AI credentials. Optional AI explanations describe supported findings without inventing vulnerability information.

**Security:** Provider credentials must remain in environment variables, never in the script or output.

### Step 8 — Show a Bounded Fix Recommendation

**Action:** Present a proposed dependency update or other supported remediation recommendation.

**Expected output:** The audience sees a specific, bounded fix proposal tied to an identified finding.

**Fallback:** Clearly label a proposal-only demonstration if automated remediation is unavailable.

### Step 9 — Explain Human Approval

**Action:** Show or explain the explicit approval requirement before a patch can be applied.

**Expected output:** The workflow requires human approval. No patch is automatically applied without authorization.

### Step 10 — Rescan and Summarize Verified Results

**Action:** If the patch-and-rescan workflow is available, run a rescan after an approved change. Otherwise, explain the pending verification stage.

**Expected output:** Only verified rescan results are presented as confirmed improvements. Unsupported functionality is clearly identified as pending.

## Rehearsal and Validation

Use `docs/demo-validation/dec-8-rehearsal.md` as the single source of truth for the December 8 rehearsal.

- December 4: Internal team demo
- December 7: Internal team demo
- December 8: Final rehearsal and buffer day
- December 9: Interim presentation

## Presentation Safety Rules

- Never fabricate CVEs, dependency edges, or severity scores.
- Clearly label synthetic fixtures as **SYNTHETIC / DEMO ONLY**.
- Never expose API credentials.
- Require explicit human approval before applying patches.
- Do not claim that remediation succeeded without verified rescan evidence.
- Use deterministic fallback when an external AI service is unavailable.
- Identify incomplete prototype functionality accurately.

## Outstanding Team Decisions

- Confirm whether live patch-and-rescan is included or whether only a patch proposal is demonstrated.
- Confirm which dependency ecosystem will be used.
- Confirm the time allocated to this demonstration segment.
- Confirm which validation evidence should be committed.

**Default approach:** One ecosystem, approximately 10 minutes, bounded patch proposal, and validation evidence committed to `docs/demo-validation/`.

The patch-and-rescan decision must be documented in `docs/REVIEW-DECISIONS.md` by November 24.

## Final Status

**Demo script:** Draft completed; execution not yet verified.

**Rehearsal:** Pending.

**Acceptance:** Pending actual validation results.
