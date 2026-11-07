# W9 Handoff — Vale (Engine + Reporter)
# 2026-11-02 to 2026-11-08

## Goal
Close the PHEI gap: reconcile `calculate_phei()` against the **agreed topology-only target** (0–100 impact score using reachable dependents and existing importance/criticality, separate from OSV severity). Document what is missing; do not fabricate.

## Evidence
- `calculate_phei()` (risk_analyzer.py:124–200) currently uses `get_cve_severity(node_key)` (NVD/OSV severity) as node risk values (lines 147–154), then computes `path_weight × impact_multiplicity`.
- **Agreed target**: topology-based 0–100 impact score using reachable dependents and existing importance/criticality, **separate from OSV severity**. No invented edge-weight formula.
- **Current state**: PHEI is **partial/unavailable**. It mixes severity into the score (contradicting the agreed direction). The agreed PHEI target is **topology-only** (0–100 impact score using reachable dependents and existing importance/criticality), **separate from systemic risk**. Severity is handled by `calculate_systemic_risk()`, not by `calculate_phei()`. This is not an open decision — topology-only is the agreed direction. PHEI is unavailable until topology data (reachable dependents, importance/criticality) is available.
- `calculate_systemic_risk()` (lines 203–258) uses severity; this is a different function.
- NVD/OSV wiring exists (15 focused tests pass); real scan on repo root returned 0 findings.
- **Scan evidence (2026-11-03):** `osv-scanner scan . --experimental-exclude tests examples docs --format json --output-file /tmp/recon-dg-osvscan-w9-real.json` → exit code 0, **0 findings** (clean scan). `src/web/osv_normalizer.py` corrected to dashboard contract (`vulnerability_id`, `package_name`, `numeric severity_score`, no `risk_level` label; aliases merged per group). 15 focused offline tests pass (`tests/test_risk_analyzer_nvd_integration.py`). Full suite: 275 tests pass.
- **⚠️ CRITICAL DISTINCTION:** NVD/OSV client wiring **exists** and is covered by 15 focused offline tests. A clean real-project scan was run. **However, live CVE data has NOT been demonstrated flowing into the systemic risk score on a real project.** `calculate_systemic_risk()` handles severity (OSV authoritative: Low 0.1–3.9, Medium 4.0–6.9, High 7.0–10.0; missing→Unknown). No CVSS edge weight; systemic risk is topology-only (path-max × impact-multiplicity, capped at 10.0). T-DE-02 remains **partial**, not complete. W10 must demonstrate: real scan → real CVE data → `calculate_systemic_risk()` on a controlled project with known topology.
- **MOCK_CVE_DB removed 2026-11-03 audit:** `get_cve_severity(node_key)` calls `NVDClient.query_nvd_api()`, then `query_osv_api()`. Production `get_cve_severity` with no client returns `{}` (never produces mock findings). Three new tests (13–15) prove API failure cannot produce mock findings.
- `src/agent/normalizer.py` (445 lines) remains the older agent-format normalizer; `src/web/osv_normalizer.py` is the dashboard-format normalizer. No single canonical normalizer yet — two exist with different schemas.

## Deliverable by Friday
- Document the PHEI gap in `docs/STATUS.md` §PHEI: what the agreed target is, what the current implementation does, what is missing (topology data: reachable dependents, importance/criticality).
- Leave `calculate_phei()` as-is (document as partial/unavailable); do not rewrite without team agreement.
- One reproducible real-project OSV-Scanner scan attempt through the pipeline, documenting what works and what topology/risk limits exist.

## Acceptance
- `docs/STATUS.md` §PHEI clearly states: topology-only target, current state uses severity, PHEI is unavailable pending topology data.
- No fabricated findings or scores.
- `git diff --check` clean.

## Dependencies
- Nick's W9 parser deliverable (≥3 formats) is a prerequisite for W10's real-scan demo.
- W10 Mode B serializer depends on this documentation being clear.

## Notes
- Severity→PHEI is not an open decision. Vale's agreed direction: topology-only. If trustworthy topology or approved rule absent → report unavailable.
- NVD API rate limits: 5 req/30s without key, 50 req/30s with key — cache aggressively or mock for demo?
- OSV fallback scope: npm, PyPI, Go, Rust, or only npm/PyPI?
- `go.mod` indirect dependencies: direct only or transitive? (team decision)
- Do NOT restore any archived W1–W8 handoff files.
