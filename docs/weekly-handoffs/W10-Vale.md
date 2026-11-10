# W10 Handoff — Vale (Engine + Reporter: Mode B serializer)

## Goal and demo value

**Interim-demo scope:** The Dec 9 presentation is an interim demonstration of progress toward the larger RECON-DG project — not a declaration that the full project is complete. The December deliverable is a working prototype (scan → graph → OSV findings → systemic risk → dashboard → AI explanation → bounded fix → human approval → rescan → verified results), not a finished application.

**Demo opportunities before presentation:** Dec 4 (Fri) and Dec 7 (Mon) are scheduled as internal team demos to validate the pipeline end-to-end before the Dec 9 presentation. Dec 8 (Tue) is a rehearsal/buffer day.

**One sentence:** Implement the dependency-graph serializer (T-DE-03 Mode B) in `src/reporter/report_generator.py` so that a real CVE scan can produce a structured `RiskReport` with findings, evidence, and remediation plan — the blocker for the W11 end-to-end CVE→systemic-risk demo.

## Proposed accountable owner

Vale.

## Prerequisites

- `src/reporter/report_generator.py` must contain the inventory-only serializer (Mode A) — confirmed present in published tree `11937e4a9a9ea60eeea64c510d35855e170cfe31`.
- `src/reporter/interface.py` defines the `RiskReport` dataclass schema.
- `src/reporter/inventory.py` implements the inventory serializer.
- TASKS.md §T-DE-03: Reporter schema + deterministic fallback — **Partial** (Mode A done; Mode B unimplemented).
- TASKS.md §T-DE-02 audit note: W10 must demonstrate end-to-end real scan → real CVE data → `calculate_systemic_risk()` on a controlled project.
- ROADMAP §W3: Mode B is a W3 deliverable missed; rescheduled to W10.
- `src/engine/risk_analyzer.py` implements `calculate_phei()` (topology-only) and `calculate_systemic_risk()` (severity-aware). PHEI is topology-only by design (path-max × impact-multiplicity, capped 10.0).

## Input / Output contract

| Direction | Artifact | Format |
|-----------|----------|--------|
| Input | `src/reporter/report_generator.py` (Mode A only) | Python module with inventory serializer |
| Output | `src/reporter/report_generator.py` with Mode B serializer | Python module with Mode B: emits `RiskReport` with `findings[]`, `evidence[]`, `risk`, `remediation_plan[]` |

## Deliverable (one bounded item)

`src/reporter/report_generator.py` Mode B serializer: emits `RiskReport` with `findings[]`, `evidence[]` (OSV data), `risk` (status + score), `remediation_plan[]` — **no fabricated data**. Handles topology-only systemic risk (no fabricated edge weights). Inventory-only input → `risk.status == "unavailable"` (no score fabricated).

## Acceptance criteria

- [ ] Mode B serializer emits `RiskReport` with `findings[]`, `evidence[]`, `risk`, `remediation_plan[]` — no fabricated data
- [ ] Mode B serializer handles topology-only systemic risk (no fabricated edge weights)
- [ ] `python -m pytest tests/test_report_generator.py -q` passes (all existing + new)
- [ ] `python -m pytest tests/test_inventory_reporter.py -q` passes (all existing + new)
- [ ] `git diff --check` clean
- [ ] No out-of-spec extension emitted this week; a risk-path field (e.g. `top_risk_path`) is deferred to a separate schema decision

## Verification commands / evidence

```bash
# Run reporter tests
python -m pytest tests/test_report_generator.py tests/test_inventory_reporter.py -q

# Expected: all tests pass (no new failures)

# Run full suite
python -m pytest tests/ -q

# Expected: no new failures (historical count ~241–248; verify before demo)
```

## Security / privacy controls

- No fabricated findings, scores, or edges.
- Inventory-only input → `risk.status == "unavailable"` (no score fabricated).
- Mode B uses the same `RiskReport` schema as Mode A — no out-of-spec fields.
- The `calculate_phei()` function is topology-only (path-max × impact-multiplicity, capped 10.0); severity is handled by `calculate_systemic_risk()`, not by `calculate_phei()`.
- `--model OFF` demonstrated (deterministic fallback).

## Fallback

| Unavailable service | Fallback behavior |
|---------------------|-------------------|
| Topology-only systemic risk | Demo with topology-only systemic risk; note severity mapping handled by `calculate_systemic_risk()` |
| Dashboard render failure | Validate `report.json` directly as JSON |
| Systemic risk `None` / `UnavailableTopologyError` on real graph | Demonstrate "unavailable" as feature, not bug |

## Stop conditions

- If the Mode B serializer produces fabricated data (edges, scores, findings not traceable to source), stop and report the fabrication rather than continuing.
- If `calculate_systemic_risk()` or `calculate_phei()` cannot be called without a real graph, stop and document the gap.

## Questions / blockers

- Which controlled project to use for the W11 CVE→systemic-risk demo? (team decision)
- Should the demo use a Go project (Nick's W10 deliverable) or a Python project with known CVEs? (team decision)
- No Aliyan task this week — no natural task for Aliyan in serializer work.

---

*W10 handoff v1 — 2026-11-09. Owner: Vale. For team confirmation.*
