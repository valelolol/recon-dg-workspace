# W3: Inventory report schema + evidence-grounded suggestions (T-DE-03)

## Goal and demo value

Generate a `RiskReport` (Mode A: inventory-only) with findings, OSV evidence, and remediation plan. PHEI is **not** required for inventory-only input — risk status is `"unavailable"` when topology is unknown. Suggested fixes are evidence-grounded using project functions or cited OWASP guidance.

## Proposed accountable owner

Vale (for team confirmation)

## Prerequisites

- W2 deliverable: engine produces real PHEI score on a real graph
- `src/reporter/interface.py` has `RiskReport` dataclass (v0.1 contract)
- `src/reporter/report_generator.py` exists (before/after plain-language report)
- `src/reporter/inventory.py` has Mode A (inventory-only) serializer
- `tests/test_report_generator.py` (8 tests) and `tests/test_inventory_reporter.py` exist

## Input / Output contract

| Direction | Artifact | Format |
|-----------|----------|--------|
| Input | `DependencyGraph` (real, from W2) | `edge_availability = "known"` |
| Output | `src/reporter/report_generator.py` | `generate_report()` wired to `calculate_phei` (path-max, not global-sum) |
| Output | `src/reporter/report_generator.py` | Mode A (inventory-only) serializer |
| Output | `tests/test_report_generator.py` | Tests for Mode A serializer |

## Deliverable (one bounded item)

`src/reporter/report_generator.py` with Mode A serializer: emits `RiskReport` with `findings[]`, `evidence[]` (OSV data), `risk` (status `"unavailable"` for inventory-only), `remediation_plan[]`. Suggested fixes are evidence-grounded using project functions or cited OWASP guidance.

## Acceptance criteria

- [ ] `generate_report()` calls `calculate_phei` (path-max), not `calculate_systemic_risk` (global-sum)
- [ ] Unavailable topology → `risk.status == "unavailable"`, `risk.score is None`, message: "No score is fabricated; this is an inventory-only result"
- [ ] `findings[]` contains real CVE data (not synthetic)
- [ ] Remediation plan: fixed versions verbatim (never "latest"), severity `None` (evidence only)
- [ ] Suggested fixes are evidence-grounded using project functions or cited OWASP guidance
- [ ] `python -m pytest tests/test_report_generator.py tests/test_inventory_reporter.py -q` passes

## Verification commands / evidence

```bash
cd /home/vale/projects/recon-dg-workspace
python -m pytest tests/test_report_generator.py tests/test_inventory_reporter.py -q
```

Expected: all tests pass. Verify output schema:

```bash
python -c "
from src.reporter.report_generator import generate_report
from src.models.dependency_graph import DependencyGraph
import json
g = DependencyGraph()
# ... build real graph ...
r = generate_report(g)
print(json.dumps(r.to_dict(), indent=2))
"
```

## Security / privacy controls

- No fabricated CVE data; all findings from real scanner output
- No fabricated edges; topology must be `"known"` for PHEI
- Remediation plan uses scanner-provided fixed versions verbatim (never invented)
- Severity left `None` for unknown (no numeric CVSS score fabricated)
- No model/LLM involvement in report generation

## Fallback

| Unavailable service | Fallback behavior |
|---------------------|-------------------|
| No topology (edges) | `risk.status == "unavailable"`; no score fabricated |
| No findings | Report emits empty `findings[]`; risk unavailable |
| Malformed graph | Raise error; report not generated |

## Stop conditions

- If `generate_report()` emits a numeric PHEI score on an inventory-only graph (no edges), stop — this is a topology bug.
- "integrations across different stories" — unclear phrase in TASKS.md; needs clarification.

## Questions / blockers

- Should the report include `top_risk_path` (a risk-path field) as a proposed out-of-spec addition? TASKS.md defers this to a separate schema decision.
- Should the remediation plan include severity labels (LOW/MEDIUM/HIGH/CRITICAL)? TASKS.md defers level thresholds.
- Which manifest formats should the demo use for the live scan? (requirements.txt is guaranteed; others need W1.)

---

*Handoff v1 — 2026-10-20. Owner: Vale (for team confirmation).*
