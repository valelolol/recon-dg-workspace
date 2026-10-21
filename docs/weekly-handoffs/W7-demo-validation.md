# W7: Dashboard/report usability and demo validation (proposed — team confirmation required, no registered task ID)

## Goal and demo value

Independently validate the usability of the stdlib dashboard (`src.web`) and the `RiskReport` output for the December demo. This is a **usability/validation handoff**, not a code-change handoff. The deliverable is an independently testable validation report, not a code change. Docker is **not** a prerequisite — all validation runs against the stdlib dashboard.

## Proposed accountable owner

Aliyan (proposed — team confirmation required)

## Prerequisites

- W3 deliverable: `src/reporter/` produces a complete `RiskReport` (findings, evidence, remediation plan)
- W4 deliverable: `src.web` dashboard running on `127.0.0.1:8000`
- W5 deliverable: model backend configured (or confirmed deterministic-only)
- A real project manifest for scan input (e.g. `requirements.txt` in the repo root or a sample project)
- **No Docker dependency** — all validation runs against the stdlib dashboard

## Input / Output contract

| Direction | Artifact | Format |
|-----------|----------|--------|
| Input | `RiskReport` JSON from W3 | Structured JSON with findings, edges, PHEI score, remediation plan |
| Input | `src.web` dashboard (stdlib) | `http.server` at `127.0.0.1:8000` |
| Input | Real project manifest | `requirements.txt`, `package.json`, or `pyproject.toml` |
| Output | `docs/demo-validation/validation-report.md` | Bounded checklist with pass/fail per item |
| Output | `docs/demo-validation/demo-script.md` | Step-by-step demo sequence (show, don't tell) |

## Deliverable (one bounded item)

A **demo-validation checklist** (`docs/demo-validation/validation-report.md`) and a **demo script** (`docs/demo-validation/demo-script.md`), both independently runnable. The checklist verifies: (1) real scan runs (not synthetic), (2) PHEI score shown (not `None`), (3) patch workflow demonstrated (show, don't tell), (4) AI explanation shown (if `--model ON`), (5) unavailable topology demonstrated (contrast with available), (6) `--model OFF` demonstrated (deterministic fallback). The demo script provides a step-by-step sequence for the live demo.

## Acceptance checklist

- [ ] Real scan runs on a real project manifest (not synthetic data)
- [ ] PHEI score is numeric and displayed (not `None` or absent)
- [ ] Patch workflow demonstrated (show changes, don't describe them)
- [ ] AI explanation displayed (if `--model ON` configured; otherwise note deterministic fallback)
- [ ] Unavailable topology demonstrated (inventory-only input → "unavailable" status, contrasted with a known-topology run)
- [ ] `--model OFF` demonstrated (deterministic fallback active, no model required)
- [ ] Dashboard renders findings, risk paths, and remediation plan without errors
- [ ] All evidence is traceable to source code (no fabricated findings)
- [ ] Demo script is ≤ 10 steps, each with expected output
- [ ] Validation report signed off by a second team member (not the owner)

## Verification evidence

```bash
# 1. Run real scan
cd /home/vale/projects/recon-dg-workspace
python -m src.cli --manifest <real-manifest> --output report.json

# 2. Verify report.json has real data
python -c "import json; r=json.load(open('report.json')); print(r['risk']['score'])"

# 3. Start stdlib dashboard
python -m src.web --port 8000

# 4. Open http://127.0.0.1:8000 in browser and verify all checklist items
# 5. Run with --model OFF to verify deterministic fallback
python -m src.cli --manifest <real-manifest> --output report-off.json --model OFF
```

## Privacy / security checks

- No credentials (API keys, tokens) in `report.json` or dashboard output
- No faculty/sponsor approval required in the demo (user approval is the gate)
- No model training or fine-tuning in the demo
- `--model ON` still requires `OPENAI_API_KEY` env var (not baked into any output)
- All scan evidence is from OSV-Scanner (authoritative scanner) or NVD/OSV API enrichment (secondary)

## Fallback

| Unavailable item | Fallback behavior |
|------------------|-------------------|
| Dashboard fails to render | Report traceback; validate report.json directly as JSON |
| `--model ON` unavailable | Demonstrate `--model OFF` deterministic fallback instead |
| Real manifest unavailable | Use a known-good sample manifest (e.g. repo root `requirements.txt`) |
| PHEI score unavailable (topology unknown) | Demonstrate "unavailable" status as a feature, not a bug |

## Stop conditions

- If the real scan produces no findings (empty graph), stop and report the scan failure before proceeding.
- If the dashboard fails to render on a valid `report.json`, stop and report the traceback.
- If the demo script cannot be executed in ≤ 10 steps, stop and revise the script.
- If a team member cannot independently verify the checklist, stop and clarify the acceptance criteria.

## Questions / blockers

- Should the demo include a live patch-and-rescan sequence, or just show the patch proposal?
- Does the demo need to cover all ecosystems (npm, PyPI, Go, Rust) or just one?
- Is the demo script intended for a 10-minute or 30-minute demo slot?
- Should the validation report be committed to `docs/demo-validation/` or kept as a local artifact?
- **Team decision:** Flask+D3 optional dashboard vs. stdlib dashboard for the demo? (see W4)
- **Team decision:** llama.cpp local endpoint vs. user API key for the AI explanation demo? (see W5)

## Ownership note

> All ownership and assignment in this handoff is **proposed and pending team confirmation**. Aliyan is the proposed owner for this usability/validation deliverable. No registered task ID exists for W7 in TASKS.md; this work is proposed/optional and does not depend on Docker (T-DE-05).

---

*Handoff v1 — 2026-10-20. Owner: Aliyan (proposed — team confirmation required).*
