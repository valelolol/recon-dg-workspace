# HANDOFF — Vale: M-DE-CORE loader, serializer, reference output

## Your assignment

Build the **Mode B** pipeline: a known-topology loader, a dependency-graph serializer that produces a `report.json` with `risk.score == 6.0`, and a CLI entry point.

## What to produce

### 1. `src/parser/parser.py` — `load_known_topo_json()`

A function that reads `examples/fixtures/known_topology.json` (Nick's fixture) and returns a `DependencyGraph` with:
- `edge_availability == "known"`
- 3 nodes, 2 directed edges (a→b, b→c), unit weights
- Correct node/edge/weight values

### 2. `src/reporter/inventory.py` — Mode B serializer

Extend `serialize_inventory` to handle `edge_availability == "known"`. The output `report.json` must contain:
- `analysis_mode: "dependency_graph"`
- `topology_status: "known"`
- `risk.score: 6.0`, `risk.method: "phei"`, `risk.status: "available"`
- 3 findings with `id`, `advisory_source: "synthetic-fixture"`, `severity: null`
- `warnings[]` with the synthetic-labeled warning
- **No `top_risk_path` field** (v0.1 defines none)
- `input.type: "file"`, `input.format: "synthetic-graph"`

### 3. `src/cli.py`

A CLI entry point: `python -m src.cli <input.json> output.json` that:
- Loads the input topology
- Runs the pipeline (loader → PHEI → serializer)
- Writes the report JSON
- Prints a summary

### 4. `examples/fixtures/sample_risk_report.json`

The **6.0 reference output**. This is the single shared artifact Christian's test and Aliyan's viewer depend on. It must:
- Be valid JSON
- Have `risk.score == 6.0`, `method == "phei"`, `risk.status == "available"`
- Have 3 findings, no path field, severity `null`
- Be **deterministic** (fixed `scan_id` and `created_at`)

## Acceptance criteria

- `calculate_phei` on the loaded topology returns exactly **6.0** (scalar, not a list).
- `generate_report` routes through `calculate_phei` (path-max), not `calculate_systemic_risk` (legacy global-sum).
- `report_generator.py` is present and wired to `calculate_phei`.
- Existing Mode A tests still pass (inventory behavior preserved).
- `python -m pytest tests/test_report_generator.py tests/test_parser.py tests/test_risk_analyzer.py tests/test_inventory_reporter.py -q` passes (76 tests).
- `git diff --check` is clean.

## Where to start

1. `cd /home/vale/projects/recon-dg-workspace && git checkout feat/inventory-report`
2. `git switch -c vale-modeb`
3. Read `TASKS.md` §C0-prereq for the proposed fixture contract.
4. Read `docs/STATUS.md` §Verified/Proposed/Unverified for current state.
5. Read `docs/WEEKLY.md` for this week's focus.
6. Build in order: loader → serializer → CLI → reference sample.
7. Validate: `python -m json.tool examples/fixtures/sample_risk_report.json`.
8. Commit and push.

## Key documents to read first

- `docs/TEAM_ONBOARDING.md` — your OS-specific setup.
- `TASKS.md` §C0-prereq — proposed input-fixture contract (must be approved before Nick writes fixtures, but you can draft against the proposed shape).
- `docs/STATUS.md` — current implementation state.
- `docs/WEEKLY.md` — this week's focus and acceptance criteria.

## Notes

- The `calculate_systemic_risk` function (global-sum) is kept in place as legacy; `generate_report` must call `calculate_phei` (path-max).
- Severity is `null` per v0.1 and does **not** enter the score. The 6.0 comes from topology only (2 edges × 1.0 × 3 nodes).
- The `src/explanation/` and `src/web/` modules are uncommitted and not part of this deliverable.