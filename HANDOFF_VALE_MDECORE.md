# HANDOFF_VALE_MDECORE.md — Vale · T-DE-01/02/03
Loader, scoring/report integration, generated reference output. (M-DE-CORE week)

Goal: Make the canonical risk path PHEI and emit the demo `report.json` (Mode B)
offline, score 6.0, using only spec-supported v0.1 fields.

## Your files (edit only these)
- `src/parser/parser.py`
- `src/engine/risk_analyzer.py`
- `src/reporter/report_generator.py`
- `src/reporter/inventory.py`
- `src/cli.py` (new)
- `examples/fixtures/sample_risk_report.json` (new, generated)

## Setup (beginner-friendly)
1. `cd /home/vale/projects/recon-dg-workspace`
2. `git checkout feat/inventory-report && git pull`
3. `git switch -c feat/mdecore-vale-integration feat/inventory-report`
4. `python -m venv .venv && source .venv/bin/activate`
5. `pip install -r requirements.txt`
   (You do not need `httpx` — it is only for the live API client, out of scope.)
6. Re-read the contract before coding: `docs/specs/scan-result-v0.1.md` and the
   M-DE-CORE section of `TASKS.md`.

## Steps
1. **(W1-DE-01.L) `src/parser/parser.py`** — add `load_known_topo_json(path) ->
   DependencyGraph`. Read the known-topology fixture (3 unique packages, 2 directed
   unit-weight edges), build the graph, set `edge_availability = "known"`.
   Do NOT touch `parse_requirements`.

2. **(W1-DE-02.R) `src/engine/risk_analyzer.py`** — extend `calculate_phei` so it
   **exposes the winning (argmax) path along with its score**, without changing its
   numeric behavior. The score is the current `max_path_phei` (6.0 for the 3-node
   unit chain); the winning path is the `P` that achieved it (the one satisfying
   `path_phei > max_path_phei`). Preserve the cap at 10.0 and the
   `UnavailableTopologyError` guard. Leave `calculate_systemic_risk` (global-sum)
   in place, marked legacy/pre-decision — do not delete it. Do NOT change the PHEI
   formula; do NOT fold severity into it.

3. **(W1-DE-03.R) `src/reporter/report_generator.py`** — `generate_report()` must
   call `calculate_phei` (path-max), NOT `calculate_systemic_risk` (global-sum).
   It emits the scalar PHEI score only; v0.1 has no path field, so no risk-path
   (e.g. `top_risk_path`) is emitted.

4. **`src/reporter/inventory.py`** — add `serialize_dependency_graph(graph, cve_fixture)
   -> dict` emitting ONLY the v0.1 Mode B fields (see mapping in TASKS.md).
   `risk = {status:"available", score: <phei score>, method:"phei", reason: <wording>}`.
risk.status uses the spec enum `available`/`unavailable` (NOT `complete`); `available`
here because a numeric PHEI score is present.
   Emit the two required `warnings` (synthetic data; `findings[].severity` is `null`/unspecified
and not in the score).
   Set `findings[].id` (required unique ID) and `findings[].advisory_source` (`synthetic-fixture`)
on EACH finding; set `findings[].severity` to `null`. `vulnerability_lookup` must NOT carry
`advisory_source`. Do NOT add `packages[].risk_score`.

5. **`src/cli.py`** — new one-command entry:
   `python src/cli.py <input> [-m inventory|dependency_graph] [-f fixtures]` → writes
   `report.json`. No live API.

6. Generate and check in `examples/fixtures/sample_risk_report.json`. It MUST show
   `input.type == "file"`, `input.format == "synthetic-graph"`, `risk.score == 6.0`, `method == "phei"`,
   3 findings (each with `id`, `advisory_source`, `severity: null`), synthetic
   `warnings`, and **no path field** (v0.1 defines none).

## Required risk.reason wording
> "PHEI path-max over a known topology (edge weights x node multiplicity). findings[].severity
> is null (unspecified per v0.1) and is NOT incorporated into the score (the edge-weight
> function w_uv is undefined per design_spec s3 - pending decision)."

## PHEI argmax (how the 6.0 is obtained — no path field emitted this week)
`calculate_phei(graph)` iterates `all_paths`. For each path `P` it computes
`path_weight = sum(edge_weight for each edge in P)` and
`path_phei = path_weight * impact_multiplicity(P)`, tracking `max_path_phei`.
**The score returned is `max_path_phei` (capped at 10.0) — a scalar only; its return
shape is unchanged.** For the 3-node unit chain (A→B, B→C): 2 edges x 1.0 = path
weight 2.0, node_count 3 → 2.0 x 3 = 6.0. The score is the argmax value and is
invariant to advisory severity (`findings[].severity` is `null` per v0.1 and does not
enter `path_phei`).
v0.1 defines **no** risk-path field. A risk-path (e.g. `top_risk_path`) is **not**
emitted, rendered, or asserted in this week's report or tests — it is **deferred to a
separate schema decision**. Do not add a second return value, a companion
`calculate_phei_with_path()`, or any path field; `calculate_phei` must return **only**
the scalar score.

## Verify
- `python -m pytest tests/test_parser.py -q` (stay green)
- `python -m pytest tests/test_inventory_reporter.py -q` (stay green)
- `python -m pytest tests/test_risk_analyzer.py -q` (stay green; the new test asserts
  the 6.0 score; no path field is asserted)
- Run the CLI on Nick's fixtures; confirm `report.json` score == 6.0, **no path field**,
  and Mode A (requirements.txt) **preserves its existing fields/behavior** and the
  pre-existing tests still pass.
- Fix-IDs/timestamps: run twice with the same seed and diff the two `report.json`
  outputs — they must be byte-identical.

## Acceptance
- All pre-existing tests pass; Mode A behavior/fields preserved.
- Mode B: offline, deterministic; score 6.0; `method phei`; `input.type == "file"`, `input.format == "synthetic-graph"`;
  3 synthetic findings (each with `id`, `advisory_source`, `severity: null`);
  **no path field** (v0.1 defines none); warnings present; no `packages[].risk_score`.
- Severity documented as null/not-in-score.

## Branch & PR
```
git add src/parser/parser.py src/engine/risk_analyzer.py src/reporter/ src/cli.py \
      examples/fixtures/sample_risk_report.json
git commit -m "W1-DE-01/02/03: known-topology loader + Mode B PHEI serializer (score 6.0, no path field)"
git push origin feat/mdecore-vale-integration
```
Open a PR to `feat/inventory-report`; in the body write the subtask IDs
(W1-DE-01.L / W1-DE-02.R / W1-DE-03.R), the checkpoint result, and the exact command
that produced `sample_risk_report.json`.

## If blocked — send Vale's teammate (or the relevant teammate) EXACTLY this, in under ~20 lines
- The subtask ID + step number you're on.
- The exact command you ran.
- The full error output (copy-paste, not a paraphrase).
- Whether it looks like a dependency issue, a fixture issue, or a design question.
- One sentence on what you already tried.

## Connects
You produce the single reference `report.json` that Nick's fixtures feed and that
Christian tests and Aliyan renders. If your reference output drifts, tell the others
immediately.
