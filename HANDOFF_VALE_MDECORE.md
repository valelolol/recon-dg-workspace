# HANDOFF_VALE_MDECORE.md — Vale · M-DE-CORE loader + PHEI + reference output (T-DE-01/02/03)
**Role this week:** load Nick's synthetic fixtures, run the PHEI engine through the reporter,
emit the reference `report.json` (score 6.0, offline, deterministic), and generate
`examples/fixtures/sample_risk_report.json` from it.

> **Read once before touching anything:** this is the *center* of the demo. Everything else
> (Nick's fixtures, Christian's harness, Aliyan's viewer) hangs off what you emit. You need
> the scanner engine and the venv; you do **not** need a live NVD/OSV API, a model, a GPU, or
> any other teammate's machine. All setup is local.
>
> **One-time setup:** open a terminal and follow `docs/TEAM_ONBOARDING.md` until you have a
> local clone on your own machine (the clone path is up to you),
> Git + Python working, and a working venv active. Use only the route that matches your
> machine. Then create your personal branch (step 0).
>
> ## Terms
> - **repository (repo):** the shared project folder tracked by Git.
> - **clone:** a complete copy of the repo on your computer.
> - **branch:** a named line of work; you use a personal branch so you don't clobber
>   `feat/inventory-report`.
> - **commit:** a saved checkpoint of file changes.
> - **pull request (PR):** a reviewable request to fold your personal branch into
>   `feat/inventory-report`.
> - **virtual environment (venv):** an isolated folder of Python packages.
> - **fixture:** a small stored file of test data (a JSON file).
> - **JSON:** text format for structured data.
> - **schema/contract:** the agreed rules for what data must look like.
> - **deterministic:** same input → byte-identical output.

## The approved PHEI contract — read this before coding
This week's `calculate_phei` returns **only its scalar score**. That is the approved contract and
the handoff is being aligned to it:

- **`calculate_phei(graph)` returns only the scalar `maximum path score`** (a number). For the
  3-node unit-weight chain (synth-a → synth-b → synth-c) the score is **6.0**.
- **Preserve** its numeric behavior, the cap at 10.0, and the `UnavailableTopologyError`
  guard. Do not change the formula; do **not** fold `findings[].severity` into it (severity is
  `null`/unspecified per v0.1, and the edge-weight function `w_uv` is an open decision per
  `docs/specs/design_spec.md` §3).
- **No new path-returning API.** Do not add a second return value, do not add
  `calculate_phei_with_path()`, and do **not** add a `top_risk_path` (or similar) field to the
  report or tests. v0.1 defines no risk-path field.
- **No severity contribution invented.** The score is topology-based; it is not a complete
  vulnerability-risk score.
- **Maximum path score ≠ argmax path.** "6.0" is the numeric *value*; do not conflate it with
  *which* path produced it. This week you emit only the value.

## What exists now / what you build (do not confuse the two)
**Exists today:** `src/engine/risk_analyzer.py` with `calculate_phei(graph)`,
`src/reporter/report_generator.py`, `src/reporter/inventory.py`,
`src/models/dependency_graph.py`, and the spec `docs/specs/scan-result-v0.1.md`.
**Does not exist yet (you are creating these):** `src/parser/parser.py` (the fixture
loader), `src/cli.py`, and `examples/fixtures/sample_risk_report.json`. **Do not** pretend any
of these already exist; they are the deliverables of this handoff. Nick's fixtures
(`examples/fixtures/known_topology.json`, `cve_fixture.json`) do not exist yet either — they are
his W1-DE-01.F and W1-DE-02.S.

**You can start implementing now, against the *proposed* input-fixture shape** (TASKS.md
§C0-prereq). That shape is **still marked "proposed / pending approval"** — it is NOT a final,
approved contract. So:
- It is safe and expected to write the loader, the Mode B serializer, and the CLI **now**,
  coded to the proposed shape (3 packages `id`/`name`/`version`; 2 directed unit-weight
  edges `id`/`source`/`target`/`weight`; 3 advisories `SYNTH-2026-XXXX` with `package_id`).
- If the C0 approval changes any field name or field set, your loader may need a one-line
  adjustment once Nick's actual fixtures land. Write it to be easy to retarget.

**What waits for Nick's fixture (do not treat as complete until his files exist):**
- Running the CLI end-to-end (`python src/cli.py ... -m dependency_graph -f ...`).
- Producing the **generated** reference `examples/fixtures/sample_risk_report.json`
  (this is a *generated* artifact from a real CLI run — not a hand-authored substitute).
- The verification in §6 (existing tests pass; CLI yields `risk.score == 6.0`; two runs
  byte-identical).
Your *code* (loader/serializer/CLI) can be complete before Nick's fixture exists; only the
**end-to-end execution + generated reference** are gated on his fixtures.
This matches the C0 scope: C0 blocks the approved-fixture-*consuming* steps, not the code
drafting.

## 0. Personal branch
Confirm clean + integration branch (`git status`, `git branch`). If your tree is dirty or your
history has diverged, **do not** run `reset`, `pull --force`, or auto-stash. Run
`git status --short` and `git branch -vv` and send those outputs to whoever is reviewing before
proceeding. When clean:

```bash
git switch -c feat/mdecore-vale-integration feat/inventory-report
```

## 1. Load Nick's fixtures (W1-DE-01.L) — `src/parser/parser.py` (new)
Add `load_known_topo_json(path) -> DependencyGraph`. It reads
`examples/fixtures/known_topology.json`, builds a `DependencyGraph` from the `packages` and
`edges` arrays, and sets `edge_availability = "known"`. It must also accept the advisory file
`examples/fixtures/cve_fixture.json` (expose a second small loader, e.g.
`load_cve_fixture(path) -> dict`, so the CLI has both inputs). Do **not** touch
`parse_requirements` (Mode A) — that is existing behavior you must **preserve unchanged**.

- **Expected after this step:** the two fixture files parse into a `DependencyGraph` with 3
  unique package ids and 2 directed unit-weight edges.

## 2. Wire PHEI into the reporter (W1-DE-02.R) — `src/reporter/report_generator.py`
`generate_report()` must call `calculate_phei` (the **path-max** scalar), **not**
`calculate_systemic_risk` (the global-sum, which stays in place and is marked
legacy/pre-decision — do not delete it). `generate_report` emits the scalar PHEI score only.
v0.1 has no path field, so it emits **no** `top_risk_path` and **no** path of any kind.
Do not change the PHEI formula or return shape.

- **Expected:** running the pipeline on Nick's fixtures yields the numeric score **6.0**.

## 3. Emit the v0.1 Mode B fields (W1-DE-02.R) — `src/reporter/inventory.py`
Add `serialize_dependency_graph(graph, cve_fixture) -> dict` that emits **only** the v0.1
Mode B fields (the field mapping is in `TASKS.md` §"M-DE-CORE — field mapping to v0.1"):
- `risk.status == "available"` (a numeric PHEI score is present — use the spec enum
  `available`/`unavailable`, **not** `complete`),
- `risk.score == 6.0`,
- `risk.method == "phei"`,
- `risk.reason` using the exact wording required below.
- The two required synthetic `warnings` (tell the reader the data is a fixture and the score
  is topology-based).
- On **each** finding: `findings[].id` (required unique), `findings[].advisory_source ==
  "synthetic-fixture"`, `findings[].severity == null`.
- `vulnerability_lookup` must **not** carry `advisory_source`.
- **Do not** add `packages[].risk_score`.

> **Required `risk.reason` wording (verbatim):**
> "PHEI path-max over a known topology (edge weights x node multiplicity). findings[].severity
> is null (unspecified per v0.1) and is NOT incorporated into the score (the edge-weight
> function w_uv is undefined per design_spec s3 - pending decision)."

## 4. CLI entrypoint (W1-DE-02.R) — `src/cli.py` (new)
A one-command entry:
```
python src/cli.py <input> [-m inventory|dependency_graph] [-f fixtures]   ->  writes report.json
```
No live API, no model. It loads Nick's two fixtures, runs the PHEI engine, and serializes the
report.

## 5. Generate and check in the reference (W1-DE-03.G) — `examples/fixtures/sample_risk_report.json` (new)
Run the CLI on Nick's fixtures; copy the produced `report.json` to
`examples/fixtures/sample_risk_report.json` and check it in. It **must** show:
- `input.type == "file"`, `input.format == "synthetic-graph"`,
- `risk.score == 6.0`, `risk.method == "phei"`, `risk.status == "available"`,
- 3 findings, each with `id`, `advisory_source == "synthetic-fixture"`, `severity: null`,
- the two synthetic `warnings`,
- **no** `top_risk_path` or any path field (v0.1 defines none).

> **This file does not exist yet** — it is your deliverable. It is a *generated* reference,
> not a hand-authored sample. Christian's harness (W1-DE-03) tests against it; a hand-authored
> substitute may support *contract* work only, must be labeled synthetic, and is **not** a
> pipeline test.

## 6. Verification
From the repo root, venv active. `python` = the venv Python (TEAM_ONBOARDING.md §7).

```bash
# existing tests stay green:
python -m pytest tests/test_parser.py -q
python -m pytest tests/test_inventory_reporter.py -q
python -m pytest tests/test_risk_analyzer.py -q

# produce + inspect the reference:
python src/cli.py <Nick's known_topology fixture> -m dependency_graph -f <Nick's cve fixture>
cat report.json                       # confirm score == 6.0, no path field

# determinism: run the CLI twice and diff:
python src/cli.py ... ; mv report.json run1.json
python src/cli.py ... ; diff run1.json run2.json   # expect: identical
```
- **Expected:** the three existing pytest commands pass. The CLI prints/writes a report with
  `risk.score == 6.0` and **no path field**. Two runs differ by no bytes.

## Acceptance
- All pre-existing tests pass; Mode A (requirements.txt) behavior and fields **preserved**.
- Mode B is offline and deterministic; score 6.0; `method == "phei"`;
  `input.type == "file"`, `input.format == "synthetic-graph"`; 3 synthetic findings (each with
  `id`, `advisory_source`, `severity: null`); warnings present; **no** `top_risk_path`.
- `calculate_phei` returns **only** the scalar score (no path-returning API); no severity
  invented.
- `sample_risk_report.json` is **generated** from the real CLI run and checked in.

## How to submit (only when your work is ready — your action, not mine)
```bash
git diff
git add src/parser/parser.py src/engine/risk_analyzer.py src/reporter/report_generator.py \
        src/reporter/inventory.py src/cli.py examples/fixtures/sample_risk_report.json
git commit -m "W1-DE-01/02/03: known-topology loader + Mode B PHEI serializer (score 6.0, no path field)"
git push origin feat/mdecore-vale-integration
```
Open a **PR targeting `feat/inventory-report`**; in the body list the subtask ids
(`W1-DE-01.L` / `W1-DE-02.R` / `W1-DE-03.G`), the checkpoint result, and the exact command that
produced `sample_risk_report.json`. **Never share passwords or access tokens in the PR, your
machine, or this repo.**

## If blocked, send **Vale** (or the relevant teammate) exactly this, under ~20 lines
1. The subtask ID + step number.
2. The exact command you ran.
3. The **full** error output (copy-paste, not a paraphrase).
4. Whether it is a **dependency** issue (env/venv), a **fixture** issue (Nick's file missing),
   or a **design** question (e.g. "does the C0 input-contract shape stand?").
5. One sentence on what you already tried. **Never** include any secret.

## How this connects
You produce the single reference `report.json` that Christian's harness tests and Aliyan's
viewer renders. If your reference drifts from 6.0 or gains a path field, tell Christian and
Aliyan immediately — their work hangs off this exact shape.
