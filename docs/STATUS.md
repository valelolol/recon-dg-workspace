# STATUS — Recon-DG

**Date:** 2026-10-02 (UTC)
**Host:** vale-llm
**Branch:** `feat/inventory-report`
**Published baseline:** `b4fc87c` ("docs: correct Aliyan handoff schema/path and baseline
dates", 2026-10-02, docs-only) — the current live tip of `feat/inventory-report`.
**Remote:** `git ls-remote` (read-only) confirms `origin/feat/inventory-report` ==
  `b4fc87c`; the local tracking ref matches. Verified against the live remote.
*Historical prior states (label only, not the current state):* the last commit that
changed implementation code is `c548f32` ("wip(scanner): save source-audit week-1 work +
NVD/reporter scaffolding"); the later commits `f2303ee`, `5b8a1f7`, `1524425`, `6323285`,
and `b4fc87c` are docs-only and did not alter the code. The executed verifications below
(PHEI == 6.0, pytest 79 passed) were run at the historical point `5b8a1f7` and remain
*historical* unless re-run.
**This session:** documentation corrections (Aliyan schema/path + baseline dates) were
**committed as `b4fc87c` and pushed** to `origin/feat/inventory-report`; as of that tip
the working tree is clean. No scanner, test, fixture, manifest, or code was edited.

## Scope

RECON-DG identifies project dependencies, checks known vulnerabilities (NVD + OSV),
uses actual dependency relationships when available, and helps developers prioritize
findings via deterministic PHEI risk analysis. The December prototype includes a clear
dashboard and AI explanations grounded in the findings. Inventory-only input must not
produce invented dependency edges; risk scoring requires explicitly "known" topology.
Bandit source auditing is a supporting sub-track, **not** the December deliverable.

## Current state (HEAD `b4fc87c`)

- **Onboarding / handoffs:** rewritten for complete beginners on individual machines
  (Windows PowerShell and Linux/macOS routes in `docs/TEAM_ONBOARDING.md`).
  The current week's **active** assignments are the M-DE-CORE handoffs. The two older
  source-audit handoffs (`HANDOFF_NICK.md` / `HANDOFF_CHRISTIAN.md`) were **removed**
  this week (Bandit sub-track **parked / non-gating this week** — preserved in git
  history, task descriptions remain in `TASKS.md`).
  `README.md` and `docs/WEEKLY.md` direct readers to the shared onboarding and the
  M-DE-CORE handoffs first.
- **M-DE-CORE plan:** committed in `TASKS.md` (Mode B field mapping + proposed input-fixture
  contract, §C0-prereq). The **implementation** it assigns (known-topology loader, Mode B
  serializer, `src/cli.py`, viewer, reference output, E2E test) is **not in the tree yet**.
- **Shared-contract statements** are aligned across docs: rule = JSON `test_id` (never
  `test_name`); `rc=5` does not exist (Bandit 1.9.4: `rc=0`=clean, `rc=1`=findings,
  `rc>=2`=error); "clean" is composite (`rc=0` AND valid JSON AND empty `results` AND
  empty `errors`); `-ll` is a valid severity filter that omits low severity and is
  omitted here; 4 tested rules / 8 cases; `os.system` is B605, not B602.
- **PHEI return value:** `calculate_phei` returns **only the scalar score** (6.0 for the
  3-node unit chain); **no** path field is emitted, rendered, or asserted. The numeric
  result is the "maximum path score," not an argmax path. No `top_risk_path`.
- **Missing reference sample:** `examples/fixtures/` (and `sample_risk_report.json`) do
  **not** exist in the tree. The reference `report.json` is **not** checked in. This is a
  prerequisite for Christian's E2E assertion and Aliyan's viewer — see the handoffs.

## Evidence-supported implementation progress (implementation state at HEAD `c548f32`;
verified at the historical point `5b8a1f7`; unchanged by the docs-only commits
`1524425`, `6323285`, and `b4fc87c`)

- **Parser (T-DE-01):** `requirements.txt` done + `build_mock_graph()` (3-node unit
  chain A→B→C, edge weights 1.0). Known-topology loader **not yet built**
  (W1-DE-01.L, Vale).
- **Engine (T-DE-02):** PHEI path-max implemented and verified. `calculate_phei` returns
  **6.0** for the 3-node unit chain and is invariant to CVE severity. Central finding:
  `report_generator.generate_report` still calls the global-sum `calculate_systemic_risk`,
  **not** PHEI (W1-DE-02.R must correct this). NVD/OSV client present but not wired into PHEI.
- **Reporter (T-DE-03):** inventory serializer (`serialize_inventory`) works; it **rejects
  any graph with edges** (requires `edge_availability == "unavailable"`). Mode B
  `serialize_dependency_graph` **not started**. No `src/cli.py` and no `src/dashboard/` yet.
- **Source-audit (T-SA-01/02/03):** unchanged this week; supporting / non-gating.
  `scan_demo.py` crashes (`NameError: venv_path`); `multi_check_wrapper.py` mislabels
  `rule_id` (`"blacklist"`) and uses the nonexistent `rc=5`; `tests/test_harness.py`
  does not run correctly (wrong examples path, invalid `-ll`, expects B704 for pickle).
  Nick (T-SA-02) and Christian (T-SA-03) own the corrections — see the T-SA-02 /
  T-SA-03 sections of `TASKS.md` (the source-audit handoff files were removed this week).

## Blockers (as of HEAD `b4fc87c`)

- Mode B (dependency-graph serializer) does not exist yet — required to emit the 6.0 report
  (W1-DE-03.R).
- **No reference `report.json` / `examples/fixtures/`** — required for Christian's byte-identity
  E2E assertion and Aliyan's viewer. Must be produced by Vale (W1-DE-03.R).
- `httpx` is imported by `nvd_client.py` but undeclared in any manifest (separate fix;
  not needed for the core path this week).
- `tests/test_harness.py` collects **0 tests** (pytest cannot collect `TestCase`/
  `TestHarness` — both define `__init__`); the "79 passed" total does not cover the
  Bandit harness.
- No live NVD/OSV end-to-end run this session (findings are synthetic fixtures).
- Dashboard framework, AI layer, and Docker are not started (out of scope this week).

## Pending decisions (unchanged)

1. **Severity in the score.** The design spec leaves the edge-weight function `w_uv`
   undefined. Current PHEI is topology-only — CVE severity is **unspecified**
   (`findings[].severity` is `null` per v0.1) and does **not** enter the score. Decide
   whether/how severity would enter `w_uv` once a severity standard is agreed.
   **Open, assigned to Vale.** Do not call the current 6.0 a complete vulnerability-risk
   score.
2. **AI backend:** local model (llama.cpp) vs. user-provided API key?
3. **Dashboard stack:** Flask + D3.js (recommended) vs. FastAPI + React? (Full T-DE-04
   dashboard out of scope this week; only a provisional static-viewer spike is proposed.)
4. **Bandit course requirement.** Is the source-audit sub-track a course deliverable this
   week? Status: **UNKNOWN** (no mandate found in repo). Treated as non-gating.
5. **Scanner exit-code semantics** (see TASKS.md unresolved #1): the scanner itself
   uses its own exit codes (0/1/2); Bandit's `rc=1` = findings is separate.

## Next bounded task

- **M-DE-CORE checkpoint.** Sign the Mode B field-mapping contract and the **proposed
  input-fixture contract** (TASKS.md §C0-prereq — approval required before Nick authors
  fixtures), then Vale implements the known-topology loader (W1-DE-01.L) + Mode B
  serializer (W1-DE-03.R) to emit the 6.0 reference `report.json`. Only after that
  can Christian's E2E byte-assertion and Aliyan's viewer be run against a real sample.
- **What the pending C0 fixture-contract decision does and does not block.** C0 (the
  shared contract + the proposed input-fixture contract, `TASKS.md` §C0-prereq) gates
  exactly two things: **(a)** Nick authoring the two M-DE-CORE fixtures, and **(b)**
  anything that **consumes** those approved fixtures — Vale's end-to-end CLI run +
  generated reference sample, Christian's running E2E assertions, and Aliyan's viewer run
  against real data. C0 does **not** gate (i) drafting/writing Vale's loader / Mode B
  serializer / CLI against the proposed shape, (ii) drafting Christian's test scaffolding
  + expected-results doc, or (iii) reviewing or sharing the handoffs.
- **Beginner onboarding doc committed:** `docs/TEAM_ONBOARDING.md` is **committed** in the
  repo and ships with the published handoffs (confirmed by `git ls-files`); all four
  M-DE-CORE handoffs, `README.md`, and `docs/WEEKLY.md` link to it.

## Verified / Proposed / Unverified

- **Verified (executed, 2026-10-01, baseline HEAD `5b8a1f7`; preserved as historical,
  not re-run in this docs-only session):**
  - requirements.txt → edgeless graph → v0.1 inventory JSON.
  - `calculate_phei` == 6.0 on a **one-off synthetic** 3-node unit chain A→B→C
    (2 unit-weight edges × 3 nodes = 6.0), verified by running the current code.
    The reusable `examples/fixtures/known_topology.json` has **not** been added yet.
  - PHEI invariant to CVE severity; `report_generator` uses the wrong (global-sum)
    formula; `serialize_inventory` emits only the v0.1 fields.
  - pytest 79 passed (test_harness collects 0).
- **Proposed (M-DE-CORE, not yet in repo):** known-topology loader, Mode B serializer,
  `src/cli.py`, `src/dashboard/view.py`, the two input fixtures,
  `examples/fixtures/sample_risk_report.json`, `tests/test_e2e_risk.py`,
  `docs/E2E_EXPECTED_RESULTS.md`. **No out-of-spec fields are emitted this week:**
  v0.1 defines no risk-path field, so `top_risk_path` is **deferred to a separate
  schema decision** (not emitted, rendered, or asserted). All emitted fields are
  spec-defined v0.1 fields; the known-topology input is a JSON file, so it uses
  `input.type = file`, `input.format = "synthetic-graph"` (both spec-supported; the
  committed demo uses `synthetic-graph`). Emitted (spec-backed): `findings[].id`,
  `findings[].advisory_source` (`synthetic-fixture`), `findings[].severity = null`.
  `vulnerability_lookup.matched` = distinct package IDs with at least one finding.
  Deferred: `packages[].risk_score` (node-level PHEI undefined). `risk.status` uses the
  spec enum `available`/`unavailable`.
- **Unverified / pending:** that the new Mode B serializer emits 6.0 end-to-end
  (not yet built); severity-in-score (open, Vale); Bandit course mandate (UNKNOWN);
  that the reference sample (once produced) byte-matches Christian's determinism check (run twice with identical scan_id and created_at, then compare outputs).

> Test counts in this file are **historical** unless re-run and re-recorded. No completion
> percentages are reported.
