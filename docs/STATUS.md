# STATUS — Recon-DG

**Date:** 2026-10-01 (UTC)
**Host:** vale-llm
**Baseline HEAD:** `5b8a1f7` (`feat/inventory-report`) — this file was rebuilt as a clean final
record for the M-DE-CORE week. The working tree at the moment these edits are applied is
**modified** by the documentation and new-handoff edits in this section (uncommitted;
nothing is committed or pushed).
**Working tree at baseline checkout:** clean (fetched, fast-forwardable; no local changes).
**This session:** documentation + verification only. No scanner, test, example-pair, or
active-handoff files edited. The two obsolete root handoffs from the prior cleanup remain
removed. Shared-contract statements are aligned (test_id vs test_name, the `-ll` severity
floor, the clean-scan definition, 4 tested rules vs 8 cases, and os.system=B605 not B602).

## Scope
RECON-DG identifies project dependencies, checks known vulnerabilities (NVD + OSV),
uses actual dependency relationships when available, and helps developers prioritize
findings via deterministic PHEI risk analysis. The December prototype includes a clear
dashboard and AI explanations grounded in the findings. Inventory-only input must not
produce invented dependency edges; risk scoring requires explicitly "known" topology.
Bandit source auditing is a supporting sub-track, not the deliverable.

## Evidence-supported progress
- **Parser (T-DE-01):** `requirements.txt` done + `build_mock_graph()` (3-node unit
  chain A→B→C, edge weights 1.0). Known-topology loader **not yet built**
  (W1-DE-01.L, Vale).
- **Engine (T-DE-02):** PHEI path-max implemented and verified. `calculate_phei` returns
  **6.0** for the 3-node unit chain and is invariant to CVE severity (6.0 at zero severities
  and 6.0 at 0.99 severities). Central finding preserved: `report_generator.generate_report`
  still calls the global-sum `calculate_systemic_risk`, **not** PHEI. NVD/OSV client present
  but not wired into PHEI.
- **Reporter (T-DE-03):** inventory serializer (`serialize_inventory`) works; it **rejects
  any graph with edges** (requires `edge_availability == "unavailable"`). Mode B
  `serialize_dependency_graph` **not started**. No `src/cli.py` and no `src/dashboard/` yet.
- **Source-audit (T-SA-01/02/03):** unchanged this week; non-gating.

## Blockers
- Mode B (dependency-graph serializer) does not exist yet — required to emit the 6.0 report
  (W1-DE-03.R).
- `httpx` is imported by `nvd_client.py` but undeclared in any manifest (separate fix;
  not needed for the core path this week).
- `tests/test_harness.py` collects **0 tests** (pytest cannot collect `TestCase`/
  `TestHarness` — both define `__init__`); the "79 passed" total does not cover the
  Bandit harness.
- No live NVD/OSV end-to-end run this session (findings are synthetic fixtures).
- Dashboard framework, AI layer, and Docker are not started (out of scope this week).

## Pending decisions
1. **Severity in the score.** The design spec leaves the edge-weight function `w_uv`
   undefined. Current PHEI is topology-only — CVE severity is **unspecified** (`findings[].severity` is `null`;
v0.1 defines no severity values yet) and does not enter the score. Decide whether/how
severity would enter `w_uv` once a severity standard is agreed. **Open, assigned to Vale.**
   Do not call the current 6.0 a complete vulnerability-risk score.
2. **AI backend:** local model (llama.cpp) vs. user-provided API key?
3. **Dashboard stack:** Flask + D3.js (recommended) vs. FastAPI + React? (Full T-DE-04
   dashboard out of scope this week; only a provisional static-viewer spike is proposed.)
4. **Bandit course requirement.** Is the source-audit sub-track a course deliverable this
   week? Status: **UNKNOWN** (no mandate found in repo). Treated as non-gating.
5. **Scanner exit-code semantics** (see TASKS.md unresolved #1): the scanner itself
   uses its own exit codes (0/1/2); Bandit's rc=1 = findings is separate.

## Next bounded task
- **M-DE-CORE checkpoint.** Sign the Mode B field-mapping contract (TASKS.md), then Vale
  implements the known-topology loader (W1-DE-01.L) + Mode B serializer (W1-DE-03.R) to
  emit the 6.0 reference `report.json`.

## Verified / Proposed / Unverified
- **Verified (executed, 2026-10-01, baseline HEAD 5b8a1f7):** requirements.txt → edgeless
  graph → v0.1 inventory JSON; `calculate_phei` == 6.0 on a **one-off synthetic** 3-node
  unit chain A→B→C (2 unit-weight edges × 3 nodes = 6.0), verified by running the current
  code — the reusable `examples/fixtures/known_topology.json` has **not** been added yet
  (W1-DE-01.L, Vale). PHEI is invariant to CVE severity; `report_generator` uses the wrong
  (global-sum) formula; `serialize_inventory` emits only the v0.1 fields
  (no `advisory_source`); pytest 79 passed
  (test_harness collects 0); `httpx` undeclared.
- **Proposed (M-DE-CORE, not yet in repo):** known-topology loader, Mode B serializer,
  `src/cli.py`, `src/dashboard/view.py`, the two fixtures, `examples/fixtures/sample_risk_report.json`,
  `tests/test_e2e_risk.py`, `docs/E2E_EXPECTED_RESULTS.md`. **No out-of-spec fields are
  emitted this week:** v0.1 defines no risk-path field, so `top_risk_path` is **deferred
  to a separate schema decision** (not emitted, rendered, or asserted). All emitted
  fields are spec-defined v0.1 fields; the known-topology input is a JSON file, so it
  uses `input.type = file`, `input.format = "synthetic-graph"` (both spec-supported;
  the committed demo uses `synthetic-graph`).
  Emitted (spec-backed): `findings[].id`, `findings[].advisory_source`
  (`synthetic-fixture`), `findings[].severity = null`. `vulnerability_lookup.matched` =
  distinct package IDs with at least one finding. Deferred: `packages[].risk_score`
  (node-level PHEI undefined). `risk.status` uses the spec enum `available`/`unavailable`.
- **Unverified / pending:** that the new Mode B serializer emits 6.0 end-to-end (not
  yet built); severity-in-score (open, Vale); Bandit course mandate (UNKNOWN).

> Test counts in this file are **historical** unless re-run and re-recorded. No completion
> percentages are reported.
