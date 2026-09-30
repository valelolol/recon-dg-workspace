# STATUS — Recon-DG

**Date:** 2026-09-30 (UTC)
**Host:** vale-llm
**Branch / HEAD:** `feat/inventory-report` / `f2303ee` (base at the start of this
documentation cleanup; this commit adds the reconciliation on top of it)
**Working tree:** clean at checkout (fetched and fast-forwardable; no local changes).
This review edits documentation only — no scanner, test, example-pair, or
teammate-deliverable files. It removes the two obsolete root handoffs
(`HANDOFF_WEEK1_NICK_CHRISTIAN.md`, `WEEK1_DELIVERABLES_AND_PLAN.md`), adds a root
`README.md`, and aligns the shared-contract statements (test_id vs test_name, the
`-ll` severity floor, the clean-scan definition, 4 tested rules vs 8 cases, and
os.system=B605 not B602).

## Scope
RECON-DG identifies project dependencies, checks known vulnerabilities (NVD + OSV),
uses actual dependency relationships when available, and helps developers prioritize
findings via deterministic PHEI risk analysis. The December prototype includes a clear
dashboard and AI explanations grounded in the findings. Inventory-only input must not
produce invented dependency edges; risk scoring requires explicitly "known" topology.
Bandit source auditing is a supporting sub-track, not the deliverable.

## Evidence-supported progress
- **Parser (T-DE-01):** `requirements.txt` parsing implemented, with `build_mock_graph()`
  helper. Other manifest formats: not started.
- **Engine (T-DE-02):** PHEI path-max scoring implemented in `src/engine/risk_analyzer.py`
  with `UnavailableTopologyError` guard. NVD/OSV client present but **not run end-to-end**
  against a real project.
- **Reporter (T-DE-03):** `RiskReport` schema + `src/reporter/interface.py` present;
  inventory serializer implemented; dependency-graph serializer and AI layer
  (`src/agent/`) **not started**.
- **Source-audit (T-SA-01/02/03):** `multi_check_wrapper.py` detects the eval finding but
  writes `rule_id="blacklist"` (reads `test_name`) and uses rc=5; `scan_demo.py`
  crashes (`NameError: venv_path`); `test_harness.py` does not run.

## Blockers
- No live NVD/OSV integration test has been run this session.
- `tests/test_nvd_integration.py` reported failing earlier (68 pass / 7 fail, historical).
- No dashboard, no AI layer, no Docker yet.

## Pending decisions
1. **AI backend:** local model (llama.cpp) vs. user-provided API key?
2. **Dashboard stack:** Flask + D3.js (recommended) vs. FastAPI + React?
3. **Scanner exit-code semantics** (see TASKS.md unresolved #1): the scanner itself
   uses its own exit codes (0/1/2); Bandit's rc=1 = findings is separate. Clarify if
   needed for docs.

## Next bounded task
- **T-DE-02:** wire the NVD/OSV client into the graph so `get_cve_severity()` returns
  real data for `requirements.txt` inputs; run end-to-end against a real project and
  re-record the actual test result here.

> Test counts in this file are **historical** unless re-run and re-recorded. No
> completion percentages are reported.
