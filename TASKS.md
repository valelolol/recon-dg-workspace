# TASKS.md — Predictive Risk Mapping Agent

## Project Scope (December deliverable)

recon-dg is a **dependency risk mapper**. One command must, for a given project:

1. **Scan** → build a dependency graph (which third-party packages are used + how they
   connect).
2. **Check** → look up known CVEs for each package (NVD + OSV).
3. **Score systemic risk** → not "this package has a flaw," but whether low-severity
   flaws combine along critical dependency paths into a real threat (PHEI path-max).
4. **Display** → a clear dashboard showing the graph, per-package risk, and the top
   risk paths.
5. **Explain** → an AI backend that turns each finding into plain-language explanations
   and helps developers prioritize what to fix.

**Constraint:** inventory-only input must not produce invented dependency edges. Risk
scoring requires an explicitly "known" topology; with inventory-only input the edges
array stays empty and risk is unavailable.

### The two scanner tracks — do NOT conflate them
- **Core (December deliverable):** dependency/CVE assessment over the graph —
  `src/parser`, `src/models`, `src/engine`, `src/reporter`, `src/agent`, dashboard.
- **Supporting sub-track (Week 1):** source-code static analysis via Bandit —
  `examples/source-audit-week1/`, `src/scanner/`. It finds vulns *inside the code you*
  *scan* (a useful extra signal and a good pipeline/harness exercise). It is **not**
  the December deliverable and must stay **separate** from dependency findings.

### December-critical path (in order)
1. Parser: enough manifest formats to scan a real project.
2. Engine: wire NVD/OSV into the graph so **real** CVE data flows into PHEI.
3. Reporter: structured report schema + deterministic fallback.
4. Dashboard: web app (graph + risks + per-package risk).
5. AI explanations: `src/agent/` pluggable model layer (plain-language + prioritization).
6. Docker: portable image + local-dev compose.

## Task register

Stable IDs used by `docs/STATUS.md`, `docs/WEEKLY.md`, and the handoffs. "Unverified"
means a completion claim that is not yet backed by a run command or a passing test in
the tree — treat it as not done until verified.

| Task ID | Title | Track | Owner | Status | Depends on |
|---------|-------|-------|-------|--------|-----------|
| T-DE-01 | Parser: multi-format manifest support | Core | Vale | In progress | v0.1 contract (done) |
| T-DE-02 | Engine: real CVE lookups + PHEI reconciliation | Core | Vale | In progress | T-DE-01, T-DE-03 |
| T-DE-03 | Reporter schema + deterministic fallback | Core | Vale | In progress | T-DE-01, T-DE-02 |
| T-DE-04 | Dashboard: graph + risk + per-package view | Core | Aliyan (provisional) | Not started | T-DE-02, T-DE-03 |
| T-DE-05 | Docker packaging + local compose | Core | Team | Not started | T-DE-04 |
| T-SA-01 | Scanner pipeline (Bandit) → correct report | Supporting | Vale | In progress (unverified) | shared contract (done) |
| T-SA-02 | Check config + security-checks docs | Supporting | Nick | In progress (unverified) | shared contract (done) |
| T-SA-03 | Harness + example pairs + results table | Supporting | Christian | In progress (unverified) | T-SA-01, T-SA-02 |

Bandit handoff files (`HANDOFF_NICK.md`, `HANDOFF_CHRISTIAN.md`) were removed this week — the Bandit track is **parked / non-gating this week** and is not the December deliverable. Task descriptions remain in this file (T-SA-02 / T-SA-03 below) and the shared contract lives in `examples/source-audit-week1/RECON-DG_MONTH1_ROADMAP.md` §"Shared contract".

## M-DE-CORE — One-Week Core Dependency-Risk Report

> **Status:** the *plan* below is committed (HEAD `b4fc87c`). The *implementation* it
> describes (known-topology loader, Mode B serializer, `src/cli.py`, viewer, reference
> output, E2E test) is **not in the tree yet** — these are the deliverables the handoffs
> assign. Do not read any file below as "already built."

Goal: one command → a **v0.1 `report.json`** with **no live NVD/OSV calls**, in two
modes:
- **Mode A — inventory** (unchanged): `requirements.txt` → edgeless graph,
  `analysis_mode: inventory`, `topology_status: unavailable`, `edges: []`, risk unavailable.
  Acceptance: existing fields/behavior preserved and existing tests pass.
- **Mode B — dependency-graph** (new this week): a clearly-labeled synthetic
  `known_topology.json` + `cve_fixture.json` → graph with `edge_availability: known`
  → **topology-based PHEI** score (**6.0**) → `report.json` (packages, edges,
  `findings`, `vulnerability_lookup`, `warnings`) + a static HTML
  view (`report.html`, no framework).

**Score wording (all outputs must carry it):** *"This is a labeled synthetic
dependency-risk demo. Graph and CVE data are fictional fixtures. The PHEI score
6.0 is topology-based (edge weights × node multiplicity). Advisory severity is
unspecified — `findings[].severity` is `null` per v0.1 — and is NOT included in the
score because the edge-weight function w_uv is undefined (design_spec §3). This is a
topology PHEI report, not a complete vulnerability-risk score."*

**Out of scope this week:** live NVD/OSV, the full dashboard framework (Phase 4
Flask+D3 is T-DE-04's December meaning and is preserved, not rewritten — the viewer
is a provisional spike toward it), the AI layer, Docker, severity-in-score, and
LOW/MEDIUM/HIGH/CRITICAL labels (level thresholds deferred).

**Contract checkpoint C0 (sign before parallel work):** the Mode B field mapping below
and the **proposed input-fixture contract** (§ C0-prereq). All emitted fields are
spec-defined v0.1 fields — **no out-of-spec extension is emitted this week**; a
risk-path field (e.g. `top_risk_path`) is deferred to a separate schema decision.
Scope: C0 gates Nick's fixture authoring and the downstream fixture-consuming steps
(Vale's E2E + generated reference, Christian's running assertions, Aliyan's viewer)
— it does not gate drafting the loader/serializer/CLI or the handoff review (see
`docs/STATUS.md` §C0).

| Subtask | Parent | Owner | Owned file(s) — exactly one owner each | First checkpoint | Acceptance |
|---------|--------|-------|----------------------------------------|------------------|------------|
| W1-DE-01.F | T-DE-01 | Nick | `examples/fixtures/known_topology.json` | Fixture loads; 3 unique nodes, 2 directed unit-weight edges; labeled synthetic | Round-trips to a `known` graph; no duplicate IDs |
| W1-DE-02.S | T-DE-02 | Nick | `examples/fixtures/cve_fixture.json`, `docs/limitations.md` | Fixture loads; IDs `SYNTH-2026-xxxx`; limitations note names source + severity-not-in-score limit | Synthetic-labeled; no real identifiers |
| W1-DE-01.L | T-DE-01 | Vale | `src/parser/parser.py` | `load_known_topo_json()` → graph `edge_availability="known"`; correct nodes/edges/weights | `calculate_phei` on it == 6.0; `parse_requirements` untouched |
| W1-DE-02.R | T-DE-02 | Vale | `src/engine/risk_analyzer.py`, `src/reporter/report_generator.py` | `calculate_phei` returns the argmax scalar score (6.0); `generate_report` calls PHEI (path-max), not `calculate_systemic_risk` (global-sum); `w_uv` logged as OPEN | Score numerics preserved (6.0) and invariant to severity; no formula change/invented; no path field emitted; severity not in score |
| W1-DE-03.R | T-DE-03 | Vale | `src/reporter/inventory.py`, `src/cli.py`, `examples/fixtures/sample_risk_report.json` | `sample_risk_report.json`: `input.type=="file"`, `input.format=="synthetic-graph"`, `risk.score==6.0`, `method=="phei"`, 3 findings, synthetic-labeled, no path field | Matches v0.1; Mode A fields/behavior preserved + existing tests pass; offline, deterministic |
| W1-DE-04.V | T-DE-04 | Aliyan (provisional) | `src/dashboard/view.py` | `view.py <report.json>` → `report.html`: packages, edges, score, findings; **no level labels** | Data-driven; no framework; numeric score + status only |
| W1-DE-03.T | T-DE-02/03 | Christian | `tests/test_e2e_risk.py`, `docs/E2E_EXPECTED_RESULTS.md` | Passing offline test asserts the 6.0 reference (and no path field) | Deterministic: run twice with the same fixed scan_id and created_at and compare outputs |
| — | T-SA-01/02/03 | — | (unchanged) | — | **Non-gating this week; course requirement UNKNOWN (pending confirmation).** |

**Resolved field mapping (all spec-supported; see STATUS.md Verified/Proposed/Unverified):**
- `input = { type: file, filename: "known_topology.json", format:
  "synthetic-graph" }` — the known-topology case is a JSON file, so its `type` is
  `file`; `format` is a free string and `synthetic-graph` is a spec-valid value (the
  spec lists it as an example; the committed demo uses it). `type` is a separate
  field with enum `directory`/`lockfile`/`manual`/`file`.
- `analysis_mode: dependency_graph`, `topology_status: known`.
- `packages[]`: id, name, version, hash (null). `edges[]`: id, source_id, target_id,
  type (edge weight is an input consumed by PHEI, not an output field).
- `vulnerability_lookup`: `{ status, total_packages, checked_package_ids, matched }`
  only — **no `advisory_source`** in the lookup (it belongs on each finding, not the
  lookup). `matched` = the number of **distinct** package IDs with at least one finding
  — 3 here only because each of the 3 findings is on a different checked package.
- `findings[]`: one per synthetic advisory — required `id`, `package_id` (references a
  checked package), `advisory_source` (e.g. `synthetic-fixture`), `advisory_id`
  (`SYNTH-2026-xxxx`), `severity` **`null`** (v0.1 defines no severity values yet),
  `title`, `description` (marked synthetic). Synthetic findings are included; severity
  is unspecified and does not affect the score.
- `risk`: `{ status: available, score: 6.0, method: phei, reason }` — risk status enum
  is `available`/`unavailable` (NOT `complete`); `available` here because a numeric
  PHEI score is present. Reason: topology-based (edge weights × node multiplicity); severity
  is unspecified (`findings[].severity` is `null`) and is not in the score.
- **No path field emitted.** v0.1 defines no risk-path field; a risk-path (e.g. a
  `top_risk_path`) is **not** part of this week's report and is deferred to a
  separate schema decision. **`packages[].risk_score`: deferred** (node-level PHEI
  undefined; emitting it would require inventing a definition).
- `warnings[]`: carries (a) "CVE/advisory data is a synthetic fixture, not a live
  lookup; `findings[].severity` is unspecified (`null`) and not in the score; the edge-
  weight function w_uv is an open decision."

**PHEI argmax (how the 6.0 is obtained; no path field is emitted this week):**
`calculate_phei` computes each path's value as
`path_phei = sum_edge_weights(P) × impact_multiplicity(P)` and returns the scalar
maximum (`max_path_phei`). For the 3-node unit chain (A→B, B→C): 2 edges × 1.0 =
path weight 2.0, × 3 nodes = 6.0. The score is this argmax value, capped at 10.0,
and is invariant to CVE severity (severity is `null` per v0.1 and does not enter the
score).
`calculate_phei` returns **only the scalar score** — its return shape is **unchanged**.
v0.1 defines **no** risk-path field, so no path (e.g. a `top_risk_path`) is emitted,
rendered, or asserted in this week's report or tests. Any risk-path output is a
**proposed** out-of-spec addition to be decided separately (not this week); it is
deferred, not added.

### C0-prereq — Proposed input-fixture contract (APPROVAL REQUIRED before Nick authors)

There is **no committed input-fixture shape** in the repository yet (the spec and the
committed demo define only the *output* report; `examples/fixtures/` does not exist).
The shape below is **proposed** and must be **approved at C0** before Nick writes the
fixtures. Approval = an explicit user decision; do not treat this as agreed until then.

`examples/fixtures/known_topology.json` — known-topology *input* (not the output report):
```json
{
  "_demo_fixture": "Synthetic known-topology INPUT. Fictional packages; not a real dependency graph.",
  "packages": [
    { "id": "synth-a", "name": "synth-a", "version": "0.0.0" },
    { "id": "synth-b", "name": "synth-b", "version": "0.0.0" },
    { "id": "synth-c", "name": "synth-c", "version": "0.0.0" }
  ],
  "edges": [
    { "id": "e1", "source": "synth-a", "target": "synth-b", "weight": 1.0 },
    { "id": "e2", "source": "synth-b", "target": "synth-c", "weight": 1.0 }
  ]
}
```

`examples/fixtures/cve_fixture.json` — synthetic advisory *input*:
```json
{
  "_demo_fixture": "Synthetic advisory INPUT. Fictional advisories; not real CVEs.",
  "advisories": [
    {
      "id": "SYNTH-2026-0001",
      "package_id": "synth-a",
      "title": "Synthetic advisory A",
      "description": "Synthetic example advisory for synth-a. Not a real vulnerability."
    },
    {
      "id": "SYNTH-2026-0002",
      "package_id": "synth-b",
      "title": "Synthetic advisory B",
      "description": "Synthetic example advisory for synth-b. Not a real vulnerability."
    },
    {
      "id": "SYNTH-2026-0003",
      "package_id": "synth-c",
      "title": "Synthetic advisory C",
      "description": "Synthetic example advisory for synth-c. Not a real vulnerability."
    }
  ]
}
```

**Rules for the proposed shape:**
- **Packages** `packages[]`: each has `id` (unique string), `name`, `version`. The
  *output* report uses a *separate* `packages` shape (see the spec) — these two
  `packages` arrays are **distinct** (input vs output); do not conflate them.
- **Edges** `edges[]`: each has `id`, `source`, `target` (each references a package
  `id` in `packages[]`), and `weight` (number; unit weight `1.0`). Three packages,
  two directed unit-weight edges (`a→b`, `b→c`) is the intended chain.
- **Advisories** `advisories[]`: each has `id` (form `SYNTH-2026-XXXX`, all unique),
  `package_id` (references a package `id` in the topology), `title`, `description`.
  Three advisories, one per package (synth-a, synth-b, synth-c).
- **Required:** `_demo_fixture` (synthetic label), and, per item above, the fields
  listed. **Uniqueness:** package `id`s unique; edge `id`s unique; advisory `id`s
  unique. **Invalid references:** an edge `source`/`target` or an advisory
  `package_id` must name an existing package `id`; otherwise the loader must reject
  it (do not invent the package).
- **No real identifiers:** no real CVE numbers, package versions, or advisory IDs.

> **Not a loader promise:** nothing in the tree currently accepts this shape. `load_known_topo_json()`
> is *proposed* (W1-DE-01.L, Vale) and does not exist yet. This contract only defines what Nick's
> input fixtures *should* look like once the shape is approved.

## Supporting sub-track: Source-Audit / Bandit (Week 1, NOT the December core)

Kept separate from dependency findings. See `examples/source-audit-week1/` and
`src/scanner/bandit_config.py`. Month-1 scope:

- **T-SA-01 Vale** — scanner: one command `python scan_demo.py <input> <output.json>`
  writes valid JSON; each finding has `rule_id` (from `test_id`, never `test_name`),
  `filename`, `line_number`, 1-line evidence, severity, confidence, `fix_suggestion`.
  Move the working wrapper into `src/scanner/`. Move the working logic into the canonical
  module rather than leaving it only in `examples/`.
  - [ ] Fix the `NameError` in `scan_demo.py` (`venv_path` defined once at top of `main()`).
  - [ ] Rewrite the Bandit command: drop `-r .` and `-ll`; use
    `[bandit, "-f", "json", "-t", check_id, str(source_path)]`.
  - [ ] Exit-code semantics: `rc=1` = findings, `rc=0` = clean, `rc>=2` = error.
  - [ ] Read `test_id`, not `test_name`, into `Finding.rule_id`.
  - [ ] Add the evidence snippet from the finding's `line_range`.
  - [ ] Run all four checks (B307, B301, B602, B608); aggregate into one report.
  - [ ] Verify against the eval pair (B307 found / safe pair clean) and the pickle
    pair (B301 found / safe pair clean); confirm `rule_id` = `"B307"`/`"B301"`.
  - Evidence: **unverified** — `scan_demo.py` currently crashes (`NameError: venv_path`);
    `multi_check_wrapper.py` runs and catches the eval finding but writes
    `rule_id="blacklist"` and uses rc=5. Claims below are *not* from a fresh run this
    session.

- **T-SA-02 Nick** — `bandit_config.py` rule mapping + `docs/security-checks.md`:
  correct shell→B602, deserialization→B301, B704=markupsafe XSS (not deser); write
  per-check expectations (catches / doesn't catch / false-positives / one-line fix).
  (No active handoff file — Bandit track is **parked / non-gating this week**; the T-SA-02 description is this section, and the shared contract is in `examples/source-audit-week1/RECON-DG_MONTH1_ROADMAP.md`.)
  - [ ] B608 block: SQL **only** → `["B608:sql-injection"]`; rename to
    "SQL Injection" (shell is a separate check, B602).
  - [ ] B704 block: this is **markupsafe XSS**, not deserialization. Delete it (3
    categories) or replace with the real `B704:markupsafe-unsafe` entry (4th category).
  - [ ] B602 block: keep the rules; rename `name` to "Shell Command Injection".
  - [ ] B301 block: correct — keep.
  - [ ] `CVE_EXAMPLES`: move the deser CVEs from the B704 key to B301.
  - [ ] `MITIGATION_PATTERNS`: fix the B704 key the same way.
  - [ ] `docs/security-checks.md`: Category 2 Shell `B608 → B602` (Bandit rule →
    `B602:subprocess-popen-no-shell-false`); Category 3 Deserialization `B704 → B301`
    (Bandit rule → `B301:python-unsafe-deserialization`); fix the summary table.
  - [ ] Record Bandit/Python version and the "rc=5 doesn't exist / rc=1=findings"
    contract in `docs/limitations.md`.
  - Evidence: **unverified** — config and docs still carry the backwards mapping; not
    run this session.

- **T-SA-03 Christian** — `tests/test_harness.py` + example pairs + results table:
  fix path / `-ll` flag / B704→B301; assert on `test_id` (never `test_name`); add
  shell/B602 + SQL/B608 pairs; cover the 4 tested rules (B307, B301, B602, B608)
  as 8 vulnerable/secure cases, plus unsupported-rule→error; build the evidence
  table; prove the 3 Month-1 checks (vuln→finding, safe→none, unsupported→error).
  (No active handoff file — Bandit track is **parked / non-gating this week**; the T-SA-03 description is this section, and the shared contract is in `examples/source-audit-week1/RECON-DG_MONTH1_ROADMAP.md`.)
  - [ ] Fix examples path: `Path(__file__).parent.parent / "examples" /
    "source-audit-week1"`.
  - [ ] Fix `run_scanner`: drop `-ll`, drop `check=True`, read `test_id`, handle
    exit codes per the contract (rc≥2 → raise error).
  - [ ] Write `status` key and call `_calculate_status`.
  - [ ] Register 8 cases (4 rules × vulnerable/secure): B307, B301, B602, B608.
  - [ ] Add `vulnerable_example_shell.py`/`safer_example_shell.py` (B602) and
    `vulnerable_example_sql.py`/`safer_example_sql.py` (B608).
  - [ ] Run harness; table shows TP/FP/FN/TN and accuracy; `test_results.json` has
    per-row `status`; rc≥2 reported as error, never as "0 vulns."
  - Evidence: **unverified** — harness does not run (wrong examples path + invalid
    `-ll` + expects B704 for pickle).

### Shared source-audit contract (single source of truth)
- **Rule = JSON `test_id`.** `test_name` is **not** a reliable rule ID — its value
  varies by rule/version (e.g. `blacklist` for B307/B301,
  `subprocess_popen_with_shell_equals_true` for B602,
  `hardcoded_sql_expressions` for B608). Never read the rule from `test_name`.
- **Exit codes — `rc=5` does NOT exist:** `0`=clean (missing file → rc=0 with `errors`
  populated) · `1`=**findings** · `2`=internal error · `3`=unknown.
- **Any rc ≥ 2 = error state — report it; NEVER turn it into "0 vulnerabilities."**
- **"Clean" is composite, not just `rc=0`:** a scan is clean only when the process
  result AND the JSON agree — `rc=0` **and** valid JSON **and** an empty `results`
  list **and** no entries in `errors`. A missing file also returns `rc=0` (with
  `errors` populated), so `rc=0` alone is **not** proof of success.
- **CLI shape (bare rule IDs only):** `bandit -f json -t B602 /path/to/file.py`
  (`-c` is `--config-file` (INI), not a rule. `-ll` *is* a valid severity filter —
  it reports **medium-or-higher** only and **omits low-severity findings** — so it
  is omitted here; use no severity flag when low-severity findings must be measured.)
- **Canonical rule table (Bandit 1.9.4, verified):** B307=eval/exec, B301=pickle
  deserialization, B602=shell command injection (NOT `os.system` — that is B605),
  B608=SQL injection, B704=markupsafe XSS (NOT deserialization).
- **Four tested rules vs eight cases:** the 8-case harness (T-SA-03) tests the four
  rules B307, B301, B602, B608 — each vulnerable and secure (4 × 2 = 8). B704 is a
  fifth rule in the table but is **not** tested in the 8-case harness; do not
  describe the harness as "5 rules."

## Phase 1: Parser (Multi-format Manifest Support) — December-critical → T-DE-01
Owner: Vale. Depends: shared `DependencyGraph` IR (T-DE-03 schema).
- [x] Parse `requirements.txt` (`package==version`) — `src/parser/parser.py:7–57`
- [x] `build_mock_graph()` test helper — `src/parser/parser.py:59–75`
- [ ] Add `package.json` (JSON) parser via `json` module
- [ ] Add `pyproject.toml` / `setup.cfg` parser via `tomllib`
- [ ] Add `go.mod` / `Gopfile.lock` parser
- [ ] Add `Cargo.toml` / `Cargo.lock` parser
- [ ] Add `Gemfile` / `package-lock.json` parsers
- [ ] Normalize all formats into shared `DependencyGraph` IR
- [x] Tests: `tests/test_parser.py` (mock graph + file read)

## Phase 2: Engine (Real CVE Lookups + PHEI Reconciliation) — December-critical → T-DE-02
Owner: Vale. Depends: parser (T-DE-01), reporter schema (T-DE-03).
- [x] PHEI path-max scoring implemented in `src/engine/risk_analyzer.py`
  (replaces the old global-sum; resolves the path-max vs global-sum divergence)
- [ ] Wire NVD API client into the graph so `get_cve_severity(node_key)` returns real data
- [ ] OSV API fallback for ecosystems not in NVD (npm, PyPI, Go, Rust)
- [ ] Severity normalization (NVD CVSS ↔ OSV severity ↔ PHEI scale)
- [ ] Rate-limiting / retry / exponential backoff for API clients
- [ ] Update `tests/test_risk_analyzer.py` with mocked API responses
- [ ] Run PHEI end-to-end on a **real** project (currently only code, unverified)

## Phase 3: Reporter & Agent Layer — December-critical → T-DE-03
Owner: Vale. Depends: engine (T-DE-02).
- [x] Structured output schema: `RiskReport` dataclass + `src/reporter/interface.py`
  (v0.1 contract: `docs/specs/scan-result-v0.1.md`; inventory serializer implemented,
  dependency-graph serializer **unimplemented**)
- [ ] Agree graph construction + scoring semantics; export graph adjacency for dashboard
- [ ] Generate dependency risk-path summaries using the agreed scoring contract
- [ ] Produce plain-language risk narratives per component
- [ ] **AI layer (`src/agent/`):** pluggable model backend (local endpoint or API key),
  grounded in the structured report + before/after risk diff — **not started**
- [ ] Deterministic plain-language fallback when no model is configured / generation fails
- [ ] Tests: `tests/test_reporter.py`, `tests/test_agent.py`

## Phase 4: Dashboard — December-critical (the visible deliverable) → T-DE-04
Owner: Team. Depends: engine (T-DE-02) + reporter (T-DE-03).
- [ ] Create `src/dashboard/` — lightweight web app (Flask + D3 recommended for speed)
- [ ] REST endpoints: `/risk`, `/graph`, `/paths/<node>`
- [ ] Interactive graph visualization (D3.js / Cytoscape.js)
- [ ] Real-time risk score display with trend history
- [ ] Filter by ecosystem, severity threshold, node criticality

## Phase 5: Docker Packaging — December deliverable → T-DE-05
Owner: Team. Depends: dashboard (T-DE-04).
- [ ] Write `Dockerfile` — multi-stage build (builder → runtime)
- [ ] Write `docker-compose.yml` for local dev stack (app + optional DB)
- [ ] Add `.dockerignore` and `requirements.txt` for image
- [ ] Test containerized run against sample manifests
- [ ] Document `docker compose up` deployment steps

## Status

### Current baseline (published HEAD `b4fc87c`, 2026-10-02)
- **Date:** 2026-10-02 (UTC). **Branch:** `feat/inventory-report`. **HEAD:** `b4fc87c`
  ("docs: correct Aliyan handoff schema/path and baseline dates").
- **Prior baseline (historical):** `6323285` ("docs: publish current team handoffs and
  clean up obsolete guidance", 2026-10-02) and `1524425` ("Publish reviewed M-DE-CORE
  plan and four handoffs", 2026-10-01) — both docs-only commits that published the plan
  and the four handoffs; implementation code was unchanged by either.
- **Working tree:** currently **dirty** — **7 files are modified** (this review's
  documentation corrections) and **nothing is staged**; the edits are uncommitted.
  (As of the committed tip `b4fc87c` the tree was clean, with those docs committed
  and pushed.)
- **Remote:** the local `origin/feat/inventory-report` tracking ref matches HEAD at
  `b4fc87c`; verified this session (the push succeeded and the local remote-tracking
  ref equals HEAD).
- **This session:** documentation only (see `docs/STATUS.md` for the exact file list).
  Those edits were **committed in `b4fc87c`**.

### Implementation state (last implementation change at HEAD c548f32 — the NVD/reporter/
scanner scaffolding commit; the state below was last independently confirmed at the
historical verification point `5b8a1f7` and is unchanged by the handoff commit at
1524425 and the docs-only commits `6323285` and `b4fc87c`)
- **Parser (T-DE-01):** `requirements.txt` done (1 of ~6 manifest formats).
- **Engine (T-DE-02):** PHEI path-max scoring implemented
  (`calculate_path_weight` / `calculate_impact_multiplicity` / `calculate_phei`) +
  `UnavailableTopologyError` guard. NVD/OSV client code present
  (`src/engine/nvd_client.py`) but **not yet run end-to-end** against a real project;
  `tests/test_nvd_integration.py` was reported failing in an earlier session (see
  `docs/STATUS.md` for the unverified count).
- **Reporter (T-DE-03):** `RiskReport` dataclass + `src/reporter/interface.py` +
  `report_generator.py` present. Inventory serializer implemented; **dependency-graph
  serializer unimplemented**; **no dashboard yet**.
- **Agent (T-DE-03 AI layer):** empty — not started.
- **Source-audit (T-SA-01/02/03):** `multi_check_wrapper.py` runs and detects the eval
  finding but mislabels `rule_id` (`"blacklist"` instead of `B307`) and has a char-count
  bug (`"1474 results"`); `scan_demo.py` crashes (`NameError: venv_path`);
  `test_harness.py` does not run. Corrections in flight — **Nick** = rule mapping +
  `docs/security-checks.md` (T-SA-02); **Christian** = harness (path, `-ll` flag,
  B704→B301, 4 tested rules / 8 cases) + new shell/B602 & SQL/B608 example pairs (T-SA-03).
  This is the supporting track, **not** the December deliverable.

> Test counts are **historical** unless re-run: an earlier note recorded "pytest 79 passed";
> the T-DE-02 NVD integration suite was reported failing in the same window. Do not quote
> these as current without re-running.

## Unresolved technical contradictions (do not guess)
1. **Exit-code claim:** `examples/source-audit-week1/README.md` states B307 findings
   produce "exit code 5". The shared contract (and Bandit 1.9.4) says rc=5 does not
   exist; rc=1 = findings. Which semantics the *scanner* itself (not Bandit) will use is
   not decided. **Unresolved.**
2. **Test-count discrepancy:** WEEK1 doc says "79 passed"; TASKS status says
   "7 of 79" failing; an earlier note says 68 pass / 7 fail. No test run this session
   can confirm. **Unverified.**
3. **Dashboard stack:** Flask+D3 (recommended in TASKS/ARCHITECTURE) vs. other options.
   **Unresolved — needs user decision (see docs/WEEKLY.md).**
