# RECON-DG — Dependency Risk Mapper

**Scope:** recon-dg is a **dependency risk mapper**. One command takes a project and:
(1) scans it into a dependency graph (which third-party packages are used and how
they connect), (2) checks each package for known CVEs (NVD + OSV), (3) scores
*systemic* risk — whether low-severity flaws combine along critical dependency
paths into a real threat (PHEI path-max) — (4) displays the results in a dashboard,
and (5) explains each finding in plain language via an AI backend.

**Intended full pipeline (the December deliverable — *planned; not all of it is
implemented yet*):** the (1)–(5) steps above are the full intended pipeline.

**What works this week (M-DE-CORE):** the Mode A **inventory serializer**
(`src/reporter/inventory.py`), the **PHEI** path-max function
(`calculate_phei` in `src/engine/risk_analyzer.py`), the before/after
**report generator** (`src/reporter/report_generator.py`), and a new **agent
layer** (`src/agent/`) that runs a bounded, evidence-grounded investigation over
a normalized OSV-Scanner scan (see "Agent layer" below). The **Mode B**
dependency-graph serializer and the synthetic reference `report.json` are still
*planned* deliverables, not yet working features. Earlier verification results
(e.g., PHEI == 6.0 on a synthetic 3-node unit chain, and the "pytest 79 passed"
count) are **historical** — they date to an earlier commit. Re-running the full
suite this week gives **205 passed, 2 warnings, 29 subtests** (test_harness collects 0
tests for the parked Bandit sub-track). Steps (2) live NVD/OSV, (4) the
dashboard, and (5) a *real* AI model backend are **planned** and not yet
running; the agent below runs fully without a model via a deterministic policy.

**Core track (December deliverable):** dependency inventory → CVE enrichment →
deterministic risk analysis → reporting → dashboard → AI explanations.
*As of this week the inventory serializer, the PHEI function, the report
generator, and the agent layer (`src/agent/`) are in the tree and tested; the
Mode B serializer + synthetic `report.json`, live NVD/OSV, the dashboard, and a
real AI model backend are not yet implemented.*

**Supporting sub-track:** a Bandit source-code static-analysis prototype that finds
vulnerabilities *inside the code scanned* (a useful extra signal and a pipeline/harness
exercise). It must stay separate from dependency findings and must not displace the
core track.

## Getting started (read this first)

- **`docs/TEAM_ONBOARDING.md`** — how to clone the repo and set up **your own computer**
  (Git + Python checks, a personal branch, a virtual environment, and how to validate
  your JSON fixtures). It defines the ten terms you will meet and gives separate
  PowerShell / terminal routes.
- **`docs/WEEKLY.md`** — this week's (M-DE-CORE) focus, acceptance criteria, and the
  **current** M-DE-CORE handoffs. It tells you which handoff is *active this week*.
- **`TASKS.md`** — the task register (stable IDs), phase plans, and the shared
  source-audit contract.
- **`docs/STATUS.md`** — the current state (date, branch/HEAD, working-tree state).

## Two tracks — do not conflate

| | Core (December deliverable) | Supporting (source-audit) |
|---|---|---|
| Question | Which dependencies are risky, and how bad? | What vulnerabilities does the code contain? |
| Engine | NVD/OSV + PHEI graph scoring | Bandit static analysis |
| Location | `src/parser`, `src/models`, `src/engine`, `src/reporter`, `src/agent`, dashboard | `examples/source-audit-week1/`, `src/scanner/` |
| Output | dependency risk score + CVE findings (risk paths are deferred per the open path-field schema decision) | source-code findings (kept separate) |

## Agent layer

`src/agent/` is the *agentic* heart of the dependency-risk mapper. It is deliberately **not**
"OSV-Scanner with an LLM summary." The agent:

- operates on the **real** OSV-Scanner output, normalized into the repo's
  `DependencyGraph` + first-class `Finding` objects (`src/agent/normalizer.py`);
- runs a **bounded** loop — a `max_turns` hard cap *plus* a natural stopping rule
  (all high-severity findings investigated, risk computed, summary emitted);
- makes a **conditional** tool choice each turn, deciding from its own state
  (which findings exist, which are high-severity, whether topology is known);
- records **every** tool call — tool name, arguments, and the structured
  observation — into an append-only **`EvidenceTrail`**. That trail is the
  observable artifact a reviewer, dashboard, or downstream AI reads to audit *why*
  each conclusion was drawn;
- **never invents data.** Every claim about a finding is backed by a field from the
  OSV-Scanner output (id, advisory, CVSS, affected range, published date).

A pluggable ``llm`` callable may steer tool selection (the product's AI backend),
but it can only pick from an **allowlisted** tool set and must return valid
arguments; if it returns anything out of band, the agent falls back to a
grounded deterministic policy and records that fallback in the trail. This keeps
the agent fully functional with **no model** (deterministic policy) while a real
model can steer it when one is available — and keeps the *evidence* grounded
either way.

| Tool | Args | Observation |
|------|------|-------------|
| `findings` | — | all findings (count + ids) |
| `get_finding` | `vulnerability_id` | one `Finding` as dict |
| `package_info` | `package_name`, `version` | vulnerabilities for a package node |
| `package_context` | `package_name`, `version` (opt `ecosystem`, `vulnerability_id`) | deps.dev published context, labelled `generic_published`; strictly additive, review-only |
| `high_severity` | `threshold` | high-severity findings only |
| `risk_score` | — | PHEI path-max, or `"unavailable"` |
| `summary` | — | plain-language narrative |
| `stop` | `reason` | terminal |

`compare_scans(before, after)` produces the before/after delta (new / resolved /
unchanged findings + the PHEI risk delta, skipped when topology is unavailable).

The agent layer also carries a **remediation** stage, wired through the pipeline
(`src/agent/pipeline.py`, `investigate` / `investigate_from_json` with an optional
`after_scan_report`):

- **`build_remediation_plan(scan)`** — a *pure* function (no manifest edits, no
  installs, no network, no scoring) that emits one item per baseline finding.  Each
  item preserves the advisory ID + aliases, the package, the installed version, the
  affected range, the scanner-provided **fixed versions verbatim** (never
  "latest"/"best" and never invented), an explicit `has_fixed_version` flag, and the
  severity *evidence only* (`severity_score` left `None`; scheme types + vector
  strings preserved).  It never computes or implies a numeric CVSS score or a
  high/low category.  A plain recommended action names the scanner's fixed version
  when one exists and otherwise says a specific target cannot be asserted.
- **`verify_remediation(before_scan, plan, after_scan=None)`** — reconciles that
  plan against a **user-supplied** after scan (no network; the caller supplies the
  scan).  With **no after scan** it returns `status == "not_run"` and makes **no
  resolution claim** and asserts no fix.  With an after scan it classifies each
  plan item on the `(package, version, vulnerability_id)` key: same version in the
  after scan = `unchanged` (never counted as fixed); key absent = `resolved`; same
  advisory at a *different* version = `regressed`.  Findings new in the after scan
  that were not in the plan are counted via the existing comparison and reported as
  `new_count`, **not** attributed to the plan.  Risk/PHEI is preserved from the
  comparison and is left `unavailable` when topology is unavailable — no edges or
  scores are invented.  Verification appends a step to the caller's `EvidenceTrail`
  (and always carries its own auditable `evidence`) so that "verification ran
  (or was requested but had no after scan)" is on the record.
- A **malformed, missing, or unusable** after report fails closed to
  `status == "not_run"` and makes no resolution claim; the baseline investigation is
  always preserved.

**Status.** Implemented and tested (45 passing tests in `tests/test_agent.py`
plus 24 in `tests/test_remediation.py`),
plus an opt-in **deps.dev enrichment** layer (`src/enrichment/`, stdlib-only,
26 passing tests in `tests/test_enrichment.py`) that exposes a new
`package_context` tool (published, resolved, labelled `generic_published`;
additive, never fed to PHEI scoring). It runs fully **without** a model via the
deterministic policy. On the checked-in flat fixture (`tests/data/osv-scanner.json`:
5 findings, 4 packages, 0 edges) a 7-turn run reports `risk.status == "unavailable"`,
`risk.score is None`, with the message *"No score is fabricated; this is an
inventory-only result"* — no invented edges, no invented score, consistent with
the inventory-only contract. Wiring a **real** model backend (local llama.cpp
endpoint vs. user-provided API key) is a pending decision (see `TASKS.md`), not
not yet implemented. Full suite: **205 passed, 2 warnings, 29 subtests**.

## Key documents

- [docs/TEAM_ONBOARDING.md](docs/TEAM_ONBOARDING.md) — beginner setup on your own machine (read first)
- [AGENTS.md](AGENTS.md) — startup/completion routine, evidence rules, routing
- [TASKS.md](TASKS.md) — task register, phase plans, shared source-audit contract
- [docs/STATUS.md](docs/STATUS.md) — current state (date, branch/HEAD, working tree)
- [docs/WEEKLY.md](docs/WEEKLY.md) — weekly focus and acceptance criteria
- **Current (M-DE-CORE, this week — active first):**
  - `HANDOFF_NICK_MDECORE.md` — Nick · fixtures + limitations note (T-DE-01/02)
  - `HANDOFF_CHRISTIAN_MDECORE.md` — Christian · offline tests + expected results (T-DE-02/03)
  - `HANDOFF_VALE_MDECORE.md` — Vale · loader, PHEI/report integration, reference output (T-DE-01/02/03)
  - `HANDOFF_ALIYAN_MDECORE.md` — Aliyan (provisional) · static viewer spike (T-DE-04)
- **Supporting (source-audit, parked / non-gating this week — NOT the December deliverable):**
  - The Bandit handoff files (`HANDOFF_NICK.md` / `HANDOFF_CHRISTIAN.md`) were removed this week.
    Their task descriptions remain in `TASKS.md` (T-SA-01 / T-SA-02 / T-SA-03) and the shared
    contract in `examples/source-audit-week1/RECON-DG_MONTH1_ROADMAP.md`. Read those only if you
    are on the source-audit track.
- [examples/source-audit-week1/RECON-DG_MONTH1_ROADMAP.md](examples/source-audit-week1/RECON-DG_MONTH1_ROADMAP.md)
  — source-audit roadmap (includes the verified shared contract)

> **Read the current handoff first.** `docs/WEEKLY.md` says which handoff is active
> for the current week; the `HANDOFF_*_MDECORE.md` files are this week's. The older
> source-audit handoffs (`HANDOFF_NICK.md` / `HANDOFF_CHRISTIAN.md`) were removed this
> week (Bandit track **parked / non-gating this week**); their content lives in
> `TASKS.md` and the Month-1 roadmap. Do not treat it as the December deliverable.

## Verified shared contract (source audit)

Read `examples/source-audit-week1/RECON-DG_MONTH1_ROADMAP.md` §"Shared contract"
before touching scanner, config, or harness code:

- **Rule ID lives in JSON `test_id`, never `test_name`** (whose value varies by
  rule/version).
- **Exit codes:** `rc=5` does not exist; `0` = clean, `1` = findings, `2` = internal
  error, `3` = unknown. Any `rc >= 2` is an **error**, never "0 vulnerabilities."
- **A clean scan is composite:** `rc=0` **and** valid JSON **and** empty `results`
  **and** empty `errors`. `rc=0` alone is not proof of success (a missing file also
  returns `rc=0` with `errors` populated).
- **CLI:** `bandit -f json -t <bare_rule_id> <file.py>`. `-ll` is a *valid* severity
  filter (medium-or-higher only) and is omitted so low-severity findings are measured.
- **Rules:** B307 = eval/exec, B301 = pickle deserialization, B602 = shell command
  injection (NOT `os.system` — that is B605), B608 = SQL injection, B704 =
  markupsafe XSS (NOT deserialization).
- **Eight cases, four tested rules:** the harness (T-SA-03) tests B307, B301, B602,
  B608 — each vulnerable and secure (4 × 2 = 8). B704 is not tested in the 8-case
  harness.
