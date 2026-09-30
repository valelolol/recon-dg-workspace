# RECON-DG — Dependency Risk Mapper

**Scope:** recon-dg is a **dependency risk mapper**. One command takes a project and:
(1) scans it into a dependency graph (which third-party packages are used and how
they connect), (2) checks each package for known CVEs (NVD + OSV), (3) scores
*systemic* risk — whether low-severity flaws combine along critical dependency
paths into a real threat (PHEI path-max) — (4) displays the results in a dashboard,
and (5) explains each finding in plain language via an AI backend.

**Core track (December deliverable):** dependency inventory → CVE enrichment →
deterministic risk analysis → reporting → dashboard → AI explanations.

**Supporting sub-track:** a Bandit source-code static-analysis prototype that finds
vulnerabilities *inside the code scanned* (a useful extra signal and a pipeline/harness
exercise). It must stay separate from dependency findings and must not displace the
core track.

## Key documents

- [AGENTS.md](AGENTS.md) — startup/completion routine, evidence rules, routing
- [TASKS.md](TASKS.md) — task register, phase plans, shared source-audit contract
- [docs/STATUS.md](docs/STATUS.md) — current state (date, branch/HEAD, working tree)
- [docs/WEEKLY.md](docs/WEEKLY.md) — weekly focus and acceptance criteria
- [HANDOFF_NICK.md](HANDOFF_NICK.md) — active teammate instructions (T-SA-02)
- [HANDOFF_CHRISTIAN.md](HANDOFF_CHRISTIAN.md) — active teammate instructions (T-SA-03)
- `examples/source-audit-week1/RECON-DG_MONTH1_ROADMAP.md` — source-audit roadmap
  (includes the verified shared contract)

## Two tracks — do not conflate

| | Core (December deliverable) | Supporting (source-audit) |
|---|---|---|
| Question | Which dependencies are risky, and how bad? | What vulnerabilities does the code contain? |
| Engine | NVD/OSV + PHEI graph scoring | Bandit static analysis |
| Location | `src/parser`, `src/models`, `src/engine`, `src/reporter`, `src/agent`, dashboard | `examples/source-audit-week1/`, `src/scanner/` |
| Output | dependency risk paths + CVE findings | source-code findings (kept separate) |

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
