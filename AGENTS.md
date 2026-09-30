# RECON-DG working instructions

## Startup routine
- Verify hostname, working directory, branch, HEAD, and git status (see "Workspace and routing").
- Read `docs/STATUS.md` for current state, then the relevant `TASKS.md` task **by stable
  ID** for acceptance criteria, dependencies, and evidence.
- Consult `ARCHITECTURE.md` and `DECISIONS.md` when the work touches the graph schema,
  PHEI scoring, the reporter contract, or the core/supporting split.
- Confirm the task ID and owner before editing; do not start unassigned work.
- Scope changes (new deliverables, new tracks, new owners) **require user approval**
  before starting.

## Completion routine
- Record the actual change in the relevant `TASKS.md` task: status, acceptance-criteria
  check, and verification evidence (command + result, or "inspected in tree; not executed").
- Update `docs/STATUS.md`: date, branch/commit, working-tree state, and what changed.
  **Do not invent completion percentages or test counts.**
- If a test/scan result was not actually run this session, label the claim *historical*
  or *unverified*.
- Report: task outcome, changed files, verification command + result, unresolved issues,
  and the next bounded task.
- Do not commit or push unless the user asks.

## Workspace and routing
- Canonical working repository:
  /home/vale/projects/recon-dg-workspace on vale-llm.
- Before repository work, verify hostname, working directory,
  current branch, HEAD, and git status.
- Do not substitute downloaded archives, starter kits, another
  checkout, or GitHub's default branch for this workspace.
- Do not switch branches, merge, reset, commit, or push unless
  the user requests it.
- Preserve existing user changes.

## Project context
- Read applicable parent instructions and this file, then
  TASKS.md, DECISIONS.md, and relevant ARCHITECTURE.md sections.
- RECON-DG's primary track is dependency inventory, vulnerability
  enrichment, deterministic risk analysis, and reporting.
- The Bandit source-audit demonstration is a separate supporting
  track. Do not let it displace the primary task without instruction.
- Distinguish implemented, tested, planned, and unverified behavior.
- Resolve material conflicts between documents and code explicitly.
  Do not silently invent requirements or change the scoring formula.
- Treat LLM explanations separately from deterministic findings.
- Inventory-only input must not produce invented dependency edges; risk
  scoring requires explicitly "known" topology.

## Task execution
- Work on one bounded task with a clear acceptance criterion.
- Inspect relevant files before editing; avoid unrelated searches.
- Use the repository's existing environment and narrow checks first.
- If asked to fix a failing test, reproduce the failure first.
  If it passes, report that result instead of inventing a fix.
- Do not delegate unless explicitly authorized.
- Do not install tools or change model/server settings as part of
  repository work unless requested.

## Evidence and handoff
- A passing test establishes only what that test checks.
- Commit messages and documentation are not proof of implementation.
- Never claim a file was read or a command ran without actual evidence.
- Finish with: task outcome, changed files, verification command and
  result, unresolved issues, and the next bounded task if applicable.
- Never include credentials or authentication tokens in output.

## A2A
- A timeout does not prove the remote task stopped — never assume it did.
- Do **not** automatically resubmit an editing task after a timeout. First check
  the existing task/session and repository state, then re-submit only if the work
  is genuinely incomplete.
- Keep only one agent editing this workspace at a time.
