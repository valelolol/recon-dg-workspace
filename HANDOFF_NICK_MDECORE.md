# HANDOFF_NICK_MDECORE.md — Nick · M-DE-CORE fixtures (T-DE-01/02)
**Role this week:** author two clearly-labeled *synthetic* input fixtures and an honesty note that
makes it obvious the data is fictional and the score is topology-based.

> ## ⚠️ STATUS: BLOCKED on contract approval (C0) — do not finalize yet
> **This M-DE-CORE fixtures task is the one active assignment that is currently blocked.**
> The input-fixture *shape* you must author is **proposed, not approved** (TASKS.md §C0-prereq).
> Until the C0 contract is **explicitly approved**, you must **not** author or finalize the
> fixtures. You *can* prepare the supporting note in `docs/limitations.md` and the branch,
> but **stop before writing the two `.json` files** and send Vale the approval question
> (see §1).
>
> **This is NOT the same work as your Bandit / source-audit handoff.** Your supporting
> track task (T-SA-02 — Bandit rule config + `docs/security-checks.md`, described in the
> T-SA-02 section of `TASKS.md`) is **non-gating this week and can proceed independently**
> of the C0 approval. Do **not** conflate the two:
> - **Blocked / gated:** M-DE-CORE fixtures (`known_topology.json`, `cve_fixture.json`) →
>   requires **C0 approval first** (this file).
> - **Unblocked / non-gating:** Bandit source-audit rule config + docs (T-SA-02) → not
>   part of the December deliverable; runs in parallel, no C0 gate.
> Read the active M-DE-CORE handoff first (this file). If your team has you on the
> source-audit track instead, continue in the T-SA-02 section of `TASKS.md` (the
> `HANDOFF_NICK.md` source-audit handoff was removed this week — the Bandit sub-track is
> parked / non-gating and preserved in git history). Do **not** mix the two.

**Role this week (summary):** author two clearly-labeled *synthetic* input fixtures and an
honesty note that makes it obvious the data is fictional and the score is topology-based.

> **Read this once before touching anything:** your work is the *input* side of a small demo.
> You do **not** need the scanner, the CLI, a dashboard, a model, or a GPU. You do **not** need
> Vale's machine, Vale's username, or a live internet connection. All you need is Git + Python
> (see the shared setup in `docs/TEAM_ONBOARDING.md`).
>
> **One-time setup (do this once, before any step):** open a terminal, and follow
> `docs/TEAM_ONBOARDING.md` until you can confirm `git` and `python` work, you have a **local clone**
> of the repo in a folder you chose, and a working virtual environment (venv) is active in that
> folder. Use **only** the command route that matches your machine (Windows PowerShell *or*
> Linux/macOS terminal). Then create your personal branch (step 0 below). **Nothing here runs
> against any server.**
>
> ## Terms you'll meet
> - **repository (repo):** the shared project, a folder full of files tracked by Git.
> - **clone:** a complete copy of that repo made *on your computer* (from GitHub, not from
>   anyone else's machine).
> - **branch:** a named line of work. You do your work on a personal branch so it doesn't collide
>   with the shared integration branch.
> - **commit:** a saved checkpoint of your file changes.
> - **pull request (PR):** a request to fold your personal branch's changes into the shared
>   branch `feat/inventory-report`; a human reviews it.
> - **virtual environment (venv):** an isolated folder of Python packages so your machine's
>   Python isn't polluted.
> - **fixture:** a small piece of test data stored as a file (here, a JSON file).
> - **JSON:** a text format for structured data (key/value pairs, arrays).
> - **schema/contract:** the agreed rules describing what the data must look like.
> - **deterministic:** run the same steps, get byte-identical output.

## What you own (edit ONLY these)
- `examples/fixtures/known_topology.json` (new)
- `examples/fixtures/cve_fixture.json` (new)
- `docs/limitations.md` (existing — append one section)

**Do not change** `requirements.txt`, any code file, any test, or the scoring code.

## 0. Start your personal branch (after the one-time setup in TEAM_ONBOARDING.md)
First make sure your local copy is at the shared integration branch and clean:

```bash
# confirm where you are: inside your local clone's root, where README.md lives
git status                      # expect: no changes (if you see "modified:", see the "if your tree is dirty" note)
git branch                      # confirm you're on feat/inventory-report
```

If your tree is dirty (shows changed/untracked files) or your branch has diverged, **do not**
run `reset`, `pull --force`, or stash. Instead: run `git status --short` and `git branch -vv` and
send those outputs to Vale before proceeding. When it's clean, create your branch:

```bash
git switch -c feat/mdecore-nick-fixtures feat/inventory-report
```

Then make all file changes in **this** folder.

## 1. Wait for the C0 decision (important — do not guess the shape)
The *output* report shape is defined by `docs/specs/scan-result-v0.1.md`. The *input*
fixtures you author are **not yet defined in the code** — there is no committed loader that reads
them yet. `TASKS.md` §"C0-prereq — Proposed input-fixture contract" contains a **proposed**
minimal input shape (three synthetic packages, two unit-weight directed edges; three synthetic
advisories, one per package). **That proposed shape is NOT approved.** Approval is a C0
prerequisite and must be confirmed before you finalize the fixtures. If it has been confirmed,
author exactly to that shape. If it has **not** been confirmed, **stop at your first checkpoint**
(§4) and send Vale the question; do not invent a different shape on your own.

> **Why this matters:** Nick's fixtures are the input Vale's parser will consume. If you pick a
> shape the loader doesn't expect, the pipeline silently breaks. An explicit approval avoids that.

## 2. Author `examples/fixtures/known_topology.json` (W1-DE-01.F)
Create the folder if it doesn't exist (`examples/fixtures/`) and add a JSON file with **exactly
three unique packages** and **two directed unit-weight edges**, forming one chain. All identifiers
must be clearly synthetic (no real package names, no real CVE numbers). Use the proposed shape
from TASKS.md as the template (packages have `id`/`name`/`version`; edges have `id`/`source`/
`target`/`weight`), e.g. packages `synth-a` → `synth-b` → `synth-c` with edge weights `1.0`.

- **Do not** mix this up with the *output* report's `packages[]` — those two arrays are
  **different fields** (input vs. output).
- **Do not** add a `severity` anywhere. The finding's `severity` will be `null` (v0.1
  defines no severity values yet) and does **not** enter the score.

## 3. Author `examples/fixtures/cve_fixture.json` (W1-DE-02.S)
A file of synthetic advisories, one per package (synth-a, synth-b, synth-c). Each advisory has a
unique `advisory_id` in the form `SYNTH-2026-XXXX` and a description that explicitly says it is a
synthetic example. **No real CVE numbers, no real package/advisory IDs, and no severity**
(`severity` is `null`; the fixture does not carry severity).

## 4. Append the honesty note to `docs/limitations.md` (W1-DE-02.S)
Add one section titled **"M-DE-CORE synthetic demo"** with these three points, in plain words:
(a) the graph and the CVE data are fictional fixtures, not real data; (b) the "vulnerability
lookup" here is fixture-only — no live NVD/OSV call is made; (c) the PHEI score is
**topology-based** (edge weights × node multiplicity). Because `findings[].severity` is
`null` (unspecified per v0.1) and the edge-weight function `w_uv` is an open decision, severity
is **not** in the score — do not describe the 6.0 as a "complete vulnerability-risk score."

## 5. Verify (commands that work today — from the repo root, venv active)
Pick the route that matches your machine; `python` below means *the Python inside your active
venv* (TEAM_ONBOARDING.md §7 tells you which one that is).

```bash
# Linux / macOS — validate EACH file separately (never use a wildcard, and never redirect output
# to a file — `json.tool` would treat a second filename as an output destination):
python -m json.tool examples/fixtures/known_topology.json > /dev/null   # discard: we only care the exit code is 0
python -m json.tool examples/fixtures/cve_fixture.json    > /dev/null

# Windows PowerShell (explicit interpreter, no redirect):
.\.venv\Scripts\python.exe -m json.tool examples\fixtures\known_topology.json > $null
.\.venv\Scripts\python.exe -m json.tool examples\fixtures\cve_fixture.json    > $null
```
- **Expected (Linux/macOS):** both commands print nothing useful and return **exit code 0**. If
  a command prints an error like "Expecting value" the JSON is malformed — fix it and re-run.
- **Expected (PowerShell):** each command finishes with no error; `?` after the command shows
  `1` for no-error / non-zero only when it fails.
- **Expected (structure):** the graph fixture contains 3 **unique** package `id`s; the advisory
  fixture contains 3 unique `SYNTH-2026-*` ids, one `package_id` per package, all referencing
  package ids that actually exist in the topology fixture.
- **Grep check (no real CVEs):**
  - Linux/macOS: `grep -n "CVE-" examples/fixtures/*.json` → expect **no matches**.
  - PowerShell: `findstr /n /c:"CVE-" examples\fixtures\*.json` → expect **no matches**.

## Acceptance (definition of done)
- Both fixtures parse (exit code 0), are deterministic, and contain **no** real
  package/advisory identifiers.
- 3 unique package ids; 2 directed unit-weight edges; 3 synthetic advisories, one per package.
- `limitations.md` names the fixture source and the "severity unspecified / not in score"
  limitation, and does **not** call the 6.0 a complete risk score.

## How to submit (only when your work is ready — this is YOUR action, not mine)
```bash
git diff                # review exactly what changed (only your 3 files)
git add examples/fixtures/known_topology.json examples/fixtures/cve_fixture.json docs/limitations.md
git commit -m "W1-DE-01/02: labeled synthetic fixtures + limitations note"
git push origin feat/mdecore-nick-fixtures
```
Then open a **pull request targeting `feat/inventory-report`** (from the GitHub UI, or `gh pr create`).
In the body, list the subtask ids (`W1-DE-01.F`, `W1-DE-02.S`) and paste the two
`json.tool` exit-0 confirmations. **Do not share passwords or access tokens in the PR, your
machine, or this repo — ever.**

## If you are blocked, send **Vale** (not "Vale's teammate") exactly this, under ~20 lines
1. Which fixture/step you are on (`W1-DE-01.F` or `W1-DE-02.S`) and your branch name.
2. The exact command you ran and the **full** error output (copy-paste, not a paraphrase).
3. Whether it is a **content** question (what to write) or a **shape** question (does the C0
   proposed input contract stand?) — if shape, quote the relevant line from TASKS.md.
4. One sentence on what you already tried.
**Never** include any credential, token, or API key in the message.

## How this connects
Your two fixtures are the inputs that Vale's loader (a **future** file, `src/parser/parser.py`,
not yet built) will consume. Send Vale the file paths the moment they are done so the loader can
be written against exactly what you wrote.
