# TEAM_ONBOARDING.md — Getting a working local copy (complete beginner)

This page is the **single place** to learn how to set up the project on **your own computer**.
Read it once, then follow **only the route that matches your machine**.

## 0. Two different environments — do not mix them up

| | What it is | Do you need it? |
|---|---|---|
| **Canonical workspace (Vale's VM)** | `/home/vale/projects/recon-dg-workspace` on host **`vale-llm`**. The live `feat/inventory-report` branch lives here and is where the team integrates work. | **No.** You do **not** need Vale's username, his filesystem paths, or access to his VM to complete any assignment. |
| **Your local clone** | A copy of the repo on **your** computer, where you open a personal branch and send a Pull Request. | **Yes** — this is the only thing you need. |

**Nothing you do this week requires:** Vale's Linux username, Vale's filesystem paths, access to Vale's VM, Hermes, a local model, or a GPU. Everything below runs on your own machine.

> Pick your OS now and skip to the matching route.
> - **Windows** → [Route A](#route-a-windows-powershell)
> - **Linux or macOS** → [Route B](#route-b-linux-macos-terminal)

---

## 1. The ten terms you need (defined once, here)

- **Repository (repo):** the project's files, kept under Git version control.
- **Clone:** a complete local copy of the repo made with `git clone`.
- **Branch:** a named, independent line of work (e.g., `mdecore-nick-fixtures`). You always work on your own branch, then merge yours into the shared integration branch later.
- **Commit:** saving a labeled snapshot of your changes (`git commit`).
- **Pull Request (PR):** a request to merge *your* branch into *another* branch (here, `feat/inventory-report`). It lets others review before anything lands.
- **Virtual environment (venv):** an isolated copy of Python for your project, so its libraries do not collide with the rest of the OS.
- **Fixture:** a small, fixed input file (often JSON) used for a known, expected outcome.
- **JSON:** a plain-text data format (braces `{}`, lists `[]`, keys in double quotes).
- **Schema:** the set of allowed fields and rules for a file's structure.
- **Deterministic:** the same inputs always produce byte-identical output (no hidden randomness in time, order, or formatting).
- **Test harness:** a fixed program that runs the scanner against known examples and scores the result.
- **Assertion:** a check inside a test that must be true for the test to pass (e.g., `assert score == 6.0`).

---

## 2. Open a terminal and identify which one it is

**Windows.** Press the Windows key, type `PowerShell`, and open **Windows PowerShell** (or *Windows Terminal*). In the window, type `Get-Host | Format-List Name` and press Enter. If it prints `Name    = ConsoleHost`/`Name    = WindowsTerminal`, you are in a PowerShell-family shell — good.

**Linux.** Open the app named **Terminal** (often via the search box).

**macOS.** Open the app named **Terminal** (Launchpad → Other → Utilities → Terminal).

Confirm what you are in by running `echo $SHELL` (Linux/macOS) — expect a path ending in `bash`, `zsh`, or `sh`. On Windows, `Get-Host` is enough.

---

## 3. Check that Git and Python are installed

**Windows (PowerShell)**
```powershell
git --version
python --version
```

**Linux / macOS**
```bash
git --version
python3 --version
```

**Expected output:** `git version 2.x.x` and `Python 3.11` or newer (the project requires `>=3.11`).

**If a command is "not recognized" / "command not found":** that tool is missing. **Do not guess a path.** Send Vale (section 10) the exact command and error, plus your OS. Install from your usual source (e.g., https://git-scm.com for Git, https://www.python.org/downloads/ for Python) only after the repo owner confirms it is acceptable for the team.

---

## 4. Get a fresh clone

Choose a folder that is **yours** and that you can easily find later. The exact folder is up to you.

**Windows (PowerShell)**
```powershell
cd $HOME
git clone https://github.com/valelolol/recon-dg-workspace.git C:\my-projects\recon-dg
cd C:\my-projects\recon-dg
```

**Linux / macOS**
```bash
cd ~
git clone https://github.com/valelolol/recon-dg-workspace.git ~/projects/recon-dg
cd ~/projects/recon-dg
```

**Confirm the clone is healthy** (run in the cloned folder):
```text
git remote -v
git branch -vv
git status
```
Expected:
- `origin → https://github.com/valelolol/recon-dg-workspace.git`
- a branch named `feat/inventory-report`
- `git status` → `On branch feat/inventory-report` and `nothing to commit, working tree clean`

If any line differs, stop and send me the full output (section 10). Do **not** proceed with a clone that does not look right.

---

## 5. You already have a clone? Preserve your local work

If you cloned this repo before, **do not delete it** and do **not** overwrite it. First check for work that is not yet committed:

```text
git status
git branch -vv
```

- **If `git status` shows modified or untracked files:** you have local work. **Do not `pull` or switch branches yet.** Either commit it to a scratch branch (`git checkout -b local-wip && git add -A && git commit -m "wip: local work before setup"`) so it is safe, **or** send Vale the `git status` output before doing anything else.
- **Update the integration branch with fast-forward-only updating** (no merge, no reset):
  ```text
  git checkout feat/inventory-report
  git pull --ff-only
  ```
- **If `--ff-only` reports "cannot fast-forward" (the branches diverged):** do **not** force-merge, reset, or rebase. Stop, and send Vale the error + `git status` + `git branch -vv`. We resolve it so no work is lost.

---

## 6. Start a personal branch from the integration baseline

For the current week (M-DE-CORE) the integration baseline is **`feat/inventory-report`**.
Create and switch to your own branch **before editing anything**:

**Windows (PowerShell)**
```powershell
git checkout feat/inventory-report
git pull --ff-only
git branch mdecore-<your-name>-<topic>
# you are still ON feat/inventory-report; run the next line to switch to it
git checkout mdecore-<your-name>-<topic>
```
**Linux / macOS**
```bash
git checkout feat/inventory-report
git pull --ff-only
git switch -c mdecore-<your-name>-<topic>
```

Now `git status` should say you are on your new branch and the tree is clean. If it does not, stop and report it.

---

## 7. Virtual environment — create one **only** when you need it

You do **not** need a venv for pure standard-library work (for example, authoring and validating a JSON fixture). You **do** need one to run `pytest` (tests) or `bandit` (the supporting source-audit handoffs).

### Which dependencies does the project actually need?

Check the real manifests before installing anything:
- `requirements.txt` → **`networkx` and `numpy` only.** It does **not** include pytest or Bandit.
- `requirements-dev.txt` → `requirements.txt` + **pytest + ruff.** It does **not** include Bandit.
- **Bandit** is not in any manifest; it is installed separately and only by people following the supporting source-audit handoffs.

**Install only what your task requires.**

### Create a venv

**Windows (PowerShell) — prefer the explicit interpreter path so activation-policy settings do not block you.**
```powershell
py -3.11 -m venv .venv
# Install what you need (pick only what applies to your task):
#   pytest (tests):
.venv\Scripts\python -m pip install pytest
#   Bandit (supporting source-audit handoffs only):
.venv\Scripts\python -m pip install bandit
# Verify:
.venv\Scripts\python -m pytest --version
.venv\Scripts\python -m bandit --version
```
> **Do not disable any Windows execution policy or security control.** Instead of relying on `activate`, call the interpreter by its explicit path (`.venv\Scripts\python ...`). If your machine's policy still blocks script execution, tell Vale — we handle it through an approved channel, not by lowering security.

**Linux / macOS**
```bash
python3 -m venv .venv
# Install what you need:
.venv/bin/python -m pip install pytest            # tests
.venv/bin/python -m pip install bandit            # supporting source-audit only
# Verify:
.venv/bin/python -m pytest --version
.venv/bin/python -m bandit --version
```

### Using an existing venv

If a venv already exists in your clone (look for a `.venv/` or `venv/` folder), just activate or call it:
- Windows: `.venv\Scripts\python ...` (or `.venv\Scripts\activate` if your policy allows it).
- Linux/macOS: `.venv/bin/python ...` (or `source .venv/bin/activate`).

---

## 8. Open the repo in an editor and create a file

1. Drag your cloned folder into **VS Code**, **PyCharm**, or your editor (or use "Open Folder").
2. Make sure the editor is rooted at the **repo root** — the folder that directly contains `README.md`, `src/`, and `tests/`.
3. **Create a file** with the exact name and extension: JSON files end in `.json`, Python in `.py`, notes in `.md`. Save it inside the right folder (e.g., `examples/fixtures/`).
4. **Run commands from the repo root.** Open the editor's integrated terminal and check the path shown at the left of the prompt; it should end in your repo root (the folder with `README.md`). If the path is wrong, `cd` into the repo root first.

---

## 9. Inspect the change, stage only yours, commit, push, open a PR

From the repo root:
```text
git status          # what changed (untracked files show here, not in `git diff`)
git diff            # review the exact text of your staged/tracked changes
git add <file> <file> ...        # stage ONLY the files you own — do not `git add -A` if you touched files you don't
git commit -m "W1-DE-01.F: <short description>"   # put your task ID in the message
git push origin mdecore-<your-name>-<topic>
```
Then open a **Pull Request** targeting **`feat/inventory-report`**:
- On GitHub's web page: click *Compare & pull request*, or
- If the `gh` CLI is installed **and authenticated on your machine**: `gh pr create --fill`.

In the PR body, list your **task ID(s)**, your **branch**, and **paste the verification command + its full output** (section 11 of your handoff).

---

## 10. Security — never share secrets

- **Never share your account passwords, your GitHub tokens, or any access token** with a teammate, in a PR, in a comment, or in chat.
- If a command asks for authentication, use **your own** local credentials.
- If you are locked out or something asks for "the team password", **stop** and tell the repo owner through a private channel. No teammate will ever have your password or token — that is not how this works.

---

## 11. What to send when you are blocked

Send **Vale** (the repo owner), in **under ~20 lines**, **exactly**:
1. Your **task ID** + the step you are on.
2. Your **branch** name + the **exact command** you ran.
3. The **full error/output** (copy-paste, not a paraphrase).
4. Your **OS** (Windows / macOS / Linux) + the output of `git status` and your `python --version` (or `python3 --version`).
5. One sentence on what you already tried.

**No secrets** in the message.

---

## Route A — Windows PowerShell (consolidated copy-paste)

```powershell
# 1) Get the repo (choose your own folder)
cd $HOME
git clone https://github.com/valelolol/recon-dg-workspace.git C:\my-projects\recon-dg
cd C:\my-projects\recon-dg

# 2) Confirm
git remote -v
git branch -vv
git status

# 3) Your branch from the baseline
git checkout feat/inventory-report
git pull --ff-only
git branch mdecore-<your-name>-<topic>
git checkout mdecore-<your-name>-<topic>

# 4) Virtual env (only if your task needs pytest or bandit)
py -3.11 -m venv .venv
.venv\Scripts\python -m pip install pytest
# .venv\Scripts\python -m pip install bandit    # supporting source-audit only

# 5) Validate a JSON file without writing over it (stdout to null)
.venv\Scripts\python -m json.tool examples/fixtures\known_topology.json > $null

# 6) When done
git status
git diff
git add <your file(s)>
git commit -m "W1-DE-01.F: ..."
git push origin mdecore-<your-name>-<topic>
# Then open a PR on GitHub targeting feat/inventory-report
```

## Route B — Linux / macOS (consolidated copy-paste)

```bash
# 1) Get the repo (choose your own folder)
cd ~
git clone https://github.com/valelolol/recon-dg-workspace.git ~/projects/recon-dg
cd ~/projects/recon-dg

# 2) Confirm
git remote -v
git branch -vv
git status

# 3) Your branch from the baseline
git checkout feat/inventory-report
git pull --ff-only
git switch -c mdecore-<your-name>-<topic>

# 4) Virtual env (only if your task needs pytest or bandit)
python3 -m venv .venv
.venv/bin/python -m pip install pytest
# .venv/bin/python -m pip install bandit    # supporting source-audit only

# 5) Validate a JSON file without writing over it (stdout to null)
.venv/bin/python -m json.tool examples/fixtures/known_topology.json > /dev/null

# 6) When done
git status
git diff
git add <your file(s)>
git commit -m "W1-DE-01.F: ..."
git push origin mdecore-<your-name>-<topic>
# Then open a PR on GitHub targeting feat/inventory-report
```

---

## Quick rules of thumb

- Use **one** route (match your OS). Do not mix Windows and macOS commands.
- **`git pull --ff-only`** is the only updating command you will use. If it cannot fast-forward, **stop** and ask — do not merge/reset/force.
- **Stage only the files you own.** Never `git add -A` over a teammate's work.
- **JSON is validated with one explicit file at a time**, and stdout sent to the null device (`$null` / `/dev/null`) so nothing is written into a fixture.
- **No secrets, ever.**
- When in doubt, **stop and send the full output** — losing work is worse than a quick question.
