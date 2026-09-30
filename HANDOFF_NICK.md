# HANDOFF — Nick (rule config + detection-limit documentation)

**Task:** T-SA-02 · **Repo:** `valelolol/recon-dg-workspace` · **Branch:** `feat/inventory-report` (already pushed — pull first)

## 1. What you're doing and why it matters

recon-dg is a **dependency risk mapper**: dependency graph → per-package CVE check (NVD/OSV) → systemic risk score (PHEI) → dashboard + AI explanations. Your Bandit **source-audit** is a *supporting sub-track*, not the December deliverable — it proves the scan → label → measure discipline. Your job: make the **labels correct**. Wrong rule labels poison every downstream finding, fix-suggestion, and limitation statement.

Known issue (verify against the current tree before editing): `src/scanner/bandit_config.py` mixes SQL and shell under B608, treats B704 as deserialization, and B602 carries a generic "subprocess" name. The canonical mapping (Bandit 1.9.4, verified by running) for **your three categories** is:

| Nick's category (3 this week) | Rule | What it catches |
|---|---|---|
| SQL injection | `B608` | raw string-concat `cursor.execute(...)` |
| Shell command injection | `B602` | `subprocess` calls with `shell=True` |
| Unsafe deserialization | `B301` | `pickle.loads` / `pickle.load` |

> **B704 is MarkupSafe XSS — not deserialization.** It is a real Bandit rule, but it is **NOT** one of this week's three categories. Do **not** add a fourth category. See the B704 block step and §4.
> **`os.system` is a separate rule (`B605`).** It does **not** belong to B602 (B602 is `subprocess` + `shell=True` only). Never attribute `os.system` to B602, and never show it as a "secure" pattern.

**Shared contract (source of truth):**
- **Rule = JSON `test_id`.** The `test_id` field carries the rule ID (e.g. `B608`). `test_name`'s value varies by rule/version — never infer the rule from `test_name`.
- **Exit codes — `rc=5` does not exist:** `0`=no findings · `1`=findings · `2`=internal error · `3`=unknown; `rc ≥ 2` = error, never "0 vulnerabilities."
- **A run is "clean" only when the process result AND the JSON agree:** `rc=0` *and* an empty `results` list *and* no entries in `errors`. `rc=0` alone is **not** proof of success — a missing file also returns `rc=0` (with `errors` populated), and a bad invocation can return `rc=0` without a real result. Check both.
- **CLI shape (bare rule IDs only; no `-ll`):** `bandit -f json -t B602 /path/to/file.py` (`-ll` is invalid; `-c` is `--config-file`/INI, not a rule).

## 2. Files you own and prerequisites

You own (strictly): `src/scanner/bandit_config.py`, `docs/security-checks.md`, `docs/limitations.md`. You do **not** touch the scanner engine, the harness, or Vale's scanner.

**You can start now, independently.** Vale's `scan_demo.py` fix is only needed for *later integration* — it is **not** a prerequisite for your work or your first checkpoint.

Prerequisites:
- **Use the same Python environment the project uses to run Bandit** (the project virtualenv). Everything below runs from the repo root with that env active.
- A venv with Bandit. If Bandit is not already there, **do not install it yet** — ask Vale to confirm the env first.
- The shared contract in `examples/source-audit-week1/RECON-DG_MONTH1_ROADMAP.md` §"Shared contract".

Setup. **The commands below are Linux examples.** If you are on Windows, or are unsure which OS/env applies, paste the output and ask Vale to confirm before installing anything — do not guess.

```bash
# Linux: activate the project venv (adjust the path only if the venv lives elsewhere)
source .venv/bin/activate

#   Windows equivalent:
#   .venv\Scripts\activate

# Confirm Bandit is installed in THIS env (expected: a version like "1.9.4")
python -m bandit --version

# If that errors, report what python/pip you have in this env:
python --version
python -m pip list | grep -i bandit          #   Windows: python -m pip list | findstr /i bandit
```

Jargon: *Bandit* = a Python static analyzer; *rule* = a named detector with an ID (e.g. `B602`); *finding* = a flagged line of code.

## 3. First checkpoint (send Vale — do not edit yet)

Goal: confirm the three rule definitions exist and report the installed version. Locate things **by name/ID**, not by line number — line numbers in this doc are "as of when written" and will drift; a different line number is **not** a blocker.

From the repo root, with the project env active:

```bash
# Report the installed Bandit version (one line)
python -m bandit --version

# Locate the three rule definitions in the config (search by rule ID).
grep -n "B608\|B602\|B301" src/scanner/bandit_config.py
#   Windows (no grep): run `findstr /n /C:B608 src/scanner/bandit_config.py`,
#   and the same for B602 and B301.
```

**Expected:**
- `python -m bandit --version` prints a version (e.g. `1.9.4`).
- Each of `B608`, `B602`, and `B301` has a `SecurityCheck` entry in `bandit_config.py`.

**Report back:** the version string, plus one line per rule describing what you found (the check `name` and its `rules` list).

**Stop only if:** a rule is entirely missing from the config, or a definition is *materially* different from what §4 expects (e.g. the rules list is not what's described — not just shifted to another line). A line-number shift alone is **not** a reason to stop. If you stop, paste the exact `grep`/`findstr` output + the relevant `SecurityCheck` block, plus your branch.

## 4. Steps (with expected outcomes)

Run these in the project env. Verify with a Bandit run only when a matching fixture exists; a rule whose fixture doesn't exist yet is **blocked-on-Christian's fixtures**, not a failure.

> Fixture reality check: `examples/source-audit-week1/vulnerable_example.py` uses **`eval()`** — that is **B307**, none of your three rules. Running B608 / B602 / B301 on it will return no findings, and **that is expected, not a failure**. Do not "expect B608/B602 from vulnerable_example.py."

1. **B608 block → SQL only.** Currently `name="SQL/Shell Command Injection"` with `rules=["B608:sql-injection", "B608:shell-injection"]`. The second rule is wrong — shell is a separate rule (B602 / B605). Set `name="SQL Injection"` and `rules=["B608:sql-injection"]`.
   - *Expected:* one SQL-only check under B608.
   - *Send me if:* the current block already differs from what's described — paste it.

2. **B704 block → delete.** Currently labeled "Unsafe Deserialization" with `rules=["B704:pickle-deserialization"]`. That mapping is wrong — B704 is MarkupSafe **XSS**, not deserialization. Delete the entire `B704` `SecurityCheck` entry. Do **not** re-add it as a category this week; B704 (MarkupSafe XSS) is **outside** this three-category deliverable.
   - *Expected:* the mislabeled `B704` entry is gone and **no deserialization is mapped to B704**. The checks left in `SECURITY_CHECKS` are B608, B602, B301 (your three) **plus** B307, which you leave exactly as-is — it is not part of this deliverable and not something to add or remove.
   - *Send me if:* you're unsure whether B307 belongs — leave B307 exactly as-is; it is not yours to change.

3. **B602 block → rename only.** Currently `name="Unsafe Subprocess"` with the two `subprocess` rules. Rename `name` to **"Shell Command Injection"**. Keep the rules as-is (they are subprocess-related). Remember B602 = `subprocess` + `shell=True`; `os.system` is B605 and is **not** B602.
   - *Expected:* a "Shell Command Injection" check with unchanged subprocess rules.
   - *Send me if:* a rule in the block is not subprocess-related.

4. **B301 block → keep.** Currently correct ("Unsafe Deserialization", `rules=["B301:python-unsafe-deserialization"]`). Leave it as-is.
   - *Expected:* no change.
   - *Send me if:* the rule id isn't `B301:python-unsafe-deserialization`.

5. **`CVE_EXAMPLES` + `MITIGATION_PATTERNS` — re-home the keys.**
   - `CVE_EXAMPLES`: the deserialization examples currently sit under the `"B704"` key — rename that key to `"B301"` (no B301 key exists yet, so renaming *is* the move).
   - `MITIGATION_PATTERNS`: rename the `"B704"` (pickle) key to `"B301"`. Also, the `"B608"` key contains a `"shell_injection"` mitigation that doesn't belong to SQL — drop it from B608 and keep the shell/subprocess mitigation with B602. Remove any `os.system` pattern from those shell mitigations (os.system is B605; never "secure" for B602).
   - *Expected:* every key's CVEs/mitigations match its rule; no deserialization content under a non-deser key.
   - *Send me if:* a key's contents don't match what you'd expect for its rule.

6. **`docs/security-checks.md`.**
   - Category "Shell" rule: `B608 → B602` (Bandit rules `B602:subprocess-popen-no-shell-false` / `B602:subprocess-no-shell`); state it fires on Python `subprocess` + `shell=True`, and that `os.system` is B605 (not covered).
   - Category "Deserialization" rule: `B704 → B301` (Bandit rule `B301:python-unsafe-deserialization`).
   - Add one line: **B704 is MarkupSafe XSS; it is not part of this week's three categories** (and it is not the pickle rule).
   - Fix the two summary-table rows to match.
   - *Expected:* a fresh reader sees only the correct mapping for the 3 categories.
   - *Send me if:* the doc's rule names don't match the `rules` lists in `bandit_config.py`.

7. **`docs/limitations.md`.** Per-category false positives/negatives + the Bandit/Python versions (report the **actual** installed version from §3) + the exit-code contract (`rc=5` doesn't exist / `rc=1`=findings / rc≥2=error, and "clean requires the process result AND the JSON to agree").
   - *Expected:* the doc matches the verified version.
   - *Send me if:* you can't confirm a version — paste the `python -m bandit --version` output.

**Verify (non-negotiable — never trust the doc alone; run in the project env, `bandit` = `.venv/bin/bandit` on Linux, `.venv\Scripts\bandit.exe` on Windows, with the venv activated):**

```bash
# B301 — MATCHING FIXTURE EXISTS (pickle.loads / pickle.load)
# NOTE: vulnerable_example_3.py's docstring mislabels this "B704". The real rule is B301.
#       Confirm via the JSON `test_id` field, NOT the docstring.
bandit -f json -t B301 examples/source-audit-week1/vulnerable_example_3.py
#   Expected: a `results` entry whose test_id == "B301".
#   If you get a different id, send it and do NOT "fix" the fixture — it is Christian's file.

# B608 (SQL) and B602 (shell) — NO matching fixture exists in the tree yet.
# Do NOT run these against vulnerable_example.py (it is eval/B307 → no findings, as expected).
# Their vulnerable/safe pairs are owned by Christian (T-SA-03) and are named in
# TASKS.md (vulnerable_example_sql.py / vulnerable_example_shell.py and their
# safer_*_sql / safer_*_shell companions). Until those land, mark B608/B602
# verification "blocked-on-Christian's fixtures" — do NOT invent a fixture filename.
# When his pairs exist, run:
#   bandit -f json -t B608 examples/source-audit-week1/vulnerable_example_sql.py
#   bandit -f json -t B602 examples/source-audit-week1/vulnerable_example_shell.py
#   Expected: a `results` entry with test_id == "B608" and == "B602" respectively.
```

## 5. Completion checklist

- [ ] `bandit_config.py`: B608 = SQL only; B602 = shell (subprocess + `shell=True`); B301 = deser; B704 **deleted** (no 4th category)
- [ ] `CVE_EXAMPLES`/`MITIGATION_PATTERNS`: deser content re-homed to the B301 key; shell mitigation out of the B608 key; no `os.system` in B602 mitigations
- [ ] `security-checks.md`: Shell → B602, Deser → B301, summary table fixed, `os.system`=B605 note, B704="MarkupSafe XSS, out of scope" note
- [ ] `limitations.md`: per-category FPs/FNs + actual version + full exit-code contract
- [ ] B301 verification returns `test_id == "B301"`; B608/B602 marked blocked-on-Christian's fixtures

## 6. Submitting (verified repo details)

Verified with `git remote -v`: remote `git@github.com:valelolol/recon-dg-workspace.git` → https://github.com/valelolol/recon-dg-workspace. Current branch: `feat/inventory-report`.

1. `git fetch origin && git checkout feat/inventory-report && git pull`
2. `git checkout -b feature/tsa02-nick-config-docs`
3. `git add src/scanner/bandit_config.py docs/security-checks.md docs/limitations.md` (only your files)
4. `git commit -m "fix(config): correct B602/B301 mapping; drop B704-as-deser"`
5. `git push origin feature/tsa02-nick-config-docs`
6. Open a PR targeting `feat/inventory-report` from the GitHub page (or `gh pr create` if the gh CLI is authenticated), mention Vale in the description.

## 7. If blocked, send Vale

The exact error output, the command, your branch, and the file you were on. Examples: no Bandit in the env → paste `python -m pip list`; a verification command returns the wrong `test_id` → paste the full JSON line; a rule is **missing or materially different** (not just at a different line number) → paste the §3 grep output + the `SecurityCheck` block. If a rule behaves in a way you don't understand, paste the raw output — don't guess.

---

Line numbers cited anywhere in this handoff are **illustrative only, as of when written**. Locate definitions by rule name/ID, and do **not** treat a line-number shift as a blocker. Only a missing or materially different rule or file stops you.
