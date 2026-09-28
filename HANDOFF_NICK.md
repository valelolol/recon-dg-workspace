# HANDOFF — Nick (Security Check Config + Check Docs)

**Repo:** `recon-dg-workspace` · **Branch:** `feat/inventory-report` (already pushed — pull first)
**Your ownership (strict):** `src/scanner/bandit_config.py`, `docs/security-checks.md`,
`docs/limitations.md`. **You do NOT touch** the scanner engine (`src/scanner/` beyond the
config), the harness, or Vale's scanner.

## The big picture (why this matters)

recon-dg is a **dependency risk mapper**. The *December* deliverable is: scan a project's
dependency graph → check each package for known CVEs (NVD/OSV) → score systemic risk
(PHEI) → a **dashboard** + **AI explaining findings in plaintext**.

The **source-code audit** (Bandit) you're on is a *supporting sub-track*. It is not the
December product — it proves the scan → label → measure discipline. Your job is to make the
labels **correct**, because wrong labels poison every downstream finding (and the report's
"fix suggestion" / "limitations" text).

**⚠️ The rule mapping is currently backwards in the config and the docs.** If it ships,
every finding gets labeled wrong. The correct Bandit 1.9.4 mapping (verified by running,
not the docs) is:

| Category | Rule ID | What it catches |
|----------|---------|-----------------|
| SQL injection | **B608** | raw `cursor.execute()` string concat |
| Shell command injection | **B602** | `subprocess`/`os.system` with user input + `shell=True` |
| Unsafe deserialization | **B301** | `pickle.loads` / `pickle.load` |
| markupsafe XSS (NOT deser) | B704 | markupsafe unsafe usage |

Two rules your docs get backwards: **Shell is B602 (not B608)** and **deserialization is B301
(not B704)**. B704 is markupsafe XSS — a *fourth* category, not deserialization.

## The shared contract (read first, it's the source of truth)

- **Rule = JSON `test_id`.** `test_name` is *always* the literal string `"blacklist"`.
  It does NOT hold the rule. Never read the rule from `test_name`.
- **Exit codes — `rc=5` does NOT exist:** `0`=clean (also: missing file → rc=0 with `errors`
  populated) · `1`=**findings** · `2`=internal error · `3`=unknown.
- **Any rc ≥ 2 = error state — report it, NEVER turn it into "0 vulnerabilities."**
- **CLI shape (bare rule IDs only; no `-ll`):**
  `bandit -f json -t B602 /path/to/file.py`
  (`-ll` is invalid; `-c` is `--config-file` (INI), not a rule.)

## Step-by-step — `src/scanner/bandit_config.py` (275 lines)

Verified current state (run `grep -n "SecurityCheck(" src/scanner/bandit_config.py`):

- **L25–31 `B608` block** — `name="SQL/Shell Command Injection"`, `rules=["B608:sql-injection",
  "B608:shell-injection"]`. **Fix:** this is SQL **only**. Rename to `"SQL Injection"`,
  rules → `["B608:sql-injection"]`. Shell is a separate check (B602), not here.
- **L34–37 `B704` block** — `name="Unsafe Deserialization"`, `rules=["B704:pickle-deserialization"]`.
  **Fix:** this is WRONG. Deserialization is B301. B704 is markupsafe XSS.
  - If you are delivering the **3 categories** (SQL/Shell/Deser), **delete this block**
    entirely — B301 (L61–65) already correctly covers deserialization.
  - If you want a 4th category, replace it with the real B704 markupsafe XSS entry
    (`rules=["B704:markupsafe-unsafe"]`).
- **L52–56 `B602` block** — `name="Unsafe Subprocess"`, `rules=["B602:subprocess-popen-no-shell-false",
  "B602:subprocess-no-shell"]`. **Keep the rules** (correct). Consider renaming `name` to
  `"Shell Command Injection"` to match the docs.
- **L61–65 `B301` block** — `"Unsafe Deserialization"`, `rules=["B301:python-unsafe-deserialization"]`.
  **Correct — keep.**
- **`CVE_EXAMPLES`** (L121+) — `B704` key (L141–160) holds *deserialization* CVEs
  (Apache Commons FileUpload / Spring / Apache Commons YAML). **Fix:** move those deser
  CVEs to the `B301` key; the real B704 (if you keep it) should list *markupsafe XSS*
  CVEs. If you drop the B704 block, drop its CVE examples too.
- **`MITIGATION_PATTERNS`** (L204+) — `B704` (L220+) holds deser mitigations. **Fix**
  the same way as CVE_EXAMPLES.

## Step-by-step — `docs/security-checks.md` (248 lines)

- **Category 1 "SQL Injection (B608)"** (L24–87) — **correct, keep.**
- **Category 2 "Shell Command Injection (B608)"** (L90–151) — **Fix: B608 → B602.**
  - Rule ID row → B602; "Bandit Rule" → `B602:subprocess-popen-no-shell-false` (and
    `-subprocess-no-shell`). Keep the vuln patterns (they're fine).
  - The CVEs you listed (Tomcat shell, WordPress upload, Apache Commons) are *Java/PHP*
    CVEs — fine as "real-world shell injection" examples, but add a one-line note that
    Bandit's B602 fires on *Python* `subprocess`/`os.system` usage, not Java.
- **Category 3 "Unsafe Deserialization (B704)"** (L154–229) — **Fix: B704 → B301.**
  - Rule ID → B301; "Bandit Rule" → `B301:python-unsafe-deserialization`.
  - Keep the `pickle.loads` / `yaml.load` patterns (correct for Python).
- **Summary table** (L234–239) — fix the two wrong rows:
  `| Shell Injection | B602 | CWE-78 | ... |` and `| Deserialization | B301 | CWE-502 | ... |`.

## Verify with the tool (non-negotiable — assignment rule: never trust the docs)

Run these from the repo root, confirm the `test_id` in the output:

```bash
cd /home/vale/projects/recon-dg-workspace
# SQL (B608) — expect test_id: B608
.venv/bin/bandit -f json -t B608 examples/source-audit-week1/vulnerable_example.py
# Shell (B602) — expect test_id: B602 (build a tiny shell example if you don't have one)
.venv/bin/bandit -f json -t B602 examples/source-audit-week1/vulnerable_example.py
# Deser (B301) — expect test_id: B301
.venv/bin/bandit -f json -t B301 examples/source-audit-week1/vulnerable_example_3.py
```

Also check: `python3 -c "import bandit; print(bandit.__version__)"` → report it in
`docs/limitations.md` (version drift changes which rules fire).

## Deliverable + commit

1. `bandit_config.py` — B608=SQL only, B602=shell, B301=deser, B704 removed or =markupsafe.
2. `docs/security-checks.md` — Shell→B602, Deser→B301, summary table fixed.
3. `docs/limitations.md` — record false positives/negatives per category + Bandit/Python
   version + the "rc=5 doesn't exist / rc=1=findings" contract.
4. Commit:
   `git commit -m "fix(config): correct B602/B301 mapping; drop B704-as-deser"`
5. Push to `feat/inventory-report` so Vale's and Christian's work is clean.

**Definition of done (Nick):** a fresh read of `security-checks.md` and `bandit_config.py`
shows only the canonical mapping; every claim in the docs is verified by the commands above;
commit is on `feat/inventory-report`.
