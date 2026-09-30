# GitHub Issue: Security Check Config + Check Docs

**Assignee:** Nick
**Labels:** `documentation`, `security-categories`, `priority-high`

> **Project scope:** recon-dg is a **dependency risk mapper**. The source-code
> scanner (Bandit) is a supporting sub-track that must label findings correctly so
> the report's "fix suggestion" and "limitations" text are trustworthy.
>
> **Why this exists:** the rule mapping in the docs and config is **backwards**.
> If it ships, every finding gets labeled wrong. Nick's config file is the single
> source of truth the scanner reads to decide which rules exist and what they are
> called. Get it right here and every downstream report is correct.

---

## Shared contract (do not break — single source of truth)

- Rule ID lives in **`test_id`**; `test_name` is always `"blacklist"` — never the rule.
- Exit codes: `0` clean · `1` findings · `>=2` error. **No rc=5.**
- CLI: `bandit -f json -t <bare_rule_id> <file>` — bare rule IDs, no `-ll`.

Canonical table (wins over every other doc):

| Rule | Category | What it catches |
|---|---|---|
| B307 | eval / exec | `eval()`, `exec()` |
| B301 | unsafe-deserialization | `pickle.loads` / `pickle.load` |
| B602 | shell command injection | `subprocess/os.system` with user input |
| B608 | SQL injection | raw `cursor.execute()` string concat |
| B704 | markupsafe XSS | **(NOT deserialization)** |

---

## Scope — what Nick owns (nothing else)

- `src/scanner/bandit_config.py` — the check configuration.
- `docs/security-checks.md` — the corrected rule table + per-check expectations.
- Does **NOT** touch the scanner engine or the test harness (Vale / Christian).

**Fixing the backwards mapping (this is the core bug):**
| Current (WRONG) | Correct |
|---|---|
| Shell command injection → B608 | Shell → **B602** |
| Deserialization (pickle) → B704 | Deserialization → **B301** |
| B704 = deserialization | B704 = **markupsafe XSS** (or remove from deser category) |

Note: the current `rules` lists use the `B608:sql-injection` format, which is **not**
a valid Bandit `-t` filter. Use **bare rule IDs** (B602, B301, B608, B307) and verify
each against `bandit -f json -t <rule> <file>`.

---

## Step-by-step

1. **Verify by hand first (this is the ground truth, not the config):**
   ```bash
   printf 'import os\nos.system(f"ls {x}")\n' > /tmp/shell_vuln.py
   bandit -f json -t B602 /tmp/shell_vuln.py        # expect test_id=B602, rc=1

   printf "import pickle\ndata = pickle.loads(b'x')\n" > /tmp/pickle_vuln.py
   bandit -f json -t B301 /tmp/pickle_vuln.py      # expect test_id=B301, rc=1
   ```
   Confirm: `test_id` = expected rule, `test_name` = `"blacklist"`, `rc` = `1`.

2. **Fix `bandit_config.py`:** shell → **B602**, deserialization → **B301**, B704 →
   markupsafe XSS (not deser). Use bare rule IDs in the `rules` lists.
3. **Fix `docs/security-checks.md`** to match the canonical table exactly, so docs and
   config agree (one source of truth).
4. **Write per-check expectations** for the categories you own (B602 + B301):
   - What it catches / what it does NOT catch.
   - Known false-positives (e.g. B301 on a `pickle.load` from a locally-generated,
     user-unreachable file).
   - One-line fix suggestion (feeds the report's `fix_suggestion`).
   - Known limits (Bandit has no taint/data-flow: B602 only catches the hardcoded
     `shell=True` flag, not dynamic argument assembly).

---

## VERIFY before you commit
```bash
git diff            # ONLY rule mapping + docs — nothing else
bandit -f json -t B602 /tmp/shell_vuln.py   # still B602, rc=1
bandit -f json -t B301 /tmp/pickle_vuln.py  # still B301, rc=1
```

## DONE when
- `bandit_config.py`: shell→B602, deser→B301, B704=markupsafe-XSS.
- `docs/security-checks.md` matches the table AND has B602/B301 expectations.
- You can point at the exact config line that makes `bandit -f json -t B602 <shell file>` work.
- Committed to `feat/inventory-report`:
  `fix(config): correct B602/B301 mapping; drop B704-as-deser`

**Gotchas:** rc=5 is not real (delete any assertion expecting it). `test_name` is a
red herring — always `"blacklist"`. Don't write the scanner or the harness.
