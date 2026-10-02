# HANDOFF_ALIYAN_MDECORE.md — Aliyan (provisional) · M-DE-CORE viewer spike (T-DE-04)
**Role this week:** a *self-contained static* viewer (plain HTML, no framework) that reads a
`report.json` and shows packages, edges, the numeric PHEI score, the `risk.status`, and the
findings. This is a **PROVISIONAL** step toward the full T-DE-04 dashboard (Phase 4), **not**
the full app. The full December dashboard (Flask+D3 or FastAPI+React, graph + risk +
per-package view) is preserved and untouched by this week's work.

> **Read once before touching anything:** this is a small static page — no server, no model,
> no GPU, no live network, and you do **not** need anyone else's machine. Your one dependency is
> a `report.json` to render, which is **Vale's deliverable and does not exist yet**. Read
> "What exists now" below carefully — it changes what you can run *today*.
>
> **One-time setup:** open a terminal and follow `docs/TEAM_ONBOARDING.md` until you have a
> local clone in a folder you chose, Git + Python working, and a working venv active. Use only
> the route that matches your machine. Then create your personal branch (step 0).
>
> **No new dependencies are needed** — this is pure Python + the standard library (`html`,
> `json`, `argparse`). Do not install Flask, D3, or a JavaScript framework.
>
> ## Terms
> - **repository (repo):** the shared project folder tracked by Git.
> - **clone:** a complete copy of the repo on your computer.
> - **branch / commit / pull request (PR):** a named line of work, a saved checkpoint, and a
>   reviewable request to fold your branch into `feat/inventory-report` (see the other handoffs
>   for the full meaning).
> - **virtual environment (venv):** an isolated folder of Python packages.
> - **fixture:** a stored file of test data (a JSON file).
> - **JSON:** text format for structured data.
> - **schema/contract:** the agreed rules for what data must look like.

## What you own (edit ONLY this)
- `src/dashboard/view.py` (new)

**Do not change** code files you don't own, fixtures, `requirements.txt`, or the scoring formula.

## 0. Personal branch
Confirm clean + integration branch (`git status`, `git branch`) as in the other M-DE-CORE
handoffs. If your tree is dirty or your history diverged, **do not** run `reset`/`pull --force`/
auto-stash; run `git status --short` and `git branch -vv` and send those outputs to Vale before
proceeding. When clean:

```bash
git switch -c feat/mdecore-aliyan-viewer feat/inventory-report
```

## What exists now — read this before you start
**Exists today:** the v0.1 output spec (`docs/specs/scan-result-v0.1.md`) and the fields it
defines. That spec is the **only** thing you may render.
**Does not exist yet:** a real `report.json`. The reference `examples/fixtures/sample_risk_report.json`
is **Vale's deliverable** (W1-DE-03) and is **not checked in yet**. You must therefore build the
viewer *today* against the **spec**, and run it *today* only against a **hand-authored, clearly
labeled synthetic** sample you create in a scratch location (not `examples/fixtures/`, which
must hold Vale's *generated* reference when it lands). **Do not** create a fake `sample_risk_report.json`
in the repo and claim it is the reference or checked-in.

> **Why this split matters:** a hand-authored sample is fine for proving the viewer *renders*
> the v0.1 fields correctly; it is **not** proof of an end-to-end pipeline. Testing a hand
> sample alone is not a pipeline test.

## 1. Build the viewer (W1-DE-04.V) — `src/dashboard/view.py` (new)
CLI:
```
python src/dashboard/view.py <report.json> [-o report.html]
```
It reads the JSON, and writes a single self-contained `report.html` (inline CSS, no JS
library, no Flask, no D3, no framework).

Render, from the `report.json` argument, **only fields defined by the v0.1 spec**:
- **Packages:** `id` / `name` / `version`.
- **Edges:** `source` → `target`.
- **Risk:** the **numeric score** and the existing `risk.status`.
- **Findings:** `id`, `advisory_source`, `advisory_id`, `title`, `description`.
- **Warnings:** the synthetic warnings (they tell the reader the data is a fixture and the
  score is topology-based).

## 2. The two rules you must not violate
1. **Numeric score + status only. No level words.** Do **not** render `LOW` / `MEDIUM` /
   `HIGH` / `CRITICAL` — level thresholds are a *deferred decision* and the spec has no such
   field. Render the number (e.g. `6.0`) and the `risk.status` value.
   **Sensible handling of an unavailable score:** if `risk.score` is missing, or `risk.status ==
   "unavailable"` (topology not known), do **not** print a fake `0`. Render a message such as
   *"Score unavailable — topology not known (status: unavailable)."* Handle `null` gracefully
   (render `"unspecified"`/blank), since `findings[].severity` is `null` (unspecified per v0.1)
   and **not** a level.
2. **Escape every piece of report text before putting it in the HTML.** The report is *untrusted
   data* (it may come from a scan of arbitrary code). Before inserting `title`, `description`,
   warning text, or any user-facing string into the HTML, pass it through the standard-library
   `html.escape()` (use `quote=True` when it appears in an HTML attribute, or place it in an
   element's text node where `html.escape()` without quoting is sufficient). This prevents a
   malformed or hostile report from injecting markup into your page. **Do not** interpolate
   raw report strings into the HTML.
3. **No path.** v0.1 defines no `top_risk_path` (or similar) field, and none is present in
   `report.json`. Render nothing for a path. Do not invent one.

## 3. Create a scratch synthetic sample (for *today's* testing only)
In a folder **outside** the repo or in a scratch location (e.g. `/tmp/`), hand-author a small
`report.json` that contains the v0.1 fields (packages, edges, `risk` with a numeric score and
`status`, findings, warnings). **Label it clearly as hand-authored and synthetic** (a comment or
a filename like `scratch_synthetic_report.json`). This is for proving rendering today — it is
**not** the reference and must never be checked in as `sample_risk_report.json`.

## 4. Verify
From the repo root, venv active. `python` = the venv Python (TEAM_ONBOARDING.md §7).

```bash
# Linux / macOS — use your scratch synthetic sample (NOT a fake reference):
python src/dashboard/view.py /tmp/scratch_synthetic_report.json -o /tmp/a.html
python src/dashboard/view.py /tmp/scratch_synthetic_report.json -o /tmp/b.html
diff /tmp/a.html /tmp/b.html            # expect: identical (deterministic viewer)

# inspect the page:
grep -n "Low\|Medium:\|High:\|Critical:" /tmp/a.html   # expect: no severity LEVEL words; score shown as a number
```
- **Expected (Linux/macOS):** `diff` is empty (identical pages); the HTML shows the numeric
  score (e.g. `6.0`) plus `risk.status`, and **no** LOW/MEDIUM/HIGH/CRITICAL level words;
  findings render as text.
- **Windows PowerShell equivalent:**
  ```powershell
  .\.venv\Scripts\python.exe src\dashboard\view.py .\..\..\..\..\tmp\scratch_synthetic_report.json -o .\..\..\..\..\tmp\a.html
  .\.venv\Scripts\python.exe src\dashboard\view.py .\..\..\..\..\tmp\scratch_synthetic_report.json -o .\..\..\..\..\tmp\b.html
  Compare-Object (Get-Content .\..\..\..\..\tmp\a.html) (Get-Content .\..\..\..\..\tmp\b.html)   # expect: empty
  Select-String -Path .\..\..\..\..\tmp\a.html -Pattern 'Low|MEDIUM|High|Critical'
  ```
  (Adjust the relative path to where your scratch sample lives. On Windows, use the full
  absolute path to `view.py` and the sample to avoid relative-path surprises.)
- **Open** `/tmp/a.html` (or the Windows output) in a browser: packages, edges, the numeric
  score, `risk.status`, and findings are all visible; no level words; any `null` severity
  renders as `"unspecified"`/blank.
- **When Vale's real reference lands** (`examples/fixtures/sample_risk_report.json` exists):
  re-run the same command pointed at that real file. The viewer must render it data-driven (it
  should not have hard-coded the values). **A hand sample alone is not an end-to-end pipeline
  test** — say so in your PR.

## Acceptance
- `src/dashboard/view.py` exists and renders the v0.1 fields from a `report.json` argument.
- **No** framework, **no** D3, **no** Flask.
- **No** severity level labels; numeric score + `risk.status` only; `null` rendered as
  `"unspecified"`/blank; unavailable score handled with a message (not a fake `0`).
- All report text is **HTML-escaped** before insertion (XSS-safe).
- Two runs on the same input produce byte-identical HTML.
- Runs on the real reference once Vale delivers it (data-driven); a scratch hand sample is used
  only for today's rendering check and is labeled synthetic.

## How to submit (only when your work is ready — your action, not mine)
```bash
git diff
git add src/dashboard/view.py
git commit -m "W1-DE-04.V: provisional static viewer for M-DE-CORE (HTML-escaped, numeric score only)"
git push origin feat/mdecore-aliyan-viewer
```
Open a **PR targeting `feat/inventory-report`**; list `W1-DE-04.V`, paste the two-run `diff`
result proving determinism, and state it is **PROVISIONAL** (the full T-DE-04 dashboard remains
the Phase 4 deliverable). **Never share passwords or access tokens in the PR.**

## If blocked, send **Vale** (or your teammate) exactly this, under ~20 lines
1. The exact command + full error/output.
2. Whether the field you're trying to render is **missing from `report.json`** (that is a
   contract question for Vale) or the **HTML rendering** is wrong (yours). Name the field.
3. If it's a fit question (provisional vs. full dashboard): say "this is more/less than I
   expected" and name the specific field or behavior. T-DE-04 ownership is **provisional** —
   Vale may absorb `view.py` if it isn't a fit; that is a normal decision, not a failure.
4. One sentence on what you tried. **Never** include any secret.

## How this connects
You render the reference `report.json` Vale emits. If a field you need isn't there, that's a
contract question for Vale — **don't invent it** in the viewer. When Vale's real reference lands,
point the same viewer command at it and confirm the page renders without hard-coded values.
