# HANDOFF_NICK_MDECORE.md — Nick · T-DE-01/02
Synthetic input fixtures + limitations note. (M-DE-CORE week)

Goal: Author two clearly-labeled synthetic input fixtures and the honesty note that
makes it obvious the data is fictional and the score is topology-only.

## Your files (edit only these)
- `examples/fixtures/known_topology.json` (new)
- `examples/fixtures/cve_fixture.json` (new)
- `docs/limitations.md` (existing — append a section)

## Setup (beginner-friendly)
1. `cd /home/vale/projects/recon-dg-workspace`
2. `git checkout feat/inventory-report && git pull`
3. `git switch -c feat/mdecore-nick-fixtures feat/inventory-report`
4. `python -m venv .venv && source .venv/bin/activate`
5. Read the contract: `docs/specs/scan-result-v0.1.md` and the M-DE-CORE section of
   `TASKS.md`. You are writing INPUT fixtures, not output.

## Steps
1. **(W1-DE-01.F) `examples/fixtures/known_topology.json`** — a known-topology input for
   the parser: 3 UNIQUE packages (e.g. `synth-a`, `synth-b`, `synth-c`), 2 directed
   edges (`synth-a` → `synth-b`, `synth-b` → `synth-c`), unit edge weights (1.0).
   Every identifier must be clearly synthetic. No duplicate package IDs.
2. **(W1-DE-02.S) `examples/fixtures/cve_fixture.json`** — synthetic advisories for the
   packages. Each advisory uses `advisory_source` (`synthetic-fixture`), `advisory_id`
   in the form `SYNTH-2026-XXXX`, a description that explicitly says it is a synthetic
   example, and **no severity** — v0.1 does not define severity values yet, so the
   finding's `severity` must be `null` (the fixture does not carry a severity). NO real
   CVE numbers, NO real package/advisory IDs.
3. **(W1-DE-02.S) Append a section to `docs/limitations.md`** titled "M-DE-CORE
   synthetic demo": (a) graph + CVE data are fictional fixtures, (b) vulnerability
   lookup is fixture-only (no live NVD/OSV), (c) the PHEI score is topology-based;    `findings[].severity` is `null` (unspecified per v0.1) and does not enter the
   function `w_uv` is undefined.   not enter the score.

## Verify
- Validate both JSONs parse: `python -m json.tool examples/fixtures/*.json`.
- Confirm 3 unique package IDs in the graph fixture.
- Grep your files for any real CVE number (`CVE-`) — there must be none.

## Acceptance
- Both fixtures load deterministically.
- No real package/advisory identifiers.
- `limitations.md` names the fixture source and the severity-unspecified/not-in-score limit
    (`findings[].severity` is `null` per v0.1; severity does not enter the score).

## Branch & PR
```
git add examples/fixtures/known_topology.json examples/fixtures/cve_fixture.json \
      docs/limitations.md
git commit -m "W1-DE-01/02: labeled synthetic fixtures + limitations note"
git push origin feat/mdecore-nick-fixtures
```
Open a PR to `feat/inventory-report`; list W1-DE-01.F / W1-DE-02.S in the body and
paste the `python -m json.tool` confirmation.

## If blocked — send Vale's teammate (or the relevant teammate) EXACTLY this, in under ~20 lines
- Which fixture/step (W1-DE-01.F or W1-DE-02.S) you're on.
- The command + full error output if a JSON won't parse.
- Whether the question is "what shape does the parser expect" (send the relevant
  TASKS.md field mapping) or a content question.
- One sentence on what you tried.

## Connects
Your two fixtures are the inputs Vale's pipeline consumes. Send Vale the paths the
moment they're done so the loader can be written against them.
