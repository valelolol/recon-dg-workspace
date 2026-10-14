# HANDOFF — Nick: M-DE-CORE demo fixtures (synthetic only, not central milestone)

## Your assignment

Create **two synthetic input fixtures** for the Mode B dependency-graph report. These are **fictional** — they are not real CVEs or real packages. They exist only to exercise the pipeline without live API calls.

**Important:** These fixtures are **demo-only** per the synthetic data rule (TASKS.md: "synthetic graph/advisory data is only for clearly labeled offline tests or a separate demo. It is **never** scanner evidence."). They are **not** the central product milestone. The central milestone is Vale's Mode B pipeline (loader → serializer → CLI → reference output). Your work supports that milestone as a labeled demo input.

## What to produce

### 1. `examples/fixtures/known_topology.json`

A synthetic **known-topology input** (not the output report). Fictional packages with a directed unit-weight chain:

```json
{
  "_demo_fixture": "Synthetic known-topology INPUT. Fictional packages; not a real dependency graph.",
  "packages": [
    { "id": "synth-a", "name": "synth-a", "version": "0.0.0" },
    { "id": "synth-b", "name": "synth-b", "version": "0.0.0" },
    { "id": "synth-c", "name": "synth-c", "version": "0.0.0" }
  ],
  "edges": [
    { "id": "e1", "source": "synth-a", "target": "synth-b", "weight": 1.0 },
    { "id": "e2", "source": "synth-b", "target": "synth-c", "weight": 1.0 }
  ]
}
```

### 2. `examples/fixtures/cve_fixture.json`

A synthetic **advisory input**:

```json
{
  "_demo_fixture": "Synthetic advisory INPUT. Fictional advisories; not real CVEs.",
  "advisories": [
    {
      "id": "SYNTH-2026-0001",
      "package_id": "synth-a",
      "title": "Synthetic advisory A",
      "description": "Synthetic example advisory for synth-a. Not a real vulnerability."
    },
    {
      "id": "SYNTH-2026-0002",
      "package_id": "synth-b",
      "title": "Synthetic advisory B",
      "description": "Synthetic example advisory for synth-b. Not a real vulnerability."
    },
    {
      "id": "SYNTH-2026-0003",
      "package_id": "synth-c",
      "title": "Synthetic advisory C",
      "description": "Synthetic example advisory for synth-c. Not a real vulnerability."
    }
  ]
}
```

### 3. `docs/limitations.md`

A short note (one paragraph, ~50 words) that:
- States the fixture data is synthetic and not real CVE data.
- Notes that `findings[].severity` is `null` (unspecified per v0.1) and does **not** enter the PHEI score.
- Names the source of the synthetic data (`SYNTH-2026-XXXX` IDs).

## Acceptance criteria

- Both JSON files are valid JSON (run `python -m json.tool examples/fixtures/known_topology.json` and the same for `cve_fixture.json`).
- IDs use the form `SYNTH-2026-XXXX`; no real CVE numbers or real package versions appear.
- The topology has exactly 3 unique packages and 2 directed unit-weight edges (a→b, b→c).
- The fixture loads without error when parsed by the loader Vale will write.
- No real identifiers (CVE IDs, real package names/versions) appear anywhere.

## Where to start

1. `cd /home/vale/projects/recon-dg-workspace && git checkout feat/inventory-report`
2. `git switch -c nick-fixtures`
3. Create `examples/fixtures/` directory, write the two JSON files and the limitations note.
4. Validate with `python -m json.tool`.
5. Commit and push: `git add -A && git commit -m "W1-DE-01.F + W1-DE-02.S: synthetic fixtures + limitations" && git push origin nick-fixtures`
6. Open a PR targeting `feat/inventory-report`.

## Key documents to read first

- `docs/TEAM_ONBOARDING.md` — your OS-specific setup (clone, branch, venv).
- `TASKS.md` §C0-prereq — the proposed input-fixture contract (approval required before you write).
- `docs/WEEKLY.md` — this week's focus and acceptance criteria.

## Questions?

If the C0 approval hasn't landed yet, draft the fixtures against the proposed shape above and note that in your PR. The shape is the one documented in TASKS.md §C0-prereq.