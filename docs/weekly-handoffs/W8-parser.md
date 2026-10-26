# W8: One additional parser format (T-DE-01)

> **For:** Nick — beginner-friendly, reusable handoff.
> **Branch:** `feat/inventory-report`
> **Workspace:** `/home/vale/projects/recon-dg-workspace`
> **Template:** `docs/weekly-handoff-template.md`
> **PR target:** `feat/inventory-report` (confirmed by `docs/TEAM_ONBOARDING.md:279`; do NOT target `main`)
> **HEAD:** `e455881`

---

## Goal and demo value

One sentence: Extend `src/parser/parser.py` with **one** additional manifest format: **`pyproject.toml`** (the standard Python project manifest). Producing a `DependencyGraph` with `edge_availability = "unavailable"` (inventory-only). The real OSV-Scanner scan is Vale's W8 task (see W8-engine-and-reporter.md).

## Proposed accountable owner

Nick (for team confirmation)

## Prerequisites

- W1 handoff `docs/weekly-handoffs/W1-parser.md` — Nick's existing parser work
- `src/parser/parser.py` — existing `parse_requirements()` (simple `==` parser, lines ~5–48) and `build_mock_graph()` (synthetic helper)
- `src/models/dependency_graph.py` — `DependencyGraph` class with `edge_availability` (1,467 bytes)
- `tests/test_parser.py` — existing test file
- No synthetic data — real `requirements.txt` or `package.json` from a real project (the existing `build_mock_graph()` is synthetic and should not be used for W8 scan output)

## Input / Output contract

|| Direction | Artifact | Format |
|-----------|----------|--------|
| Input | `pyproject.toml` file (the repo's own root `./pyproject.toml`, the real project manifest) | TOML with `[project] dependencies` and `[project.optional-dependencies]` |
| Output | `src/parser/parser.py` | New `parse_<format>()` (one function only)
| Output | `tests/test_parser.py` | Tests for the new parser

## Deliverable (one bounded item)

`src/parser/parser.py` with one additional `parse_*()` function (e.g. `parse_package_json()`) normalizing to `DependencyGraph` with `edge_availability = "unavailable"`.

## Acceptance criteria

- [ ] `parse_<format>(path)` returns `DependencyGraph` with correct nodes (or the chosen additional format)
- [ ] The new parser sets `edge_availability = "unavailable"` (inventory-only)
- [ ] `python -m pytest tests/test_parser.py -q` passes (all new + existing tests)

## Verification commands / evidence

```bash
cd /home/vale/projects/recon-dg-workspace
python -m pytest tests/test_parser.py -q
```

## Security / privacy controls

- No fabricated edges — inventory-only → `edge_availability = "unavailable"`
- No real credentials in parsed data

## Fallback

|| Unavailable service | Fallback behavior |
|---------------------|-------------------|
| `go.mod` parsing too complex | Defer to W9; demo with 2 formats
| NVD/OSV rate limit (5 req/30s) | Cache aggressively; mock for demo |
| Parser returns empty graph | Stop and report the format-specific bug |

## Stop conditions

- If the new parser produces no nodes from a real manifest, stop and report the format-specific bug rather than continuing.

## Questions / blockers

- `go.mod` indirect dependencies: direct only or transitive? (team decision)
- Which real manifest should the parser target? (resolved: `./pyproject.toml` at repo root)
- Should the parser handle `package-lock.json` (npm lockfile) in W8 or W9? (deferred to W9)
- **Important:** The existing `src/parser/parser.py` `parse_requirements()` sets `edge_availability = "unavailable"` — this is correct for inventory-only. It does NOT produce topology edges.

---

*Handoff v2 — 2026-10-27. Owner: Nick (for team confirmation). Corrected: `parse_requirements()` line numbers (~5–48), `build_mock_graph()` is synthetic, `src/models/dependency_graph.py` exists (1,467 bytes).*
