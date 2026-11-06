# W9 Handoff — Nick (Parser)
# 2026-11-03 to 2026-11-09

## Goal
Add `parse_package_json()` to `src/parser/parser.py` to bring the parser to **2/4 minimum formats** (requirements.txt + pyproject.toml + package.json). go.mod remains the blocker for the ≥4 target.

## Evidence
- `src/parser/parser.py` has `parse_requirements` (line 11) and `parse_pyproject_toml` (line 78). `build_mock_graph` (line 113) is a test helper, not a parser.
- TASKS.md Phase 1 shows `[ ] package.json` and `[ ] pyproject.toml` — stale; pyproject.toml is already implemented.
- ROADMAP.md W1 target: ≥4 formats (requirements.txt, package.json, pyproject.toml, go.mod).
- `src/models/dependency_graph.py` defines `DependencyNode` + `DependencyGraph` (NetworkX DiGraph). Edge availability: inventory-only → `"unavailable"`.
- **Historical note:** W1 handoff `docs/weekly-handoffs/W1-parser.md` removed from repo (see four-handoff rule in `docs/weekly-handoff-template.md`); stable record in `docs/ROADMAP.md` §49–58.
- **Delivered (PR #4, merged `5d1101d`, 2026-11-02):** `parse_pyproject_toml()` (59 lines), fixture `tests/fixtures/pyproject_with_deps.toml` (19 lines), 5 new test methods in `tests/test_parser.py` (62 lines added). The repo-root `pyproject.toml` declares no dependencies (confirmed by `test_repo_pyproject_has_no_dependencies`).
- `src/parser/parser.py` `parse_requirements()` sets `edge_availability = "unavailable"` — correct for inventory-only; it does NOT produce topology edges.

## Deliverable by Friday
- `parse_package_json(file_path: str) -> DependencyGraph` in `src/parser/parser.py`.
- Parses `dependencies` and `devDependencies` from `package.json` (npm ecosystem).
- Normalizes to shared `DependencyGraph` with `edge_availability = "unavailable"` (inventory-only).
- Focused fixture: `examples/fixtures/sample_package.json` (3 packages, 2 dev deps).
- Tests: `tests/test_parser.py` extended (≥3 new tests).

## Acceptance
- `python -m pytest tests/test_parser.py -q` passes.
- `parse_package_json` returns a `DependencyGraph` with correct node count and edge_availability == "unavailable".
- No fabricated edge weights; no dependency inference beyond what `package.json` declares.

## Dependencies
- None. Standalone deliverable.
- W10 (Mode B serializer) depends on ≥4 formats being complete.

## Notes
- go.mod is the remaining blocker for the ≥4 target. Defer to W10 if complexity is high.
- `go.mod` indirect dependencies: direct only or transitive? (team decision)
- Do NOT restore any archived W1–W8 handoff files.
