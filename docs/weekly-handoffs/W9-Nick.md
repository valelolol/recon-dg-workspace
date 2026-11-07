# W9 Handoff — Nick (Parser)
# 2026-11-03 to 2026-11-09

## Goal
Parser is at **3/4 minimum formats** (requirements.txt + pyproject.toml + package.json). go.mod remains the blocker for the ≥4 target.

## Evidence
- `src/parser/parser.py` has `parse_requirements` (line 11), `parse_pyproject_toml` (line 78), and `parse_package_json` (W9, committed `1ad2a7b`). `build_mock_graph` (line 113) is a test helper, not a parser.
- TASKS.md Phase 1 shows `[x] package.json` (3/4 minimum formats reached).
- ROADMAP.md W1 target: ≥4 formats (requirements.txt, package.json, pyproject.toml, go.mod).
- `src/models/dependency_graph.py` defines `DependencyNode` + `DependencyGraph` (NetworkX DiGraph). Edge availability: inventory-only → `"unavailable"`.
- **Delivered (W9, committed `1ad2a7b`):** `parse_package_json()` (W9 Nick deliverable). Parser now at **3/4 minimum formats**.
- `src/parser/parser.py` `parse_requirements()` sets `edge_availability = "unavailable"` — correct for inventory-only; it does NOT produce topology edges.

## Deliverable by Friday
- `parse_go_mod(file_path: str) -> DependencyGraph` in `src/parser/parser.py` (the remaining 4th format).
- Parses `require` entries from `go.mod` (Go ecosystem).
- Normalizes to shared `DependencyGraph` with `edge_availability = "unavailable"` (inventory-only).
- Focused fixture: `examples/fixtures/sample_go.mod` (3 modules, 2 indirect).
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
