# W1: Multi-format manifest parser (T-DE-01)

## Goal and demo value

Parser supports ≥4 manifest formats (`requirements.txt`, `package.json`, `pyproject.toml`, `go.mod`) → shared `DependencyGraph` IR. Without this, no downstream step has real data to work with.

## Proposed accountable owner

Nick (for team confirmation)

## Prerequisites

- `src/models/dependency_graph.py` exists and defines `DependencyGraph` with `edge_availability` attribute
- `src/parser/parser.py` already has `parse_requirements()` (requirements.txt, line 7–51)
- `tests/test_parser.py` exists with a mock-graph helper (`build_mock_graph()`, line 54–72)

## Input / Output contract

| Direction | Artifact | Format |
|-----------|----------|--------|
| Input | `requirements.txt` | Already parsed; serves as the baseline to extend |
| Output | `src/parser/parser.py` | New functions: `parse_package_json()`, `parse_pyproject_toml()`, `parse_go_mod()` |
| Output | `tests/test_parser.py` | Tests for each new parser function |

## Deliverable (one bounded item)

Three new parser functions in `src/parser/parser.py`, each normalizing to `DependencyGraph` with `edge_availability = "unavailable"` (inventory-only input), plus tests.

## Acceptance criteria

- [ ] `parse_package_json()` reads a JSON `package.json`, extracts `dependencies` + `devDependencies`, creates `DependencyNode` entries, returns graph with `edge_availability = "unavailable"`
- [ ] `parse_pyproject_toml()` reads a TOML `pyproject.toml` via `tomllib`, extracts `[project.dependencies]`, creates nodes, returns graph with `edge_availability = "unavailable"`
- [ ] `parse_go_mod()` reads a `go.mod` file, extracts `require (...)` block, creates nodes, returns graph with `edge_availability = "unavailable"`
- [ ] No existing `parse_requirements()` behavior changes (backward compatible)
- [ ] `python -m pytest tests/test_parser.py -q` passes (all existing + new tests)

## Verification commands / evidence

```bash
cd /home/vale/projects/recon-dg-workspace
python -m pytest tests/test_parser.py -q
```

Expected: all tests pass (count will reflect new tests added).

## Security / privacy controls

- Inventory-only parsing → `edge_availability = "unavailable"` (no edges fabricated)
- No network calls during parsing
- No model/LLM involvement

## Fallback

| Unavailable service | Fallback behavior |
|---------------------|-------------------|
| Missing manifest file | `FileNotFoundError` raised (existing behavior, `parse_requirements` line 18) |
| Malformed JSON/TOML | Silently skip malformed lines (existing pattern, line 42–43) |
| Missing `tomllib` | Python 3.11+ stdlib; if unavailable, raise `ImportError` with a note about Python version |

## Stop conditions

- If any parser function crashes on a real-world manifest (e.g. `package.json` with `workspaces` field, `pyproject.toml` with conditional dependencies), stop and report the specific format limitation rather than continuing.
- If `tomllib` is not available (Python < 3.11), report the version requirement before coding.

## Questions / blockers

- Does the team want `go.mod` parsed in W1, or defer to W2? (go.mod parsing is more complex due to indirect dependencies.)
- Should `parse_requirements()` also handle `>=`, `<=`, `~=` version specifiers, or only `==`?
- "integrations across different stories" — unclear phrase in TASKS.md; needs clarification before proceeding.

---

*Handoff v1 — 2026-10-20. Owner: Nick (for team confirmation).*
