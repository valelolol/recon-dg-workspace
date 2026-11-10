# W10 Handoff — Nick (Parser: go.mod support)

## Goal and demo value

**Interim-demo scope:** The Dec 9 presentation is an interim demonstration of progress toward the larger RECON-DG project — not a declaration that the full project is complete. The December deliverable is a working prototype (scan → graph → OSV findings → systemic risk → dashboard → AI explanation → bounded fix → human approval → rescan → verified results), not a finished application.

**Demo opportunities before presentation:** Dec 4 (Fri) and Dec 7 (Mon) are scheduled as internal team demos to validate the pipeline end-to-end before the Dec 9 presentation. Dec 8 (Tue) is a rehearsal/buffer day.

**One sentence:** Complete the ≥4-format parser target by adding `go.mod` parsing to `src/parser/parser.py`, enabling the W11 end-to-end CVE→systemic-risk demo on a Go project.

## Proposed accountable owner

Nick (for team confirmation).

## Prerequisites

- `src/parser/parser.py` must already contain `parse_requirements()`, `parse_pyproject_toml()`, and `parse_package_json()` (3/4 minimum, confirmed in published tree `11937e4a9a9ea60eeea64c510d35855e170cfe31`).
- `src/models/dependency_graph.py` defines `DependencyNode` + `DependencyGraph` (NetworkX DiGraph). Edge availability: inventory-only → `"unavailable"`.
- TASKS.md §T-DE-01: Parser: multi-format manifest support — **In progress** (3/4).
- TASKS.md §T-DE-02 audit note: W10 must demonstrate end-to-end real scan → real CVE data → `calculate_systemic_risk()` on a controlled project.

## Input / Output contract

| Direction | Artifact | Format |
|-----------|----------|--------|
| Input | `src/parser/parser.py` (current 3-format state) | Python module with `parse_requirements`, `parse_pyproject_toml`, `parse_package_json` |
| Output | `src/parser/parser.py` with added `parse_go_mod()` | Python module with 4th parser function, normalizing to `DependencyGraph` |

## Deliverable (one bounded item)

`parse_go_mod(file_path: str) -> DependencyGraph` in `src/parser/parser.py` — the 4th format. Parses `require` entries from `go.mod` (Go ecosystem), normalizes to shared `DependencyGraph` with `edge_availability = "unavailable"` (inventory-only).

**Focused fixture:** `examples/fixtures/sample_go.mod` (3 modules, 2 indirect).

## Acceptance criteria

- [ ] `parse_go_mod` returns a `DependencyGraph` with correct node count and `edge_availability == "unavailable"`
- [ ] `python -m pytest tests/test_parser.py -q` passes (all existing + new)
- [ ] No fabricated edge weights; no dependency inference beyond what `go.mod` declares
- [ ] `git diff --check` clean
- [ ] `examples/fixtures/sample_go.mod` exists and is labeled synthetic

## Verification commands / evidence

```bash
# Run parser tests
python -m pytest tests/test_parser.py -q

# Expected: all tests pass (no new failures)

# Verify go.mod fixture loads
python -c "from src.parser.parser import parse_go_mod; g = parse_go_mod('examples/fixtures/sample_go.mod'); print(g.nodes(), g.edges())"

# Expected: non-empty nodes, edges = [] (inventory-only → unavailable)
```

## Security / privacy controls

- No fabricated edges; inventory-only → `UnavailableTopologyError`
- `go.mod` indirect dependencies: direct only (team decision pending)
- Do NOT restore any archived W1–W9 handoff files

## Fallback

| Unavailable service | Fallback behavior |
|---------------------|-------------------|
| `go.mod` parsing fails | Report format-specific bug; do not fabricate nodes |
| Fixture missing | Create `examples/fixtures/sample_go.mod` with 3 modules, 2 indirect; label synthetic |

## Stop conditions

- If `go.mod` parsing produces no nodes from a real manifest, stop and report the format-specific bug rather than continuing.
- If `parse_go_mod` conflicts with `parse_package_json` or `parse_pyproject_toml` in the shared `DependencyGraph` schema, stop and report the schema conflict.

## Questions / blockers

- `go.mod` indirect dependencies: direct only or transitive? (team decision pending)
- Should the demo use a Go project or a Python project with known CVEs? (team decision)
- No Aliyan task this week — no natural task for Aliyan in parser work.

---

*W10 handoff v1 — 2026-11-09. Owner: Nick (proposed). For team confirmation.*
