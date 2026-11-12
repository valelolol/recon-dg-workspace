# REVIEW-DECISIONS — decisions recorded during weekly review

## RD-W10-01: go.mod indirect dependencies — direct only (default)

**Owner:** Nick · **Due:** W11 Tue Nov 17, 2026 · **Status:** Proposed (for team confirmation)
**Source:** `docs/weekly-handoffs/W10-Nick.md` → Questions / blockers

**Decision:** `parse_go_mod()` keeps only **direct** requirements by default. `require`
entries marked `// indirect` are skipped unless the caller passes
`include_indirect=True`.

**Rationale:**
- This is the W10 handoff's stated default ("direct only, matches `go.mod`'s `require`
  section semantics").
- The parser reports only what `go.mod` declares. It never resolves transitive
  dependencies itself, and it never adds edges (`edge_availability = "unavailable"`).
- Transitive vulnerability coverage comes from OSV-Scanner, which reads the module graph
  directly, so the inventory parser does not need to duplicate it.

**Consequences / follow-ups:**
- With the default, a vulnerable **indirect** module appears in OSV-Scanner findings but
  not in the parser's inventory graph. If the W11 demo needs both views to line up, call
  `parse_go_mod(path, include_indirect=True)` instead. No code change is needed.
- Verified by `tests/test_parser.py::TestGoModParsing` against the synthetic fixture
  `examples/fixtures/sample_go.mod` (3 modules, 2 indirect): 1 node by default,
  3 with `include_indirect=True`, 0 edges in both cases.
