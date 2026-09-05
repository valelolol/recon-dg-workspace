# DECISIONS.md — Architectural Decision Log

## 2026-09-05: Removed `src/reporter/report_generator.py`
The file `src/reporter/report_generator.py` was removed from the codebase because it contained syntax errors that prevented parsing — specifically, unterminated f-strings and malformed multi-line strings. The reporter module (`src/reporter/`) currently contains only an empty `__init__.py`, confirming the file was deleted. **Decision:** Do not attempt to repair the broken file. Instead, write `report_generator.py` from scratch in Phase 3, following the structured output and pathway-summary requirements defined in TASKS.md and the project charter.

## 2026-09-05: PHEI Scoring Formula Discrepancy — Path-Max vs Global-Sum
`docs/specs/design_spec.md` defines the PHEI (Predictive Vulnerability Index) as the maximum risk over all paths through the dependency graph (`max over paths P`). However, `src/engine/risk_analyzer.py` implements a global-sum aggregation: it sums weighted edge risk across the entire graph, averages over edge count, and amplifies by `√(node_count)`. These are fundamentally different algorithms producing different threat models (path-maximum vs. system-wide aggregation). **Decision:** Defer resolution to Phase 2. The scoring formula must be aligned with the PHEI spec before integrating real CVE data, since the lookup and scoring logic are tightly coupled.
