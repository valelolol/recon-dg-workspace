# Project Changes Summary - Last Week

**Date Range:** September 16, 2026  
**Author:** Valentin Nevarez  
**Total Commits:** 2

---

## Overview

This week focused on two major improvements:
1. **Defining the scan result output contract** - Establishing a standardized JSON schema for scan results
2. **Fixing requirements inventory parsing** - Improving error handling and adding topology guards

---

## Detailed Changes

### 1. Define Scan Result v0.1 Contract and Demonstration Fixtures
**Commit:** `4af2d8e`  
**Branches:** `feat/inventory-report`, `docs/scan-result-contract`

#### What Changed:
Created a comprehensive JSON schema specification and example files for scan results.

#### Files Added:
- `docs/specs/scan-result-v0.1.md` (158 lines)
- `examples/scan-results/dependency-graph-demo.json` (76 lines)
- `examples/scan-results/inventory-only.json` (52 lines)

#### Key Features Defined:

**Scan Result Structure:**
```json
{
  "schema_version": "0.1",
  "scan_id": "uuid-v4",
  "created_at": "ISO-8601 UTC",
  "status": "complete|partial|failed",
  "input": {...},
  "analysis_mode": "inventory|dependency_graph",
  "topology_status": "known|unavailable",
  "packages": [...],
  "edges": [...],
  "vulnerability_lookup": {...},
  "findings": [...],
  "risk": {...},
  "warnings": [...]
}
```

**Critical Design Decisions:**

1. **Package IDs are scan-local** - Package IDs are unique within a single scan but NOT guaranteed stable across scans. This is intentional because the same package name/version can be installed multiple times in different locations.

2. **Topology Status Guard** - When `topology_status` is `"unavailable"`, the `edges` array MUST be empty and risk scoring cannot be performed. This prevents invalid risk calculations.

3. **Vulnerability Lookup Coverage** - The schema tracks which packages were successfully checked via `checked_package_ids` array, enabling auditability of vulnerability scanning coverage.

4. **Risk Scoring Guard** - Risk analysis requires explicitly "known" topology. If topology is unavailable, `risk.status` becomes `"unavailable"` with a descriptive reason.

5. **Inventory Mode Constraints** - Inventory scans (package discovery only) require `topology_status: "unavailable"` but can still perform package-level vulnerability checks.

---

### 2. Fix Requirements Inventory Parsing and Guard Unavailable Topology
**Commit:** `f0ffac4`  
**Branch:** `fix/requirements-inventory`

#### What Changed:
Improved error handling in the requirements parser and added guards to prevent risk analysis when topology is unavailable.

#### Files Modified:
- `src/engine/risk_analyzer.py` (+39, -44 lines)
- `src/models/dependency_graph.py` (+1 line)
- `src/parser/parser.py` (+45, -8 lines)
- `tests/test_parser.py` (+124, -3 lines)

#### Key Improvements:

**1. New Exception Class:**
```python
class UnavailableTopologyError(Exception):
    """Raised when risk analysis is requested but dependency topology is unavailable."""
```

**2. Topology Guard in Risk Analyzer:**
```python
if graph.edge_availability != "known":
    raise UnavailableTopologyError(
        f"Cannot calculate systemic risk: dependency topology state is "
        f"'{graph.edge_availability}'. Only explicitly 'known' topology is "
        f"accepted for scoring."
    )
```

**3. Parser Error Handling:**
- **Before:** Silently printed warnings and returned empty graphs for missing files
- **After:** Raises `FileNotFoundError` for missing files and `IOError` for read errors

**4. Topology Status Tracking:**
Added `edge_availability` field to `DependencyGraph`:
- `"known"` - Full dependency graph with edges (from synthetic graph input)
- `"unavailable"` - Package list only, no edges (from requirements.txt)
- `"none"` - Freshly created, empty graph

**5. Parser Behavior Changes:**
- **Removed:** Fabricated "system_core" node and edges from requirements.txt parsing
- **Added:** Explicit `edge_availability = "unavailable"` for requirements.txt
- **Added:** `edge_availability = "known"` for synthetic graph input

**6. Test Coverage:**
Added comprehensive tests for:
- Missing file handling (raises `FileNotFoundError`)
- Empty file handling (returns empty graph, doesn't raise)
- Distinguishing empty vs missing files
- Unavailable topology guards (raises `UnavailableTopologyError`)
- Mock graph still works for scoring

---

## Impact on Project Partners

### For Developers:
1. **Breaking Change:** The parser now raises exceptions instead of silently returning empty graphs. Update error handling in your code.

2. **New API:** Use `UnavailableTopologyError` to handle cases where risk analysis is requested without proper topology.

3. **Schema Compliance:** When implementing serializers, follow the v0.1 contract for scan results.

### For QA/Testing:
1. **Test Coverage:** New tests ensure robust error handling for edge cases (missing files, empty files, unavailable topology).

2. **Fixture Files:** Use the new example JSON files as reference implementations for expected output formats.

### For Product/Operations:
1. **Clearer Error Messages:** Users will now see explicit error messages when files are missing or topology is unavailable.

2. **Audit Trail:** The `checked_package_ids` field enables tracking which packages were actually scanned for vulnerabilities.

3. **Safety First:** Risk scoring now explicitly fails when topology is unavailable, preventing invalid or misleading risk scores.

---

## Next Steps

1. **Implement Serializer:** Create a serializer to convert parsed data to the v0.1 JSON schema format.

2. **Severity Standard:** Define a severity standard for findings (currently `severity: null`).

3. **Risk Scoring Method:** Implement and configure a risk scoring method (currently unavailable).

4. **Integration Testing:** Test the full pipeline with real requirements files and dependency graphs.

---

## Technical Debt Notes

- The v0.1 contract is marked as a prototype; severity fields are not yet defined.
- Risk scoring method is pending implementation.
- A serializer connecting the existing parser to the new format has not been implemented.

---

*Generated automatically from git history. For questions, contact the development team.*
