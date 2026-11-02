# E2E expected results (W1-DE-03.T)

Expected results for `tests/test_e2e_risk.py`. The tests run offline and use fixed
`scan_id` / `created_at` values.

```bash
python -m pytest tests/test_e2e_risk.py -v
```

## Current state: Mode B is partly blocked

These prerequisites are not in the repository, so the tests that need them **skip and
name what is missing**. A skip means "not verified yet", not "passed".

| Missing | Owner | Task |
|---------|-------|------|
| `examples/fixtures/sample_risk_report.json` | Vale | W1-DE-03.R |
| `load_known_topo_json()` in `src/parser/parser.py` | Vale | W1-DE-01.L |
| `serialize_inventory` support for known topology (it raises `ValueError` today) | Vale | W1-DE-03.R |
| `examples/fixtures/known_topology.json` | Nick | W1-DE-01.F |

The handoff's acceptance criteria for the 6.0 reference and byte-identity are **not met**
until those exist and the skipped tests pass.

## Scenario 1: Mode A (inventory)

Input: `tests/fixtures/requirements_simple.txt`. Runs today.

| Test | Expected |
|------|----------|
| `test_mode_a_inventory_report_has_no_score_or_edges` | `analysis_mode` is `inventory`, `topology_status` is `unavailable`, 3 packages, no edges or findings; `risk.status` is `unavailable`, `risk.score` and `risk.method` are `null`; no `top_risk_path` |
| `test_mode_a_graph_is_refused_by_phei` | `calculate_phei` raises `UnavailableTopologyError` |

## Scenario 2: Mode B (graph)

Input: the 3-node unit chain A→B→C from `TASKS.md` §C0-prereq. PHEI is 2 edges × 1.0 × 3
nodes = 6.0.

| Test | Expected | Today |
|------|----------|-------|
| `test_mode_b_phei_on_reference_topology_is_six` | `calculate_phei` returns scalar `6.0` | Runs |
| `test_mode_b_generate_report_states_the_reference_score` | Markdown report contains `6.000` and `Path-Max` | Runs |
| `test_mode_b_reference_risk_is_six_phei_available` | `risk.score == 6.0`, `risk.method == "phei"`, `risk.status == "available"` | Skips |
| `test_mode_b_reference_contract_fields` | `dependency_graph`, `known`, `input.type == "file"`, `input.format == "synthetic-graph"`, 3 findings | Skips |
| `test_mode_b_reference_emits_no_path_field` | No `top_risk_path` at the top level or in `risk` | Skips |
| `test_mode_b_reference_findings_have_null_severity` | Every `findings[].severity` is `null` | Skips |
| `test_mode_b_reference_warns_data_is_synthetic` | A `warnings[]` entry contains `synthetic fixture` | Skips |
| `test_mode_b_pipeline_matches_reference_exactly` | Pipeline output equals the reference, using the reference's `scan_id` and `created_at` | Skips |

## Scenario 3: Determinism

| Test | Expected | Today |
|------|----------|-------|
| `test_mode_a_output_is_byte_identical_across_runs` | Two runs produce identical bytes | Runs |
| `test_generate_report_is_identical_across_runs` | Two runs produce identical text | Runs |
| `test_mode_b_output_is_byte_identical_across_runs` | Two runs produce identical bytes | Skips |

## Assumptions to confirm with Vale

- **The handoff's pipeline does not match `generate_report`.** It takes two graphs and returns
  Markdown, so it cannot be serialized into the reference JSON. The byte comparison uses
  `load_known_topo_json()` → `calculate_phei()` → `serialize_inventory()` → `json.dumps(result, indent=2)`,
  following `HANDOFF_VALE_MDECORE.md`. `generate_report` is tested separately.
- **`serialize_inventory(graph, filename, scan_id=..., created_at=...)` is assumed to stay the
  call.** If Mode B needs extra arguments, such as the advisory fixture, `_mode_b_json()` in the
  test must change.
- **Line endings are normalized.** The reference is read in text mode so a CRLF checkout still
  matches. Every other byte must match, including the absence of a trailing newline.

## Not tested

- Real NVD or OSV lookups, or any live API.
- The OSV-Scanner binary.
- The dashboard page or the explanation layer.
- The real-world accuracy of the 6.0 score. It is a synthetic reference, and the edge-weight
  function `w_uv` is still an open decision.
