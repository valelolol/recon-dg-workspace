"""Offline end-to-end tests for the demo report (W1-DE-03.T).

Three scenarios, documented in ``docs/E2E_EXPECTED_RESULTS.md``:

* **Mode A (inventory):** requirements.txt -> scan-result v0.1 JSON, no score.
* **Mode B (graph):** known topology -> PHEI 6.0 -> report matching the checked-in
  reference ``examples/fixtures/sample_risk_report.json``.
* **Determinism:** the same fixed ``scan_id`` / ``created_at`` give identical output.

Mode B depends on W1-DE-01.L / W1-DE-03.R (Vale): the reference report,
``load_known_topo_json()``, and known-topology support in ``serialize_inventory``.
Tests that need a missing piece **skip and name it** rather than pass, so a skip
here means "not verified yet".  The PHEI tests build the 3-node chain directly and
run today.

No network, no scanner binary, and no live API are involved.  Plain ``def test_...``
functions only, as the handoff asks.
"""
from __future__ import annotations

import json
import os

import pytest

from src.engine.risk_analyzer import UnavailableTopologyError, calculate_phei
from src.models.dependency_graph import DependencyGraph, DependencyNode
from src.parser import parser as parser_module
from src.parser.parser import parse_requirements
from src.reporter.inventory import requirements_to_json, serialize_inventory
from src.reporter.report_generator import generate_report

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REQUIREMENTS = os.path.join(REPO_ROOT, "tests", "fixtures", "requirements_simple.txt")
KNOWN_TOPOLOGY = os.path.join(REPO_ROOT, "examples", "fixtures", "known_topology.json")
REFERENCE = os.path.join(REPO_ROOT, "examples", "fixtures", "sample_risk_report.json")

FIXED_SCAN_ID = "aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa"
FIXED_CREATED_AT = "2026-01-01T00:00:00.000Z"


def _known_unit_chain() -> DependencyGraph:
    """The reference topology: A->B->C with unit weights (TASKS.md §C0-prereq)."""
    g = DependencyGraph()
    g.edge_availability = "known"
    for name in ("synth-a", "synth-b", "synth-c"):
        g.add_node(DependencyNode(name, "0.0.0"))
    g.add_edge(("synth-a", "0.0.0"), ("synth-b", "0.0.0"), weight=1.0)
    g.add_edge(("synth-b", "0.0.0"), ("synth-c", "0.0.0"), weight=1.0)
    return g


def _reference_text() -> str:
    """The reference report as text, or skip if Vale's file is not checked in.

    Read in text mode so a CRLF checkout (``core.autocrlf``) compares the same as
    the LF output of ``json.dumps``; every other byte must match.
    """
    if not os.path.exists(REFERENCE):
        pytest.skip("needs examples/fixtures/sample_risk_report.json (W1-DE-03.R, Vale)")
    with open(REFERENCE, encoding="utf-8") as f:
        return f.read()


def _reference() -> dict:
    return json.loads(_reference_text())


def _mode_b_json(scan_id: str, created_at: str) -> str:
    """Run the Mode B pipeline and serialize it the way ``requirements_to_json`` does.

    A loader that exists alongside a serializer that still rejects known topology
    fails here instead of skipping: that is a real integration gap.
    """
    loader = getattr(parser_module, "load_known_topo_json", None)
    if loader is None:
        pytest.skip("needs load_known_topo_json() in src/parser/parser.py (W1-DE-01.L, Vale)")
    if not os.path.exists(KNOWN_TOPOLOGY):
        pytest.skip("needs examples/fixtures/known_topology.json (W1-DE-01.F, Nick)")
    graph = loader(KNOWN_TOPOLOGY)
    assert calculate_phei(graph) == 6.0
    result = serialize_inventory(graph, KNOWN_TOPOLOGY, scan_id=scan_id, created_at=created_at)
    return json.dumps(result, indent=2)


# --- Scenario 1: Mode A (inventory) ---------------------------------------


def test_mode_a_inventory_report_has_no_score_or_edges() -> None:
    """An inventory scan reports its packages and never fabricates a score."""
    report = json.loads(requirements_to_json(
        REQUIREMENTS, scan_id=FIXED_SCAN_ID, created_at=FIXED_CREATED_AT))
    assert report["schema_version"] == "0.1"
    assert report["scan_id"] == FIXED_SCAN_ID
    assert report["created_at"] == FIXED_CREATED_AT
    assert report["analysis_mode"] == "inventory"
    assert report["topology_status"] == "unavailable"
    assert {p["name"] for p in report["packages"]} == {"requests", "urllib3", "certifi"}
    assert report["edges"] == []
    assert report["findings"] == []
    assert report["risk"]["status"] == "unavailable"
    assert report["risk"]["score"] is None
    assert report["risk"]["method"] is None
    assert "top_risk_path" not in report


def test_mode_a_graph_is_refused_by_phei() -> None:
    """The graph behind an inventory report cannot reach a numeric score."""
    with pytest.raises(UnavailableTopologyError):
        calculate_phei(parse_requirements(REQUIREMENTS))


# --- Scenario 2: Mode B (graph) -------------------------------------------


def test_mode_b_phei_on_reference_topology_is_six() -> None:
    """2 unit edges x 3 nodes = 6.0, returned as a scalar."""
    assert calculate_phei(_known_unit_chain()) == 6.0


def test_mode_b_generate_report_states_the_reference_score() -> None:
    """``generate_report`` returns Markdown, not the v0.1 JSON, and carries 6.000."""
    text = generate_report(_known_unit_chain(), _known_unit_chain())
    assert "6.000" in text
    assert "Path-Max" in text


def test_mode_b_reference_risk_is_six_phei_available() -> None:
    risk = _reference()["risk"]
    assert risk["score"] == 6.0
    assert risk["method"] == "phei"
    assert risk["status"] == "available"


def test_mode_b_reference_contract_fields() -> None:
    report = _reference()
    assert report["analysis_mode"] == "dependency_graph"
    assert report["topology_status"] == "known"
    assert report["input"]["type"] == "file"
    assert report["input"]["format"] == "synthetic-graph"
    assert len(report["findings"]) == 3


def test_mode_b_reference_emits_no_path_field() -> None:
    """v0.1 defines no risk-path field, at the top level or inside ``risk``."""
    report = _reference()
    assert "top_risk_path" not in report
    assert "top_risk_path" not in report["risk"]


def test_mode_b_reference_findings_have_null_severity() -> None:
    findings = _reference()["findings"]
    assert findings
    assert all(f["severity"] is None for f in findings)


def test_mode_b_reference_warns_data_is_synthetic() -> None:
    warnings = _reference()["warnings"]
    assert any("synthetic fixture" in w for w in warnings)


def test_mode_b_pipeline_matches_reference_exactly() -> None:
    """Pipeline output equals the reference, using the reference's own fixed ids."""
    expected = _reference_text()
    reference = json.loads(expected)
    assert _mode_b_json(reference["scan_id"], reference["created_at"]) == expected


# --- Scenario 3: determinism ----------------------------------------------


def test_mode_a_output_is_byte_identical_across_runs() -> None:
    first = requirements_to_json(REQUIREMENTS, scan_id=FIXED_SCAN_ID, created_at=FIXED_CREATED_AT)
    second = requirements_to_json(REQUIREMENTS, scan_id=FIXED_SCAN_ID, created_at=FIXED_CREATED_AT)
    assert first.encode("utf-8") == second.encode("utf-8")


def test_generate_report_is_identical_across_runs() -> None:
    first = generate_report(_known_unit_chain(), _known_unit_chain())
    second = generate_report(_known_unit_chain(), _known_unit_chain())
    assert first == second


def test_mode_b_output_is_byte_identical_across_runs() -> None:
    first = _mode_b_json(FIXED_SCAN_ID, FIXED_CREATED_AT)
    second = _mode_b_json(FIXED_SCAN_ID, FIXED_CREATED_AT)
    assert first.encode("utf-8") == second.encode("utf-8")
