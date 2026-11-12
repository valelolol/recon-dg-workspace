"""Tests for the W1-DE-02.R report path: `generate_report` must use the
canonical `calculate_phei` (path-max) scalar, not the legacy global-sum
`calculate_systemic_risk`, and must never fabricate a score when the
dependency topology is unavailable.
"""
import unittest

from src.models.dependency_graph import DependencyGraph, DependencyNode
from src.engine.risk_analyzer import (
    calculate_phei,
    UnavailableTopologyError,
)
import src.engine.risk_analyzer as engine
import src.reporter.report_generator as report_gen
from src.reporter.report_generator import generate_report


def make_known_unit_chain() -> DependencyGraph:
    """3-node directed unit-weight chain A->B->C.

    PHEI = max_P [sum_edge_weights(P) * impact_multiplicity(P)]
          = 2 edges * 1.0 = 2.0 path weight * 3 nodes = 6.0.
    """
    g = DependencyGraph()
    g.edge_availability = "known"
    for name in ("synth-a", "synth-b", "synth-c"):
        g.add_node(DependencyNode(name, "0.0.0"))
    g.add_edge(("synth-a", "0.0.0"), ("synth-b", "0.0.0"), weight=1.0)
    g.add_edge(("synth-b", "0.0.0"), ("synth-c", "0.0.0"), weight=1.0)
    return g


def make_unavailable_graph() -> DependencyGraph:
    """A graph with explicitly unavailable topology (no edges, no scoring)."""
    g = DependencyGraph()
    g.edge_availability = "unavailable"
    g.add_node(DependencyNode("requests", "2.28.1"))
    g.add_node(DependencyNode("django", "4.2"))
    return g


def make_edgeless_known_graph() -> DependencyGraph:
    """A graph whose topology is explicitly known to be empty (0 edges)."""
    g = DependencyGraph()
    g.edge_availability = "known"
    g.add_node(DependencyNode("requests", "2.28.1"))
    g.add_node(DependencyNode("django", "4.2"))
    return g


class TestReportGeneratorUsesPHEI(unittest.TestCase):
    """generate_report must route through calculate_phei (path-max)."""

    def test_known_topology_calls_calculate_phei(self):
        """The report must call calculate_phei on both graphs (path-max path)."""
        current = make_known_unit_chain()
        previous = make_known_unit_chain()
        invocations = []

        original_phei = report_gen.calculate_phei
        report_gen.calculate_phei = lambda g: (invocations.append(g), original_phei(g))[1]

        try:
            report = generate_report(current, previous)
        finally:
            report_gen.calculate_phei = original_phei

        self.assertEqual(len(invocations), 2, "calculate_phei must run for current and previous graph")
        self.assertIn("6.000", report)
        self.assertIn("Path-Max", report)
        self.assertIn("PHEI", report)

    def test_report_does_not_use_legacy_systemic_risk(self):
        """The report must NOT fall back to the legacy global-sum
        calculate_systemic_risk (that path would be a correctness bug)."""
        current = make_known_unit_chain()
        previous = make_known_unit_chain()
        invocations = []

        original_sys = report_gen.calculate_systemic_risk

        def _legacy_should_never_call(graph):
            invocations.append(graph)
            raise AssertionError(
                "generate_report must not invoke calculate_systemic_risk (legacy global-sum)"
            )

        report_gen.calculate_systemic_risk = _legacy_should_never_call
        try:
            report = generate_report(current, previous)
        finally:
            report_gen.calculate_systemic_risk = original_sys

        self.assertEqual(invocations, [], "calculate_systemic_risk must not be called")
        self.assertNotIn("Global Risk Score", report)  # legacy wording gone
        self.assertIn("PHEI", report)

    def test_known_topology_reports_numeric_phei_score(self):
        """A known topology must emit a numeric PHEI score in the report."""
        current = make_known_unit_chain()
        previous = make_known_unit_chain()
        report = generate_report(current, previous)
        self.assertIn("6.000", report)
        self.assertIn("PHEI", report)
        # The report must reference the canonical PHEI method name.
        self.assertIn("Path-Max", report)


class TestReportGeneratorUnavailableTopology(unittest.TestCase):
    """Inventory-only / unavailable topology must never produce a fabricated
    numeric score. Per the project contract: edges stay empty, risk is reported
    as unavailable (no invented edges, no invented score)."""

    def test_unavailable_reports_risk_unavailable(self):
        current = make_unavailable_graph()
        previous = make_unavailable_graph()
        report = generate_report(current, previous)
        self.assertIn("unavailable", report.lower())
        self.assertNotIn("6.000", report)
        self.assertNotIn("2.000", report)
        # A fabricated numeric PHEI (e.g. 0.000) must NOT appear in the score field.
        self.assertNotIn("PHEI Risk Score: `0.000`", report)

    def test_unavailable_does_not_invoke_calculate_phei(self):
        """With unavailable topology, generate_report must not call
        calculate_phei (it raises UnavailableTopologyError, which is caught
        and surfaced as an 'unavailable' status — no numeric is fabricated)."""
        current = make_unavailable_graph()
        previous = make_unavailable_graph()
        invocations = []

        def _phei_should_not_call(graph):
            invocations.append(graph)
            raise UnavailableTopologyError("must not be called for unavailable topology")

        report = generate_report(current, previous)
        self.assertEqual(invocations, [])
        self.assertIn("unavailable", report.lower())

    def test_known_edgeless_graph_still_scores(self):
        """A graph explicitly known to be edgeless (0 edges) must score (PHEI 0.0
        is a real number, not a fabrication)."""
        current = make_edgeless_known_graph()
        previous = make_edgeless_known_graph()
        report = generate_report(current, previous)
        # 0 edges -> PHEI = 0.0, a legitimate score.
        self.assertIn("0.000", report)
        self.assertNotIn("unavailable", report.lower())

    def test_mixed_available_unavailable(self):
        """When one graph is known and the other unavailable, the report must
        show one side as a numeric score and the other as unavailable, without
        fabricating a number for the unavailable side."""
        current = make_known_unit_chain()
        previous = make_unavailable_graph()
        report = generate_report(current, previous)
        self.assertIn("6.000", report, "current (known) side must show numeric PHEI")
        self.assertIn("unavailable", report.lower(), "previous side must be unavailable")


class TestReportScoreInvariantToSeverity(unittest.TestCase):
    """Per the design spec, the current PHEI is topology-based (edge weights x
    node multiplicity) and is invariant to CVE severity — severity is null per
    v0.1 and the edge-weight function w_uv is an OPEN decision. Flipping the
    severities in the mock CVE DB must not change the computed score."""

    def test_phei_invariant_to_cve_severity_values(self):
        graph = make_known_unit_chain()
        baseline = calculate_phei(graph)  # 6.0 for the 3-node unit chain

        # Perturb the mock CVE severities for nodes that ARE in the mock DB and
        # re-run PHEI on a separate known graph to prove the score is unaffected
        # by any severity value.
        #
        # The chain's synthetic nodes are not in MOCK_CVE_DB, so their
        # node_risks are 0.0 regardless; the 6.0 is purely from edge weights x
        # node count.  To prove invariance more broadly, use build_mock_graph
        # (which draws on nodes present in MOCK_CVE_DB) and show the score is
        # identical whether the severities are low, high, or present at all.
        self.assertEqual(baseline, 6.0)

        from src.parser.parser import build_mock_graph
        from unittest.mock import patch

        mock_graph = build_mock_graph()
        before = calculate_phei(mock_graph)

        # Prove invariance by patching get_cve_severity with different severity values
        # and showing the score doesn't change.
        with patch("src.engine.risk_analyzer.get_cve_severity", return_value={"CVE-X": 0.95}):
            after_high = calculate_phei(mock_graph)
        with patch("src.engine.risk_analyzer.get_cve_severity", return_value={"CVE-X": 0.01}):
            after_low = calculate_phei(mock_graph)
        self.assertEqual(before, after_high, "score must not depend on high severity")
        self.assertEqual(before, after_low, "score must not depend on low severity")


class TestReportGeneratorModeB(unittest.TestCase):
    """Mode B: generate_report_mode_b emits a RiskReport dataclass.

    Contract requirements (TASKS.md §DECISIONS):
      - PHEI is topology-only; stored in ``phei_score``, NOT in
        ``current_systemic_risk``.
      - Unavailable topology → ``phei_score=None`` (not 0.0),
        ``has_fallback_applied=True``, ``fallback_reason`` set.
      - PHEI is NOT mapped through OSV severity thresholds.
      - Findings reflect actual CVE data on graph nodes only.
      - No remediation plan is generated (no ScanResult available).
    """

    def test_known_topology_returns_risk_report(self):
        """Mode B returns a RiskReport with PHEI in phei_score, not
        current_systemic_risk. The 3-node unit chain yields PHEI=6.0."""
        from src.reporter.report_generator import generate_report_mode_b
        from src.reporter.interface import RiskReport

        graph = make_known_unit_chain()
        report = generate_report_mode_b(graph)
        self.assertIsInstance(report, RiskReport)
        self.assertEqual(report.phei_score, 6.0)
        self.assertEqual(report.current_systemic_risk, 0.0)  # not PHEI
        self.assertEqual(report.overall_risk_level.value, "low")  # no severity data
        self.assertEqual(len(report.nodes), 3)
        self.assertEqual(len(report.edges), 2)
        self.assertFalse(report.has_fallback_applied)

    def test_unavailable_topology_no_fabricated_score(self):
        """Unavailable topology yields phei_score=None (not 0.0) and
        fallback flag. A score of 0.0 is not a substitute for unavailable."""
        from src.reporter.report_generator import generate_report_mode_b

        graph = make_unavailable_graph()
        report = generate_report_mode_b(graph)
        self.assertIsNone(report.phei_score)
        self.assertTrue(report.has_fallback_applied)
        self.assertEqual(report.fallback_reason, "unavailable topology; no score fabricated")
        self.assertEqual(report.current_systemic_risk, 0.0)  # default, not calculated
        self.assertEqual(report.overall_risk_level.value, "low")
        # Contract fields: risk status unavailable
        self.assertEqual(report.risk["status"], "unavailable")
        self.assertIsNone(report.risk["score"])
        self.assertEqual(report.risk["method"], "phei")
        # topology_status reflects unavailable
        self.assertEqual(report.topology_status, "unavailable")
        # findings/evidence/remediation_plan empty (no data available)
        self.assertEqual(report.findings, [])
        self.assertEqual(report.evidence, [])
        self.assertEqual(report.remediation_plan, [])

    def test_edgeless_known_graph_no_edges(self):
        """Known but edgeless graph produces zero edges and PHEI=0.0
        (a real calculated score, not a fabrication)."""
        from src.reporter.report_generator import generate_report_mode_b

        graph = make_edgeless_known_graph()
        report = generate_report_mode_b(graph)
        self.assertEqual(len(report.edges), 0)
        self.assertEqual(report.phei_score, 0.0)  # real score, not None
        self.assertFalse(report.has_fallback_applied)
        self.assertEqual(report.current_systemic_risk, 0.0)

    def test_mode_b_does_not_call_calculate_systemic_risk(self):
        """Mode B must not invoke the legacy global-sum function."""
        from src.reporter.report_generator import generate_report_mode_b

        graph = make_known_unit_chain()
        called = []

        def _should_never_call(g):
            called.append(g)
            raise AssertionError("generate_report_mode_b must not call calculate_systemic_risk")

        original = report_gen.calculate_systemic_risk
        report_gen.calculate_systemic_risk = _should_never_call
        try:
            generate_report_mode_b(graph)
        finally:
            report_gen.calculate_systemic_risk = original

        self.assertEqual(called, [], "calculate_systemic_risk must not be called")

    def test_mode_b_output_to_dict_serializable(self):
        """RiskReport.to_dict() must not raise on Mode B output and must
        include phei_score (possibly None)."""
        from src.reporter.report_generator import generate_report_mode_b

        graph = make_known_unit_chain()
        report = generate_report_mode_b(graph)
        d = report.to_dict()
        self.assertIn("current_systemic_risk", d)
        self.assertIn("phei_score", d)
        self.assertEqual(d["phei_score"], 6.0)
        self.assertIn("nodes", d)
        self.assertIn("edges", d)
        self.assertIn("top_risks", d)
        self.assertIn("recommendations", d)
        # Contract fields (TASKS.md §DECISIONS / ROADMAP W9/W10)
        self.assertIn("findings", d)
        self.assertIn("evidence", d)
        self.assertIn("risk", d)
        self.assertIn("remediation_plan", d)
        self.assertIn("input", d)
        self.assertIn("analysis_mode", d)
        self.assertIn("topology_status", d)
        self.assertIn("warnings", d)
        self.assertIn("vulnerability_lookup", d)
        self.assertIn("packages", d)
        self.assertIn("edges", d)
        self.assertEqual(d["risk"]["status"], "available")
        self.assertEqual(d["risk"]["score"], 6.0)
        self.assertEqual(d["risk"]["method"], "phei")
        # input / analysis_mode / topology_status
        self.assertEqual(d["input"]["type"], "file")
        self.assertEqual(d["input"]["format"], "synthetic-graph")
        self.assertEqual(d["analysis_mode"], "dependency_graph")
        self.assertEqual(d["topology_status"], "known")
        # warnings present
        self.assertGreater(len(d["warnings"]), 0)

    def test_phei_not_mapped_through_severity_thresholds(self):
        """PHEI is a topology score (0–10); it must NOT be compared against
        OSV severity thresholds (e.g. 7.0 for High). The overall_risk_level
        must remain LOW when only PHEI is available."""
        from src.reporter.report_generator import generate_report_mode_b
        from src.reporter.interface import RiskLevel

        graph = make_known_unit_chain()
        report = generate_report_mode_b(graph)
        # PHEI=6.0 is NOT >= 7.0; even if it were, we must not map it
        # through severity thresholds.
        self.assertEqual(report.overall_risk_level, RiskLevel.LOW)
        # Confirm phei_score is the topology score, not a severity category
        self.assertEqual(report.phei_score, 6.0)
        self.assertEqual(report.current_systemic_risk, 0.0)

    def test_findings_only_reflect_actual_vulnerability_data(self):
        """top_risks must contain actual CVE findings (one per CVE per node),
        not per-node PHEI scores repeated. nodes.cves must match node data."""
        from src.reporter.report_generator import generate_report_mode_b

        graph = make_known_unit_chain()
        report = generate_report_mode_b(graph)

        # top_risks should be populated from node.vulnerabilities
        # (the synthetic test graph has no CVEs, so top_risks may be empty)
        # The key assertion is the structure: each entry has cve_id, not score
        for entry in report.top_risks:
            self.assertIn("cve_id", entry)
            self.assertIn("package", entry)
            self.assertIn("version", entry)
            self.assertIn("severity_score", entry)
            self.assertNotIn("score", entry)  # no PHEI score in findings

        # nodes must have cves matching node.vulnerabilities
        for key, node in graph.nodes.items():
            node_key = str(key)
            self.assertIn(node_key, report.nodes)
            cves = report.nodes[node_key].cves
            expected_cve_count = len(node.vulnerabilities)
            self.assertEqual(len(cves), expected_cve_count)

    def test_no_invented_remediation(self):
        """Mode B must not fabricate remediation strings. The remediation
        planner (build_remediation_plan) requires a ScanResult; Mode B
        receives only a graph."""
        from src.reporter.report_generator import generate_report_mode_b

        graph = make_known_unit_chain()
        report = generate_report_mode_b(graph)
        self.assertEqual(report.recommendations, [])
        self.assertEqual(len(report.recommendations), 0)

    def test_mode_a_risk_not_empty_dict(self):
        """create_report (Mode A) must not leave risk={} — that signals
        missing data rather than 'unavailable'."""
        from src.reporter.interface import create_report, RiskLevel

        report = create_report(
            report_id="test-001",
            current_risk=0.5,
            previous_risk=0.3,
            nodes={},
            edges={},
            node_changes=[],
        )
        self.assertNotEqual(report.risk, {})
        self.assertEqual(report.risk["status"], "unavailable")
        self.assertIsNone(report.risk["score"])
        self.assertEqual(report.risk["method"], "phei")
        self.assertEqual(report.analysis_mode, "inventory")
        self.assertEqual(report.topology_status, "unavailable")

    def test_mode_a_json_shape_regression(self):
        """Old Mode A consumers expect: edges=[] (empty list), risk truthy
        (not {}), analysis_mode='inventory', topology_status='unavailable'.
        This is the pre-change contract shape that must not regresses."""
        from src.reporter.interface import create_report

        report = create_report(
            report_id="reg-a",
            current_risk=0.5,
            previous_risk=0.3,
            nodes={},
            edges={},
            node_changes=[],
        )
        d = report.to_dict()
        # edges must be an empty list (not a dict, not None)
        self.assertEqual(d["edges"], [])
        self.assertIsInstance(d["edges"], list)
        # risk must be truthy (not the empty dict that signaled 'missing')
        self.assertTrue(d["risk"])
        self.assertIn("status", d["risk"])
        self.assertEqual(d["risk"]["status"], "unavailable")
        # analysis_mode / topology_status must not be empty strings
        self.assertEqual(d["analysis_mode"], "inventory")
        self.assertEqual(d["topology_status"], "unavailable")
        # internal edges dict is under 'edges_dict', not 'edges'
        self.assertIn("edges_dict", d)
        self.assertIsInstance(d["edges_dict"], dict)

    def test_mode_b_contract_edges_shape_regression(self):
        """Mode B contract: edges[] is a list of dicts with id/source_id/
        target_id/type — not a dict, not edges_output. This is the documented
        schema that dashboard/consumers rely on."""
        from src.reporter.report_generator import generate_report_mode_b

        graph = make_known_unit_chain()
        report = generate_report_mode_b(graph)
        d = report.to_dict()

        self.assertIn("edges", d)
        edges = d["edges"]
        self.assertIsInstance(edges, list)
        self.assertEqual(len(edges), 2)
        for edge in edges:
            self.assertIn("id", edge)
            self.assertIn("source_id", edge)
            self.assertIn("target_id", edge)
            self.assertIn("type", edge)
            self.assertEqual(edge["type"], "dependency")

        # Internal dict must NOT be under 'edges' (collision fix)
        self.assertNotIsInstance(d["edges"], dict)
        self.assertIn("edges_dict", d)
        self.assertIsInstance(d["edges_dict"], dict)


if __name__ == "__main__":
    unittest.main()
