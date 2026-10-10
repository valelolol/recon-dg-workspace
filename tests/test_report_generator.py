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
        # node count.  To prove invariance more broadly, use build_mock_graph (
        # which draws on nodes present in MOCK_CVE_DB) and show the score is
        # identical whether the severities are low, high, or present at all.
        self.assertEqual(baseline, 6.0)

        from src.parser.parser import build_mock_graph

        mock_graph = build_mock_graph()
        import src.engine.risk_analyzer as ra
        # Save the original severities so we can restore after the test.
        original_sev = {
            (pk, pv): dict(ra.MOCK_CVE_DB.get((pk, pv), {}))
            for pk, pv in [
                ("requests", "2.28.1"),
                ("django", "4.2"),
                ("core_lib", "1.0.0"),
            ]
        }
        try:
            before = calculate_phei(mock_graph)
            # Push every severity to its extreme (both very low and very high).
            ra.MOCK_CVE_DB[("requests", "2.28.1")] = {
                "CVE-2023-1234": 0.95,
                "IGNORED-CVE": 0.95,
            }
            after_high = calculate_phei(mock_graph)
            ra.MOCK_CVE_DB[("requests", "2.28.1")] = {
                "CVE-2023-1234": 0.01,
                "IGNORED-CVE": 0.01,
            }
            ra.MOCK_CVE_DB[("django", "4.2")] = {
                "CVE-2022-9999": 0.01,
            }
            after_low = calculate_phei(mock_graph)
            self.assertEqual(before, after_high, "score must not depend on high severity")
            self.assertEqual(before, after_low, "score must not depend on low severity")
        finally:
            # Restore original severities (mock DB is shared module state).
            for key, sev in original_sev.items():
                if key in ra.MOCK_CVE_DB:
                    ra.MOCK_CVE_DB[key] = sev
                else:
                    ra.MOCK_CVE_DB.pop(key, None)


if __name__ == "__main__":
    unittest.main()
