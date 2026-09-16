
import os
import unittest

from src.models.dependency_graph import DependencyGraph, DependencyNode
from src.parser.parser import build_mock_graph, parse_requirements
from src.engine.risk_analyzer import calculate_systemic_risk, UnavailableTopologyError


class TestDependencyGraphParsing(unittest.TestCase):

    def test_simple_graph_build(self):
        """Tests the helper to ensure nodes and basic edges are created."""
        graph = build_mock_graph()
        self.assertIsInstance(graph, DependencyGraph)

        # Expected nodes: requests, django, system_core
        self.assertEqual(len(graph.get_nodes_list()), 3)

        # Expected edges: (requests -> core), (django -> core)
        self.assertEqual(len(graph.get_edges_list()), 2)

    def test_parser_file_read(self):
        """Tests the primary parser with a mock requirements file."""
        mock_requirements_path = "./temp_requirements.txt"
        test_content = "requests==2.28.1\ndjango==4.2\nflask==2.0.0"
        with open(mock_requirements_path, "w") as f:
            f.write(test_content)

        graph = parse_requirements(mock_requirements_path)

        # We expect 3 nodes (req, django, flask) — no fabricated system_core
        self.assertEqual(len(graph.get_nodes_list()), 3)

        # Verify exact package names and versions are preserved
        node_keys = graph.get_nodes_list()
        self.assertIn(("requests", "2.28.1"), node_keys)
        self.assertIn(("django", "4.2"), node_keys)
        self.assertIn(("flask", "2.0.0"), node_keys)

        # No fabricated edges should be present
        self.assertEqual(len(graph.get_edges_list()), 0)

        # Topology is unavailable (requirements.txt doesn't encode edges)
        self.assertEqual(graph.edge_availability, "unavailable")

        # Clean up the mock file
        os.remove(mock_requirements_path)

    def test_parser_missing_file_raises(self):
        """Missing input file must produce an explicit failure."""
        with self.assertRaises(FileNotFoundError):
            parse_requirements("nonexistent_requirements.txt")

    def test_parser_empty_file_returns_empty_graph(self):
        """Valid but empty file returns an empty graph, not a failure."""
        mock_empty_path = "./temp_empty_requirements.txt"
        with open(mock_empty_path, "w") as f:
            f.write("")  # empty file

        graph = parse_requirements(mock_empty_path)

        self.assertEqual(len(graph.get_nodes_list()), 0)
        self.assertEqual(len(graph.get_edges_list()), 0)
        self.assertEqual(graph.edge_availability, "unavailable")

        os.remove(mock_empty_path)

    def test_parser_empty_vs_missing_are_distinct(self):
        """Empty-file behavior must be distinguishable from missing-file."""
        mock_empty_path = "./temp_empty_detect.txt"
        with open(mock_empty_path, "w") as f:
            f.write("")

        empty_graph = parse_requirements(mock_empty_path)
        # Empty file: succeeds, returns empty graph
        self.assertEqual(len(empty_graph.get_nodes_list()), 0)
        os.remove(mock_empty_path)

        # Missing file: raises
        with self.assertRaises(FileNotFoundError):
            parse_requirements("./nonexistent_detect.txt")


class TestUnavailableTopology(unittest.TestCase):
    """Verify unavailable topology cannot silently return 0.0."""

    def test_unavailable_topology_raises_exception(self):
        """Scoring with unavailable topology raises a clear exception."""
        mock_path = "./temp_topo_detect.txt"
        with open(mock_path, "w") as f:
            f.write("requests==2.28.1\n")
        graph = parse_requirements(mock_path)
        os.remove(mock_path)

        # Unavailable topology must raise, not return 0.0
        with self.assertRaises(UnavailableTopologyError):
            calculate_systemic_risk(graph)

    def test_build_mock_graph_still_works_for_scoring(self):
        """build_mock_graph() still produces a scoreable graph."""
        graph = build_mock_graph()
        # Must NOT raise
        risk = calculate_systemic_risk(graph)
        self.assertIsInstance(risk, float)
        self.assertGreaterEqual(risk, 0.0)

    def test_default_graph_rejected(self):
        """A freshly created graph (edge_availability='none') must be rejected."""
        graph = DependencyGraph()
        graph.add_node(DependencyNode("requests", "2.28.1"))
        graph.add_node(DependencyNode("django", "4.2"))

        with self.assertRaises(UnavailableTopologyError) as ctx:
            calculate_systemic_risk(graph)
        self.assertIn("'none'", str(ctx.exception))

    def test_invalid_topology_state_rejected(self):
        """An invalid edge_availability value must raise, not score."""
        graph = DependencyGraph()
        graph.edge_availability = "invalid_state"
        graph.add_node(DependencyNode("requests", "2.28.1"))

        with self.assertRaises(UnavailableTopologyError):
            calculate_systemic_risk(graph)

    def test_known_edgeless_graph_not_rejected_for_no_edges(self):
        """A graph explicitly marked 'known' but with zero edges must not be
        rejected solely because it is edgeless — topology is known to be empty."""
        graph = DependencyGraph()
        graph.edge_availability = "known"
        graph.add_node(DependencyNode("requests", "2.28.1"))
        graph.add_node(DependencyNode("django", "4.2"))

        # Should NOT raise; edges may legitimately be empty for a known graph
        risk = calculate_systemic_risk(graph)
        self.assertIsInstance(risk, float)


if __name__ == "__main__":
    unittest.main()
