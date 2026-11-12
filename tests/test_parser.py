
import os
import tempfile
import unittest

from src.models.dependency_graph import DependencyGraph, DependencyNode
from src.parser.parser import build_mock_graph, parse_go_mod, parse_pyproject_toml, parse_requirements
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


FIXTURE_DIR = os.path.join(os.path.dirname(__file__), "fixtures")
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class TestPyprojectParsing(unittest.TestCase):

    def _parse_text(self, text):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "pyproject.toml")
            with open(path, "w") as f:
                f.write(text)
            return parse_pyproject_toml(path)

    def test_fixture_main_and_optional_dependencies(self):
        graph = parse_pyproject_toml(os.path.join(FIXTURE_DIR, "pyproject_with_deps.toml"))

        self.assertCountEqual(
            graph.get_nodes_list(),
            [
                ("requests", ">=2.28.1"),
                ("django", "4.2"),
                ("numpy", ">=1.24.0"),
                ("pytest", ">=7.0"),
                ("ruff", "0.1.0"),
                ("sphinx", ">=5.0"),
            ],
        )
        self.assertEqual(len(graph.get_edges_list()), 0)
        self.assertEqual(graph.edge_availability, "unavailable")

    def test_repo_pyproject_has_no_dependencies(self):
        graph = parse_pyproject_toml(os.path.join(REPO_ROOT, "pyproject.toml"))

        self.assertEqual(graph.get_nodes_list(), [])
        self.assertEqual(graph.edge_availability, "unavailable")

    def test_extras_markers_and_bare_names(self):
        graph = self._parse_text(
            '[project]\nname = "x"\ndependencies = [\n'
            '  "requests[security]==2.31.0",\n'
            '  "tomli>=1.1; python_version < \'3.11\'",\n'
            '  "flask",\n'
            ']\n'
        )

        self.assertCountEqual(
            graph.get_nodes_list(),
            [("requests", "2.31.0"), ("tomli", ">=1.1"), ("flask", "unspecified")],
        )

    def test_missing_file_raises(self):
        with self.assertRaises(FileNotFoundError):
            parse_pyproject_toml("nonexistent_pyproject.toml")

    def test_invalid_toml_raises(self):
        with self.assertRaises(IOError):
            self._parse_text("[project\nname = ")


SAMPLE_GO_MOD = os.path.join(REPO_ROOT, "examples", "fixtures", "sample_go.mod")


class TestGoModParsing(unittest.TestCase):

    def _parse_text(self, text, **kwargs):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "go.mod")
            with open(path, "w") as f:
                f.write(text)
            return parse_go_mod(path, **kwargs)

    def test_fixture_direct_only_by_default(self):
        graph = parse_go_mod(SAMPLE_GO_MOD)

        self.assertEqual(graph.get_nodes_list(), [("github.com/gin-gonic/gin", "v1.9.1")])
        self.assertEqual(graph.get_edges_list(), [])
        self.assertEqual(graph.edge_availability, "unavailable")

    def test_fixture_include_indirect(self):
        graph = parse_go_mod(SAMPLE_GO_MOD, include_indirect=True)

        self.assertCountEqual(
            graph.get_nodes_list(),
            [
                ("github.com/gin-gonic/gin", "v1.9.1"),
                ("golang.org/x/net", "v0.17.0"),
                ("golang.org/x/text", "v0.13.0"),
            ],
        )
        self.assertEqual(graph.get_edges_list(), [])
        self.assertEqual(graph.edge_availability, "unavailable")

    def test_fixture_is_labeled_synthetic(self):
        with open(SAMPLE_GO_MOD) as f:
            self.assertIn("SYNTHETIC", f.readline())

    def test_ignores_replace_exclude_and_comments(self):
        graph = self._parse_text(
            "module example.com/x\n\ngo 1.22\n\n"
            "// a comment\n"
            "require (\n"
            "\t// comment inside block\n"
            "\tgithub.com/a/b v1.0.0\n"
            "\tgithub.com/c/d v2.1.0+incompatible\n"
            ")\n\n"
            "replace github.com/a/b => github.com/fork/b v1.0.1\n"
            "exclude (\n\tgithub.com/e/f v0.1.0\n)\n"
        )

        self.assertCountEqual(
            graph.get_nodes_list(),
            [("github.com/a/b", "v1.0.0"), ("github.com/c/d", "v2.1.0+incompatible")],
        )

    def test_go_mod_without_requires_returns_empty_graph(self):
        graph = self._parse_text("module example.com/x\n\ngo 1.22\n")

        self.assertEqual(graph.get_nodes_list(), [])
        self.assertEqual(graph.edge_availability, "unavailable")

    def test_missing_file_raises(self):
        with self.assertRaises(FileNotFoundError):
            parse_go_mod("nonexistent_go.mod")

    def test_scoring_inventory_only_go_graph_raises(self):
        with self.assertRaises(UnavailableTopologyError):
            calculate_systemic_risk(parse_go_mod(SAMPLE_GO_MOD))


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
