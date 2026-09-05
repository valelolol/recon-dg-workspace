
import os
import unittest

from src.models.dependency_graph import DependencyGraph
from src.parser.parser import build_mock_graph, parse_requirements


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
        
        # We expect 3 nodes (req, django, flask) connected to system_core
        self.assertEqual(len(graph.get_nodes_list()), 4)
        
        # Clean up the mock file
        os.remove(mock_requirements_path)
