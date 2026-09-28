import unittest

from src.engine.risk_analyzer import (
    calculate_systemic_risk,
    calculate_phei,
    calculate_path_weight,
    calculate_impact_multiplicity,
)
from src.parser.parser import build_mock_graph


class TestRiskAnalyzer(unittest.TestCase):
    
    def test_basic_phei_calculation(self):
        """Test basic PHEI calculation on the mocked graph."""
        graph = build_mock_graph()
        
        # Calculate PHEI
        phei = calculate_phei(graph)
        
        # PHEI should be a non-negative float
        self.assertIsInstance(phei, float)
        self.assertGreaterEqual(phei, 0.0)
        
        # PHEI should be capped at 10.0
        self.assertLessEqual(phei, 10.0)
        
        print(f"Mock PHEI Score: {phei}")
        self.assertAlmostEqual(phei, 2.0, delta=0.5)
    
    def test_path_weight_calculation(self):
        """Test path weight calculation along a dependency chain."""
        graph = build_mock_graph()
        
        # Define a path from requests to system_core
        path = [
            ("requests", "2.28.1"),
            ("system_core", "1.0.0")
        ]
        
        # Calculate weight
        weight = calculate_path_weight(path, graph)
        
        # Should equal the edge weight between the nodes
        self.assertEqual(weight, 1.0)
    
    def test_path_impact_multiplicity(self):
        """Test impact multiplicity calculation for a path."""
        graph = build_mock_graph()
        
        # Define a path with 2 nodes
        path = [
            ("requests", "2.28.1"),
            ("system_core", "1.0.0")
        ]
        
        # Impact multiplicity should be number of unique nodes
        multiplicity = calculate_impact_multiplicity(path, graph)
        
        self.assertEqual(multiplicity, 2)
    
    def test_empty_graph_phei(self):
        """Test PHEI calculation on an empty graph."""
        from src.models.dependency_graph import DependencyGraph
        
        graph = DependencyGraph()
        graph.edge_availability = "known"
        
        phei = calculate_phei(graph)
        self.assertEqual(phei, 0.0)
    
    def test_phei_with_single_path(self):
        """Test PHEI with a single known path."""
        from src.models.dependency_graph import DependencyGraph, DependencyNode
        
        graph = DependencyGraph()
        graph.edge_availability = "known"
        
        # Add two nodes with an edge
        node1 = DependencyNode("pkg1", "1.0.0")
        node2 = DependencyNode("pkg2", "2.0.0")
        graph.add_node(node1)
        graph.add_node(node2)
        graph.add_edge(("pkg1", "1.0.0"), ("pkg2", "2.0.0"), weight=2.0)
        
        # Calculate PHEI
        phei = calculate_phei(graph)
        
        # Path weight = 2.0, multiplicity = 2
        # PHEI = 2.0 * 2 = 4.0
        self.assertAlmostEqual(phei, 4.0, delta=0.01)


if __name__ == "__main__":
    unittest.main()
