
import unittest

from src.engine.risk_analyzer import calculate_systemic_risk
from src.parser.parser import build_mock_graph


class TestSystemicRiskAnalyzer(unittest.TestCase):
    
    def test_basic_risk_calculation(self):
        """Tests the basic systemic risk calculation on the mocked graph."""
        # Mock setup: The mock graph involves requests/django -> system_core
        graph = build_mock_graph()
        
        # The calculated risk depends on the static mock CVEs defined in risk_analyzer.py
        # We check that the result is a positive number and finite.
        risk = calculate_systemic_risk(graph)
        
        self.assertIsInstance(risk, float)
        self.assertGreaterEqual(risk, 0.0)
        
        # We expect a non-zero risk score because CVEs exist
        print(f"Mock Systemic Risk: {risk}")
        self.assertAlmostEqual(risk, 1.5, delta=1.0) # Tolerance due to complexity
