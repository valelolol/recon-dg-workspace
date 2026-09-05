

import networkx.algorithms.centrality as nx_centrality
import numpy as np

from src.models.dependency_graph import DependencyGraph

# --- Mock Data Service ---
# Global function to simulate fetching CVE data
# In a real system, this would query a database (NVD, OSV).
MOCK_CVE_DB: dict[tuple[str, str], dict[str, float]] = {
    # (Package, Version): {CVE_ID: Severity_Score (1.0=Critical, 0.1=Low)}
    ("requests", "2.28.1"): {
        "CVE-2023-1234": 0.85, # High severity
        "IGNORED-CVE": 0.05
    },
    ("django", "4.2"): {
        "CVE-2022-9999": 0.3, # Medium severity
    },
    ("core_lib", "1.0.0"): {
        # Assume the system core has a vulnerability that impacts everything
        "CVE-2021-1000": 0.95
    }
}

def get_cve_severity(node_key: tuple[str, str]) -> dict[str, float]:
    """Retrieves mock CVE scores for a given dependency node."""
    return MOCK_CVE_DB.get(node_key, {})

def calculate_systemic_risk(graph: DependencyGraph) -> float:
    """
    Calculates the aggregate systemic risk score for the entire dependency graph.
    The score factors in:
    1. Global vulnerability severity (CVE weight).
    2. Node centrality (how essential a failing dependency is).
    3. Edge dependency weight (how critical the connection itself is).
    """
    
    
    # 1. Calculate Max Vulnerability Score per Node (Focus on worst case)
    node_risks: dict[tuple[str, str], float] = {}
    for node_key in graph.get_nodes_list():
        cve_scores = get_cve_severity(node_key)
        if cve_scores:
            # Max vulnerability score for this component
            node_risks[node_key] = max(cve_scores.values())
        else:
            node_risks[node_key] = 0.0

    # 2. Calculate Centrality Scores (How dependent is the network on this node)
    # We use the graph's underlying NetworkX representation
    nx_graph = graph.graph
    if nx_graph.number_of_nodes() < 2:
        return 0.0
        
    # Betweenness centrality is a good proxy for critical path dependency
    centrality = nx_centrality.betweenness_centrality(nx_graph)
    
    # 3. Calculate Weighted Edge/Systemic Risk
    edge_risk_sum = 0.0
    for (source_key, target_key), weight_edge in graph.edge_weights.items():
        # Node importance factors (centrality)
        source_c = centrality.get(source_key, 0.0)
        target_c = centrality.get(target_key, 0.0)
        
        # Vulnerability Factors (Severity)
        source_vuln = node_risks.get(source_key, 0.0)
        target_vuln = node_risks.get(target_key, 0.0)
        
        # Combined dynamic risk formula: 
        # Edge Risk = Edge Weight * (Source Vulnerability + Target Vulnerability)
        #             * (Source Centrality * Target Centrality + 1)
        # This heavily penalizes connections between two highly vulnerable, central components.
        dynamic_risk = weight_edge * (source_vuln + target_vuln) * (source_c * target_c + 1.0)
        edge_risk_sum += dynamic_risk
    
    # Normalize and scale the risk: take the average edge risk amplified by the total node count
    systemic_risk = edge_risk_sum / max(1.0, nx_graph.number_of_edges()) * np.sqrt(nx_graph.number_of_nodes())
    
    return min(systemic_risk, 10.0) # Cap risk score for easier interpretation
