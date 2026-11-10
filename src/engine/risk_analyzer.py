import networkx.algorithms.centrality as nx_centrality
import networkx as nx
import numpy as np
from typing import Optional

from src.models.dependency_graph import DependencyGraph
from src.engine.nvd_client import get_client as _get_nvd_client, NVDClient


def get_cve_severity(
    node_key: tuple[str, str],
    client: Optional["NVDClient"] = None,
) -> dict[str, float]:
    """Retrieves CVE severity data for a given dependency node.

    Order of lookup:
        1. Injected ``client`` (for tests / explicit injection).
        2. Global default NVD client (``src.engine.nvd_client.get_client()``).

    Returns an empty dict when no data is found — this is not an error;
    it means the node has no known CVEs (or the source is unavailable)
    and the caller should treat the node as having ``severity_score: None``.

    Args:
        node_key: (package_name, version) tuple.
        client: Optional injected NVDClient for testing. When provided,
            only that client is queried (no fallback to MOCK_CVE_DB).

    Returns:
        Mapping of CVE ID → severity score (0.0–1.0), or empty dict.
    """
    # 1. Injected client (tests) — no fallback
    if client is not None:
        ecosystem, package, version = _resolve_ecosystem_and_query(node_key)
        if ecosystem is not None:
            result = client.query_nvd_api(ecosystem, package, version)
            if result is not None:
                return result
            # NVD returned nothing → try OSV fallback
            osv_result = client.query_osv_api(ecosystem, package, version)
            if osv_result is not None:
                return osv_result
        return {}

    # 2. Global default client
    default = _get_nvd_client()
    if default is not None:
        ecosystem, package, version = _resolve_ecosystem_and_query(node_key)
        if ecosystem is not None:
            result = default.query_nvd_api(ecosystem, package, version)
            if result is not None:
                return result
            osv_result = default.query_osv_api(ecosystem, package, version)
            if osv_result is not None:
                return osv_result
        return {}

    # No client available (production default: _default_client is None).
    # Return empty dict — do NOT fall back to MOCK_CVE_DB in production.
    # MOCK_CVE_DB is only available via an explicit test/demo path (see
    # src/engine/nvd_client.py's set_client() or the test helper).
    return {}


def _resolve_ecosystem_and_query(
    node_key: tuple[str, str],
) -> tuple[Optional[str], str, str]:
    """Return (ecosystem, package, version) for the NVD/OSV query.

    The node_key is (package_name, version). For the current project
    (Python), the ecosystem is "PyPI".  This is a simple mapping;
    for a full implementation this would consult the DependencyGraph's
    package metadata to resolve the correct ecosystem per package.
    """
    package, version = node_key
    return ("PyPI", package, version)


class UnavailableTopologyError(Exception):
    """Raised when risk analysis is requested but dependency topology is unavailable."""
    pass


def calculate_path_weight(path: list[tuple[str, str]], graph: DependencyGraph) -> float:
    """
    Calculate the sum of edge weights along a path.
    
    Args:
        path: List of node keys representing the path from source to target
        graph: DependencyGraph containing the edge weights (for type consistency)
        
    Returns:
        Sum of edge weights along the path
    """
    weight_sum = 0.0
    for i in range(len(path) - 1):
        source_key = path[i]
        target_key = path[i + 1]
        edge_key = (source_key, target_key)
        
        if edge_key in graph.edge_weights:
            weight_sum += graph.edge_weights[edge_key]
    
    return weight_sum


def calculate_impact_multiplicity(path: list[tuple[str, str]], graph: DependencyGraph) -> int:
    """
    Calculate the number of unique nodes impacted by a path.
    
    This counts all nodes in the path, as each node in a dependency chain
    can be impacted by vulnerabilities propagating through that path.
    
    Args:
        path: List of node keys representing the path from source to target
        graph: DependencyGraph containing the nodes (for type consistency)
        
    Returns:
        Number of unique nodes in the path
    """
    return len(set(path))


def calculate_phei(graph: DependencyGraph) -> float:
    """
    Calculate the PHEI (Predictive Vulnerability) Index using path-maximum scoring.
    
    Formula: PHEI(G) = max_P [ (Σ_edge_weights(P)) × ImpactMultiplicity(P) ]
    
    This identifies the single most dangerous exploitation route across all
    possible paths from leaf nodes to critical assets.
    
    Args:
        graph: DependencyGraph with vulnerability data and edge weights
        
    Returns:
        PHEI score (0.0 to 10.0), capped for interpretability
    """
    # Only "known" topology is acceptable for scoring
    if graph.edge_availability != "known":
        raise UnavailableTopologyError(
            f"Cannot calculate PHEI: dependency topology state is '{graph.edge_availability}'. "
            f"Only explicitly 'known' topology is accepted for scoring."
        )
    
    # 1. Calculate Max Vulnerability Score per Node
    node_risks: dict[tuple[str, str], float] = {}
    for node_key in graph.get_nodes_list():
        cve_scores = get_cve_severity(node_key)
        if cve_scores:
            # Max vulnerability score for this component
            node_risks[node_key] = max(cve_scores.values())
        else:
            node_risks[node_key] = 0.0
    
    # 2. Enumerate all paths and calculate PHEI for each
    max_phei = 0.0
    
    # Get all possible paths in the graph
    nx_graph = graph.graph
    
    # Check if graph has enough nodes for path analysis
    if nx_graph.number_of_nodes() < 2:
        return 0.0
    
    # Get all nodes in the graph
    all_nodes = list(nx_graph.nodes())
    if not all_nodes:
        return 0.0
    
    # Find all simple paths between all node pairs
    for source in all_nodes:
        for target in all_nodes:
            if source == target:
                continue
                
            try:
                # Find all paths from source to target
                paths_to_target = list(nx.all_simple_paths(nx_graph, source, target))
                
                for path in paths_to_target:
                    # Skip paths with fewer than 2 nodes
                    if len(path) < 2:
                        continue
                    
                    path_weight = calculate_path_weight(path, graph)
                    impact_multiplicity = calculate_impact_multiplicity(path, graph)
                    
                    # PHEI for this path = weight × multiplicity
                    path_phei = path_weight * impact_multiplicity
                    
                    # Update maximum if this path is more dangerous
                    if path_phei > max_phei:
                        max_phei = path_phei
            except nx.NetworkXNoPath:
                # No path exists between source and target
                continue
    
    # Normalize and scale the risk: cap at 10.0 for easier interpretation
    return min(max_phei, 10.0)


def calculate_systemic_risk(graph: DependencyGraph) -> float:
    """
    Calculates the aggregate systemic risk score for the entire dependency graph.
    The score factors in:
    1. Global vulnerability severity (CVE weight).
    2. Node centrality (how essential a failing dependency is).
    3. Edge dependency weight (how critical the connection itself is).

    Raises UnavailableTopologyError whenever topology is not explicitly "known".
    """

    # Only explicitly "known" topology is acceptable for scoring.
    # Default ("none"), unavailable ("unavailable"), and any invalid value
    # all indicate that the dependency graph is not ready for risk analysis.
    if graph.edge_availability != "known":
        raise UnavailableTopologyError(
            f"Cannot calculate systemic risk: dependency topology state is "
            f"'{graph.edge_availability}'. Only explicitly 'known' topology is "
            f"accepted for scoring."
        )

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
