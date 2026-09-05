

import networkx as nx


class DependencyNode:
    def __init__(self, package_name: str, version: str, is_critical: bool = False):
        self.package_name = package_name
        self.version = version
        self.is_critical = is_critical
        self.vulnerabilities: dict[str, float] = {}  # CVE ID: Severity Score

    def __repr__(self):
        return f"DependencyNode({self.package_name}@{self.version})"

class DependencyGraph:
    def __init__(self):
        self.graph = nx.DiGraph()
        self.nodes: dict[tuple[str, str], DependencyNode] = {} # Key: (package, version)
        self.edge_weights: dict[tuple[str, str], float] = {} # Key: (source, target)

    def add_node(self, node: DependencyNode):
        key = (node.package_name, node.version)
        if key not in self.nodes:
            self.nodes[key] = node
            self.graph.add_node(key)

    def add_edge(self, source_key: tuple[str, str], target_key: tuple[str, str], weight: float = 1.0):
        """Adds a directed edge between two dependencies."""
        self.edge_weights[(source_key, target_key)] = weight
        self.graph.add_edge(source_key, target_key, weight=weight)

    def get_nodes_list(self) -> list[tuple[str, str]]:
        return list(self.nodes.keys())

    def get_edges_list(self) -> list[tuple[tuple[str, str], tuple[str, str]]]:
        return list(self.edge_weights.keys())
