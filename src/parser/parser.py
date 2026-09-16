
import os

from src.models.dependency_graph import DependencyGraph, DependencyNode


def parse_requirements(file_path: str) -> DependencyGraph:
    """
    Reads a 'requirements.txt' style file and builds a DependencyGraph.
    Assumes package==version format.

    Raises FileNotFoundError if the file does not exist.
    Returns a graph with edge_availability = 'unavailable' because
    requirements.txt does not encode dependency topology (edges).
    """
    graph = DependencyGraph()

    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Requirements file not found: {file_path}")

    # Step 1: Parse dependencies and create nodes
    try:
        with open(file_path) as f:
            lines = f.readlines()
    except Exception as e:
        raise IOError(f"Error reading file '{file_path}': {e}")

    for line in lines:
        line = line.strip()
        if not line or line.startswith('#'):
            continue

        # Simple parsing logic: package==version
        if "==" in line:
            try:
                package, version = line.split("==")
                package = package.strip()
                version = version.strip()
                node = DependencyNode(package, version)
                graph.add_node(node)
            except ValueError:
                # Silently skip malformed lines
                pass

    # Mark topology as unavailable: requirements.txt lists packages but
    # does not encode their inter-dependency graph.  An edgeless graph
    # with edge_availability == 'unavailable' is distinct from a graph
    # with edge_availability == 'none' (never populated).
    graph.edge_availability = "unavailable"

    return graph


def build_mock_graph() -> DependencyGraph:
    """Helper function for tests to create a graph structure."""
    graph = DependencyGraph()

    # Initialize the central, critical component
    core_node = DependencyNode("system_core", "1.0.0", is_critical=True)
    graph.add_node(core_node)

    # Add initial dependencies that connect to core
    graph.add_node(DependencyNode("requests", "2.28.1"))
    graph.add_node(DependencyNode("django", "4.2"))

    # Add edges from the dependencies to the core
    graph.add_edge(("requests", "2.28.1"), ("system_core", "1.0.0"), weight=1.0)
    graph.add_edge(("django", "4.2"), ("system_core", "1.0.0"), weight=1.0)

    graph.edge_availability = "known"

    return graph
