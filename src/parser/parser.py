
import os

from src.models.dependency_graph import DependencyGraph, DependencyNode


def parse_requirements(file_path: str) -> DependencyGraph:
    """
    Reads a 'requirements.txt' style file and builds a DependencyGraph.
    Assumes package==version format.
    """
    graph = DependencyGraph()
    
    if not os.path.exists(file_path):
        print(f"Warning: {file_path} not found. Returning empty graph.")
        return graph

    # Step 1: Parse dependencies and create nodes
    try:
        with open(file_path) as f:
            lines = f.readlines()
    except Exception as e:
        print(f"Error reading file: {e}. Returning empty graph.")
        return graph

    all_dependencies: list[tuple[str, str]] = []
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
                all_dependencies.append((package, version))
            except ValueError:
                # Silently skip malformed lines
                pass
            
    # Step 2: Mock Edge Creation 
    # Simulate that every node connects to a "system_core" component if it's not already defined
    core_node = DependencyNode("system_core", "1.0.0", is_critical=True)
    graph.add_node(core_node)
    
    # Create edges from every dependency to system_core
    for package, version in all_dependencies:
        source_key = (package, version)
        core_key = ("system_core", "1.0.0")
        # Initial weight of 1.0 (will be updated by the Risk Analyzer later)
        graph.add_edge(source_key, core_key, weight=1.0)
        
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

    return graph
