
import os
import re
import tomllib

from src.models.dependency_graph import DependencyGraph, DependencyNode

_PEP508_NAME = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)")


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


def _split_requirement(spec: str) -> tuple[str, str] | None:
    """Split a PEP 508 string into (name, version).

    An exact '==' pin yields the pinned version; any other specifier is kept
    verbatim (e.g. '>=2.28.1') so a range is never reported as a pinned
    version, and a bare name yields 'unspecified'.
    """
    requirement = spec.split(";", 1)[0].strip()
    match = _PEP508_NAME.match(requirement)
    if not match:
        return None
    name = match.group(1)
    rest = requirement[match.end():].strip()
    if rest.startswith("["):
        rest = rest[rest.find("]") + 1:].strip()
    if rest.startswith("==") and "," not in rest:
        return name, rest[2:].strip()
    return name, rest or "unspecified"


def parse_pyproject_toml(file_path: str) -> DependencyGraph:
    """
    Reads a 'pyproject.toml' file and builds a DependencyGraph from
    [project].dependencies and [project.optional-dependencies].

    Raises FileNotFoundError if the file does not exist.
    Returns a graph with edge_availability = 'unavailable' because
    pyproject.toml does not encode dependency topology (edges).
    """
    graph = DependencyGraph()

    if not os.path.exists(file_path):
        raise FileNotFoundError(f"pyproject.toml not found: {file_path}")

    try:
        with open(file_path, "rb") as f:
            data = tomllib.load(f)
    except (OSError, tomllib.TOMLDecodeError) as e:
        raise OSError(f"Error reading file '{file_path}': {e}") from e

    project = data.get("project", {})
    specs = list(project.get("dependencies", []))
    for group in project.get("optional-dependencies", {}).values():
        specs.extend(group)

    for spec in specs:
        parsed = _split_requirement(spec)
        if parsed is not None:
            graph.add_node(DependencyNode(*parsed))

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
