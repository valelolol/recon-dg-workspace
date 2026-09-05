# Predictive Vulnerability Mapping — Architecture

## Project Overview

Current security methods are reactive, assessing only known CVEs and failing to predict systemic risk arising from interconnected exploitation of multiple low-severity issues across complex software dependency graphs. This project shifts vulnerability assessment to a proactive stance by predicting catastrophic failure through multi-node component interaction analysis, strengthening the software supply chain before exploitable pathways emerge.

## Module Structure

| Module | Description |
| --- | --- |
| `src/parser` | Ingests and normalizes dependency manifest formats (e.g., `requirements.txt`, `package.json`) into an intermediate representation for downstream graph construction. |
| `src/models` | Defines the directed, weighted graph data structures representing component dependencies, their relationships, and associated metadata. |
| `src/engine` | Implements the core risk-scoring algorithms, traversing the dependency graph to compute the PHEI (Predictive Vulnerability) Index for each component and the system as a whole. |
| `src/reporter` | Generates human-readable risk summaries and structured output, including predicted exploitation pathways and visualizable graph representations for dashboard integration. |

## Graph Schema

| Class | Purpose | Key Attributes |
| --- | --- | --- |
| `DependencyNode` | Represents a single package component (identified by name and version) and stores its known vulnerabilities as a `{CVE ID: Severity}` mapping. | `package_name: str` — unique package name; `version: str` — package version; `is_critical: bool` — whether the node represents a critical dependency; `vulnerabilities: dict[str, float]` — CVE-to-severity mapping. |
| `DependencyGraph` | Manages the full directed acyclic graph of dependencies using NetworkX, tracking nodes by `(package, version)` keys and edges by source–target tuples with an associated risk weight. | `graph: DiGraph` — NetworkX digraph backing all traversal operations; `nodes: dict` — lookup by `(package, version)`; `edge_weights: dict` — risk weights per `(source, target)` pair. Provides `add_node`, `add_edge`, `get_nodes_list`, and `get_edges_list` for graph construction and iteration. |

## Risk Scoring

`calculate_systemic_risk(graph)` in `src/engine/risk_analyzer.py` computes a single aggregate score (capped at 10.0) through three stages:

1. **Max CVE severity per node** — for each node, `get_cve_severity()` looks up its `{CVE ID: severity}` dict (currently from a hardcoded `MOCK_CVE_DB`; in production this would query NVD/OSV), and the node's risk is the maximum severity value across all its CVEs (0.0 if none).
2. **Betweenness centrality** — computed over the underlying NetworkX digraph via `betweenness_centrality()`; it measures how often a node lies on shortest paths between all other node pairs, serving as a proxy for the node's structural importance in the dependency network.
3. **Weighted edge formula** — for every edge `(source, target)` with weight `w`, the dynamic risk is `w × (source_vuln + target_vuln) × (source_c × target_c + 1.0)`, where `vuln` is the node's max CVE severity and `c` is its betweenness centrality. The sum of all edge risks is averaged over the number of edges, amplified by `√(node_count)`, and capped at 10.0.

The formula heavily penalizes edges between two highly vulnerable, central components — the very pattern that defines a systemic risk pathway.

## Known Divergences

The design specification (`docs/specs/design_spec.md`) defines PHEI as `max over all paths P` in the graph of a path-based risk product, i.e., the most dangerous single path determines the system risk. `risk_analyzer.py`, however, **sums weighted edge risk across the entire graph**, averages it over edge count, and amplifies by `√(node_count)`. This is a fundamentally different aggregation strategy — path-maximum vs. global-sum — and needs to be resolved to ensure the implementation matches the intended threat model.
