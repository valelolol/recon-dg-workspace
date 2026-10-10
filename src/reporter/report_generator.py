from typing import Tuple

from src.models.dependency_graph import DependencyGraph
from src.engine.risk_analyzer import calculate_phei, calculate_systemic_risk, UnavailableTopologyError


def generate_report(current_graph: DependencyGraph, previous_graph: DependencyGraph) -> str:
    """
    Compares two dependency graphs and generates a structured, plain-language
    technical report detailing all changes and PHEI (path-max) risk implications.

    Risk scoring uses the canonical calculate_phei (path-max) calculation;
    topology-unavailable scans report risk as unavailable rather than
    fabricating a numeric score.
    """

    # --- 1. Risk Score Change (PHEI Path-Max) ---

    def _score(graph: DependencyGraph):
        """Return (score, status) for a graph using the canonical
        calculate_phei (path-max) calculation.  Unavailable topology yields
        (None, 'unavailable') rather than a fabricated score."""
        try:
            return calculate_phei(graph), "available"
        except UnavailableTopologyError:
            return None, "unavailable"

    current_risk, current_status = _score(current_graph)
    previous_risk, previous_status = _score(previous_graph)

    if current_status == "available" and previous_status == "available":
        risk_diff = current_risk - previous_risk
        risk_percent_change = (risk_diff / max(1e-6, previous_risk)) * 100

        risk_section = f"""
## 📊 Risk Score Update (PHEI Path-Max)

**Current PHEI Risk Score:** `{current_risk:.3f}`
**Previous PHEI Risk Score:** `{previous_risk:.3f}`

The PHEI path-max risk has **{'increased' if risk_diff > 0 else 'decreased' if risk_diff < 0 else 'remained stable'}** by **{risk_diff:+.3f}** (a {risk_percent_change:.1f}% {'increase' if risk_percent_change > 0 else 'decrease' if risk_percent_change < 0 else 'change of zero'} from the previous baseline).

This fluctuation suggests **{'heightened caution' if risk_diff > 0.5 else 'stable exposure' if risk_diff < -0.5 else 'minor fluctuation'}** in the dependency landscape.
"""
    elif current_status == "available":
        risk_section = f"""
## 📊 Risk Score Update (PHEI Path-Max)

**Current PHEI Risk Score:** `{current_risk:.3f}`
**Previous PHEI Risk Score:** `unavailable`

Risk scoring became available in this scan: a PHEI path-max score of
`{current_risk:.3f}` is now reported (previous scan had no known dependency
topology to score).
"""
    elif previous_status == "available":
        risk_section = f"""
## 📊 Risk Score Update (PHEI Path-Max)

**Current PHEI Risk Score:** `unavailable`
**Previous PHEI Risk Score:** `{previous_risk:.3f}`

Risk scoring is unavailable in this scan: the dependency topology could not
be resolved. A PHEI path-max score of `{previous_risk:.3f}` was reported for
the previous scan.
"""
    else:
        risk_section = """
## 📊 Risk Score Update (PHEI Path-Max)

**Current PHEI Risk Score:** `unavailable`
**Previous PHEI Risk Score:** `unavailable`

Risk scoring remains unavailable for both scans: dependency topology could not
be resolved in either, and no score is fabricated.
"""

    report_parts = []
    report_parts.append(risk_section)

    # --- 2. Dependency Changes (Added/Removed) ---

    current_keys = set(current_graph.get_nodes_list())
    previous_keys = set(previous_graph.get_nodes_list())

    added_keys = current_keys - previous_keys
    removed_keys = previous_keys - current_keys

    dependency_section = ""
    if added_keys or removed_keys:
        dependency_section += """
## 🌳 Core Dependency Topology Changes

### 🟢 Newly Introduced Dependencies
"""
        for key in added_keys:
            node = current_graph.nodes[key]
            dependency_section += f"- **{node.package_name}@{node.version}**: Initialized. Requires immediate review due to lack of prior systemic context.\n"

        dependency_section += """
### 🔴 Dependencies Removed or Deprecated
"""
        for key in removed_keys:
            node = previous_graph.nodes[key]
            dependency_section += f"- **{node.package_name}@{node.version}**: Removed. Check if functionality was migrated or if this removal creates a new, unforeseen dependency chain.\n"
    else:
        dependency_section = """## 🌳 Core Dependency Topology Changes

No significant changes were detected in the registered dependency nodes since the last scan.
"""
    report_parts.append(dependency_section)

    # --- 3. Final Narrative Summary ---

    final_summary = f"""
## 📝 Summary and Analyst Commentary

Overall, the graph structure is {'more complex' if len(added_keys) > 1 else 'stable'}. The shift in risk profile requires focused attention on components: {'{}' if added_keys else 'N/A'} to understand the root cause of the current risk. Further analysis of critical path dependencies is recommended to quantify the true blast radius of any single failure point.
"""
    report_parts.append(final_summary.format(list(added_keys)))

    return "\n\n".join(report_parts)
