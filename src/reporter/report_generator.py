
from typing import Tuple
from src.models.dependency_graph import DependencyGraph
from src.engine.risk_analyzer import calculate_systemic_risk

def generate_report(current_graph: DependencyGraph, previous_graph: DependencyGraph) -> str:
    """
    Compares two dependency graphs and generates a structured, plain-language 
    technical report detailing all changes and risk implications.
    """
    
    report_parts = []
    
    # --- 1. Risk Score Change ---
    current_risk = calculate_systemic_risk(current_graph)
    previous_risk = calculate_systemic_risk(previous_graph)
    
    risk_diff = current_risk - previous_risk
    risk_percent_change = (risk_diff / max(1e-6, previous_risk)) * 100

    risk_section = f"""
## 📊 Systemic Risk Assessment Update

**Current Global Risk Score:** `{current_risk:.3f}` 
**Previous Global Risk Score:** `{previous_risk:.3f}`

The systemic risk has **{'increased' if risk_diff > 0 else 'decreased' if risk_diff < 0 else 'remained stable'}** by **{risk_diff:+.3f}** (a {risk_percent_change:.1f}% {'increase' if risk_percent_change > 0 else 'decrease' if risk_percent_change < 0 else 'change of zero'} from the previous baseline).

This fluctuation suggests **{'heightened caution' if risk_diff > 0.5 else 'stable exposure' if risk_diff < -0.5 else 'minor fluctuation'}** in the dependency landscape.
"""
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
            dependency_section += f"- **{node.package_name}@{node.version}**: Initialized. Requires immediate review due to lack of prior systemic context.
"

        dependency_section += """
### 🔴 Dependencies Removed or Deprecated
"""
        for key in removed_keys:
            node = current_graph.nodes[key]
            dependency_section += f"- **{node.package_name}@{node.version}**: Removed. Check if functionality was migrated or if this removal creates a new, unforeseen dependency chain.
"
    else:
        dependency_section = """## 🌳 Core Dependency Topology Changes

No significant changes were detected in the registered dependency nodes since the last scan.
"""
    report_parts.append(dependency_section)
    
    # --- 3. Final Narrative Summary ---
    
    final_summary = """
## 📝 Summary and Analyst Commentary

Overall, the graph structure is {'more complex' if len(added_keys) > 1 else 'stable'}. The shift in systemic risk requires focused attention on components: {'{}' if added_keys else 'N/A'} to understand the root cause of the current risk profile. Further analysis of critical path dependencies is recommended to quantify the true blast radius of any single failure point.
"""
    report_parts.append(final_summary.format(list(added_keys)))
    
    return "

".join(report_parts)

# Mock function for testing purposes
def generate_report_mock(current_graph: DependencyGraph, previous_graph: DependencyGraph) -> str:
    # Mocking fixed outputs for testing simplicity
    return "Mock Report generated successfully (Test validation needed)"
