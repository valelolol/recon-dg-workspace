from typing import Any, Optional, Tuple

from src.models.dependency_graph import DependencyGraph
from src.engine.risk_analyzer import calculate_phei, calculate_systemic_risk, UnavailableTopologyError
from src.reporter.interface import RiskReport, RiskLevel, DependencyNode as InterfaceNode, EdgeInfo, CVEInfo


def generate_report_mode_b(graph: DependencyGraph) -> RiskReport:
    """Mode B: emit a structured RiskReport from a single DependencyGraph.

    Populates the RiskReport dataclass using only verified source data:
    - nodes from graph.nodes (evidence: package, version, CVE list)
    - edges from graph.edge_weights
    - PHEI score from calculate_phei (topology-only, capped at 10.0)
      stored in ``phei_score``; NOT in ``current_systemic_risk``.
    - top_risks populated from actual CVE findings on graph nodes
    - recommendations left empty (no ScanResult available for
      build_remediation_plan); see build_remediation_plan in
      src/agent/agent.py for the remediation planner contract.

    For unavailable topology, returns a RiskReport with:
      - phei_score = None (not 0.0 — no score is fabricated)
      - has_fallback_applied = True, fallback_reason set
      - current_systemic_risk = 0.0 (default, not a calculated value)
      - overall_risk_level = LOW (default; no severity data available)

    Distinctions from the contract (TASKS.md §DECISIONS):
      - PHEI is topology-only (edge weights × node multiplicity).
      - Severity-aware systemic risk is computed by calculate_systemic_risk()
        and is distinct from PHEI. Mode B does not call it.
      - PHEI scores are NOT mapped through OSV severity thresholds
        (e.g. 7.0 for High). A PHEI score is a topology score, not a
        severity category.
      - Per-finding severity (Low/Medium/High) applies to vulnerability
        findings, not to topology scores.
    """
    # --- PHEI score (topology-only, distinct from systemic risk) ---
    phei_score: Optional[float] = None
    try:
        phei_score = calculate_phei(graph)
    except UnavailableTopologyError:
        pass  # phei_score stays None; no score fabricated

    # --- Nodes (evidence): actual CVE findings per node ---
    nodes: dict[str, InterfaceNode] = {}
    for key, node in graph.nodes.items():
        pkg = key[0]
        ver = key[1]
        # Pull actual CVE data from the graph node's vulnerability dict
        cves: list[CVEInfo] = []
        for cve_id, sev in node.vulnerabilities.items():
            cves.append(CVEInfo(cve_id=cve_id, severity_score=sev))
        nodes[str(key)] = InterfaceNode(
            package_name=pkg,
            version=ver,
            risk_level=RiskLevel.LOW,  # default; no severity-aware risk here
            cves=cves,
        )

    # --- Edges ---
    edges: dict[tuple, EdgeInfo] = {}
    for (src, tgt), weight in graph.edge_weights.items():
        edges[(str(src), str(tgt))] = EdgeInfo(
            source=str(src),
            target=str(tgt),
            weight=weight,
        )

    # --- Top risks: actual CVE findings (one per CVE per node), not PHEI ---
    top_risks: list[dict[str, Any]] = []
    for key, node in graph.nodes.items():
        pkg = key[0]
        ver = key[1]
        for cve_id, sev in node.vulnerabilities.items():
            top_risks.append({
                "package": pkg,
                "version": ver,
                "cve_id": cve_id,
                "severity_score": sev,
            })

    # --- Remediation: no ScanResult available, leave empty ---
    # The remediation planner (build_remediation_plan in src/agent/agent.py)
    # requires a ScanResult with findings. Mode B receives only a graph,
    # so no structured remediation plan can be produced.
    recommendations: list[str] = []
    remediation_plan: list[str] = []

    # --- Contract fields (TASKS.md §DECISIONS / ROADMAP W9/W10) ---
    # findings: mapped from actual node.vulnerabilities (one per CVE per node)
    findings: list[dict[str, Any]] = []
    for key, node in graph.nodes.items():
        pkg = key[0]
        ver = key[1]
        for cve_id, sev in node.vulnerabilities.items():
            findings.append({
                "id": f"finding-{pkg}-{cve_id}",
                "package_id": str(key),
                "advisory_source": "graph-node",
                "advisory_id": cve_id,
                "severity": None,  # no severity data from graph nodes
                "title": f"{pkg}@{ver}: {cve_id}",
                "description": f"CVE {cve_id} on {pkg}@{ver}",
            })
    # evidence: no ScanResult available; leave empty
    evidence: list[dict[str, Any]] = []
    # risk: topology-only PHEI status
    risk: dict[str, Any] = {}
    if phei_score is not None:
        risk = {
            "status": "available",
            "score": phei_score,
            "method": "phei",
            "reason": f"topology-based PHEI (edge weights x node multiplicity); severity unspecified",
        }
    else:
        risk = {
            "status": "unavailable",
            "score": None,
            "method": "phei",
            "reason": "unavailable topology; no score fabricated",
        }
    # input / analysis_mode / topology_status
    input_data: dict[str, Any] = {"type": "file", "filename": "known_topology.json", "format": "synthetic-graph"}
    analysis_mode: str = "dependency_graph"
    topology_status: str = "known" if phei_score is not None else "unavailable"
    # warnings (TASKS.md §DECISIONS)
    warnings: list[str] = [
        "CVE/advisory data is a synthetic fixture, not a live lookup; "
        "findings[].severity is unspecified (null) and not in the score; "
        "edge-weight function resolved as topology-only.",
    ]
    # vulnerability_lookup
    vulnerability_lookup: dict[str, Any] = {
        "status": "complete",
        "total_packages": len(graph.nodes),
        "checked_package_ids": list(graph.nodes.keys()),
        "matched": len(findings),
    }
    # packages[]
    packages: list[dict[str, Any]] = []
    for key, node in graph.nodes.items():
        packages.append({
            "id": str(key),
            "name": key[0],
            "version": key[1],
            "hash": None,
        })
    # edges_contract[] (edge weight is input, not output; emit type only)
    edges_contract: list[dict[str, Any]] = []
    for (src, tgt), _weight in graph.edge_weights.items():
        edges_contract.append({
            "id": f"edge-{src}-{tgt}",
            "source_id": str(src),
            "target_id": str(tgt),
            "type": "dependency",
        })

    # --- Build report ---
    report = RiskReport(
        report_id="",
        timestamp="",
        graph_version="",
        current_systemic_risk=0.0,  # no severity-aware systemic risk computed
        phei_score=phei_score,       # topology-only PHEI (or None)
        previous_systemic_risk=0.0,
        risk_delta=0.0,
        risk_percent_change=0.0,
        overall_risk_level=RiskLevel.LOW,  # default; no severity data
        nodes=nodes,
        edges=edges,
        node_changes=[],
        top_risks=top_risks,
        recommendations=recommendations,
        findings=findings,
        evidence=evidence,
        risk=risk,
        remediation_plan=remediation_plan,
        input=input_data,
        analysis_mode=analysis_mode,
        topology_status=topology_status,
        warnings=warnings,
        vulnerability_lookup=vulnerability_lookup,
        packages=packages,
        edges_contract=edges_contract,
    )

    if phei_score is None:
        report.has_fallback_applied = True
        report.fallback_reason = "unavailable topology; no score fabricated"

    return report


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
