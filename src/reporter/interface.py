"""
Dependency Risk Reporter Interface

This module defines the structured interface for dependency risk reporting.
It provides a consistent schema for both structured (JSON) and human-readable outputs.
"""

from __future__ import annotations
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from enum import Enum


class RiskLevel(Enum):
    """Enum for risk severity levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class CVEInfo:
    """Represents a CVE vulnerability in a dependency."""
    cve_id: str
    severity_score: float
    description: Optional[str] = None


@dataclass
class DependencyNode:
    """Represents a single dependency node in the graph."""
    package_name: str
    version: str
    risk_level: RiskLevel = RiskLevel.LOW
    cves: List[CVEInfo] = field(default_factory=list)
    centrality_score: float = 0.0


@dataclass
class EdgeInfo:
    """Represents a dependency edge between nodes."""
    source: str
    target: str
    weight: float
    risk_contribution: float = 0.0


@dataclass
class NodeChangeEvent:
    """Represents a change event for a single node."""
    package_name: str
    version: str
    change_type: str  # 'added', 'removed', 'updated'
    risk_delta: float = 0.0
    cve_changes: List[str] = field(default_factory=list)


@dataclass
class RiskReport:
    """
    Structured dependency risk report.
    
    This is the primary output type for the reporter. It provides both
    structured JSON output and human-readable summary generation.
    """
    
    # Report metadata
    report_id: str = ""
    timestamp: str = ""
    graph_version: str = ""
    
    # Core metrics
    current_systemic_risk: float = 0.0
    previous_systemic_risk: float = 0.0
    risk_delta: float = 0.0
    risk_percent_change: float = 0.0
    overall_risk_level: RiskLevel = RiskLevel.LOW
    
    # Node-level analysis
    nodes: Dict[str, DependencyNode] = field(default_factory=dict)
    edges: Dict[tuple, EdgeInfo] = field(default_factory=dict)
    
    # Change tracking
    node_changes: List[NodeChangeEvent] = field(default_factory=list)
    
    # Risk breakdown by category
    vuln_risk: float = 0.0
    centrality_risk: float = 0.0
    edge_risk: float = 0.0
    
    # Top risks (sorted by contribution)
    top_risks: List[Dict[str, Any]] = field(default_factory=list)
    
    # Recommendations
    recommendations: List[str] = field(default_factory=list)
    
    # Fallback behavior for edge cases
    has_fallback_applied: bool = False
    fallback_reason: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert report to dictionary for JSON serialization.
        
        Returns a flat dictionary suitable for direct JSON output.
        """
        return {
            "report_id": self.report_id,
            "timestamp": self.timestamp,
            "graph_version": self.graph_version,
            "current_systemic_risk": round(self.current_systemic_risk, 6),
            "previous_systemic_risk": round(self.previous_systemic_risk, 6),
            "risk_delta": round(self.risk_delta, 6),
            "risk_percent_change": round(self.risk_percent_change, 2),
            "overall_risk_level": self.overall_risk_level.value,
            "nodes": {
                k: {
                    "package_name": v.package_name,
                    "version": v.version,
                    "risk_level": v.risk_level.value,
                    "centrality_score": round(v.centrality_score, 6),
                    "cves": [
                        {"cve_id": c.cve_id, "severity_score": c.severity_score, "description": c.description}
                        for c in v.cves
                    ]
                }
                for k, v in self.nodes.items()
            },
            "edges": {
                f"{s} -> {t}": {
                    "weight": w.weight,
                    "risk_contribution": round(w.risk_contribution, 6)
                }
                for (s, t), w in self.edges.items()
            },
            "node_changes": [
                {
                    "package_name": c.package_name,
                    "version": c.version,
                    "change_type": c.change_type,
                    "risk_delta": round(c.risk_delta, 6),
                    "cve_changes": c.cve_changes
                }
                for c in self.node_changes
            ],
            "risk_breakdown": {
                "vuln_risk": round(self.vuln_risk, 6),
                "centrality_risk": round(self.centrality_risk, 6),
                "edge_risk": round(self.edge_risk, 6)
            },
            "top_risks": self.top_risks,
            "recommendations": self.recommendations,
            "fallback_applied": self.has_fallback_applied,
            "fallback_reason": self.fallback_reason
        }
    
    def to_json(self) -> str:
        """Convert report to JSON string."""
        import json
        return json.dumps(self.to_dict(), indent=2)
    
    def generate_summary(self, verbose: bool = False) -> str:
        """
        Generate a human-readable summary of the report.
        
        Args:
            verbose: If True, include detailed breakdowns.
        
        Returns:
            Human-readable summary string.
        """
        lines = []
        
        # Header
        lines.append("=" * 60)
        lines.append(f"Dependency Risk Report #{self.report_id}")
        lines.append(f"Timestamp: {self.timestamp}")
        lines.append("=" * 60)
        lines.append("")
        
        # Core metrics
        lines.append("CORE METRICS")
        lines.append("-" * 40)
        lines.append(f"Current Systemic Risk: {self.current_systemic_risk:.4f}")
        lines.append(f"Previous Systemic Risk: {self.previous_systemic_risk:.4f}")
        lines.append(f"Risk Delta: {self.risk_delta:+.4f} ({self.risk_percent_change:+.2f}%)")
        lines.append(f"Overall Risk Level: {self.overall_risk_level.value.upper()}")
        lines.append("")
        
        # Risk breakdown
        lines.append("RISK BREAKDOWN")
        lines.append("-" * 40)
        lines.append(f"Vulnerability Risk: {self.vuln_risk:.4f}")
        lines.append(f"Centrality Risk: {self.centrality_risk:.4f}")
        lines.append(f"Edge Risk: {self.edge_risk:.4f}")
        lines.append("")
        
        # Top risks
        if self.top_risks:
            lines.append("TOP RISKS")
            lines.append("-" * 40)
            for i, risk in enumerate(self.top_risks[:5], 1):
                lines.append(f"{i}. {risk['description']} (weight: {risk.get('weight', 'N/A')})")
            lines.append("")
        
        # Node changes
        if self.node_changes:
            lines.append("RECENT CHANGES")
            lines.append("-" * 40)
            for change in self.node_changes:
                lines.append(f"  {change.change_type.upper()}: {change.package_name}@{change.version}")
                if change.risk_delta != 0:
                    lines.append(f"    Risk delta: {change.risk_delta:+.4f}")
            lines.append("")
        
        # Recommendations
        if self.recommendations:
            lines.append("RECOMMENDATIONS")
            lines.append("-" * 40)
            for rec in self.recommendations:
                lines.append(f"  • {rec}")
            lines.append("")
        
        # Footer
        lines.append("=" * 60)
        
        return "\n".join(lines)
    
    def generate_full_report(self) -> str:
        """
        Generate a comprehensive report with verbose details.
        
        Returns:
            Full human-readable report string.
        """
        lines = []
        lines.append(self.generate_summary(verbose=True))
        
        # Detailed node information
        lines.append("")
        lines.append("NODE DETAILS")
        lines.append("-" * 40)
        for name, node in self.nodes.items():
            lines.append(f"\n{node.package_name}@{node.version}:")
            lines.append(f"  Risk Level: {node.risk_level.value.upper()}")
            lines.append(f"  Centrality: {node.centrality_score:.6f}")
            if node.cves:
                lines.append(f"  CVEs ({len(node.cves)}):")
                for cve in node.cves:
                    lines.append(f"    - {cve.cve_id} ({cve.severity_score:.2f})")
        
        # Detailed edge information
        lines.append("")
        lines.append("EDGE DETAILS")
        lines.append("-" * 40)
        for (src, tgt), edge in self.edges.items():
            lines.append(f"\n{src} -> {tgt}:")
            lines.append(f"  Weight: {edge.weight}")
            lines.append(f"  Risk Contribution: {edge.risk_contribution:.6f}")
        
        return "\n".join(lines)


def create_report(
    report_id: str,
    current_risk: float,
    previous_risk: float,
    nodes: Dict[str, DependencyNode],
    edges: Dict[tuple, EdgeInfo],
    node_changes: List[NodeChangeEvent],
    top_risks: List[Dict[str, Any]] = None,
    recommendations: List[str] = None,
    **kwargs
) -> RiskReport:
    """
    Factory function to create a RiskReport instance.
    
    Args:
        report_id: Unique identifier for this report
        current_risk: Current systemic risk score
        previous_risk: Previous systemic risk score
        nodes: Dictionary of node data
        edges: Dictionary of edge data
        node_changes: List of change events
        top_risks: Top risk items
        recommendations: Recommendations list
        **kwargs: Additional options including fallback handling
        
    Returns:
        Configured RiskReport instance
    """
    # Calculate risk level from score
    if current_risk >= 1.0:
        risk_level = RiskLevel.CRITICAL
    elif current_risk >= 0.5:
        risk_level = RiskLevel.HIGH
    elif current_risk >= 0.25:
        risk_level = RiskLevel.MEDIUM
    else:
        risk_level = RiskLevel.LOW
    
    # Handle override or fallback for risk level
    if kwargs.get("risk_level") is not None:
        risk_level = kwargs["risk_level"]
    
    report = RiskReport(
        report_id=report_id,
        timestamp=kwargs.get("timestamp", ""),
        graph_version=kwargs.get("graph_version", ""),
        current_systemic_risk=current_risk,
        previous_systemic_risk=previous_risk,
        risk_delta=current_risk - previous_risk,
        risk_percent_change=((current_risk - previous_risk) / max(1e-6, previous_risk)) * 100,
        overall_risk_level=risk_level,
        nodes=nodes,
        edges=edges,
        node_changes=node_changes,
        top_risks=top_risks or [],
        recommendations=recommendations or []
    )
    
    # Handle fallback behavior
    if kwargs.get("fallback_applied", False):
        report.has_fallback_applied = True
        report.fallback_reason = kwargs.get("fallback_reason", "N/A")
    
    return report
