"""RECON-DG agent track.

The agentic dependency-investigation workflow.

RECON-DG's main contribution is **not** the scanner (it wraps the established
open-source OSV-Scanner) but a *conditional, bounded* investigation layer that:

  1. runs the scanner through a thin subprocess wrapper (`scan_runner`);
  2. normalizes raw OSV-Scanner JSON into the repo's `DependencyGraph` +
     first-class `Finding` objects (`normalizer`);
  3. runs a bounded loop that conditionally uses an allowlisted tool set to
     investigate each finding and records an **evidence trail** every turn
     (`agent`);
  4. compares two scans to show what is new / resolved / unchanged
     (`agent.compare_scans`).

Every tool call is logged to a per-turn `EvidenceTrail`. The trail is what a
reviewer or a downstream dashboard reads to audit *why* the agent concluded
what it concluded. The design deliberately keeps the tool loop deterministic and
grounded (it operates on real OSV-Scanner output, not on invented data); an
optional pluggable LLM (`llm` callable) may *enrich* the narrative but can only
draw on the same evidence, so it can never fabricate a finding.
"""

from src.agent.agent import Agent, EvidenceTrail, compare_scans
from src.agent.normalizer import Finding, normalize_scan, osv_json_to_graph, ScanResult
from src.agent.scan_runner import ScanRunResult, construct_command, run_scan, run_scan_from_json
# End-to-end glue: manifest/report -> scan -> normalize -> agent -> report.
from src.agent.pipeline import investigate, investigate_from_json

__all__ = [
    "Agent",
    "EvidenceTrail",
    "Finding",
    "construct_command",
    "compare_scans",
    "normalize_scan",
    "osv_json_to_graph",
    "run_scan",
    "run_scan_from_json",
    "investigate",
    "investigate_from_json",
    "ScanResult",
]

__version__ = "0.1.0"
