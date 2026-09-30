# Predictive Vulnerability Mapping — Architecture

## Project Overview

Current security methods are reactive, assessing only known CVEs and failing to predict systemic risk arising from interconnected exploitation of multiple low-severity issues across complex software dependency graphs. This project shifts vulnerability assessment to a proactive stance by predicting catastrophic failure through multi-node component interaction analysis, strengthening the software supply chain before exploitable pathways emerge.

## Module Structure

| Module | Description |
| --- | --- |
| `src/parser` | Ingests and normalizes dependency manifest formats (e.g., `requirements.txt`, `package.json`, `pyproject.toml`, `go.mod`, `Cargo.toml`) into shared `DependencyGraph` IR. |
| `src/models` | Defines the directed, weighted graph data structures representing component dependencies, their relationships, and associated metadata. |
| `src/engine` | Implements the core risk-scoring algorithms (NVD API integration, OSV fallback, rate-limiting, caching) and PHEI path-maximum scoring formula. |
| `src/reporter` | Generates structured JSON reports, human-readable summaries, and LLM explanations with deterministic fallback behavior. |

## Graph Schema

| Class | Purpose | Key Attributes |
| --- | --- | --- |
| `DependencyNode` | Represents a single package component (identified by name and version) and stores its known vulnerabilities as a `{CVE ID: Severity}` mapping. | `package_name: str` — unique package name; `version: str` — package version; `is_critical: bool` — whether the node represents a critical dependency; `vulnerabilities: dict[str, float]` — CVE-to-severity mapping. |
| `DependencyGraph` | Manages the full directed acyclic graph of dependencies using NetworkX, tracking nodes by `(package, version)` keys and edges by source–target tuples with an associated risk weight. | `graph: DiGraph` — NetworkX digraph backing all traversal operations; `nodes: dict` — lookup by `(package, version)`; `edge_weights: dict` — risk weights per `(source, target)` pair. Provides `add_node`, `add_edge`, `get_nodes_list`, and `get_edges_list` for graph construction and iteration. |

## Risk Scoring

**PHEI (Predictive Vulnerability) Index** — Path-maximum scoring with functional-domain multipliers.

Formula: `PHEI(G) = max_P [ (Σ_edge_weights(P)) × ImpactMultiplicity(P) ]`

### Implementation Stages:
1. **Max CVE severity per node** — `get_cve_severity()` queries NVD API (with OSV fallback for npm/PyPI/Go/Rust), returning `{CVE_ID: severity}` dict. Node risk = max severity across CVEs (0.0 if none).
2. **Path traversal** — All paths from leaf nodes to critical assets are enumerated via NetworkX.
3. **Edge weight accumulation** — For each path P, sum edge weights `w_uv` (dependency criticality, trust boundaries, interaction depth).
4. **Impact multiplicity** — Paths traversing multiple functional domains (Network → Auth → File I/O) receive exponential multiplier.
5. **PHEI calculation** — Maximum path risk across all paths determines systemic risk, capped at 10.0.

The implementation penalizes the most dangerous single pathway, not the sum of all risks. This matches the threat model: catastrophic failure emerges from the weakest link in the longest chain, not cumulative exposure.

## Agent Layer

The `src/agent` module provides optional, pluggable LLM-generated explanations using a configured local endpoint or API key. Deterministic scan orchestration and risk scoring operate independently. Structured reports persist when no model is configured, with deterministic plain-language fallback. Hermes is a development tool and is not a runtime dependency of recon-dg.

## Architecture Decisions

### **Scoring Formula Resolution (2026-09-17)**

**Decision:** Adopt path-maximum scoring (PHEI Index) over global-sum.

**Rationale:**
- The threat model defines catastrophic failure as emerging from the weakest link in the longest chain, not cumulative exposure
- Global-sum averages risk across all edges, diluting critical pathway signals
- Path-maximum identifies the single most dangerous exploitation route
- Functional-domain multipliers amplify paths crossing trust boundaries (e.g., Network → Auth → File I/O)

**Implementation:**
- `calculate_path_weight()` computes sum of edge risks along each path
- `calculate_impact_multiplicity()` adds exponential factor for paths crossing multiple functional domains
- `calculate_systemic_risk()` implements PHEI: `max_P [sum_edge_weights(P) × ImpactMultiplicity(P)]`
- Documented in `ARCHITECTURE.md`

**Alignment:** Matches `docs/specs/design_spec.md` Section 3 formula.

## NVD/OSV Integration

The `src/engine/nvd_client.py` module implements:
- **NVD API client** with rate-limiting (`RateLimiter`), exponential backoff, and `CachedResponse`
- **OSV API fallback** for npm/PyPI/Go/Rust ecosystems
- **Key format:** `{ecosystem}:{package}:{version}:{cve_id}`
- **Severity normalization:** NVD CVSS → OSV severity → PHEI scale

## Reporter Interface

The `src/reporter/` module provides:
- **`RiskReport` dataclass** with structured JSON schema (report_id, timestamp, risk_delta, detailed_findings, recommendations)
- **`explanation_prompt_design.md`** for LLM-generated human-readable summaries
- **Deterministic fallback** when external APIs fail (unverified flag, 30% confidence reduction)
- **Tests:** 18 pytest cases validating schema compliance, risk calculation, and determinism
