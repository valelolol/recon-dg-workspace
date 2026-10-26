# W2: Engine wiring — real OSV + PHEI on known topology (T-DE-02)

## Goal and demo value

Wire the NVD/OSV API enrichment fallback client into the graph so real CVE data flows into PHEI scoring. The demo cannot show PHEI without real vulnerability data on a graph with known topology. Inventory-only input (no edges) reports risk as unavailable — no score fabricated.

## Proposed accountable owner

Vale (for team confirmation)

## Prerequisites

- W1 deliverable: parser supporting ≥4 formats → `DependencyGraph` with real nodes
- `src/engine/risk_analyzer.py` already has `calculate_phei()` (path-max, capped at 10.0) + `UnavailableTopologyError`
- `src/engine/nvd_client.py` exists with `RateLimiter`, `CachedResponse`
- `tests/test_nvd_integration.py` exists (11 tests, historically passing)
- `tests/test_risk_analyzer.py` exists (5 tests, historically passing)

## Input / Output contract

| Direction | Artifact | Format |
|-----------|----------|--------|
| Input | `DependencyGraph` from W1 (real nodes, edges) | `DependencyGraph` with `edge_availability = "known"` |
| Output | `src/engine/nvd_client.py` | Real NVD/OSV API enrichment calls; `get_cve_severity(node_key)` returns real data |
| Output | `src/engine/risk_analyzer.py` | `calculate_phei` runs on real graph with known topology; inventory-only → `UnavailableTopologyError` |
| Output | `tests/test_osv_integration.py` | Updated tests with mocked real API responses |

## Deliverable (one bounded item)

`src/engine/nvd_client.py` wired to the real NVD/OSV API enrichment fallback (with rate-limiting, exponential backoff), and `calculate_phei` producing a real score on a real project graph with known topology. Inventory-only input → `UnavailableTopologyError` → risk status `"unavailable"`.

## Acceptance criteria

- [ ] `get_cve_severity(node_key)` returns real CVE severity from OSV for a known package
- [ ] Rate-limiting enforced (no more than configured requests/second)
- [ ] Exponential backoff on 429/503 responses
- [ ] `calculate_phei` on a real graph with known topology returns a numeric score (not `None`)
- [ ] `calculate_phei` on an inventory-only graph (no edges) raises `UnavailableTopologyError`
- [ ] `python -m pytest tests/test_nvd_integration.py tests/test_risk_analyzer.py -q` passes

## Verification commands / evidence

```bash
cd /home/vale/projects/recon-dg-workspace
python -m pytest tests/test_nvd_integration.py tests/test_risk_analyzer.py -q
```

Expected: all tests pass. For a live demo, run against a real project manifest:

**The repo has no verified integrated workflow that turns a manifest scan into a dashboard-compatible report.** The `src.web` module is a read-only dashboard server that serves an existing `report.json` file; it does **not** accept `--manifest` or `--output` flags, nor does it scan manifests or generate reports.

The scanner and reporter components exist in the repo. The missing capability is a verified command or workflow that connects a manifest scan to generation of a dashboard-compatible report file.

> **OSV-Scanner** can run as a separate external scanner (e.g. `osv-scanner --json` on a `requirements.txt`). Its JSON output is the authoritative CVE evidence for the project but is **not** directly consumed by the dashboard — a report-generation step must translate it into the `RiskReport` schema before `src.web` can serve it.

## Security / privacy controls

- NVD/OSV API enrichment: public, no key required
- Rate-limiting prevents abuse of NVD/OSV API
- No fabricated severity scores; unknown stays `None`
- No model/LLM involvement in scoring
|- No NVD API key required — OSV-Scanner is the authoritative source

## Fallback

| Unavailable service | Fallback behavior |
|---------------------|-------------------|
| NVD/OSV API enrichment (offline) | `UnavailableTopologyError` → risk unavailable; no score fabricated |
| Rate limit exceeded | Exponential backoff (capped at 5 retries); if all fail, report `unavailable` |
| Malformed API response | Log error; skip that node; continue with remaining nodes |

## Stop conditions

- If the OSV endpoint is unreachable, stop and report the connectivity issue before proceeding.
- If `calculate_phei` produces a score on an inventory-only graph (no edges), stop — this is a topology bug, not a scoring bug.

## Questions / blockers

- NVD API rate limits: **5 requests per rolling 30 seconds** without an API key, **50 per rolling 30 seconds** with an API key (https://nvd.nist.gov/developers/start-here). For demo purposes, should we cache aggressively or mock the API?
- OSV fallback scope: does it cover npm, PyPI, Go, Rust, or only npm/PyPI?
- Should the engine handle `go.mod` indirect dependencies (transitive), or only direct?

---

*Handoff v1 — 2026-10-20. Owner: Vale (for team confirmation).*
