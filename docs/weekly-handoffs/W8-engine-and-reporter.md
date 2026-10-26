|# W8: Engine NVD/OSV gap analysis + verify reporter (T-DE-02 / T-DE-03)

> **For:** Vale — beginner-friendly, reusable handoff.
> **Branch:** `feat/inventory-report`
> **Workspace:** `/home/vale/projects/recon-dg-workspace`
> **Template:** `docs/weekly-handoff-template.md`
> **PR target:** `feat/inventory-report` (confirmed by `docs/TEAM_ONBOARDING.md:279`; do NOT target `main`)
> **HEAD:** `e455881`

---

## Goal and demo value

One sentence: Run one reproducible real-project OSV-Scanner scan attempt through the existing pipeline, documenting what works, gaps, and topology/risk limits. Do not promise NVD wiring or a graph serializer.

## Proposed accountable owner

Vale (for team confirmation)

## Prerequisites

- W2 handoff `docs/weekly-handoffs/W2-engine.md` — existing NVD/OSV client code
- `src/engine/nvd_client.py` — `RateLimiter`, `CachedResponse`, `get_cve_severity()` (exists, rate-limited, uses `httpx`)
- `src/engine/risk_analyzer.py` — `calculate_phei()` (path-max, capped at 10.0) + `UnavailableTopologyError` + `MOCK_CVE_DB` (mock data, **not wired to NVD client**)
- `src/reporter/report_generator.py` — **already implemented**: `generate_report(current_graph, previous_graph)` with PHEI path-max scoring and `UnavailableTopologyError` handling (not unimplemented)
- `src/reporter/inventory.py` — existing inventory serializer (reference)
- `src/reporter/interface.py` — `RiskReport` dataclass schema
- Nick's W8 parser output (one additional format → `DependencyGraph`)

## Input / Output contract

|| Direction | Artifact | Format |
|-----------|----------|--------|
| Input | `DependencyGraph` from Nick's parser | `edge_availability = "unavailable"` (inventory-only) |
| Input | `report.json` from the existing pipeline (inventory-only, no real scan) | inventory-only output (from existing pipeline) |
| Output | `src/engine/risk_analyzer.py` — **no edit needed in W8** | Document the gap: `get_cve_severity()` reads `MOCK_CVE_DB`, not `nvd_client.py` |
| Output | `src/reporter/report_generator.py` — **already exists** | Verify `generate_report()` works; no new serializer needed |
| Output | Gap analysis doc | What works, what is missing, W9 plan |

## Deliverable (one bounded item)

**One reproducible real-project OSV-Scanner scan attempt through the existing pipeline** (not new code): document what works, gaps, and topology/risk limits. Do not promise NVD wiring or a graph serializer.

## Acceptance criteria

- [ ] One reproducible real-project OSV-Scanner scan attempt produces a `report.json` (not synthetic)
- [ ] Document what works, what is missing, and topology/risk limits
- [ ] `calculate_phei` on inventory-only graph raises `UnavailableTopologyError` (verified — not fabricated)
- [ ] `src/reporter/report_generator.py` exists and is functional (verified by inspection, not new code)
- [ ] Do not promise NVD wiring or a graph serializer

## Verification commands / evidence

```bash
# Verify the gap: grep for MOCK_CVE_DB usage in risk_analyzer
cd /home/vale/projects/recon-dg-workspace
grep -n "MOCK_CVE_DB\|get_cve_severity\|nvd_client" src/engine/risk_analyzer.py
# Verify report_generator exists
ls src/reporter/report_generator.py
|# Run the existing pipeline on an inventory-only graph (after Nick's parser)
python -m src.web --report report.json --port 8000
```

## Security / privacy controls

- NVD/OSV API: public, no key required; rate-limiting enforced
- No fabricated severity scores; unknown stays `None`
- No model/LLM involvement in scoring
- Real scan output is authoritative — not synthetic

## Fallback

|| Unavailable service | Fallback behavior |
|---------------------|-------------------|
| NVD/OSV API offline | `UnavailableTopologyError` → risk unavailable; no score fabricated |
| Rate limit exceeded | Exponential backoff (capped at 5 retries); if all fail, report `unavailable` |
| Malformed API response | Log error; skip that node; continue |

## Stop conditions

- If the OSV endpoint is unreachable, stop and report the connectivity issue.
- If `calculate_phei` produces a score on an inventory-only graph (no edges), stop — topology bug.
- If the first real scan produces no findings, stop and report the scan failure.

## Questions / blockers

- NVD API rate limits: 5 req/30s without key, 50 req/30s with key — cache aggressively or mock for demo?
- OSV fallback scope: npm, PyPI, Go, Rust, or only npm/PyPI?
- `go.mod` indirect dependencies: direct only or transitive? (team decision)
- W9 NVD wiring: should it replace `MOCK_CVE_DB` or coexist? (team decision)
- Scan target: repo root (has `requirements.txt`; `src/agent/scan_runner.py` handles OSV-Scanner CLI)

---

*Handoff v2 — 2026-10-27. Owner: Vale (for team confirmation). Corrected: W8 scope = gap analysis (not full integration); `src/reporter/report_generator.py` already exists; `risk_analyzer.py` uses `MOCK_CVE_DB` (not `nvd_client.py`).*
