|# W8: Demo validation + usability checklist (W7 consolidation)

> **For:** Aliyan — beginner-friendly, reusable handoff.
> **Branch:** `feat/inventory-report`
> **Workspace:** `/home/vale/projects/recon-dg-workspace`
> **Template:** `docs/weekly-handoff-template.md`
> **PR target:** `feat/inventory-report` (confirmed by `docs/TEAM_ONBOARDING.md:279`; do NOT target `main`)
> **HEAD:** `e455881`

---

## Goal and demo value

One sentence: **Add a bounded search bar + numeric `severity_score` threshold filter to the existing read-only `src/web/dashboard.html`** (after checking the feature is not already present). Keep Docker and Flask/D3 out of W8.

## Proposed accountable owner

Aliyan (proposed — team confirmation required)

## Prerequisites

- W8 handoff (Vale): first real `report.json` from a live scan
- W8 handoff (Christian): dashboard validation
- `src/web/` — existing stdlib `http.server` dashboard (committed 83b10fb; `server.py` 7,892 bytes, `dashboard.html` 11,939 bytes)
- `src/explanation/deterministic.py` — grounded deterministic explanations (5,311 bytes)
- `src/explanation/local_model.py` — OpenAI-compatible local model client (14,362 bytes)
- `src/agent/` — agent pipeline (agent.py 46KB, pipeline.py 19KB, scan_runner.py 12KB, normalizer.py 17KB)
- **No Docker dependency** — all validation runs against the stdlib dashboard
- **Note:** `docs/demo-validation/` does not yet exist; it is a proposed deliverable location, not a prerequisite

## Input / Output contract

|| Direction | Artifact | Format |
|-----------|----------|--------|
| Input | `report.json` from Vale's real scan | Structured JSON with `findings[].{package_name, version, severity_score (may be null), vulnerability_id, aliases, ecosystem, published, vulnerability_spec, fixed_versions}`, `risk.score`, `ai_explanations` |
| Input | `src/web/dashboard.html` (existing, 11,939 bytes) | Read-only stdlib `http.server` page at `127.0.0.1:8000`; findings schema confirmed: `severity_score` (float | null, inclusive ≥ threshold filter), `package_name`, `vulnerability_id`, `aliases`, `ecosystem`, `published`, `vulnerability_spec`, `fixed_versions`, `ai_explanations`. No `evidence` field on findings. |
| Output | `src/web/dashboard.html` | Search bar + severity filter dropdown (no new Python files, no new dependencies) |

## Deliverable (one bounded item)

A single-file improvement to `src/web/dashboard.html`: (1) add a bounded search bar above the findings table that filters findings by `package_name` (case-insensitive, partial match), (2) add a numeric `severity_score` threshold filter dropdown that shows only findings at or above the selected threshold — for findings with `severity_score` null, treat them as "Unknown" and include them when no filter is active or when the user explicitly selects "All". Scores ≥ 7.0 match the selected threshold; scores below 7.0 are below threshold; null scores remain Unknown and are not classified. This threshold is a dashboard-level choice; the report model carries `severity_score: float | null` only, with no categorical classification. All JavaScript is inlined in the existing HTML file. No new Python files, no new dependencies, no Flask/D3 rewrite, no Docker.

## Acceptance criteria

- [ ] Search bar filters findings by `package_name` (case-insensitive, partial match)
- [ ] Severity filter dropdown shows only findings at or above the selected numeric `severity_score` threshold; scores ≥ 7.0 match the selected threshold; scores below 7.0 are below threshold; null scores remain Unknown and are not classified
- [ ] Findings with `severity_score` null are shown when no filter is active; when a severity filter is active, null-score findings are excluded (or shown under an "Unknown" option if the user selects it)
- [ ] Dashboard still starts without errors: `python -m src.web --report <real-report.json> --port 8000`
- [ ] No new Python files created; all JS is inlined in `src/web/dashboard.html`
- [ ] No third-party dependencies added
- [ ] No Flask/D3 rewrite — the improvement is a bounded HTML/JS addition
- [ ] No Docker in W8
- [ ] Search/filter works with the real `report.json` output from Vale's W8 scan

## Verification commands / evidence

```bash
cd /home/vale/projects/recon-dg-workspace
# Start the dashboard with Vale's real report
python -m src.web --report report.json --host 127.0.0.1 --port 8000 --model OFF
```

Then verify in browser at `http://127.0.0.1:8000`:
1. Findings table renders (insertion order — no sort)
2. Type a package name in the search bar → only matching findings remain visible (case-insensitive, partial match)
3. Select a severity level from the dropdown → only findings at or above that numeric `severity_score` threshold show; scores ≥ 7.0 match the selected threshold; scores below 7.0 are below threshold; null scores remain Unknown and are not classified
4. Select "All" from the dropdown → all findings show again (including null-score)
5. All findings cards show the deterministic explanation (from `ai_explanations`, not an evidence trail)

```bash
# Verify no new files were created
git status --short | grep -v '^?? docs/'
# Verify dashboard.html changed (should show M dashboard.html)
git diff --stat src/web/dashboard.html
```

## Security / privacy controls

- The dashboard is **read-only**: it serves report and page; does NOT re-run scans
- `--model` defaults to **OFF**; only `--model ON` enables AI
- No credentials committed in dashboard code
- No Docker in W8
- Search/filter JS runs client-side only; no network calls
- No Flask/D3 — all JS is inlined in the existing HTML file

## Privacy / security checks

- No credentials (API keys, tokens) in `report.json` or dashboard output
- No faculty/sponsor approval required in the demo (user approval is the gate)
- No model training or fine-tuning in the demo
- `--model ON` still requires `OPENAI_API_KEY` env var (not baked into any output)
- All scan evidence is from OSV-Scanner (authoritative scanner) or NVD/OSV API enrichment (secondary)

## Fallback

|| Unavailable item | Fallback behavior |
|------------------|-------------------|
| Dashboard fails to render | Report traceback; validate `report.json` directly as JSON |
| `--model ON` unavailable | Demonstrate `--model OFF` deterministic fallback instead |
| Real manifest unavailable | Use a known-good sample manifest (e.g. repo root `requirements.txt`) |
| PHEI score unavailable (topology unknown) | Demonstrate "unavailable" status as a feature, not a bug |

## Stop conditions

- If the real scan produces no findings (empty graph), stop and report the scan failure.
- If the dashboard fails to render on a valid `report.json`, stop and report the traceback.
- If the demo script cannot be executed in ≤ 10 steps, stop and revise the script.
- If a team member cannot independently verify the checklist, stop and clarify the acceptance criteria.

## Questions / blockers

- Should the demo include a live patch-and-rescan sequence, or just show the patch proposal?
- Does the demo need to cover all ecosystems (npm, PyPI, Go, Rust) or just one?
- Is the demo script intended for a 10-minute or 30-minute demo slot?
- Should the validation report be committed to `docs/demo-validation/` or kept as a local artifact?
- **Team decision:** llama.cpp local endpoint vs. user API key for the AI explanation demo? (see W5)

---

*Handoff v3 — 2026-10-27. Owner: Aliyan (proposed — team confirmation required). Revised task: search bar + severity filter dropdown in `src/web/dashboard.html` only. Corrected: dashboard renders findings in insertion order (no sort); no `evidence` field on findings; `EvidenceTrail` is the agent's per-turn tool-call log (`src/agent/agent.py:84`), not a report field. No Flask/D3 rewrite, no Docker. Verified: dashboard.html 11,939 bytes, server.py 7,892 bytes, findings schema has `package_name`/`severity_score` (may be null)/`vulnerability_id`/`aliases`/`ecosystem`/`published`/`vulnerability_spec`/`fixed_versions`, plus `ai_explanations` (deterministic explanations). No new Python files needed.*
