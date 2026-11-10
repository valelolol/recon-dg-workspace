# W10 Handoff — Aliyan (Demo Validation)

## Goal and demo value

**Interim-demo scope:** The Dec 9 presentation is an interim demonstration of progress toward the larger RECON-DG project — not a declaration that the full project is complete. The December deliverable is a working prototype (scan → graph → OSV findings → systemic risk → dashboard → AI explanation → bounded fix → human approval → rescan → verified results), not a finished application.

**Demo opportunities before presentation:** Dec 4 (Fri) and Dec 7 (Mon) are scheduled as internal team demos to validate the pipeline end-to-end before the Dec 9 presentation. Dec 8 (Tue) is a rehearsal/buffer day.

**One sentence:** Create the `docs/demo-validation/` directory with the Dec 8 rehearsal checklist (`dec-8-rehearsal.md`) and the ≤10-step demo script (`demo-script.md`) for the December 9 presentation — the single source of truth for demo readiness.

## Proposed accountable owner

Aliyan.

## Prerequisites

- `docs/demo-validation/` directory does not exist yet (confirmed in published tree `11937e4a9a9ea60eeea64c510d35855e170cfe31`).
- `docs/demo-presentation-outline.md` exists (committed in published tree) with the ≥15-min + 5-min Q&A structure.
- `docs/fixtures/report-fixture-demo.json` (committed in `1ad2a7b8`) uses `severity` (not `severity_score`); normalizer expects `severity_score`. **Mismatch documented by Christian.**
- `docs/demo-validation/` directory does not exist yet.
- `ai_explanations` carries deterministic explanations (from `src/explanation/deterministic.py`, 5,311 bytes); `src/explanation/local_model.py` (14,362 bytes) is the optional local-model client.
- `--model ON` still requires `OPENAI_API_KEY` env var (not baked into any output).
- TASKS.md §T-DE-04: Dashboard — **Not started** (Flask+D3 deferred; stdlib dashboard sufficient for Dec 9).
- Dec 8 rehearsal: one place only — `docs/demo-validation/dec-8-rehearsal.md`.
- Dec 9 presentation: the December deliverable demo (interim demonstration of progress toward the larger RECON-DG project, not a declaration of full completion).

## Input / Output contract

| Direction | Artifact | Format |
|-----------|----------|--------|
| Input | `docs/demo-presentation-outline.md` (published tree) | Markdown presentation outline |
| Output | `docs/demo-validation/dec-8-rehearsal.md` + `docs/demo-validation/demo-script.md` | Markdown files (single source of truth) |

## Deliverable (one bounded item)

`docs/demo-validation/` directory with:
- `dec-8-rehearsal.md` (the Dec 8 rehearsal checklist, ≥6 checkpoints, single source of truth).
- `demo-script.md` (≤10 steps, each with expected output).

## Acceptance criteria

- [ ] `docs/demo-validation/dec-8-rehearsal.md` exists with ≥6 checkpoints
- [ ] `docs/demo-validation/demo-script.md` has ≤10 steps, each with expected output
- [ ] `docs/demo-validation/` checklist ≥80% pass on the committed stdlib dashboard (verified by running the checklist)
- [ ] `git diff --check` clean
- [ ] Demo script covers the required flow: scan controlled vulnerable project → show evidence-backed OSV findings/severity → produce AI explanation and bounded fix recommendation using user-selected OpenAI/ChatGPT, Claude, or custom endpoint → require explicit human approval before applying the patch → rescan and report only verified results
- [ ] Never presents fixture findings as real-project findings (all fixture findings clearly labeled)

## Verification commands / evidence

```bash
# Verify demo-validation directory exists
ls docs/demo-validation/

# Expected: dec-8-rehearsal.md, demo-script.md

# Verify checklist is runnable
python -c "
import markdown
# Run each checkpoint; record pass/fail
"

# Expected: ≥80% pass
```

## Security / privacy controls

- Demo AI explanation: any OpenAI/ChatGPT, Claude, or a custom endpoint (URL/IP/port with credentials if required) with deterministic fallback; the user selects and configures the provider.
- `--model OFF` demonstrated (deterministic fallback).
- **No fabricated CVEs, no fabricated edges, no fabricated scores.**
- **Never present fixture findings as real-project findings.** All fixture findings must be clearly labeled as synthetic/demo-only.
- No credentials in the demo script (env vars only).
- No model training or fine-tuning (out of scope).

## Fallback

| Unavailable service | Fallback behavior |
|---------------------|-------------------|
| No controlled project with known CVEs | Demonstrate with synthetic fixture (clearly labeled) + note that real CVE→systemic-risk is pending a real project |
| Dashboard render failure | Validate `report.json` directly as JSON; note gap |
| Systemic risk `None` / `UnavailableTopologyError` on real graph | Demonstrate "unavailable" as feature, not bug |
| Docker | dismissed; no Docker in W10 (out of scope) |

## Stop conditions

- If the demo script cannot be ≤10 steps, stop and report the scope gap rather than inflating the step count.
- If the Dec 8 rehearsal checklist cannot reach ≥80% pass, stop and report the gap.

## Questions / blockers

- Should demo include live patch-and-rescan sequence or just show patch proposal?
- Does demo need to cover all ecosystems (npm, PyPI, Go, Rust) or just one?
- Is demo script for 10-minute or 30-minute slot?
- Should validation report be committed to `docs/demo-validation/` or kept as local artifact?
- **Demo AI explanation: any OpenAI/ChatGPT, Claude, or a custom endpoint** (URL/IP/port with credentials if required) with deterministic fallback; the user selects and configures the provider. (see ROADMAP §W5)

---

*W10 handoff v1 — 2026-11-09. Owner: Aliyan (proposed). For team confirmation.*
