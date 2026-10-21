# W6: Optional Docker packaging (T-DE-05)

## Goal and demo value

Build a portable Docker image (multi-stage) and `docker-compose.yml` for local dev. Docker is **optional** — the stdlib dashboard and agent run on any Python 3.10+ machine. This handoff is bounded to Docker packaging only; it does not include final demo rehearsal, dashboard-validation, or usability testing (those belong to W7).

## Proposed accountable owner

Christian (proposed — team confirmation required)

## Prerequisites

- W4 deliverable: `src.web` dashboard running on `127.0.0.1:8000`
- W5 deliverable: model backend configured (or confirmed deterministic-only)
- `requirements.txt` lists all runtime dependencies
- `tests/` all pass on the working branch
- No W7 deliverables required (W7 is a separate usability-validation handoff)

## Input / Output contract

| Direction | Artifact | Format |
|-----------|----------|--------|
| Input | `RiskReport` from W3 | Structured JSON with findings, edges, PHEI score, remediation plan |
| Input | `requirements.txt` | Runtime deps |
| Output | `Dockerfile` (optional) | Multi-stage build (only if team chooses Docker) |
| Output | `.dockerignore` (optional) | Excludes tests, docs, git |
| Output | `docker-compose.yml` (optional) | Local dev stack (app + optional DB) |
| Output | `README.md` | Docker build + run instructions (if Docker chosen) |
| Output | `src/web/` | Extended stdlib dashboard (mandatory, W4 deliverable) |

## Deliverable (one bounded item)

**Optional (bounded):** `Dockerfile` (multi-stage: builder → runtime), `docker-compose.yml`, `.dockerignore`, and `README.md` for Docker packaging. Docker is optional — manual install via `requirements.txt` is sufficient for the demo. The full pipeline run, dashboard validation, and demo-script preparation belong to W7 (demo-validation).

## Acceptance criteria

- [ ] `generate_report()` produces a complete `RiskReport` with real data
- [ ] All findings are grounded (evidence traceable to source code)
- [ ] `python -m src.web` renders the stdlib dashboard correctly
- [ ] Deterministic explanations are active (no model required)
- [ ] `python -m pytest tests/ -q` passes
- [ ] **Optional (Docker):** `docker build -t recon-dg:demo .` succeeds
- [ ] **Optional (Docker):** `docker run --rm -p 5000:5000 recon-dg:demo python -m src.web --port 5000` starts the dashboard
- [ ] **Optional (Docker):** Container is minimal (no dev deps, no git, no docs)
- [ ] **Optional (Docker):** `README.md` documents Docker build + run instructions
- [ ] **Optional (Docker):** `.dockerignore` excludes `tests/`, `docs/`, `.git/`, `*.pyc`
- [ ] **Optional (Docker):** `docker-compose.yml` starts a local dev stack (app + optional DB)

## Verification commands / evidence

```bash
cd /home/vale/projects/recon-dg-workspace
python -m pytest tests/ -q
python -m src.web --port 8000
# Open http://127.0.0.1:8000 in browser
```

**Optional (Docker):**
```bash
docker build -t recon-dg:demo .
docker run --rm -p 5000:5000 recon-dg:demo python -m src.web --port 5000
# Open http://127.0.0.1:5000 in browser
```

## Security / privacy controls

- No credentials committed in `Dockerfile` or `.dockerignore`
- `requirements.txt` lists only runtime deps (no dev deps)
- Container runs as non-root (if possible)
- `--model ON` still requires `OPENAI_API_KEY` env var (not baked into image)
- No model training or fine-tuning — out of scope

## Fallback

| Unavailable service | Fallback behavior |
|---------------------|-------------------|
| Docker not installed | `requirements.txt` + `README.md` is sufficient for manual install |
| Docker build fails | Report the specific error (missing dep, syntax, etc.) |
| Container crashes on startup | Report the traceback; likely a missing dep or config issue |
| Model endpoint unavailable | Deterministic explanations (already the default) |

## Stop conditions

- If the full pipeline fails on a real project, stop and report the specific error before proceeding.
- If the stdlib dashboard fails to render, stop and report the traceback.

## Questions / blockers

- Should the Docker image include llama.cpp (large image ~2GB+) or assume the user provides the model file? (optional)
- Should `docker-compose.yml` be included for local dev with llama.cpp? (optional)
- Should the demo use a specific manifest file (e.g. `requirements.txt` in the repo root)?
- **Team decision:** Flask+D3 optional dashboard vs. stdlib dashboard only? (see W4)
- **Team decision:** llama.cpp local endpoint vs. user API key? (see W5)

---

*Handoff v1 — 2026-10-20. Owner: Christian (for team confirmation).*
