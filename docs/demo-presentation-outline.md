# December Demo Presentation Outline — RECON-DG

> **Audience:** Faculty sponsor, team (Vale, Nick, Christian, Aliyan), reviewers
> **Length:** ~15 minutes + 5 min Q&A
> **Environment:** Stdlib `src.web` dashboard on demo machine (or local machine). Docker is optional.

---

## 1. Problem & Motivation (2 min)

- **Problem:** Dependency vulnerabilities are common but hard to prioritize.
- **Why RECON-DG:** It maps the *systemic* risk — how low-severity flaws combine along critical paths.
- **What the demo shows:** A live scan of a real project → risk map → actionable findings → approved fix.

## 2. Architecture (2 min)

- Show the **system context diagram** (`docs/diagrams/system-context.md`)
- Show the **data flow diagram** (`docs/diagrams/data-flow.md`)
- Show the **patch workflow** (`docs/diagrams/patch-workflow.md`)
- Emphasize: real scanner (OSV-Scanner), real PHEI scoring, real topology-aware risk, real AI explanations (opt-in, defaults OFF).

## 3. Live Demo (7 min)

### 3a. Scanner (2 min)
- Run OSV-Scanner on a real project (e.g., `requirements.txt` in the repo)
- Show the structured output (JSON, not raw text)
- Show the `DependencyGraph` with real nodes

### 3b. Risk Analysis (2 min)
- Show PHEI score on the graph (path-max, not global-sum)
- Show the top risk path
- Show the `UnavailableTopologyError` for inventory-only input (contrast)

### 3c. Report (1 min)
- Show the `RiskReport` (inventory report schema) with findings, edges, PHEI, remediation plan
- Show the `not_run` state (red card, zero count summary)

### 3d. Dashboard (1 min)
- Open the stdlib `src.web` dashboard in the browser
- Show the findings table + risk summary
- **Optional:** Open the Flask+D3 dashboard (if team chose it)
- Show the AI explanation (if `--model ON` is configured)

### 3e. Patch Workflow (1 min)
- Show a finding → proposed patch → user approval → after-scan verification
- Emphasize: **no fabricated CVEs, no fabricated edges, no fabricated scores**

## 4. What's NOT Done (1 min)

- No model training or fine-tuning
- No synthetic fixtures as scanner evidence (historical/demo-only)
- No faculty/sponsor approval step in runtime
- Flask+D3 is optional — stdlib `src.web` dashboard is the default
- Docker is optional — manual install via `requirements.txt` is sufficient

## 5. Next Steps (1 min)

- W5: Model backend decision (llama.cpp vs. user API key) — **pending team decision**
- W6: Docker packaging (optional — manual install is sufficient)
- W7: Final demo validation and preparation (independently testable checklist + demo script)
- Future: deps.dev integration (optional), more manifest formats, CI integration

## 6. Q&A (5 min)

---

## Demo checklist

- [ ] `python -m src.web` starts the stdlib dashboard on `127.0.0.1:8000`
- [ ] Dashboard renders in browser
- [ ] Real scan runs (not synthetic)
- [ ] PHEI score shown (not `None`)
- [ ] Patch workflow demonstrated (show, don't tell)
- [ ] AI explanation shown (if `--model ON`)
- [ ] Unavailable topology demonstrated (contrast with available)
- [ ] `--model OFF` demonstrated (deterministic fallback)
- [ ] **Optional (Docker):** `docker build -t recon-dg:demo .` succeeds
- [ ] **Optional (Docker):** `docker run --rm -p 5000:5000 recon-dg:demo python -m src.web --port 5000` starts

## Notes

- **No fabricated data:** all findings from real OSV-Scanner.
- **Flask+D3 optional:** stdlib `src.web` dashboard is the default.
- **Docker optional:** manual install via `requirements.txt` is sufficient for the demo.
- **No credentials:** API key in env var only.
- **No model training:** out of scope.

---

*Outline v1 — 2026-10-20. All proposed owners marked "for team confirmation."*
