# W5: Wire the configured model endpoint (T-DE-05)

## Goal and demo value

The opt-in explanation layer (already implemented, defaults `--model OFF`) is wired to the team's chosen endpoint (llama.cpp local model or user API key). Deterministic grounded fallback remains active when the model is unavailable. All model output is additive only (never modifies findings).

## Proposed accountable owner

Vale (for team confirmation)

## Prerequisites

- W3 deliverable: `generate_report()` produces a complete `RiskReport`
- `src/explanation/local_model.py` exists (targeting `/v1/chat/completions` via stdlib `urllib`)
- `src/explanation/deterministic.py` exists (grounded deterministic explainer)
- `src/explanation/__init__.py` has `add_explanations(report, use_model=True)`
- `tests/test_explanation.py` (23) and `tests/test_explanation_http.py` (7) exist
- **Team decision pending:** llama.cpp local endpoint vs. user API key

## Input / Output contract

| Direction | Artifact | Format |
|-----------|----------|--------|
| Input | `RiskReport` from W3 | Structured JSON with findings |
| Input | `OPENAI_BASE_URL` / `OPENAI_API_KEY` env vars | Configuration for the model endpoint |
| Output | `src/explanation/local_model.py` | Configured to the chosen endpoint (llama.cpp or user key) |
| Output | `src/explanation/__init__.py` | `add_explanations` wired to the chosen backend |
| Output | `tests/test_explanation.py` | Tests for the chosen backend |

## Deliverable (one bounded item)

`src/explanation/local_model.py` configured to the team's chosen endpoint (llama.cpp or user API key), with `--model ON` enabling AI explanations in the dashboard.

## Acceptance criteria

- [ ] `OPENAI_BASE_URL` and `OPENAI_API_KEY` env vars configure the endpoint
- [ ] `--model ON` (case-insensitive) enables the local-model backend
- [ ] `--model OFF` (default) uses deterministic explainer only
- [ ] Per-finding deterministic fallback on any failure (no config, network/timeout, non-2xx, malformed body, empty completion, `max_calls` cap)
- [ ] Model output is **additive only**: `report["ai_explanations"]` entries with `{text, source}` — never modifies findings, severity, fixed versions, risk, remediation, or verification
- [ ] `explanation_source` counts model vs. deterministic entries per finding
- [ ] `python -m pytest tests/test_explanation.py tests/test_explanation_http.py -q` passes

## Verification commands / evidence

```bash
cd /home/vale/projects/recon-dg-workspace
python -m pytest tests/test_explanation.py tests/test_explanation_http.py -q
```

For live demo (llama.cpp):
```bash
# Start llama.cpp server (local)
./llama-server -m <model.gguf> --host 127.0.0.1 --port 8080

# Set env and run
OPENAI_BASE_URL=http://127.0.0.1:8080/v1 OPENAI_API_KEY=sk-... python -m src.web --model ON
```

## Security / privacy controls

- **Model defaults OFF** — requires explicit `--model ON` opt-in
- API key stored in env var only; never committed
- `OPENAI_BASE_URL` may be HTTP or HTTPS — **open privacy decision**: the endpoint receives the API key and finding data in either case
- Finding data sent to the endpoint: package name, version, vulnerability ID, aliases, severity score, severity vector, severity types, published date, affected range, fixed versions, recommended action
- `max_calls` cap prevents unbounded requests
- No credentials or endpoint secrets committed in source
- **No model training or fine-tuning** — out of scope

## Fallback

| Unavailable service | Fallback behavior |
|---------------------|-------------------|
| No `OPENAI_BASE_URL` configured | Deterministic fallback (default behavior) |
| No `OPENAI_API_KEY` configured | Deterministic fallback |
| Network/timeout error | Per-finding deterministic fallback |
| Non-2xx HTTP response | Per-finding deterministic fallback |
| Malformed JSON body | Per-finding deterministic fallback |
| Empty completion | Per-finding deterministic fallback |
| `max_calls` exceeded | Remaining findings fall back to deterministic |
| Endpoint is HTTP (not HTTPS) | **Documented as open privacy decision** — team to decide if this is acceptable |

## Stop conditions

- If the team cannot agree on llama.cpp vs. user API key before the demo, fall back to deterministic-only (the demo still works without a model).
- If the endpoint returns non-2xx for all findings, stop and report the connectivity/credential issue.

## Questions / blockers

- **Team decision:** llama.cpp local endpoint vs. user API key? This is a pending decision documented in TASKS.md and `docs/STATUS.md`.
- If llama.cpp: which model? (quantized GGUF, size constraints for the demo environment)
- If user API key: which provider? (OpenAI, Anthropic, etc.)
- Does the demo environment have llama.cpp installed?

---

*Handoff v1 — 2026-10-20. Owner: Vale (for team confirmation).*
