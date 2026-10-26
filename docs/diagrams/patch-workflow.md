# Finding-to-Approved-Patch Workflow

> Mermaid source. Paste into a Mermaid renderer or `docs/diagrams/patch-workflow.mmd` for version control.

```mermaid
flowchart TD
    S1[Scanner finds vulnerability] --> S2[OSV-Scanner]
    S2 --> S3[Record evidence: package, version, CVE, severity]
    S3 --> S4[Edge availability = known?]

    S4 -->|No| S5[UnavailableTopologyError]
    S5 --> S6[Report risk as unavailable]
    S6 --> S7[No score fabricated]

    S4 -->|Yes| S8[Calculate PHEI score]
    S8 --> S9[Top risk path identified]

    S9 --> S10[Agent receives finding]
    S10 --> S11[Grounded analysis]
    S11 --> S12[Proposed patch/diff]

    S12 --> S13[Show exact changes to user]
    S13 --> S14{User approves?}

    S14 -->|No| S15[Reject; return to analysis]
    S15 --> S11

    S14 -->|Yes| S16[Apply patch]
    S16 --> S17[Validate changed files]
    S17 --> S18[Run tests]
    S18 --> S19[After-scan: verify fix]

    S19 --> S20{Resolved?}
    S20 -->|No| S21[Flag as unresolved]
    S21 --> S22[Report: patch applied, not verified]

    S20 -->|Yes| S23[Report: resolved]

    S10 --> S24[AI explanation? --model ON]
    S24 --> S25[llama.cpp / User API]
    S25 --> S26[Deterministic fallback]

    S26 --> S12

    classDef scanner fill:#e3f2fd,stroke:#1565c0,stroke-width:2px
    classDef agent fill:#fff3e0,stroke:#e65100,stroke-width:2px
    classDef user fill:#e8f5e9,stroke:#2e7d32,stroke-width:2px
    classDef unavail fill:#ffebee,stroke:#c62828,stroke-width:2px
    classDef ai fill:#f3e5f5,stroke:#6a1b9a,stroke-width:2px

    class S1,S2,S3,S4,S8,S9 scanner
    class S10,S11,S12,S24,S25,S26 agent
    class S13,S14,S15,S16,S17,S18,S19,S20,S21,S22,S23 user
    class S5,S6,S7 unavail
    class S24,S25,S26 ai
```

## Workflow rules

| Step | Rule |
|------|------|
| S4 (topology) | If `edge_availability != "known"` → `UnavailableTopologyError`. No score fabricated. |
| S13 (show patch) | Show **exact** changes to the user before applying. |
| S14 (approval) | Apply **only** after user explicitly approves that specific patch. |
| S19 (verify) | Claim resolved **only** when after-scan supports it. |
| S24 (AI) | `--model ON` required. Model output is additive only (never modifies findings). |
| S26 (fallback) | Deterministic fallback on any failure (no config, network, non-2xx, malformed, empty). |

## Key constraints

- **No faculty/sponsor approval step in runtime**: only the user approves patches.
- **No fabricated CVE data**: all findings from OSV-Scanner.
- **No fabricated edges**: topology must be `"known"` for PHEI.
- **No model training or fine-tuning**: out of scope.
- **Flask+D3 optional**: stdlib `src.web` dashboard is the default.
- **Docker optional**: manual install via `requirements.txt` is sufficient for the demo.

## Notes

- The workflow is the **product's** runtime behavior, not a Hermes configuration.
- Flask+D3 is optional — the stdlib `src.web` dashboard is sufficient for the December demo.
- Docker packaging is optional — manual install via `requirements.txt` is sufficient.
