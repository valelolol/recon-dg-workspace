# System Context Diagram

> Mermaid source. Paste into a Mermaid renderer or `docs/diagrams/system-context.mmd` for version control.

```mermaid
graph TB
    subgraph User["User / Faculty Sponsor"]
        U1[Supplies manifest]
        U2[Reviews dashboard]
        U3[Approves patch]
    end

    subgraph ReconDG["RECON-DG (this project)"]
        subgraph Parser["W1: Parser"]
            P1[requirements.txt]
            P2[package.json]
            P3[pyproject.toml]
            P4[go.mod]
        end

        subgraph Engine["W2: Engine"]
            E1[NVD/OSV Client]
            E2[PHEI Risk Analyzer]
        end

        subgraph Reporter["W3: Reporter"]
            R1[Inventory report schema]
        end

        subgraph Dashboard["W4: Dashboard (optional Flask+D3)"]
            D1[stdlib `src.web` dashboard]
            D2[Flask app (optional)]
            D3[D3.js graph (optional)]
            D4[Findings table]
            D5[Path viewer (optional)]
        end

        subgraph AI["W5: Model endpoint (opt-in)"]
            A1[Configured endpoint (llama.cpp / API key)]
            A2[Deterministic fallback (default)]
        end

        subgraph Docker["W6: Docker (optional)"]
            DO[Multi-stage image (optional)]
        end
    end

    subgraph External["External services"]
        NVD[NVD CVE API]
        OSV[OSV-Scanner]
        deps[deps.dev (optional)]
    end

    U1 --> P1
    U1 --> P2
    U1 --> P3
    U1 --> P4

    P1 --> E1
    P2 --> E1
    P3 --> E1
    P4 --> E1

    E1 --> NVD
    E1 --> OSV
    E1 --> deps
    E1 --> E2

    E2 --> R1

    R1 --> D1
    R1 --> D2

    D1 --> D3
    D1 --> D4
    D1 --> D5

    U2 --> D1
    U3 --> D4

    D4 --> A1
    A1 --> A2

    D1 --> DO
    R1 --> DO
```

## Legend

| Symbol | Meaning |
|--------|---------|
| `User` | The human operator (faculty sponsor, student) |
| `ReconDG` | The RECON-DG project itself |
| `Parser` | W1: multi-format manifest parser |
| `Engine` | W2: NVD/OSV enrichment client + PHEI scoring |
| `Reporter` | W3: Inventory report schema with evidence-grounded suggestions |
| `Dashboard` | W4: stdlib `src.web` dashboard (Flask+D3 optional) |
| `AI` | W5: Model endpoint (opt-in, defaults OFF) + deterministic fallback |
| `Docker` | W6: Portable packaging (optional) |
| `External` | OSV-Scanner, deps.dev (optional) — external data sources |

## Notes

- **Flask+D3 is optional** — the stdlib `src.web` dashboard is sufficient for the December demo.
- **Docker is optional** — manual install via `requirements.txt` is sufficient.
- **No data flows to/from external model training** — out of scope.
- **No data flows to/from fake/synthetic CVE data** — all findings come from OSV-Scanner.
