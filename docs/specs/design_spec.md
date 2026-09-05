# Predictive Vulnerability Dashboard Design Specification (The PHEI Index)

## 1. Project Overview and Goal
*Purpose:* To define the rigid technical contract for the Dependency Risk Dashboard's core scoring mechanism, moving beyond simple CVE aggregation to systemic, path-based threat modeling.

## 2. Graph Schema Definition (Nodes & Edges)

### 2.1. Node Schema (Component Node)
*   **Component ID:** String (Unique identifier, e.g., `library-a@1.2.3`).
*   **Type:** Enumeration (e.g., `LIBRARY`, `OS_MODULE`, `CUSTOM`).
*   **Dependency Source:** (String) Where the component was found (e.g., `package.json`, `pom.xml`).
*   **Metadata:** Map of attributes (e.g., `MaintenanceStatus: Active/Deprecated`, `LatestCommit: YYYY-MM-DD`, `Owner: Team`).

### 2.2. Edge Schema (Dependency Relationship Edge)
*   **Source Node:** (Component ID)
*   **Target Node:** (Component ID)
*   **Weight/Type:** (Critical) Must be an enumerated type. Suggestions:
    *   `DIRECT_HARD_DEP` (Manually required).
    *   `TRANSITIVE_DEP` (Indirectly required).
    *   `TRUST_BOUNDARY_CROSSING` (A dependency from external/uncontrolled source).
*   **Interaction Depth:** Integer (Depth of dependency).

## 3. The Predictive Vulnerability Score Formula: PHEI Index
*Hypothesis:* Systemic Risk is not the summation of individual risks ($\sum R_i$), but the weighted probability of failure via the most dangerous path.

$$
PHEI(G) = \text{max}_{Path P \in G} \left[ \left( \sum_{(u, v) \in P} w_{u,v} \right) \times \text{ImpactMultiplicity}(P) \right]
$$

*   **Variables to Define:**
    1.  **$P$ (Path):** The path of dependencies from a component to a critical asset.
    2.  **$w_{u,v}$ (Edge Weight):** What function combines (CVE\_Severity, TrustLevel, InteractionDepth)? This needs to be defined mathematically.
    3.  **$\text{ImpactMultiplicity}(P)$:** A factor that increases if $P$ traverses multiple distinct functional domains (e.g., Network $\to$ Authentication $\to$ File I/O).

## 4. Evidence Source Requirements
*List of data feeds required to populate the above fields (e.g., NVD/CVE, OSS/SOAR, Internal Team Vulnerability Reports).*