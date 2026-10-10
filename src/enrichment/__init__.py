"""Optional enrichment providers for the RECON-DG agent.

RECON-DG's core detection is the external **OSV-Scanner**; this package
provides *optional* context-enrichment providers (currently deps.dev).

Enrichment is strictly additive:

* it never changes, replaces, or invents OSV-Scanner findings;
* dependency graphs it returns are always labelled ``generic_published``
  (a resolved graph of a single package version in isolation) and are
  **never** treated as the scanned project's resolved graph;
* if a provider is unavailable (network / not-found / rate-limit / server
  error), the valid scanner findings are preserved and the failure is
  recorded with provenance.

No network is attempted at import time; clients are only constructed when
a consumer explicitly requests enrichment.
"""

from src.enrichment.deps_dev import (
    API_BASE,
    DepsDevClient,
    DepsDevResponse,
    PublishedDependencyGraph,
    build_package_context,
)

__all__ = [
    "API_BASE",
    "DepsDevClient",
    "DepsDevResponse",
    "PublishedDependencyGraph",
    "build_package_context",
]
