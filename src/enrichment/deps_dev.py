"""deps.dev v3 enrichment client — *optional*, additive context only.

This module implements a small client for the **deps.dev v3** HTTP API
(:data:`API_BASE`) that RECON-DG may use to *enrich* a normalized OSV-Scanner
finding. It is intentionally:

* **stdlib only** — ``urllib.request`` + ``json``; no third-party dependency.
* **strictly additive** — it never rewrites, replaces, or invents OSV-Scanner
  findings.  If a lookup fails (not found, rate-limited, server error, or
  network), the caller receives a structured result that records the failure
  and *preserves* the original scanner findings (see :func:`build_package_context`).
* **explicit coordinates only** — lookups use explicit ``(system, package,
  version)`` or an explicit advisory id; nothing is guessed or scraped.
* **clearly provenanced** — resolved dependency graphs returned here are always
  labelled ``generic_published``: a *published, standalone* resolved graph for
  a single package version in isolation.  They are **never** treated as the
  scanned project's resolved graph and **never** feed project-specific PHEI
  scoring (see :class:`PublishedDependencyGraph`).

The v3 endpoints used (verified against
<https://docs.deps.dev/api/v3/index.html>) are:

* ``GET {base}/systems/{system}/packages/{pkg}/versions/{ver}``
  (GetVersion) — fields ``advisoryKeys`` (a list of ``{"id": ...}``),
  ``publishedAt``, ``licenses``, ``isDeprecated``, ``deprecatedReason``.
* ``GET {base}/systems/{system}/packages/{pkg}/versions/{ver}/dependencies``
  (GetDependencies) — ``{"dependencies": [{"package", "version", "type"}, ...]}``.
  This endpoint returns ``404`` for a version that has no resolvable
  transitive dependencies (a *leaf* package) or is unknown; that case is
  reported as an *empty* graph (no edges are ever invented) rather than as an
  error.
* ``GET {base}/advisories/{id}`` (GetAdvisory) — ``advisoryKey`` (``{"id": ...}``),
  ``title``, ``url``, ``aliases`` (CVEs/etc.), ``cvss3Score``, ``cvss3Vector``.

No network request is attempted at import time.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


API_BASE = "https://api.deps.dev/v3"

# --- Enrichment exceptions ---------------------------------------------------
# All subclasses of :class:`DepsDevError` are "provider" errors.  They are
# *expected* failures for an optional enrichment path and must therefore be
# handled additively (recorded, then continue with the scanner's findings).
class DepsDevError(Exception):
    """Base class for all deps.dev enrichment failures."""


class DepsDevNotFoundError(DepsDevError):
    """The requested package/version (or advisory) is not present in deps.dev.

    Note: :meth:`get_version_dependencies` deliberately treats a ``404`` as an
    *empty* dependency graph rather than raising this error, because a leaf
    package (no transitive deps) legitimately has no resolved graph.  Use this
    error (raised by :meth:`get_version` / :meth:`get_advisory`) when the
    *package or advisory itself* does not exist.
    """


class DepsDevRateLimitError(DepsDevError):
    """HTTP 429 — the deps.dev service is rate-limiting us."""


class DepsDevServerError(DepsDevError):
    """HTTP 5xx — a transient server-side failure on deps.dev."""


class DepsDevNetworkError(DepsDevError):
    """A network-level failure (DNS, connection reset, timeout, etc.)."""


# --- Response value objects ---------------------------------------------------
@dataclass(frozen=True)
class DepsDevResponse:
    """The parsed GetVersion response for one package version.

    ``provenance`` is always ``generic_published``: this is published data
    about a single package version, *not* the scanned project's resolved graph.
    """

    system: str
    package: str
    version: str
    status_code: int
    published_at: Optional[str] = None
    is_deprecated: Optional[bool] = None
    deprecated_reason: Optional[str] = None
    licenses: Tuple[str, ...] = ()
    advisory_ids: Tuple[str, ...] = ()
    provenance: str = "generic_published"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "system": self.system,
            "package": self.package,
            "version": self.version,
            "status_code": self.status_code,
            "published_at": self.published_at,
            "is_deprecated": self.is_deprecated,
            "deprecated_reason": self.deprecated_reason,
            "licenses": list(self.licenses),
            "advisory_ids": list(self.advisory_ids),
            "provenance": self.provenance,
        }


@dataclass(frozen=True)
class PublishedDependencyGraph:
    """A *published, standalone* resolved dependency graph for one package
    version (deps.dev ``/dependencies``).

    ``dependencies`` lists ``{"package", "version", "type"}`` edges as reported
    by deps.dev.  ``provenance`` is always ``generic_published``; this graph is
    for context only and must never be merged into — or used to score — the
    scanned project's own resolved graph.

    ``status_code`` is preserved so callers can distinguish a confirmed empty
    graph (200 with ``[]``) from an unresolvable one (404) and report that
    honestly in the evidence trail.
    """

    system: str
    package: str
    version: str
    dependencies: Tuple[Dict[str, Any], ...] = ()
    status_code: int = 0
    provenance: str = "generic_published"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "system": self.system,
            "package": self.package,
            "version": self.version,
            "dependencies": [dict(d) for d in self.dependencies],
            "status_code": self.status_code,
            "provenance": self.provenance,
        }


def _system_for(package: str) -> str:
    """Return a normalized deps.dev system slug from an OSV ecosystem name.

    RECON-DG primarily deals with Python, but the client is system-agnostic:
    the caller may pass an explicit ``system``; when one is omitted we map the
    OSV-Scanner ``ecosystem`` field (e.g. ``PyPI`` -> ``pyPI``) defensively.
    """
    mapping = {
        "PyPI": "pyPI",
        "pypi": "pyPI",
        "npm": "npm",
        "Go": "go",
        "go": "go",
        "Maven": "maven",
        "maven": "maven",
    }
    return mapping.get(package, package.lower()) if package else "pyPI"


class DepsDevClient:
    """Thin client for the deps.dev v3 API (stdlib ``urllib``).

    Args
    ----
    base_url : str
        API base (default :data:`API_BASE`).
    timeout : float
        Per-request timeout in seconds (bounded; default 15.0).
    user_agent : str
        ``User-Agent`` sent on each request.
    """

    def __init__(
        self,
        base_url: str = API_BASE,
        timeout: float = 15.0,
        user_agent: str = "recon-dg/0.1 (optional enrichment; additive only)",
    ) -> None:
        # Always a valid, absolute base URL.
        self.base_url = base_url.rstrip("/")
        self.timeout = max(float(timeout), 1.0)
        self.user_agent = user_agent or self.user_agent

    # ------------------------------------------------------------------
    # HTTP transport (patchable in tests) ---------------------------------
    def _fetch(self, url: str) -> Tuple[int, Any, bytes]:
        """Perform one bounded HTTP GET.

        Returns ``(status_code, parsed_json_or_None, raw_bytes)``.  A non-2xx
        status is *not* an exception here — the caller interprets the code.
        Network failures raise :class:`DepsDevNetworkError`.
        """
        req = urllib.request.Request(
            url,
            headers={"User-Agent": self.user_agent, "Accept": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                status = int(getattr(resp, "status", resp.code))
                body = resp.read()
        except urllib.error.HTTPError as exc:
            status = int(exc.code)
            body = exc.read()
        except (urllib.error.URLError, OSError, TimeoutError) as exc:
            raise DepsDevNetworkError(f"net error for {url}: {exc}") from exc

        try:
            parsed = json.loads(body.decode("utf-8", "replace"))
        except (ValueError, UnicodeDecodeError):
            parsed = None
        return status, parsed, body

    # ------------------------------------------------------------------
    # Endpoint wrappers ---------------------------------------------------
    def get_version(
        self, package: str, version: str, system: str,
    ) -> DepsDevResponse:
        """GetVersion: metadata + advisory ids for ``system/package@version``.

        Raises
        ------
        DepsDevNotFoundError   HTTP 404 (package/version not in deps.dev).
        DepsDevRateLimitError  HTTP 429.
        DepsDevServerError     HTTP 5xx.
        DepsDevNetworkError    network failure.
        DepsDevError           any other non-2xx status.
        """
        url = (
            f"{self.base_url}/systems/{self._clean(system)}/packages/"
            f"{self._clean(package)}/versions/{self._clean(version)}"
        )
        status, parsed, raw = self._fetch(url)
        if status == 200 and isinstance(parsed, dict):
            advisory_keys = parsed.get("advisoryKeys") or []
            advisory_ids: List[str] = []
            for item in advisory_keys:
                if isinstance(item, dict):
                    ident = item.get("id")
                    if ident:
                        advisory_ids.append(str(ident))
                elif isinstance(item, str) and item:
                    advisory_ids.append(item)
            licenses = parsed.get("licenses") or []
            if not isinstance(licenses, (list, tuple)):
                licenses = [licenses]
            return DepsDevResponse(
                system=self._clean(system),
                package=self._clean(package),
                version=self._clean(version),
                status_code=status,
                published_at=parsed.get("publishedAt"),
                is_deprecated=parsed.get("isDeprecated"),
                deprecated_reason=parsed.get("deprecatedReason"),
                licenses=tuple(str(l) for l in licenses),
                advisory_ids=tuple(advisory_ids),
                provenance="generic_published",
            )
        # Non-200 (or unexpected JSON) -> classify and raise.
        if status == 404:
            raise DepsDevNotFoundError(
                f"package {system}/{package}@{version} not found in deps.dev "
                f"({status})"
            )
        raise self._error_for_status(status, url, raw)

    def get_version_dependencies(
        self, package: str, version: str, system: str,
    ) -> PublishedDependencyGraph:
        """GetDependencies: the *published* resolved graph for a version.

        A ``404`` is interpreted as an **empty** graph (no resolvable
        transitive deps / leaf package) and is returned as such rather than
        raised — enrichment must never invent edges or drop findings over an
        unresolvable graph.  The ``status_code`` is preserved on the returned
        graph so the caller can report it honestly.
        """
        url = (
            f"{self.base_url}/systems/{self._clean(system)}/packages/"
            f"{self._clean(package)}/versions/{self._clean(version)}/dependencies"
        )
        status, parsed, raw = self._fetch(url)
        if status == 200 and isinstance(parsed, dict):
            deps = parsed.get("dependencies") or []
            if not isinstance(deps, list):
                deps = []
            normalized = []
            for d in deps:
                if isinstance(d, dict):
                    normalized.append(
                        {
                            "package": d.get("package"),
                            "version": d.get("version"),
                            "type": d.get("type"),
                        }
                    )
            return PublishedDependencyGraph(
                system=self._clean(system),
                package=self._clean(package),
                version=self._clean(version),
                dependencies=tuple(normalized),
                status_code=status,
                provenance="generic_published",
            )
        if status == 404:
            # Leaf package / unknown version -> no edges are added (additive).
            return PublishedDependencyGraph(
                system=self._clean(system),
                package=self._clean(package),
                version=self._clean(version),
                dependencies=(),
                status_code=status,  # 404: not a confirmed empty graph
                provenance="generic_published",
            )
        raise self._error_for_status(status, url, raw)

    def get_advisory(self, advisory_id: str) -> Dict[str, Any]:
        """GetAdvisory: details for one explicit advisory id.

        Returns a dict with ``id``, ``title``, ``url``, ``aliases`` (CVEs/etc.),
        ``cvss3Score`` (float or None), ``cvss3Vector``.  Advisory ids are
        taken explicitly (never guessed).
        """
        if not advisory_id:
            raise DepsDevError("get_advisory requires a non-empty advisory id")
        url = (
            f"{self.base_url}/advisories/"
            f"{urllib.parse.quote(self._clean(advisory_id), safe='')}"
        )
        status, parsed, raw = self._fetch(url)
        if status == 200 and isinstance(parsed, dict):
            advisory_key = parsed.get("advisoryKey") or {}
            ident = advisory_key.get("id") if isinstance(advisory_key, dict) else advisory_id
            score = parsed.get("cvss3Score")
            return {
                "id": ident or advisory_id,
                "title": parsed.get("title"),
                "url": parsed.get("url"),
                "aliases": parsed.get("aliases") or [],
                "cvss3Score": float(score) if isinstance(score, (int, float)) else None,
                "cvss3Vector": parsed.get("cvss3Vector"),
            }
        if status == 404:
            raise DepsDevNotFoundError(
                f"advisory {advisory_id!r} not found in deps.dev ({status})"
            )
        raise self._error_for_status(status, url, raw)

    # ------------------------------------------------------------------
    # Helpers -------------------------------------------------------------
    @staticmethod
    def _clean(value: Optional[str]) -> str:
        """URL-safe, normalized identifier fragment."""
        if value is None:
            return ""
        return str(value).strip().strip("@")

    def _error_for_status(self, status: int, url: str, raw: bytes) -> DepsDevError:
        """Map an unhandled non-2xx status to a typed enrichment error."""
        if status == 404:
            return DepsDevNotFoundError(f"deps.dev {status} for {url}")
        if status == 429:
            return DepsDevRateLimitError(
                f"deps.dev rate limit (429) for {url}"
            )
        if status >= 500:
            return DepsDevServerError(
                f"deps.dev server error ({status}) for {url}; raw={raw[:200]!r}"
            )
        body = raw[:200].decode("utf-8", "replace")
        return DepsDevError(
            f"deps.dev unexpected status {status} for {url}; body={body!r}"
        )


# --- Convenience builder ----------------------------------------------------
def build_package_context(
    package: str,
    version: str,
    system: str = "pyPI",
    client: Optional[DepsDevClient] = None,
    advisory_ids: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Assemble an *additive* enrichment context for one scanned package.

    This is the function the agent (item 3) calls.  It performs up to three
    explicit deps.dev lookups — the version (GetVersion), its published resolved
    dependencies (GetDependencies), and (optionally) explicit advisory detail
    (GetAdvisory) — and *never raises*: any provider failure is captured into
    ``errors`` and ``status``.  The returned dict is safe to attach as evidence
    to an OSV-Scanner finding without risking that the original findings are
    erased by a provider outage.

    Args
    ----
    package, version, system
        Explicit coordinates of the scanned package (system defaults to ``pyPI``).
    client
        A :class:`DepsDevClient` (created on demand if ``None``).
    advisory_ids
        Optional explicit list of advisory ids (e.g. the OSV ``id`` / CVE) to
        look up detail for.  Only ids supplied are queried; nothing is guessed.

    Returns
    -------
    dict
        Keys: ``package``, ``version``, ``system``, ``provenance``, ``status``
        (``ok`` / ``partial`` / ``error``), ``version_meta``, ``resolved_deps``,
        ``dependencies_status`` (``ok`` / ``empty_404`` / ``error``),
        ``advisory_details``, ``advisory_ids_from_version`` (what deps.dev
        reported for this version), and ``errors`` (list of failure messages;
        empty on full success).
    """
    if not package or not version:
        return {
            "package": package,
            "version": version,
            "system": system,
            "status": "error",
            "error": "package and version are required",
            "provenance": "generic_published",
            "errors": ["package and version are required"],
        }
    if client is None:
        client = DepsDevClient()
    errors: List[str] = []
    version_meta: Optional[Dict[str, Any]] = None
    resolved_deps: Optional[Dict[str, Any]] = None
    deps_status: str = "error"

    # 1) GetVersion (may legitimately 404).
    try:
        vresp = client.get_version(package, version, system)
        version_meta = vresp.to_dict()
    except DepsDevError as exc:
        errors.append(f"get_version: {exc}")
        # A 404 "not found" is still informative — we record it and move on.
        deps_status = "error"

    # 2) GetDependencies (404 -> empty graph, additive).
    try:
        graph = client.get_version_dependencies(package, version, system)
        resolved_deps = graph.to_dict()
        deps_status = "ok" if graph.status_code == 200 else "empty_404"
    except DepsDevError as exc:
        errors.append(f"get_version_dependencies: {exc}")
        deps_status = "error"

    # 3) Optional explicit advisory detail lookups.
    advisory_details: Dict[str, Any] = {}
    looked_up_advisories: List[str] = list(advisory_ids or [])
    if looked_up_advisories:
        for aid in looked_up_advisories:
            try:
                advisory_details[aid] = client.get_advisory(aid)
            except DepsDevError as exc:
                errors.append(f"get_advisory({aid!r}): {exc}")

    # Determine overall status.
    if not version_meta:
        status = "error"
    elif errors:
        status = "partial"
    else:
        status = "ok"

    return {
        "package": package,
        "version": version,
        "system": system,
        "status": status,
        "provenance": "generic_published",
        "version_meta": version_meta,
        "resolved_deps": resolved_deps,
        "dependencies_status": deps_status,
        "advisory_ids_from_version": list(
            version_meta["advisory_ids"]
            if version_meta else []
        ),
        "advisory_details": advisory_details,
        "errors": errors,
    }


if __name__ == "__main__":  # quick manual probe (not run by tests)
    _client = DepsDevClient(timeout=20.0)
    ctx = build_package_context("PyYAML", "5.1", "pyPI", client=_client)
    print(json.dumps(ctx, indent=2, default=str))
