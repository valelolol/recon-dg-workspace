"""Normalize OSV-Scanner JSON into RECON-DG's graph + finding objects.

The OSV-Scanner raw output has the documented shape (see
https://github.com/google/osv-scanner#output):

    {
      "results": [
        {
          "source": {"path": "...", "type": "lockfile"},
          "packages": [
            {
              "package": {"name": "PyYAML", "version": "5.1", "ecosystem": "PyPI"},
              "vulnerabilities": [
                {
                  "id": "GHSA-...",
                  "aliases": ["CVE-2020-1747"],
                  "type": "MAINTAINER_ADVISORY",
                  "published": "...",
                  "affected": [
                    {"package": {"ecosystem": "PyPI", "name": "pyyaml",
                                  "purl": "pkg:pypi/pyyaml"},
                     "ranges": [{"events": [{"introduced": "5.1"},
                                            {"fixed": "5.2b1"}],
                                "type": "ECOSYSTEM"}]
                    }
                  ],
                  "severity": null
                }
              ],
              "groups": [{"ids": ["GHSA-..."]}]
            }
          ]
        }
      ]
    }

Severity in the real **OSV-Scanner 2.6.0** output is one of exactly two
shapes (verified against the live binary):

  * ``severity: null`` — no severity known for that advisory; OR
  * ``severity: [{"type": "CVSS_V3", "score": "CVSS:3.1/..."}, ...]`` — a
    *list* of per-scheme severity entries whose ``score`` is a CVSS *vector
    string*, never a numeric score.

  Consequence: a genuine 2.6.0 report carries **no numeric CVSS score at all**.
  Therefore RECON-DG normalises ``severity_score`` to ``None`` (unknown) for that
  shape and does **not** compute a CVSS score or classify a finding as high/low.
  Every severity scheme ``type`` and its vector string are preserved verbatim on
  the :class:`Finding` (``severity_types`` / ``severity_vectors``) so the evidence
  trail can quote them exactly.  For defensive compatibility the idealized single
  block ``{"score": <number>, "vector": "..."}`` (used by some tooling and the
  legacy fixture) is still accepted, where a real numeric score is preserved.

Affected ranges in the real 2.6.0 output are expressed as ``affected[].ranges``
with ``events`` (``introduced``/``fixed``) — there is no literal ``vulnerable_spec``
field.  The normalizer renders the vulnerable range from those events (falling
back to an explicit ``vulnerable_spec``/``vulnerability_spec`` key if one is
present), so the agent always has a grounded ``vulnerability_spec``.

This module converts the output into two first-class RECON-DG objects:

- :class:`Finding` — a single package/vulnerability pair with the metadata an
  investigator actually needs (severity, CVE, spec, affected range, published,
  type).  It is a *record of evidence*: it carries the raw ``id``, ``aliases``,
  ``affected`` and ``severity`` so the agent's evidence trail can quote it
  without re-parsing.  It is an immutable value object (constructed fully at
  build time).

- :class:`ScanResult` — the whole normalized scan: the :class:`DependencyGraph`
  plus a flat list of :class:`Finding` objects.

The conversion is *evidence-grounded*: it only promotes a package into a
``DependencyGraph`` node when the OSV-Scanner itself says so, and it does not
invent edges.  For a *requirements.txt* (flat, no dependency relationships),
the graph is edge-less and the PHEI path-max is therefore ``unavailable`` —
exactly the behaviour RECON-DG requires ("inventory-only input must not
produce invented dependency edges").

This module is pure (no I/O, no network), which makes it trivially
unit-testable and reusable by the agent loop and by any downstream report /
dashboard code.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from src.models.dependency_graph import DependencyGraph, DependencyNode


@dataclass(frozen=True)
class Finding:
    """A single vulnerability finding, normalized from OSV-Scanner output.

    The object is *immutable* (a value object) so it can be safely stored in
    the agent's evidence trail without aliasing surprises.  All OSV-Scanner
    fields the agent cares about are captured at construction.
    """

    package_id: str
    package_name: str
    version: str
    ecosystem: str
    vulnerability_id: str
    aliases: tuple[str, ...] = ()
    advisory_type: str = "MAINTAINER_ADVISORY"
    published: Optional[str] = None
    vulnerability_spec: Optional[str] = None
    severity_score: Optional[float] = None
    severity_vector: Optional[str] = None
    # Full severity evidence for the real OSV-Scanner 2.6.0 shape (a list of
    # ``{"type": ..., "score": "<vector-string>"}`` entries).  Both are empty
    # for ``severity: null`` or malformed blocks — the finding is then simply
    # *unknown*, never "low".
    severity_types: tuple[str, ...] = ()
    severity_vectors: tuple[str, ...] = ()
    # Preserve the raw OSV-Scanner vulnerability dict for evidence tracing.
    _raw: Any = field(default=None, repr=False)

    def to_dict(self) -> dict[str, Any]:
        """Serialisable form (no private ``_raw``)."""
        return {
            "package_id": self.package_id,
            "package_name": self.package_name,
            "version": self.version,
            "ecosystem": self.ecosystem,
            "vulnerability_id": self.vulnerability_id,
            "aliases": list(self.aliases),
            "advisory_type": self.advisory_type,
            "published": self.published,
            "vulnerability_spec": self.vulnerability_spec,
            "severity_score": self.severity_score,
            "severity_vector": self.severity_vector,
            "severity_types": list(self.severity_types),
            "severity_vectors": list(self.severity_vectors),
        }

    def is_high_severity(self, threshold: float = 7.0) -> bool:
        """True when the CVSS score meets or exceeds ``threshold``.

        Returns ``False`` when the score is unknown (``None``) — an unknown
        severity must never be classified as high (and there is no "low" bucket
        at all to classify into either).
        """
        return self.severity_score is not None and self.severity_score >= threshold


@dataclass
class ScanResult:
    """Normalized output of one OSV-Scanner run.

    - :attr:`graph` is a :class:`DependencyGraph` (edge-less for a flat
      ``requirements.txt``, so PHEI is unavailable).
    - :attr:`findings` is a flat list of :class:`Finding` objects.
    - :attr:`source_path` is the scanned file (best-effort).
    """

    graph: DependencyGraph
    findings: list[Finding] = field(default_factory=list)
    source_path: str = ""
    # Raw top-level payload, kept for evidence / audit.
    _raw_payload: Optional[dict[str, Any]] = field(default=None, repr=False)

    def count(self) -> int:
        return len(self.findings)

    @property
    def is_empty(self) -> bool:
        return len(self.findings) == 0


def _spec_from_range(rng: dict[str, Any]) -> str:
    """Render one OSV-Scanner range (``events``) as a vulnerable-range spec."""
    introduced = None
    fixed = None
    for e in (rng.get("events") or []):
        if not isinstance(e, dict):
            continue
        introduced = e.get("introduced", introduced)
        fixed = e.get("fixed", fixed)
    if introduced is not None and fixed is not None:
        return f">={introduced},<{fixed}"
    if fixed is not None:
        return f"<{fixed}"
    if introduced is not None:
        return f">={introduced}"
    return ""


def _vuln_spec(affected: list[dict[str, Any]]) -> Optional[str]:
    """Return the vulnerable range as a spec string (defensive).

    Handles both OSV-Scanner shapes:
      * an explicit ``vulnerable_spec`` / ``vulnerability_spec`` field on a
        range (idealized/older output);
      * the real 2.6.0 shape, where each affected entry has ``ranges`` of
        ``events`` (``introduced``/``fixed``) and no literal range field —
        the spec is then rendered from those events.
    Returns ``None`` when no usable range is present.
    """
    if not affected:
        return None
    for a in affected:
        if not isinstance(a, dict):
            continue
        for r in a.get("ranges") or []:
            if not isinstance(r, dict):
                continue
            spec = r.get("vulnerable_spec") or r.get("vulnerability_spec")
            if spec:
                return str(spec)
            if r.get("events"):
                s = _spec_from_range(r)
                if s:
                    return s
    return None


def _pkg_id(package: dict[str, Any], affected: list[dict[str, Any]]) -> str:
    """Return the canonical ``pkg:pypi/<name>`` identifier (defensive).

    Real 2.6.0 affected entries carry ``package.purl`` (or, in older shapes,
    a top-level ``pkg``); either is preferred over a reconstructed id.
    """
    for a in affected:
        if not isinstance(a, dict):
            continue
        if a.get("pkg"):
            return a["pkg"]
        pkg = a.get("package")
        if isinstance(pkg, dict) and pkg.get("purl"):
            return pkg["purl"]
    name = package.get("name", "")
    return f"pkg:pypi/{name}" if name else ""


def _package_meta(package: dict[str, Any]) -> dict[str, Any]:
    """Return the package metadata dict.

    OSV-Scanner nests it under ``package`` (``{"package": {"name",
    "version", "ecosystem"}, ...}``).  Some consumers (and the before/after
    pair in this repo) may hand us a flat object.  Handle both defensively so
    the evidence is never mis-attributed as "unknown".
    """
    nested = package.get("package")
    if isinstance(nested, dict) and ("name" in nested or "version" in nested):
        return nested
    return package


def _severity(advisory: dict[str, Any]) -> tuple[Optional[float], Optional[str], tuple[str, ...], tuple[str, ...]]:
    """Extract severity evidence from one OSV-Scanner advisory (defensive).

    Returns ``(score, primary_vector, severity_types, severity_vectors)``.

    * Real 2.6.0 list shape ``[{"type": ..., "score": "CVSS..."}]`` ->
      ``score=None`` (no numeric exists), primary vector = first vector string,
      all scheme types + vectors preserved in order.
    * ``severity: null`` / missing -> all empty.
    * Legacy/idealized dict ``{"score": <number>, "vector": "..."}`` -> the
      numeric score and vector are preserved.
    * Anything malformed -> all empty (never raise, never coerce to a number).
    """
    severity = advisory.get("severity")

    if severity is None:
        return (None, None, (), ())

    if isinstance(severity, list):
        primary: Optional[str] = None
        types: list[str] = []
        vectors: list[str] = []
        for entry in severity:
            if not isinstance(entry, dict):
                continue
            t = entry.get("type")
            types.append(str(t) if t is not None else "UNSPECIFIED")
            s = entry.get("score")
            if isinstance(s, str) and s:
                vectors.append(s)
                if primary is None:
                    primary = s
        return (None, primary, tuple(types), tuple(vectors))

    if isinstance(severity, dict):
        score = severity.get("score")
        vector = severity.get("vector")
        # A real numeric score (legacy/idealized block).
        if isinstance(score, (int, float)) and not isinstance(score, bool):
            vec = vector if isinstance(vector, str) else None
            return (float(score), vec, (), (vec,) if vec else ())
        # A vector string with no numeric (defensive).
        if isinstance(vector, str):
            return (None, vector, (), (vector,))
        return (None, None, (), ())

    # malformed (str/number/etc.) -> unknown
    return (None, None, (), ())


def _finding_from(
    package: dict[str, Any],
    advisory: dict[str, Any],
) -> Finding:
    """Build a :class:`Finding` from one OSV-Scanner package/vulnerability pair.

    Severity is extracted here (not after construction) so the Finding is
    fully formed at build time and stays immutable.  The package metadata is
    read via :func:`_package_meta` so both the canonical nested OSV-Scanner
    shape and a flat shape are handled.
    """
    affected = advisory.get("affected") or []
    score, primary, types, vectors = _severity(advisory)
    meta = _package_meta(package)
    return Finding(
        package_id=_pkg_id(meta, affected),
        package_name=meta.get("name", "unknown"),
        version=meta.get("version", "unknown"),
        ecosystem=meta.get("ecosystem", "unknown"),
        vulnerability_id=advisory.get("id", "unknown"),
        aliases=tuple(advisory.get("aliases", []) or []),
        advisory_type=advisory.get("type", "MAINTAINER_ADVISORY"),
        published=advisory.get("published"),
        vulnerability_spec=_vuln_spec(affected),
        severity_score=score,
        severity_vector=primary,
        severity_types=types,
        severity_vectors=vectors,
        _raw=advisory,
    )


def normalize_scan(json_payload: dict[str, Any]) -> ScanResult:
    """Normalize a *parsed* OSV-Scanner JSON payload into a :class:`ScanResult`.

    This is the pure conversion function.  It does not read from disk; it
    operates on the already-parsed ``{"results": [...]}`` payload that the
    scan runner produces.

    Args
    ---
    json_payload : dict
        The OSV-Scanner top-level JSON object.

    Returns
    -------
    ScanResult
        A :class:`ScanResult` with the graph and findings.

    Raises
    ------
    ValueError
        If the payload is not a dict or lacks a ``results`` key.
    """
    if not isinstance(json_payload, dict):
        raise ValueError("scan payload must be a JSON object")
    results = json_payload.get("results")
    if not isinstance(results, list):
        raise ValueError("scan payload must contain a 'results' list")

    graph = DependencyGraph()
    findings: list[Finding] = []
    source_path = ""

    for result in results:
        if not isinstance(result, dict):
            continue
        source = result.get("source") or {}
        path = source.get("path")
        if path and not source_path:
            source_path = path
        packages = result.get("packages") or []
        for package in packages:
            if not isinstance(package, dict):
                continue
            meta = _package_meta(package)
            # An entry that does not actually identify a package (no ``name``
            # or ``version`` anywhere in the metadata) is malformed and is
            # skipped rather than turned into an invented ``unknown`` node —
            # the agent must never carry evidence it cannot attribute.
            if not isinstance(meta, dict) or not ("name" in meta or "version" in meta):
                continue
            name = meta.get("name", "unknown")
            version = meta.get("version", "unknown")
            # Add the node to the graph.  A flat requirements.txt has no
            # relationships, so this is an edge-less node — exactly what RECON-DG
            # requires ("inventory-only input must not produce invented edges").
            node = DependencyNode(package_name=name, version=version)
            graph.add_node(node)
            vulns = package.get("vulnerabilities") or []
            for advisory in vulns:
                if not isinstance(advisory, dict):
                    continue
                findings.append(_finding_from(package, advisory))

    return ScanResult(
        graph=graph,
        findings=findings,
        source_path=source_path,
        _raw_payload=json_payload,
    )


def osv_json_to_graph(json_payload: dict[str, Any]) -> DependencyGraph:
    """Convenience: extract just the graph (edge-less for flat inputs)."""
    return normalize_scan(json_payload).graph
