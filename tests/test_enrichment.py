"""Tests for the deps.dev v3 enrichment client (src/enrichment/deps_dev.py).

These exercise the client *without a real network* by patching the single
transport seam (``DepsDevClient._fetch``) to return canned ``(status, parsed,
raw)`` tuples.  This is the same injection discipline the scan_runner tests
use for ``subprocess.run``: the same validation / classification path the
production client takes is exercised, only the wire I/O is faked.

Contract under test (additive enrichment):
* success -> structured :class:`DepsDevResponse` / :class:`PublishedDependencyGraph`
* 404 on get_version -> DepsDevNotFoundError
* 429 -> DepsDevRateLimitError
* 5xx -> DepsDevServerError
* network fault -> DepsDevNetworkError
* 404 on GetDependencies -> empty graph (never raised; edges are never
  invented), status_code preserved
* get_advisory -> parsed dict; 404 -> DepsDevNotFoundError
* build_package_context -> never raises; on any failure returns status
  ``error``/``partial`` with ``errors`` populated and the package preserved.
"""

import unittest

from src.enrichment.deps_dev import (
    _system_for,
    API_BASE,
    DepsDevClient,
    DepsDevError,
    DepsDevNetworkError,
    DepsDevNotFoundError,
    DepsDevRateLimitError,
    DepsDevServerError,
    PublishedDependencyGraph,
    build_package_context,
)


class FakeTransport(DepsDevClient):
    """DepsDevClient whose _fetch returns pre-baked values (no I/O)."""

    def __init__(self, responses, **kwargs):
        super().__init__(timeout=2.0, **kwargs)
        self._responses = list(responses)
        self._calls = []

    def _fetch(self, url):
        self._calls.append(url)
        return self._responses.pop(0)


def _ver_json(*, advisory_ids, published_at=None, is_dep=False,
               deprecated_reason=None, licenses=("MIT",)):
    """Canned GetVersion body matching the real v3 shape."""
    return {
        "versionKey": "pkg:pypi/PyYAML/5.1",
        "publishedAt": published_at,
        "isDefault": False,
        "isDeprecated": is_dep,
        "deprecatedReason": deprecated_reason,
        "licenses": licenses,
        "advisoryKeys": [{"id": i} for i in advisory_ids],
        "links": [],
        "projectStatus": {},
    }


class TestGetVersion(unittest.TestCase):
    def test_success_returns_response_with_provenance(self):
        client = FakeTransport([
            (200, _ver_json(advisory_ids=["GHSA-1", "GHSA-2"]), b"{}"),
        ])
        resp = client.get_version("PyYAML", "5.1", "pyPI")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.package, "PyYAML")
        self.assertEqual(resp.version, "5.1")
        self.assertEqual(resp.advisory_ids, ("GHSA-1", "GHSA-2"))
        self.assertEqual(resp.licenses, ("MIT",))
        self.assertEqual(resp.provenance, "generic_published")
        self.assertEqual(len(client._calls), 1)
        # URL must be the documented v3 GetVersion path.
        self.assertIn("systems/pyPI/packages/PyYAML/versions/5.1", client._calls[0])

    def test_404_raises_not_found(self):
        client = FakeTransport([(404, {"error": "not found"}, b"{}")])
        with self.assertRaises(DepsDevNotFoundError):
            client.get_version("nope", "1.0", "pyPI")

    def test_429_raises_rate_limit(self):
        client = FakeTransport([(429, {}, b"{}")])
        with self.assertRaises(DepsDevRateLimitError):
            client.get_version("PyYAML", "5.1", "pyPI")

    def test_5xx_raises_server_error(self):
        client = FakeTransport([(503, {}, b"{}")])
        with self.assertRaises(DepsDevServerError):
            client.get_version("PyYAML", "5.1", "pyPI")

    def test_network_error_raises(self):
        class Boom:
            def __init__(self, x):
                self.x = x
        # Simulate a transport-level fault by having _fetch raise it.
        class NetBoom(DepsDevClient):
            def _fetch(self, url):
                raise DepsDevNetworkError("connection refused")
        with self.assertRaises(DepsDevNetworkError):
            NetBoom().get_version("PyYAML", "5.1", "pyPI")

    def test_non_2xx_other_raises_base_error(self):
        client = FakeTransport([(418, {}, b"{}")])
        with self.assertRaises(DepsDevError):
            client.get_version("PyYAML", "5.1", "pyPI")

    def test_non_json_body_treated_as_unparsed(self):
        # A 200 with a non-JSON body must not be accepted as a version.
        client = FakeTransport([(200, None, b"garbage not json")])
        with self.assertRaises(DepsDevError):
            client.get_version("PyYAML", "5.1", "pyPI")


class TestGetVersionDependencies(unittest.TestCase):
    def test_success_returns_graph_with_edges(self):
        deps = [
            {"package": "psycopg2", "version": "2.8", "type": "normal"},
            {"package": "six", "version": "1.15", "type": "normal"},
        ]
        client = FakeTransport([(200, {"dependencies": deps}, b"{}")])
        g = client.get_version_dependencies("requests", "2.28.0", "pyPI")
        self.assertIsInstance(g, PublishedDependencyGraph)
        self.assertEqual(len(g.dependencies), 2)
        self.assertEqual(g.dependencies[0], deps[0])
        self.assertEqual(g.status_code, 200)
        self.assertEqual(g.provenance, "generic_published")
        self.assertEqual(g.system, "pyPI")

    def test_404_returns_empty_graph_not_raised(self):
        client = FakeTransport([(404, {}, b"{}")])
        g = client.get_version_dependencies("PyYAML", "5.1", "pyPI")
        self.assertIsInstance(g, PublishedDependencyGraph)
        self.assertEqual(g.dependencies, ())
        self.assertEqual(g.status_code, 404)
        # Edges are never invented; provenance still labels it clearly.
        self.assertEqual(g.provenance, "generic_published")

    def test_429_raises_rate_limit(self):
        client = FakeTransport([(429, {}, b"{}")])
        with self.assertRaises(DepsDevRateLimitError):
            client.get_version_dependencies("requests", "2.28.0", "pyPI")

    def test_5xx_raises_server_error(self):
        client = FakeTransport([(503, {}, b"{}")])
        with self.assertRaises(DepsDevServerError):
            client.get_version_dependencies("requests", "2.28.0", "pyPI")


class TestGetAdvisory(unittest.TestCase):
    def test_success_returns_detail(self):
        client = FakeTransport([(200, {
            "advisoryKey": {"id": "GHSA-abc-1234"},
            "title": "PyYAML unsafe loading",
            "url": "https://osv.dev/vulnerability/GHSA-abc-1234",
            "aliases": ["CVE-2017-0920"],
            "cvss3Score": 9.8,
            "cvss3Vector": "CVSS:3.1/...",
        }, b"{}")])
        d = client.get_advisory("GHSA-abc-1234")
        self.assertEqual(d["id"], "GHSA-abc-1234")
        self.assertEqual(d["aliases"], ["CVE-2017-0920"])
        self.assertEqual(d["cvss3Score"], 9.8)
        self.assertIsNotNone(d["url"])

    def test_404_raises_not_found(self):
        client = FakeTransport([(404, {}, b"{}")])
        with self.assertRaises(DepsDevNotFoundError):
            client.get_advisory("GHSA-missing")

    def test_requires_id(self):
        client = DepsDevClient()
        with self.assertRaises(DepsDevError):
            client.get_advisory("")


class TestBuildPackageContext(unittest.TestCase):
    """The additive enrichment entry-point the agent (item 3) calls.
    It must *never* raise and must preserve the package even on total
    provider failure."""

    def test_full_success(self):
        client = FakeTransport([
            (200, _ver_json(advisory_ids=["GHSA-x", "GHSA-y"]), b"{}"),
            (200, {"dependencies": []}, b"{}"),
        ])
        ctx = build_package_context("PyYAML", "5.1", "pyPI", client=client)
        self.assertEqual(ctx["status"], "ok")
        self.assertEqual(ctx["package"], "PyYAML")
        self.assertEqual(ctx["provenance"], "generic_published")
        self.assertIn("advisory_ids_from_version", ctx)
        self.assertEqual(ctx["advisory_ids_from_version"], ["GHSA-x", "GHSA-y"])
        self.assertIsNone(ctx["errors"] or None)
        self.assertIsNotNone(ctx["version_meta"])
        self.assertIsNotNone(ctx["resolved_deps"])

    def test_version_not_found_is_additive_not_fatal(self):
        """If the package does not exist in deps.dev, the lookup fails but the
        caller's scanned package is preserved (no raise, errors recorded)."""
        client = FakeTransport([
            (404, {}, b"{}"),   # get_version -> not found
            (404, {}, b"{}"),   # get_version_dependencies -> empty (404)
        ])
        ctx = build_package_context("nope", "1.0", "pyPI", client=client)
        self.assertEqual(ctx["status"], "error")
        self.assertEqual(ctx["package"], "nope")
        self.assertEqual(ctx["version"], "1.0")
        self.assertIsNone(ctx["version_meta"])
        self.assertEqual(len(ctx["errors"]), 1)
        self.assertIn("get_version", " ".join(ctx["errors"]))
        # deps 404 is additive (empty graph), not recorded as an error.
        self.assertEqual(ctx["dependencies_status"], "empty_404")

    def test_dependencies_404_is_empty_not_fatal(self):
        client = FakeTransport([
            (200, _ver_json(advisory_ids=["GHSA-z"]), b"{}"),
            (404, {}, b"{}"),
        ])
        ctx = build_package_context("PyYAML", "5.1", "pyPI", client=client)
        self.assertEqual(ctx["status"], "ok")
        self.assertEqual(ctx["dependencies_status"], "empty_404")
        self.assertEqual(ctx["resolved_deps"]["dependencies"], [])
        self.assertEqual(ctx["errors"], [])

    def test_rate_limit_on_version_is_error_but_additive(self):
        """Version lookup rate-limited -> overall error, but package preserved
        (no raise)."""
        client = FakeTransport([
            (429, {}, b"{}"),
            (429, {}, b"{}"),
        ])
        ctx = build_package_context("PyYAML", "5.1", "pyPI", client=client)
        self.assertEqual(ctx["status"], "error")
        self.assertEqual(ctx["package"], "PyYAML")
        self.assertEqual(ctx["version"], "5.1")
        self.assertIn("rate limit", " ".join(ctx["errors"]).lower())
        self.assertTrue(ctx)

    def test_rate_limit_on_deps_is_partial_and_additive(self):
        """Version succeeds but deps lookup rate-limits -> *partial*: version
        metadata is preserved, deps recorded as an error, package intact."""
        client = FakeTransport([
            (200, _ver_json(advisory_ids=["GHSA-x"]), b"{}"),
            (429, {}, b"{}"),
        ])
        ctx = build_package_context("PyYAML", "5.1", "pyPI", client=client)
        self.assertEqual(ctx["status"], "partial")
        # Version metadata survived the deps failure.
        self.assertEqual(ctx["version_meta"]["package"], "PyYAML")
        self.assertEqual(ctx["dependencies_status"], "error")
        self.assertTrue(any("rate limit" in e for e in ctx["errors"]))
        # Enrichment failure must never erase the scanner's package context.
        self.assertEqual(ctx["package"], "PyYAML")
        self.assertEqual(ctx["version"], "5.1")

    def test_network_fault_is_additive(self):
        class NetBoom(DepsDevClient):
            def _fetch(self, url):
                raise DepsDevNetworkError("conn refused")
        ctx = build_package_context("PyYAML", "5.1", "pyPI", client=NetBoom())
        # No raise; failure recorded; package preserved.
        self.assertEqual(ctx["status"], "error")
        self.assertEqual(ctx["package"], "PyYAML")
        self.assertTrue(any("conn refused" in e for e in ctx["errors"]))
        self.assertEqual(ctx["provenance"], "generic_published")

    def test_explicit_advisory_lookups_are_optional_and_bounded(self):
        client = FakeTransport([
            (200, _ver_json(advisory_ids=[]), b"{}"),
            (404, {}, b"{}"),   # deps 404 -> empty
            (200, {"advisoryKey": {"id": "GHSA-a"},
                   "aliases": ["CVE-2021-1"],
                   "cvss3Score": 8.0}, b"{}"),
        ])
        ctx = build_package_context(
            "PyYAML", "5.1", "pyPI", client=client, advisory_ids=["GHSA-a"]
        )
        self.assertIn("GHSA-a", ctx["advisory_details"])
        self.assertEqual(ctx["advisory_details"]["GHSA-a"]["cvss3Score"], 8.0)
        self.assertEqual(ctx["advisory_details"]["GHSA-a"]["aliases"], ["CVE-2021-1"])

    def test_unknown_package_and_version_preserved(self):
        client = FakeTransport([(404, {}, b"{}")])
        ctx = build_package_context("", "5.1", "pyPI", client=client)
        self.assertEqual(ctx["status"], "error")
        self.assertEqual(ctx["package"], "")
        self.assertEqual(ctx["errors"], ["package and version are required"])

    def test_server_error_is_partial_when_version_ok(self):
        client = FakeTransport([
            (200, _ver_json(advisory_ids=["GHSA-x"]), b"{}"),
            (503, {}, b"{}"),
        ])
        ctx = build_package_context("requests", "2.28.0", "pyPI", client=client)
        self.assertEqual(ctx["status"], "partial")
        # Version metadata survived even though deps lookup failed.
        self.assertEqual(ctx["version_meta"]["package"], "requests")
        self.assertTrue(any("server error" in e for e in ctx["errors"]))
        self.assertEqual(ctx["dependencies_status"], "error")

    def test_provenance_never_mislabels(self):
        """Every enrichment object must be labelled generic_published, never as
        the scanned project's resolved graph."""
        client = FakeTransport([
            (200, _ver_json(advisory_ids=[]), b"{}"),
            (200, {"dependencies": [{"package": "six", "version": "1.15",
                                    "type": "normal"}]}, b"{}"),
        ])
        ctx = build_package_context("PyYAML", "5.1", "pyPI", client=client)
        self.assertEqual(ctx["provenance"], "generic_published")
        self.assertEqual(ctx["resolved_deps"]["provenance"], "generic_published")


class TestAPIConstants(unittest.TestCase):
    def test_default_base_is_documented_v3(self):
        self.assertTrue(API_BASE.startswith("https://api.deps.dev/v3"))

    def test_system_mapping(self):
        self.assertEqual(_system_for("PyPI"), "pyPI")
        self.assertEqual(_system_for("npm"), "npm")


if __name__ == "__main__":
    unittest.main()
