"""Tests for the inventory-result serializer.

Covers:
- A real fixture flowing through parsing + serialization
- Exact package identities, unique IDs, counts, statuses
- JSON round-trip (serializes → json.loads → asserts)
- Absence of absolute input paths
- Missing input file handling
- Valid empty file → zero-package inventory with unavailable risk
- Input graph data not mutated; known-topology rejection
"""

import json
import os

import pytest
import unittest

from src.models.dependency_graph import DependencyGraph, DependencyNode
from src.parser.parser import parse_requirements
from src.reporter.inventory import (
    requirements_to_json,
    serialize_inventory,
    to_json_file,
)

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def _fixture_path(name: str) -> str:
    return os.path.join(FIXTURES, name)


class TestSerializeInventory(unittest.TestCase):
    """End-to-end: parse → serialize → assert contract fields."""

    def _load_fixture(self) -> tuple:
        """Parse the simple requirements fixture and return (graph, path)."""
        path = _fixture_path("requirements_simple.txt")
        graph = parse_requirements(path)
        return graph, path

    def test_exact_package_identities(self):
        graph, path = self._load_fixture()
        result = serialize_inventory(graph, path)

        names = {p["name"] for p in result["packages"]}
        self.assertEqual(names, {"requests", "urllib3", "certifi"})

    def test_package_versions_preserved(self):
        graph, path = self._load_fixture()
        result = serialize_inventory(graph, path)

        by_name = {p["name"]: p for p in result["packages"]}
        self.assertEqual(by_name["requests"]["version"], "2.31.0")
        self.assertEqual(by_name["urllib3"]["version"], "2.0.4")
        self.assertEqual(by_name["certifi"]["version"], "2023.7.22")

    def test_unique_deterministic_ids(self):
        graph, path = self._load_fixture()
        result1 = serialize_inventory(graph, path)
        result2 = serialize_inventory(graph, path)

        ids1 = [p["id"] for p in result1["packages"]]
        ids2 = [p["id"] for p in result2["packages"]]
        self.assertEqual(ids1, ids2)

        # IDs must be unique within the scan
        self.assertEqual(len(ids1), len(set(ids1)))

    def test_ids_are_stable_ordering(self):
        """Package IDs must reflect a stable ordering (pkg-001, pkg-002, …)."""
        graph, path = self._load_fixture()
        result = serialize_inventory(graph, path)

        by_id = {p["id"]: p["name"] for p in result["packages"]}
        self.assertEqual(by_id.get("pkg-001"), "certifi")
        self.assertEqual(by_id.get("pkg-002"), "requests")
        self.assertEqual(by_id.get("pkg-003"), "urllib3")

    def test_scan_id_and_timestamp_present(self):
        graph, path = self._load_fixture()
        result = serialize_inventory(graph, path)

        self.assertIn("scan_id", result)
        self.assertIn("created_at", result)
        self.assertTrue(result["created_at"].endswith("Z"))

    def test_scan_id_can_be_supplied(self):
        graph, path = self._load_fixture()
        result = serialize_inventory(
            graph, path, scan_id="00000000-0000-4000-8000-000000000001"
        )
        self.assertEqual(result["scan_id"], "00000000-0000-4000-8000-000000000001")

    def test_created_at_can_be_supplied(self):
        graph, path = self._load_fixture()
        result = serialize_inventory(
            graph, path, created_at="2026-09-16T12:00:00.000Z"
        )
        self.assertEqual(result["created_at"], "2026-09-16T12:00:00.000Z")

    def test_status_fields(self):
        graph, path = self._load_fixture()
        result = serialize_inventory(graph, path)

        self.assertEqual(result["status"], "complete")
        self.assertEqual(result["analysis_mode"], "inventory")
        self.assertEqual(result["topology_status"], "unavailable")
        self.assertEqual(result["vulnerability_lookup"]["status"], "not_run")
        self.assertEqual(result["risk"]["status"], "unavailable")

    def test_total_packages_count(self):
        graph, path = self._load_fixture()
        result = serialize_inventory(graph, path)

        self.assertEqual(result["vulnerability_lookup"]["total_packages"], 3)
        self.assertEqual(len(result["packages"]), 3)

    def test_vulnerability_lookup_fields(self):
        graph, path = self._load_fixture()
        result = serialize_inventory(graph, path)

        vl = result["vulnerability_lookup"]
        self.assertEqual(vl["checked_package_ids"], [])
        self.assertEqual(vl["matched"], 0)

    def test_findings_empty(self):
        graph, path = self._load_fixture()
        result = serialize_inventory(graph, path)
        self.assertEqual(result["findings"], [])

    def test_edges_empty(self):
        graph, path = self._load_fixture()
        result = serialize_inventory(graph, path)
        self.assertEqual(result["edges"], [])

    def test_risk_unavailable(self):
        graph, path = self._load_fixture()
        result = serialize_inventory(graph, path)

        risk = result["risk"]
        self.assertIsNone(risk["score"])
        self.assertIsNone(risk["method"])
        self.assertIn("unavailable", risk["reason"].lower())

    def test_package_hashes_null(self):
        graph, path = self._load_fixture()
        result = serialize_inventory(graph, path)

        for pkg in result["packages"]:
            self.assertIsNone(pkg["hash"])

    def test_input_type_is_file(self):
        graph, path = self._load_fixture()
        result = serialize_inventory(graph, path)

        self.assertEqual(result["input"]["type"], "file")
        self.assertEqual(result["input"]["format"], "requirements.txt")

    def test_input_uses_basename_not_absolute_path(self):
        graph, path = self._load_fixture()
        result = serialize_inventory(graph, path)

        # Should be the filename, not the full absolute path
        self.assertEqual(result["input"]["filename"], "requirements_simple.txt")
        self.assertNotIn("/", result["input"]["filename"])
        self.assertNotIn("\\", result["input"]["filename"])

    def test_no_absolute_paths_anywhere(self):
        graph, path = self._load_fixture()
        result = serialize_inventory(graph, path)
        json_str = json.dumps(result)
        # The absolute path of the fixture should not appear anywhere
        abs_path = os.path.abspath(path)
        self.assertNotIn(abs_path, json_str)

    def test_json_round_trip(self):
        graph, path = self._load_fixture()
        result = serialize_inventory(graph, path)
        json_str = json.dumps(result)
        loaded = json.loads(json_str)
        self.assertEqual(loaded["schema_version"], "0.1")
        self.assertEqual(loaded["status"], "complete")
        self.assertEqual(len(loaded["packages"]), 3)

    def test_warnings_present(self):
        graph, path = self._load_fixture()
        result = serialize_inventory(graph, path)

        self.assertIsInstance(result["warnings"], list)
        self.assertGreater(len(result["warnings"]), 0)
        # Should mention advisory lookup not performed
        warning_text = " ".join(result["warnings"]).lower()
        self.assertIn("advisory", warning_text)

    def test_no_demo_marker(self):
        graph, path = self._load_fixture()
        result = serialize_inventory(graph, path)

        # Real output must not contain the _demo_fixture marker
        self.assertNotIn("_demo_fixture", json.dumps(result))

    def test_warnings_explain_advisory_not_run(self):
        graph, path = self._load_fixture()
        result = serialize_inventory(graph, path)

        warning_text = " ".join(result["warnings"]).lower()
        self.assertIn("advisory", warning_text)
        self.assertIn("not performed", warning_text)

    def test_dependencies_not_mutated(self):
        """Graph data after serialization should remain unchanged."""
        graph, path = self._load_fixture()
        original_nodes = set(graph.get_nodes_list())
        original_edges = set(graph.get_edges_list())

        serialize_inventory(graph, path)

        self.assertEqual(set(graph.get_nodes_list()), original_nodes)
        self.assertEqual(set(graph.get_edges_list()), original_edges)

    def test_known_topology_rejected(self):
        """Graphs with edge_availability='known' must be rejected, not silently
        serialized with edges discarded."""
        graph = DependencyGraph()
        graph.edge_availability = "known"
        graph.add_node(DependencyNode("requests", "2.31.0"))

        with self.assertRaises(ValueError):
            serialize_inventory(graph, "test.txt")

    def test_empty_input_produces_zero_package_inventory(self):
        """A valid empty file must produce a zero-package inventory."""
        path = _fixture_path("requirements_empty.txt")
        graph = parse_requirements(path)
        result = serialize_inventory(graph, path)

        self.assertEqual(result["status"], "complete")
        self.assertEqual(len(result["packages"]), 0)
        self.assertEqual(result["vulnerability_lookup"]["total_packages"], 0)
        self.assertEqual(result["vulnerability_lookup"]["matched"], 0)
        self.assertEqual(result["risk"]["status"], "unavailable")
        self.assertIn("no parseable packages", " ".join(result["warnings"]).lower())

    def test_missing_file_raises_file_not_found(self):
        """A missing requirements file must propagate FileNotFoundError."""
        path = os.path.join(FIXTURES, "nonexistent.txt")
        with self.assertRaises(FileNotFoundError):
            requirements_to_json(path)

    def test_requirements_to_json_returns_string(self):
        """Full callable: file → JSON string."""
        path = _fixture_path("requirements_simple.txt")
        json_str = requirements_to_json(path)

        self.assertIsInstance(json_str, str)
        loaded = json.loads(json_str)
        self.assertEqual(loaded["schema_version"], "0.1")
        self.assertEqual(loaded["analysis_mode"], "inventory")
        self.assertEqual(len(loaded["packages"]), 3)

    def test_requirements_to_json_with_deterministic_ids(self):
        path = _fixture_path("requirements_simple.txt")
        json_str = requirements_to_json(
            path,
            scan_id="aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa",
            created_at="2026-01-01T00:00:00.000Z",
        )
        loaded = json.loads(json_str)
        self.assertEqual(loaded["scan_id"], "aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa")
        self.assertEqual(loaded["created_at"], "2026-01-01T00:00:00.000Z")

    def test_schema_version(self):
        graph, path = self._load_fixture()
        result = serialize_inventory(graph, path)
        self.assertEqual(result["schema_version"], "0.1")


class TestToJsonFile(unittest.TestCase):
    def test_to_json_file_rejects_hardlink_alias(self):
        """to_json_file must reject hard-link aliases via os.path.samefile()."""
        import tempfile

        path = _fixture_path("requirements_simple.txt")
        with tempfile.TemporaryDirectory() as tmpdir:
            src = os.path.join(tmpdir, "input.txt")
            dst = os.path.join(tmpdir, "output.txt")
            # Create a hard link from dst -> src (copy via link, not shutil.copy)
            import shutil
            shutil.copy2(path, src)
            os.link(src, dst)
            # src and dst are hard-link aliases (same inode)
            self.assertTrue(os.path.samefile(src, dst))
            with self.assertRaises(ValueError) as ctx:
                to_json_file(src, dst)
            self.assertIn("same file", str(ctx.exception).lower())
            # Original input bytes must be unchanged
            with open(src, "rb") as f:
                original_bytes = f.read()
            self.assertIn(b"requests", original_bytes)

    def test_writes_json_file(self):
        path = _fixture_path("requirements_simple.txt")
        output = os.path.join(FIXTURES, "_output_test.json")
        try:
            result_path = to_json_file(
                path,
                output,
                scan_id="bbbbbbbb-bbbb-4bbb-bbbb-bbbbbbbbbbbb",
                created_at="2026-02-01T00:00:00.000Z",
            )
            self.assertTrue(os.path.exists(result_path))
            with open(result_path) as f:
                loaded = json.loads(f.read())
            self.assertEqual(loaded["scan_id"], "bbbbbbbb-bbbb-4bbb-bbbb-bbbbbbbbbbbb")
        finally:
            if os.path.exists(output):
                os.remove(output)


    def test_to_json_file_rejects_same_file_as_input(self):
        """to_json_file must refuse to overwrite the input file."""
        import tempfile

        path = _fixture_path("requirements_simple.txt")
        with tempfile.TemporaryDirectory() as tmpdir:
            same_file = os.path.join(tmpdir, "same.txt")
            # Copy fixture to tmpdir
            import shutil
            shutil.copy2(path, same_file)
            with self.assertRaises(ValueError) as ctx:
                to_json_file(same_file, same_file)
            self.assertIn("same file", str(ctx.exception).lower())

    def test_to_json_file_rejects_resolved_same_file_via_symlink(self):
        """to_json_file must resolve symlinks and reject even when paths differ."""
        import tempfile
        import shutil

        path = _fixture_path("requirements_simple.txt")
        with tempfile.TemporaryDirectory() as tmpdir:
            src = os.path.join(tmpdir, "input.txt")
            dst = os.path.join(tmpdir, "output.txt")
            shutil.copy2(path, src)
            os.symlink(src, dst)
            # src and dst resolve to the same file
            with self.assertRaises(ValueError) as ctx:
                to_json_file(src, dst)
            self.assertIn("same file", str(ctx.exception).lower())


class TestEdgeAvailabilityValidation(unittest.TestCase):
    """Regression: edge_availability must strictly require 'unavailable'."""

    def test_known_rejected(self):
        graph = DependencyGraph()
        graph.edge_availability = "known"
        graph.add_node(DependencyNode("foo", "1.0"))
        with self.assertRaises(ValueError) as ctx:
            serialize_inventory(graph, "t.txt")
        self.assertIn("unavailable", str(ctx.exception))

    def test_none_rejected(self):
        graph = DependencyGraph()
        graph.edge_availability = "none"
        graph.add_node(DependencyNode("foo", "1.0"))
        with self.assertRaises(ValueError):
            serialize_inventory(graph, "t.txt")

    def test_empty_graph_with_known_rejected(self):
        """Even empty graphs with known topology are rejected."""
        graph = DependencyGraph()
        graph.edge_availability = "known"
        with self.assertRaises(ValueError):
            serialize_inventory(graph, "t.txt")


class TestEdgeRejection(unittest.TestCase):
    """Regression: graphs with edges in either representation are rejected."""

    def test_edges_in_edge_weights_rejected(self):
        graph = DependencyGraph()
        graph.edge_availability = "unavailable"
        graph.add_node(DependencyNode("a", "1.0"))
        graph.add_node(DependencyNode("b", "2.0"))
        graph.add_edge(("a", "1.0"), ("b", "2.0"), weight=1.0)
        # edge_weights has an edge but graph.graph also has one
        with self.assertRaises(ValueError):
            serialize_inventory(graph, "t.txt")

    def test_edges_in_nx_graph_rejected(self):
        """Even if edge_availability='unavailable', edges in the nx DiGraph are rejected."""
        graph = DependencyGraph()
        graph.edge_availability = "unavailable"
        # Add a node
        graph.add_node(DependencyNode("a", "1.0"))
        # Directly manipulate the nx graph to have an edge without edge_weights
        # (simulating a graph where edges exist only in graph.graph)
        graph.graph.add_edge(("a", "1.0"), ("b", "2.0"), weight=1.0)
        with self.assertRaises(ValueError):
            serialize_inventory(graph, "t.txt")


class TestUUIDValidation(unittest.TestCase):
    """Regression: scan_id must be a valid RFC 4122 UUID v4."""

    def test_invalid_scan_id_raises(self):
        graph, _ = self._fixture()
        with self.assertRaises(ValueError) as ctx:
            serialize_inventory(graph, "t.txt", scan_id="not-a-uuid")
        self.assertIn("scan_id", str(ctx.exception).lower())

    def test_uuid_v1_rejected(self):
        """UUIDs with version bit != 4 are rejected."""
        graph, _ = self._fixture()
        with self.assertRaises(ValueError):
            serialize_inventory(graph, "t.txt", scan_id="00000000-0000-1000-0000-000000000001")

    def test_uuid_v7_rejected(self):
        graph, _ = self._fixture()
        with self.assertRaises(ValueError):
            serialize_inventory(graph, "t.txt", scan_id="00000000-0000-7000-0000-000000000001")

    def test_empty_string_rejected(self):
        graph, _ = self._fixture()
        with self.assertRaises(ValueError):
            serialize_inventory(graph, "t.txt", scan_id="")

    def _fixture(self):
        path = _fixture_path("requirements_simple.txt")
        graph = parse_requirements(path)
        return graph, path


class TestCreatedAtValidation(unittest.TestCase):
    """Regression: created_at must be ISO-8601 UTC ending in Z."""

    def test_missing_trailing_z_rejected(self):
        graph, _ = self._fixture()
        with self.assertRaises(ValueError) as ctx:
            serialize_inventory(graph, "t.txt", created_at="2026-09-16T12:00:00.000")
        self.assertIn("created_at", str(ctx.exception).lower())

    def test_invalid_timestamp_rejected(self):
        graph, _ = self._fixture()
        with self.assertRaises(ValueError):
            serialize_inventory(graph, "t.txt", created_at="not-a-dateZ")

    def test_valid_timestamp_accepted(self):
        graph, _ = self._fixture()
        result = serialize_inventory(
            graph, "t.txt", created_at="2026-01-01T00:00:00.000Z"
        )
        self.assertEqual(result["created_at"], "2026-01-01T00:00:00.000Z")

    def test_valid_timestamp_without_fractional_accepted(self):
        """Timestamps without fractional seconds must still work."""
        graph, _ = self._fixture()
        result = serialize_inventory(
            graph, "t.txt", created_at="2026-01-01T00:00:00Z"
        )
        self.assertEqual(result["created_at"], "2026-01-01T00:00:00Z")

    def test_date_only_rejected(self):
        """Date-only values (no time component) must be rejected."""
        graph, _ = self._fixture()
        with self.assertRaises(ValueError):
            serialize_inventory(graph, "t.txt", created_at="2026-01-01Z")

    def test_repeated_z_rejected(self):
        """Repeated Z suffix must be rejected."""
        graph, _ = self._fixture()
        with self.assertRaises(ValueError):
            serialize_inventory(graph, "t.txt", created_at="2026-01-01T12:00:00ZZ")

    def test_additional_tz_offset_rejected(self):
        """An additional timezone offset (e.g. +05:00) before Z must be rejected."""
        graph, _ = self._fixture()
        with self.assertRaises(ValueError):
            serialize_inventory(graph, "t.txt", created_at="2026-01-01T12:00:00+05:00Z")

    def _fixture(self):
        path = _fixture_path("requirements_simple.txt")
        graph = parse_requirements(path)
        return graph, path


class TestBasenameWindowsPaths(unittest.TestCase):
    """Regression: Windows-style paths on Linux must yield basename."""

    def test_windows_path_yields_basename(self):
        graph, _ = self._fixture()
        result = serialize_inventory(
            graph, "C:\\Users\\foo\\requirements.txt"
        )
        self.assertEqual(result["input"]["filename"], "requirements.txt")

    def test_mixed_path_yields_basename(self):
        graph, _ = self._fixture()
        result = serialize_inventory(
            graph, "C:/Users/foo/requirements.txt"
        )
        self.assertEqual(result["input"]["filename"], "requirements.txt")

    def test_posix_path_unchanged(self):
        graph, _ = self._fixture()
        result = serialize_inventory(graph, "/home/foo/requirements.txt")
        self.assertEqual(result["input"]["filename"], "requirements.txt")

    def _fixture(self):
        path = _fixture_path("requirements_simple.txt")
        graph = parse_requirements(path)
        return graph, path


class TestAdvisoryWarning(unittest.TestCase):
    """Regression: advisory warning must be present for both empty and nonempty inventories."""

    def test_nonempty_has_advisory_warning(self):
        graph, _ = self._fixture()
        result = serialize_inventory(graph, "t.txt")
        warning_text = " ".join(result["warnings"]).lower()
        self.assertIn("advisory lookup was not performed for this scan", warning_text)

    def test_empty_has_advisory_warning(self):
        path = _fixture_path("requirements_empty.txt")
        graph = parse_requirements(path)
        result = serialize_inventory(graph, path)
        warning_text = " ".join(result["warnings"]).lower()
        self.assertIn("no parseable packages", warning_text)
        self.assertIn("advisory lookup was not performed for this scan", warning_text)

    def _fixture(self):
        path = _fixture_path("requirements_simple.txt")
        graph = parse_requirements(path)
        return graph, path


if __name__ == "__main__":
    unittest.main()
