"""Inventory-result serializer: requirements.txt → scan-result v0.1 JSON."""

from __future__ import annotations

import json
import os
import uuid
from datetime import datetime, timezone

from src.models.dependency_graph import DependencyGraph
from src.parser.parser import parse_requirements


def _basename(path: str) -> str:
    """Return the basename of *path*, handling both POSIX and Windows separators.

    On Linux, ``os.path.basename`` does not treat ``\\`` as a separator,
    so a Windows-style path like ``C:\\foo\\bar.txt`` would return the
    entire string.  We normalise both ``\\`` and ``/`` before extracting
    the final component.
    """
    normalised = path.replace("\\", "/")
    return os.path.basename(normalised)


def _validate_scan_id(scan_id: str) -> None:
    """Validate that *scan_id* is a strict RFC 4122 UUID v4 string."""
    try:
        uid = uuid.UUID(scan_id, version=4)
    except (ValueError, AttributeError):
        raise ValueError(
            f"Invalid scan_id: '{scan_id}'. Must be a RFC 4122 UUID v4 string."
        )
    if str(uid) != scan_id:
        raise ValueError(
            f"Invalid scan_id: '{scan_id}'. UUID normalization changed the value; "
            "check formatting."
        )


def _validate_created_at(timestamp: str) -> None:
    """Validate that *timestamp* is an ISO-8601 UTC timestamp ending in Z.

    Accepted format: YYYY-MM-DDTHH:MM:SS with optional fractional seconds,
    followed by exactly one ``Z`` suffix.  Examples:
    ``2026-01-01T12:00:00Z``, ``2026-01-01T12:00:00.000Z``.

    Rejects date-only strings, repeated ``Z``, and additional timezone offsets.
    """
    # Must end with exactly one Z
    if not timestamp.endswith("Z") or "ZZ" in timestamp:
        raise ValueError(
            f"Invalid created_at: '{timestamp}'. Must be an ISO-8601 UTC "
            "timestamp ending in 'Z'."
        )
    # Remove the trailing Z
    stripped = timestamp[:-1]
    # Must contain exactly one T separator (reject date-only and space-separated)
    if stripped.count("T") != 1:
        raise ValueError(
            f"Invalid created_at: '{timestamp}'. Must be an ISO-8601 UTC "
            "timestamp (e.g. '2026-09-16T12:00:00.000Z')."
        )
    # Reject additional timezone offset (e.e. +HH:MM before Z)
    # The part before Z should not contain '+' or a trailing colon after digits
    parts = stripped.split("T")
    date_part = parts[0]
    time_part = parts[1]
    # Basic format check: date must be YYYY-MM-DD
    if len(date_part) != 10 or date_part[4] != "-" or date_part[7] != "-":
        raise ValueError(
            f"Invalid created_at: '{timestamp}'. Must be an ISO-8601 UTC "
            "timestamp (e.g. '2026-09-16T12:00:00.000Z')."
        )
    # Time part: HH:MM:SS or HH:MM:SS.frac
    frac_idx = time_part.find(".")
    if frac_idx >= 0:
        time_core = time_part[:frac_idx]
        frac = time_part[frac_idx + 1:]
        if not frac.isdigit():
            raise ValueError(
                f"Invalid created_at: '{timestamp}'. Fractional seconds must be digits."
            )
    else:
        time_core = time_part
    if len(time_core) != 8 or time_core[2] != ":" or time_core[5] != ":":
        raise ValueError(
            f"Invalid created_at: '{timestamp}'. Must be an ISO-8601 UTC "
            "timestamp (e.g. '2026-09-16T12:00:00.000Z')."
        )
    # Validate calendar/time values via datetime parsing
    try:
        datetime.fromisoformat(stripped)
    except (ValueError, AttributeError):
        raise ValueError(
            f"Invalid created_at: '{timestamp}'. Must be a valid ISO-8601 "
            "timestamp (e.g. '2026-09-16T12:00:00.000Z')."
        )


def serialize_inventory(
    graph: DependencyGraph,
    input_filename: str,
    *,
    scan_id: str | None = None,
    created_at: str | None = None,
) -> dict:
    """Serialize a DependencyGraph (from parse_requirements) into a v0.1
    scan-result dictionary.

    Parameters
    ----------
    graph : DependencyGraph
        A graph produced by parse_requirements (edge_availability must be
        ``"unavailable"``; graphs with ``"known"``, ``"none"``, or any
        topology edges are rejected because inventory mode does not handle
        edges).
    input_filename : str
        The basename (relative path) of the requirements file.  Absolute
        host paths are never used in the output.
    scan_id : str, optional
        A deterministic UUID v4 string.  Omit or pass ``None`` for a
        freshly generated identifier.
    created_at : str, optional
        An ISO-8601 UTC timestamp ending in ``Z``.  Omit or pass ``None``
        for the current time.

    Returns
    -------
    dict
        A JSON-serializable dictionary matching the scan-result v0.1 contract.

    Raises
    ------
    ValueError
        If graph edge_availability is not ``"unavailable"``, if the graph
        contains edges, or if scan_id / created_at fail validation.
    """

    # --- Validate edge_availability: only "unavailable" is accepted ---
    if graph.edge_availability != "unavailable":
        raise ValueError(
            f"serialize_inventory requires edge_availability == 'unavailable', "
            f"got '{graph.edge_availability}'. Inventory mode does not "
            "support known, none, or any graphs with topology edges."
        )

    # --- Reject graphs that contain edges in either representation ---
    has_edges_in_weights = bool(graph.edge_weights)
    has_edges_in_nx = bool(graph.graph.number_of_edges())
    if has_edges_in_weights or has_edges_in_nx:
        raise ValueError(
            "serialize_inventory does not support graphs with edges. "
            "Inventory mode requires a purely edgeless node list."
        )

    # --- Package IDs: stable ordering by (name, version) for determinism ---
    node_keys = sorted(graph.get_nodes_list(), key=lambda k: (k[0].lower(), k[1].lower()))
    packages = []
    for idx, (pkg_name, pkg_version) in enumerate(node_keys):
        packages.append({
            "id": f"pkg-{idx + 1:03d}",
            "name": pkg_name,
            "version": pkg_version,
            "hash": None,
        })

    total_packages = len(packages)

    # --- Scan identifiers ---
    if scan_id is None:
        scan_id = str(uuid.uuid4())
    else:
        _validate_scan_id(scan_id)

    if created_at is None:
        created_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    else:
        _validate_created_at(created_at)

    # --- Input metadata (basename only, never absolute) ---
    safe_name = _basename(input_filename) if input_filename else "unknown"

    warnings: list[str] = []

    if total_packages == 0:
        warnings.append("Input file contained no parseable packages.")

    warnings.append("Advisory lookup was not performed for this scan.")

    result: dict = {
        "schema_version": "0.1",
        "scan_id": scan_id,
        "created_at": created_at,
        "status": "complete",
        "input": {
            "type": "file",
            "filename": safe_name,
            "format": "requirements.txt",
        },
        "analysis_mode": "inventory",
        "topology_status": "unavailable",
        "packages": packages,
        "edges": [],
        "vulnerability_lookup": {
            "status": "not_run",
            "total_packages": total_packages,
            "checked_package_ids": [],
            "matched": 0,
        },
        "findings": [],
        "risk": {
            "status": "unavailable",
            "score": None,
            "method": None,
            "reason": (
                "Dependency topology is unavailable; edges could not be resolved "
                "from inventory scan."
            ),
        },
        "warnings": warnings,
    }

    return result


def requirements_to_json(
    file_path: str,
    *,
    scan_id: str | None = None,
    created_at: str | None = None,
) -> str:
    """Parse a requirements.txt file and return its scan result as a JSON
    string matching the v0.1 contract.

    This is the primary callable entry point: one call goes from
    requirements.txt path → JSON string.

    Parameters
    ----------
    file_path : str
        Path to the requirements.txt file.
    scan_id : str, optional
        Deterministic UUID v4 for repeatable tests.
    created_at : str, optional
        Deterministic timestamp for repeatable tests.

    Returns
    -------
    str
        A JSON string of the scan result dictionary.

    Raises
    ------
    FileNotFoundError
        If the file does not exist or cannot be read.
    ValueError
        If *scan_id* or *created_at* fail validation.
    """
    graph = parse_requirements(file_path)
    result = serialize_inventory(graph, file_path, scan_id=scan_id, created_at=created_at)
    return json.dumps(result, indent=2)


def to_json_file(
    file_path: str,
    output_path: str,
    *,
    scan_id: str | None = None,
    created_at: str | None = None,
) -> str:
    """Write a scan-result JSON file and return its path.

    Parameters
    ----------
    file_path : str
        Path to the requirements.txt file.
    output_path : str
        Where to write the JSON output.
    scan_id, created_at : see requirements_to_json

    Returns
    -------
    str
        The absolute path of the written JSON file.

    Raises
    ------
    ValueError
        If *output_path* resolves to the same file as *file_path*.
    """
    # Protect against overwriting the input file.
    # Compare resolved absolute paths (handles symlinks) and hard-link aliases.
    try:
        input_resolved = os.path.realpath(file_path)
        output_resolved = os.path.realpath(output_path)
    except (OSError, ValueError):
        # Fall back to basename comparison if realpath fails
        input_resolved = os.path.abspath(file_path)
        output_resolved = os.path.abspath(output_path)

    if input_resolved == output_resolved:
        raise ValueError(
            f"output_path ({output_path}) resolves to the same file as "
            f"input file ({file_path}). Refusing to overwrite the input file."
        )

    # Also reject hard-link aliases: if both paths exist and point to the
    # same inode via os.path.samefile(), refuse to overwrite.
    if os.path.exists(output_path):
        try:
            if os.path.samefile(input_resolved, output_resolved):
                raise ValueError(
                    f"output_path ({output_path}) is a hard-link alias of "
                    f"the same file as input ({file_path}). Refusing to overwrite."
                )
        except OSError:
            # samefile may raise OSError on some systems; rely on resolved-path check
            pass

    json_str = requirements_to_json(file_path, scan_id=scan_id, created_at=created_at)
    with open(output_path, "w") as f:
        f.write(json_str)
    return os.path.abspath(output_path)
