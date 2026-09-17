# Scan Result Contract v0.1

## Overview

This document defines the canonical JSON schema for scan results produced by
the recon-dg dependency risk analysis engine. It covers inventory scans
(package discovery) and full dependency graph scans that include advisory
lookups and risk scoring.

The inventory serializer (`src.reporter.inventory.serialize_inventory`) is
implemented. The full dependency-graph serializer remains unimplemented.

## Schema

| Field               | Type    | Required | Notes                              |
|---------------------|---------|----------|------------------------------------|
| schema_version      | string  | yes      | Must be `"0.1"`                    |
| scan_id             | string  | yes      | UUID v4                            |
| created_at          | string  | yes      | ISO-8601 UTC timestamp             |
| status              | enum    | yes      | `complete`, `partial`, `failed`   |
| input               | object  | yes      | Scan input configuration           |
| analysis_mode       | enum    | yes      | `inventory`, `dependency_graph`    |
| topology_status     | enum    | yes      | `known`, `unavailable`             |
| packages            | array   | yes      | See [Packages](#packages)          |
| edges               | array   | yes      | See [Edges](#edges)                |
| vulnerability_lookup| object  | yes      | See [Vulnerability Lookup](#vulnerability-lookup) |
| findings            | array   | yes      | See [Findings](#findings)          |
| risk                | object  | yes      | See [Risk](#risk) — always present |
| warnings            | array   | yes      | Strings describing degraded signals (always present, may be empty) |

### Input

| Field               | Type    | Notes                               |
|---------------------|---------|--------------------------------------|
| type                | string  | `"directory"`, `"lockfile"`, `"manual"`, `"file"` |
| filename            | string  | The scanned file or entry name       |
| format              | string  | Input format (e.g. `"requirements.txt"`, `"synthetic-graph"`) |
| environment         | object? | Optional metadata about the scanned environment |

Inventory serialization uses `input.type: "file"` for requirements.txt.
This corrects the original omission of `"file"` from the allowed types.

### Packages

Each package object must include:

- `id` (string): Unique instance identifier. Unique **within a scan**.
  IDs are not guaranteed stable across scans. The `id` is the **only** unique key;
  `name` plus `version` are NOT unique across installations (multiple
  installations of the same package name and version may coexist).
- `name` (string): Package name.
- `version` (string): Version string or `"unknown"`.
- `hash` (string|null): Deterministic hash of installed content, when
  available. `null` when not measured.

### Edges

Each edge object must include:

- `id` (string): Unique edge identifier.
- `source_id` (string): Must reference a valid package `id`.
- `target_id` (string): Must reference a valid package `id`.
- `type` (string): Dependency type (e.g. `"runtime"`, `"dev"`, `"test"`).

Semantics: **source depends on target** (source → target).

### Vulnerability Lookup

| Field               | Type         | Notes                               |
|---------------------|--------------|--------------------------------------|
| status              | enum         | `not_run`, `complete`, `partial`, `failed` |
| total_packages      | integer      | Number of package instances in `packages` |
| checked_package_ids | array of string | Unique valid package IDs that were successfully checked |
| matched             | integer      | Distinct package IDs with at least one finding |

Coverage is computed by consumers as `len(checked_package_ids) / total_packages`.
The `checked_package_ids` list is the auditable source of truth for which
packages were successfully checked. When `total_packages` is zero, coverage
is N/A (division by zero is undefined).

- `not_run`: no packages were checked; `checked_package_ids` is empty;
  no findings are expected.
- `complete`: every package instance was successfully checked;
  `checked_package_ids` contains all package IDs.
- `partial`: some packages were checked but not all (e.g. lookup service
  degraded). `checked_package_ids` lists only the successfully checked ones.
- `failed`: no packages were checked due to a lookup failure.

### Findings

Each finding object must include:

- `id` (string): Unique finding identifier.
- `package_id` (string): Must reference a package `id` that appears in
  `checked_package_ids`.
- `advisory_source` (string): Source name (e.g. `"npm-advisory"`, `"osv"`).
- `advisory_id` (string): Advisory identifier from the source.
- `severity` (null): Severity is not yet defined for this prototype contract.
  Until a named severity standard and its metadata are agreed upon, severity
  must be `null`. Do not introduce numeric scoring in this version.
- `title` (string): Brief description.
- `description` (string): Full advisory description.

### Risk

| Field               | Type     | Notes                              |
|---------------------|----------|------------------------------------|
| status              | enum     | `available`, `unavailable`         |
| score               | number?  | JSON `null` when unavailable; a numeric value when available |
| method              | string?  | Scoring method name; `null` when unavailable |
| reason              | string   | Nonempty explanation when `status` is `unavailable` |

`risk` is always an object (never omitted). When unavailable, `score` is
JSON `null` and `reason` is a nonempty string.

### Status Semantics

- **Scan status** (`status`) describes the overall outcome of the scan
  pipeline:
  - `complete`: all intended work finished successfully. An inventory scan
    can be `complete` even with `topology_status: "unavailable"` and
    `risk.status: "unavailable"` — unavailable optional scoring does not
    demote a scan to partial.
  - `partial`: some work finished but advisory lookup (when performed) was
    incomplete or degraded. A partial or failed advisory lookup after
    package discovery makes the scan partial.
  - `failed`: the scan pipeline encountered a fatal error.
  - Advisory lookup `not_run` does **not** automatically make an inventory
    scan partial.

- **Analysis availability** (`risk.status`) describes whether risk scoring
  was possible. This is independent of scan status.

- **Unavailable topology constraints** (`topology_status: "unavailable"`):
  the `edges` array MUST be empty and `risk.status` MUST be `unavailable`.

- **Inventory mode constraints** (v0.1): `analysis_mode` of `inventory`
  requires `topology_status` of `unavailable`. Inventory mode may support
  advisory lookup independently; the absence of topology does not prevent
  package-level advisory checks.

### Findings Semantics

- A lookup with `status: "complete"` and `findings: []` means no matching
  advisories were found within the lookup's coverage scope. This is **not**
  proof of safety; it only means the advisory database returned no matches
  for the queried packages within its known coverage.

### Demonstration Marker

Both example files use the `_demo_fixture` field (replacing the previous
`_note`) to identify themselves as demonstration fixtures. When present,
it is a string value indicating the fixture's purpose and clarifying that
the data is synthetic and not a production output.

### Timestamps

All timestamps MUST use UTC (`Z` suffix) and ISO-8601 format.
The serializer accepts YYYY-MM-DDTHH:MM:SS with optional fractional
seconds and exactly one trailing Z. Invalid calendar/time values,
date-only strings, repeated Z, and additional timezone offsets are rejected.

### Paths

All path fields MUST be relative. Absolute host paths are prohibited.

### Error Handling

Missing input files raise `FileNotFoundError`. Other read or I/O failures
may raise `OSError` (also available under the alias `IOError`).
