"""Normalize OSV-Scanner JSON output into Recon-DG report schema.

Output format (compatible with src.web.server._prepare_report fallback
and dashboard.html findings schema):
    {
        "findings": [...],
        "findings_count": int,
        "high_severity_count": int,
        "scan_source": str,
        "scan_timestamp": str (ISO 8601),
        "total_packages_scanned": int,
        "total_unique_vulnerabilities": int,
        "summary": str,
        "ai_explanations": [],
        "risk": {"status": str, "score": float | None}
    }

Each finding:
    {
        "package_name": str,
        "version": str,
        "severity_score": float | None,
        "vulnerability_id": str,
        "aliases": [str],
        "ecosystem": str,
        "published": str | None,
        "vulnerability_spec": str | None,
        "fixed_versions": [str],
        "ai_explanations": []
    }

Usage:
    python -m src.web.osv_normalizer --input /path/to/osvscan.json --output report.json
    python -m src.web.osv_normalizer --input /tmp/recon-dg-osvscan-w9-v2.json
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


def severity_label(score: float) -> str:
    """Map CVSS-like score to Recon-DG risk level."""
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


def recommendation_for(package: str, version: str, advisory: str) -> str:
    """Generate a deterministic recommendation based on advisory type."""
    if advisory.startswith("PYSEC"):
        return f"Upgrade {package} to the latest patched version (advisory {advisory})."
    if advisory.startswith("GHSA"):
        return f"Upgrade {package} to the latest patched version (GHSA {advisory})."
    return f"Review and upgrade {package} (current {version}) against advisory {advisory}."


def normalize(osv_path: str) -> Dict[str, Any]:
    """Read OSV-Scanner JSON and return a normalized Recon-DG report."""
    with open(osv_path, "r", encoding="utf-8") as f:
        raw: Any = json.load(f)

    # Collect unique findings keyed by frozenset of all IDs in the group
    # (handles cross-group alias overlap). Do NOT create one finding per
    # alias ID — merge aliases within the same group; use the first ID as
    # the primary vulnerability_id.
    findings: Dict[tuple[frozenset[str], str, str], Dict[str, Any]] = {}
    packages_seen: set = set()
    scan_sources: set = set()

    for result in raw.get("results", []):
        source = result.get("source", {})
        scan_sources.add(source.get("path", "?"))
        for pkg_entry in result.get("packages", []):
            pkg = pkg_entry.get("package", {})
            pkg_name = pkg.get("name", "?")
            pkg_ver = pkg.get("version", "?")
            eco = pkg.get("ecosystem", "?")
            packages_seen.add((pkg_name, pkg_ver, eco))

            for group in pkg_entry.get("groups", []):
                ids = group.get("ids", [])
                if not ids:
                    continue
                vid = ids[0]  # primary vulnerability_id
                aliases = list(group.get("aliases", []))
                all_ids = frozenset(ids) | frozenset(aliases)
                max_sev = group.get("max_severity")
                severity_score: Optional[float] = float(max_sev) if max_sev is not None else None
                key = (all_ids, pkg_name, pkg_ver)

                if key not in findings:
                    findings[key] = {
                        "package_name": pkg_name,
                        "version": pkg_ver,
                        "severity_score": severity_score,
                        "vulnerability_id": vid,
                        "aliases": aliases,
                        "ecosystem": eco,
                        "published": group.get("published"),
                        "vulnerability_spec": group.get("vulnerability_spec"),
                        "fixed_versions": group.get("fixed_versions", []),
                        "ai_explanations": [],
                    }
                else:
                    # Merge aliases from additional groups
                    existing = findings[key]
                    for a in aliases:
                        if a not in existing["aliases"]:
                            existing["aliases"].append(a)
                    # Keep the highest severity score
                    if severity_score is not None:
                        if existing["severity_score"] is None or severity_score > existing["severity_score"]:
                            existing["severity_score"] = severity_score
                            existing["published"] = group.get("published")
                            existing["vulnerability_spec"] = group.get("vulnerability_spec")
                            existing["fixed_versions"] = group.get("fixed_versions", [])

    # Build the report
    finding_list = sorted(findings.values(), key=lambda f: (
        -float(f["severity_score"]) if f["severity_score"] is not None else 0.0
    ))
    high_count = sum(1 for f in finding_list if f["severity_score"] is not None and f["severity_score"] >= 7.0)

    report: Dict[str, Any] = {
        "findings": finding_list,
        "findings_count": len(finding_list),
        "high_severity_count": high_count,
        "scan_source": osv_path,
        "scan_timestamp": datetime.now(timezone.utc).isoformat(),
        "total_packages_scanned": len(packages_seen),
        "total_unique_vulnerabilities": len(finding_list),
        "summary": (
            f"OSV-Scanner scan of {len(scan_sources)} file(s) "
            f"found {len(finding_list)} unique vulnerabilities "
            f"across {len(packages_seen)} package(s); "
            f"{high_count} are high or critical severity."
        ),
        "ai_explanations": [],
        "risk": {
            "status": "unavailable",
            "score": None,
        },
    }
    return report


def main(argv: Optional[list] = None) -> int:
    ap = argparse.ArgumentParser(
        description="Normalize OSV-Scanner output into Recon-DG report schema.")
    ap.add_argument("--input", required=True, help="Path to OSV-Scanner JSON output")
    ap.add_argument("--output", default="report.json", help="Output report path")
    args = ap.parse_args(argv)

    report = normalize(args.input)

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    print(f"Wrote {report['findings_count']} findings to {args.output}")
    print(f"  High/critical: {report['high_severity_count']}")
    print(f"  Packages scanned: {report['total_packages_scanned']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
