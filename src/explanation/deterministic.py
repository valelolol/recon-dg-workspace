"""Deterministic (grounded) explanation backend.

This is the *default* explanation backend for RECON-DG's explanation layer.
It produces a plain-language, one-or-two-sentence explanation for *each finding*
using **only** fields that are already present on the finding (and, where
present, the scanner-provided remediation plan).  It:

* never computes, infers, or implies a numeric CVSS score;
* never classifies a finding as high/low when the scanner gave no numeric
  severity (the real OSV-Scanner 2.6.0 "severity: null" / vector-only shape,
  where no numeric score exists);
* never edits any existing finding field, the remediation block, the
  after-scan verification block, or the PHEI risk — it is strictly *additive*;
* therefore always yields grounded, reviewable text even when a model backend
  is unavailable.

The text is composed from the same grounded facts the agent's own plain-language
explanations use (package, version, advisory id, CVE aliases, vulnerable range,
severity status, scanner-provided fixed versions) so the deterministic fallback
stays consistent with the rest of the pipeline.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional


def severity_status(f: Dict[str, Any]) -> str:
    """Grounded severity statement.

    Returns a human string that **never** fabricates a numeric score: when the
    scanner supplied a numeric ``severity_score`` it is shown exactly; otherwise
    (``None`` — the real OSV-Scanner "severity: null" shape) it says the
    severity is unspecified.  A vector string, if present, is mentioned as
    evidence (the CVSS vector is *not* a numeric score).
    """
    score = f.get("severity_score")
    if score is not None:
        s = f"CVSS {float(score):.1f} is reported"
    else:
        s = "no numeric CVSS score was reported (severity unspecified)"
    vec = f.get("severity_vector")
    if isinstance(vec, str) and vec:
        s += f"; the scanner recorded the severity vector `{vec}`"
    return s


def fixed_version_text(f: Dict[str, Any]) -> str:
    """Grounded remediation text from scanner-provided fixed versions only.

    When the scanner supplied one or more ``fixed_versions`` it names them;
    otherwise it says a specific target cannot be asserted.  Never "latest",
    never "best".
    """
    fixed = f.get("fixed_versions") or []
    fixed = [str(v) for v in fixed if str(v)]
    if fixed:
        return f"The OSV-Scanner marks {', '.join(fixed)} as fixed for this advisory; " \
               f"upgrade to one of those versions to remediate."
    return "The OSV-Scanner reported no fixed version for this advisory, so a " \
           "specific target version cannot be asserted here."


def explain_finding(
    f: Dict[str, Any],
    remediation_item: Optional[Dict[str, Any]] = None,
) -> str:
    """One grounded, plain-language explanation for a single finding.

    Args:
        f: A finding dict (as in ``report['findings']``) — only the keys that
            exist on the normalizer's ``Finding.to_dict`` output are referenced.
        remediation_item: The matching ``report['remediation']['plan']['items']``
            entry (matched by ``vulnerability_id``), if any.  Used *only* to
            surface the scanner-grounded recommended action; it is never allowed
            to override the finding's own facts.
    """
    pkg = f.get("package_name", "unknown")
    ver = f.get("version", "unknown")
    adv = f.get("vulnerability_id", "unknown")
    eco = f.get("ecosystem", "unknown")
    eco_str = f" [{eco}]" if isinstance(eco, str) and eco.strip() else ""
    aliases = f.get("aliases") or []
    aliases_str = f" ({', '.join(aliases)})" if aliases else f" ({adv})"
    spec = f.get("vulnerability_spec")
    spec_str = f" The affected range is `{spec}`." if spec else ""
    pub = f.get("published")
    pub_str = f" Published {pub}." if pub else ""

    action = ""
    if isinstance(remediation_item, dict):
        ra = remediation_item.get("recommended_action")
        if isinstance(ra, str) and ra.strip():
            action = f" Recommended action: {ra.strip()}"

    return (
        f"{pkg}@{ver}{eco_str} is vulnerable via advisory {adv}{aliases_str}; "
        f"{severity_status(f)}{spec_str}{pub_str}{action}"
    )


def explain_findings(
    findings: List[Dict[str, Any]],
    remediation_plan: Optional[Dict[str, Any]] = None,
) -> List[str]:
    """Grounded explanation per finding, matched against the remediation plan.

    ``remediation_plan`` is ``report['remediation']['plan']`` (a dict with an
    ``items`` list).  Each item is matched to a finding on ``vulnerability_id``.
    A missing / malformed plan is simply ignored — the finding is still
    explained from its own fields.  Returns a list aligned one-to-one with
    ``findings``.
    """
    by_id: Dict[str, Dict[str, Any]] = {}
    if isinstance(remediation_plan, dict):
        for item in remediation_plan.get("items") or []:
            if isinstance(item, dict) and item.get("vulnerability_id"):
                by_id[item["vulnerability_id"]] = item
    out: List[str] = []
    for f in findings:
        adv = f.get("vulnerability_id")
        item = by_id.get(adv) if isinstance(adv, str) else None
        out.append(explain_finding(f, item))
    return out
