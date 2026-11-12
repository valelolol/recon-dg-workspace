"""Offline, loopback-end-to-end tests for the RECON-DG dashboard (src/web).

The dashboard is a read-only, dependency-free web surface:

* ``python -m src.web`` (or :mod:`src.web.server` / the public ``src.web`` API)
  serves a self-contained ``src/web/dashboard.html`` at ``/`` and the structured
  report at ``/report.json``.
* It uses **only the standard library** (``http.server``): no third-party
  dependency (no Flask), no external network call, and it never re-runs scans,
  edits manifests, or implies a fix was verified.

These tests stand up a **real** ``ThreadingHTTPServer`` on 127.0.0.1 via the
public ``build_server`` helper, run its ``serve_forever()`` loop in a background
thread, and issue **real** ``urllib`` GET requests to ``/`` and ``/report.json``.
All traffic is local loopback; no external service, no scan, and no live model
is involved.

They verify item 3 of the task:
  * the dashboard can display an existing structured report;
  * it shows the report's limitations (``risk.status == "unavailable"`` ->
    "no score is fabricated"), the remediation plan, and the after-scan
    verification state **including ``not_run``** (no resolution claim);
  * the additive ``ai_explanations`` field (labelled ``source`` per finding)
    is present, and the ``explanation_source`` summary never echoes the
    API key or endpoint;
  * findings, severity, fixed versions, risk, and verification are **unchanged**
    by the explanation layer.
"""
from __future__ import annotations

import json
import os
import tempfile
import threading
import urllib.error
import urllib.request

from src.web import build_server, prepare_report
from src.web.server import main
import src.web.server


def _sample_report() -> dict:
    """A synthetic, fully-formed report matching the real report shape."""
    return {
        "report_id": "synth-report-1",
        "findings_count": 2,
        "high_severity_count": 1,
        "findings": [
            {
                "package_name": "synth-a",
                "version": "0.0.0",
                "vulnerability_id": "SYNTH-2026-0001",
                "aliases": [],
                "ecosystem": "python",
                "published": "2026-01-01",
                "vulnerability_spec": "< 2.0",
                "severity_score": None,
                "severity_vector": "CVSS:3.1/... (unspecified)",
                "severity_types": ["CVSS"],
                "fixed_versions": ["2.0"],
                "has_fixed_version": True,
            },
            {
                "package_name": "synth-b",
                "version": "0.0.0",
                "vulnerability_id": "SYNTH-2026-0002",
                "aliases": [],
                "ecosystem": "python",
                "published": "2026-01-02",
                "vulnerability_spec": "< 1.5",
                "severity_score": None,
                "severity_vector": "CVSS:3.1/... (unspecified)",
                "severity_types": ["CVSS"],
                "fixed_versions": [],
                "has_fixed_version": False,
            },
        ],
        "remediation": {
            "status": "recommended",
            "plan": {
                "items": [
                    {
                        "vulnerability_id": "SYNTH-2026-0001",
                        "package_name": "synth-a",
                        "installed_version": "0.0.0",
                        "affected_range": "< 2.0",
                        "recommended_action": "upgrade synth-a to >=2.0",
                        "fixed_versions": ["2.0"],
                        "has_fixed_version": True,
                    },
                    {
                        "vulnerability_id": "SYNTH-2026-0002",
                        "package_name": "synth-b",
                        "installed_version": "0.0.0",
                        "affected_range": "< 1.5",
                        "recommended_action": "no fixed version supplied by the scanner; "
                                              "upgrade to the latest patched release when available",
                        "fixed_versions": [],
                        "has_fixed_version": False,
                    },
                ]
            },
            "verification": {
                "status": "not_run",
                "resolution_claim": False,
                "reason": "No after scan was supplied (or it was unusable).",
                "summary": {"new": 0, "resolved": 0, "unchanged": 0, "regressed": 0},
            },
        },
        "risk": {
            "status": "unavailable",
            "score": None,
            "message": "No dependency relationships were reported (inventory-only input). "
                       "No score is fabricated; PHEI requires a known topology.",
            "method": "phei",
        },
        "source_path": "tests/fixtures/synthetic_report.json",
        "scan_mode": "inventory",
        "input": {"type": "file", "format": "synthetic-graph"},
        "warnings": [
            "CVE/advisory data is a synthetic fixture, not a live lookup; "
            "findings[].severity is unspecified (null) and is not in the score. "
            "The edge-weight function w_uv is an open decision.",
        ],
    }


def _write_report(path: str, report: dict) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)


def _get(base_url: str, path: str) -> tuple[int, str]:
    """GET ``path`` under ``base_url``; return (status, body)."""
    req = urllib.request.Request(f"{base_url}{path}", method="GET")
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return int(resp.status), resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return int(e.code), e.read().decode("utf-8", "replace")


def _serve_and_read(report: dict, use_model: bool) -> tuple[dict, str]:
    """Build a real loopback server serving ``report``; return (report_json, html)."""
    with tempfile.TemporaryDirectory() as tmp:
        rp = os.path.join(tmp, "report.json")
        _write_report(rp, report)
        server = build_server("127.0.0.1", 0, rp, use_model=use_model)  # port 0 => ephemeral
        loop = threading.Thread(target=server.serve_forever, daemon=True)
        loop.start()
        try:
            port = server.server_address[1]
            base = f"http://127.0.0.1:{port}"
            _, html_body = _get(base, "/")
            status, report_body = _get(base, "/report.json")
            assert status == 200, f"expected 200, got {status}"
            return json.loads(report_body), html_body
        finally:
            server.shutdown()   # unblocks serve_forever
            loop.join(timeout=5)
            server.server_close()


def test_dashboard_serves_page_and_report_over_loopback() -> None:
    """``/`` returns the dashboard HTML and ``/report.json`` returns the structured report."""
    report = _sample_report()
    out, html = _serve_and_read(report, use_model=False)
    # Page: 200 HTML with the RECON-DG title and the app shell.
    assert "RECON-DG" in html
    assert "<html" in html
    # Report: 200 JSON with the findings and the unavailable risk.
    assert out["findings_count"] == 2
    assert len(out["findings"]) == 2
    assert out["findings"][0]["package_name"] == "synth-a"
    assert out["risk"]["status"] == "unavailable"


def test_dashboard_reports_not_run_with_no_resolution_claim() -> None:
    """The after-scan verification state is ``not_run`` and no resolution claim is made."""
    out, _ = _serve_and_read(_sample_report(), use_model=False)
    v = out["remediation"]["verification"]
    assert v["status"] == "not_run"
    assert v["resolution_claim"] is False
    # Counts are all zero: the dashboard's ``not_run`` card renders these without
    # implying a fix succeeded (verification did not run, so nothing may be
    # claimed resolved).
    assert all(v["summary"][k] == 0 for k in ("new", "resolved", "unchanged", "regressed"))


def test_dashboard_shows_remediation_plan_and_fixed_versions() -> None:
    """The remediation plan and the scanner-provided fixed versions are served verbatim."""
    out, _ = _serve_and_read(_sample_report(), use_model=False)
    items = out["remediation"]["plan"]["items"]
    assert len(items) == 2
    assert items[0]["fixed_versions"] == ["2.0"]
    assert items[0]["has_fixed_version"] is True
    assert items[1]["fixed_versions"] == []
    assert items[1]["has_fixed_version"] is False
    # A finding with no fixed version is still served (not suppressed).
    assert items[1]["package_name"] == "synth-b"
    assert items[1]["recommended_action"]


def test_dashboard_explanations_are_additive_and_labelled() -> None:
    """The additive ai_explanations field is present, aligned, and labelled per finding."""
    out, _ = _serve_and_read(_sample_report(), use_model=False)
    exp = out["ai_explanations"]
    src = out["explanation_source"]
    assert len(exp) == len(out["findings"])
    assert all(e["source"] == "deterministic" for e in exp)  # use_model=False -> deterministic
    assert all(e["text"] for e in exp)
    assert src["model"] == 0 and src["deterministic"] == 2
    assert src["model_configured"] is False
    assert src["total"] == 2
    # Each explanation is grounded to its finding (synth-a vs synth-b differ).
    assert "synth-a" in exp[0]["text"]
    assert "synth-b" in exp[1]["text"]


def test_dashboard_explanations_do_not_touch_findings_risk_or_severity() -> None:
    """Adding explanations must not mutate findings, severity, risk, or verification."""
    original = _sample_report()
    snapshot = {
        "findings": [dict(f) for f in original["findings"]],
        "remediation": original["remediation"],
        "risk": original["risk"],
        "findings_count": original["findings_count"],
        "high_severity_count": original["high_severity_count"],
        "source_path": original["source_path"],
    }
    out, _ = _serve_and_read(original, use_model=False)
    assert out["findings"] == snapshot["findings"]
    assert out["risk"] == snapshot["risk"]
    assert out["findings_count"] == snapshot["findings_count"]
    assert out["high_severity_count"] == snapshot["high_severity_count"]
    assert out["source_path"] == snapshot["source_path"]
    # Severity stayed null; the explanation layer never invents a number.
    assert out["findings"][0]["severity_score"] is None
    assert out["findings"][1]["severity_score"] is None
    # Verification is untouched.
    assert out["remediation"]["verification"]["status"] == "not_run"


def test_dashboard_model_on_with_no_config_stays_deterministic_and_offline() -> None:
    """use_model=True but no configured endpoint/key -> deterministic; no external call."""
    out, _ = _serve_and_read(_sample_report(), use_model=True)
    exp = out["ai_explanations"]
    src = out["explanation_source"]
    assert len(exp) == len(out["findings"])
    assert all(e["source"] == "deterministic" for e in exp)
    assert src["model"] == 0 and src["deterministic"] == 2
    assert src["model_configured"] is False
    # Deterministic fallback: the server never left the machine to fetch model text.


def test_served_report_never_echoes_credentials(monkeypatch) -> None:
    """``explanation_source`` and the report text never echo the API key or endpoint."""
    secret = "sk-DASH-SECRET-NEVER-ECHOED"
    endpoint = "http://127.0.0.1:9999"
    monkeypatch.setenv("OPENAI_API_KEY", secret)
    monkeypatch.setenv("OPENAI_BASE_URL", endpoint)
    # use_model=False never uses the model path, yet the process still carries the
    # credentials in its environment; the served report must still be leak-free.
    out, _ = _serve_and_read(_sample_report(), use_model=False)
    text = json.dumps(out, sort_keys=True)
    assert secret not in text
    assert endpoint not in text
    # And the additive summary itself is neutral.
    src = out["explanation_source"]
    assert secret not in str(src)


def test_prepare_report_handles_missing_file_and_adds_explanations() -> None:
    """prepare_report falls back gracefully on a missing report and still adds the layer."""
    out = prepare_report("/nonexistent-does-not-exist-abc123.json", use_model=False)
    assert isinstance(out, dict)
    assert out.get("findings") == []
    assert "ai_explanations" in out
    assert out["ai_explanations"] == []
    assert out["explanation_source"]["total"] == 0


def prepare_report_report_path(report: dict, use_model: bool) -> dict:
    """Helper: write ``report`` to a temp file and run the public prepare_report."""
    with tempfile.TemporaryDirectory() as tmp:
        rp = os.path.join(tmp, "report.json")
        _write_report(rp, report)
        return prepare_report(rp, use_model=use_model)


def test_prepare_report_adds_explanations_to_real_report() -> None:
    """prepare_report on a real report adds aligned, additive, labelled explanations."""
    report = _sample_report()
    out = prepare_report_report_path(report, use_model=False)
    assert len(out["ai_explanations"]) == len(out["findings"])
    assert all(e["source"] == "deterministic" for e in out["ai_explanations"])
    assert out["explanation_source"]["total"] == 2
    assert out["explanation_source"]["model"] == 0
    # Additive: findings and risk untouched.
    assert out["risk"]["status"] == "unavailable"
    assert out["findings"][0]["severity_score"] is None


# ── CLI-level --model flag tests ──────────────────────────────────────────────
# These test the *argument-parsing* path (main → argparse → use_model) and
# the *end-to-end* behavior (env vars configured → request sent / not sent).

def test_cli_model_omitted_defaults_off(monkeypatch):
    """Omitted --model defaults to OFF (use_model=False)."""
    captured = []
    def fake_build(*a, **kw):
        # _build_server(host, port, report_path, use_model) — use_model is 4th positional.
        captured.append(a[3] if len(a) > 3 else kw.get("use_model"))
        class _S:
            def serve_forever(self): pass
            def shutdown(self): pass
            def server_close(self): pass
        return _S()
    monkeypatch.setattr(src.web.server, "_build_server", fake_build)
    main(["--report", "/dev/null"])
    assert captured == [False]


def test_cli_model_omitted_defaults_off_with_env(monkeypatch, tmp_path):
    """Omitted --model defaults to OFF even when OPENAI_BASE_URL/OpenAI_API_KEY are set."""
    monkeypatch.setenv("OPENAI_BASE_URL", "http://127.0.0.1:9999")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")

    report = _sample_report()
    rp = tmp_path / "r.json"
    rp.write_text(json.dumps(report))

    urlopen_calls = []
    def fake_urlopen(*a, **kw):
        urlopen_calls.append((a, kw))
        raise urllib.error.URLError("refused")
    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)

    # main() with no --model flag → use_model=False → no request
    captured = []
    def fake_build(*a, **kw):
        captured.append(a[3] if len(a) > 3 else kw.get("use_model"))
        class _S:
            def serve_forever(self): pass
            def shutdown(self): pass
            def server_close(self): pass
        return _S()
    monkeypatch.setattr(src.web.server, "_build_server", fake_build)
    main(["--report", str(rp)])

    assert captured == [False], "omitted --model must be OFF even with env vars"
    assert urlopen_calls == [], "no model request should be issued"


def test_cli_model_off_no_request(monkeypatch, tmp_path):
    """--model OFF makes no model request even when OPENAI_BASE_URL/OpenAI_API_KEY are set."""
    monkeypatch.setenv("OPENAI_BASE_URL", "http://127.0.0.1:9999")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")

    report = _sample_report()
    rp = tmp_path / "r.json"
    rp.write_text(json.dumps(report))

    urlopen_calls = []
    def fake_urlopen(*a, **kw):
        urlopen_calls.append((a, kw))
        raise urllib.error.URLError("refused")
    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)

    # _prepare_report is the bridge between CLI args and the explanation layer.
    result = prepare_report(str(rp), use_model=False)

    assert urlopen_calls == [], "OFF must never issue a model request"
    assert result["explanation_source"]["model"] == 0
    assert result["explanation_source"]["deterministic"] == 2


def test_cli_model_on_enables_request(monkeypatch, tmp_path):
    """--model ON with a configured endpoint sends a model request."""
    monkeypatch.setenv("OPENAI_BASE_URL", "http://127.0.0.1:9999")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")

    report = _sample_report()
    rp = tmp_path / "r.json"
    rp.write_text(json.dumps(report))

    urlopen_calls = []
    class _FakeResp:
        def read(self):
            return b'{"choices":[{"message":{"content":"ok"}}]}'
        def getheader(self, name, default=None):
            if name == "Content-Type":
                return "application/json"
            return default
    def fake_urlopen(*a, **kw):
        urlopen_calls.append((a, kw))
        return _FakeResp()
    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)

    result = prepare_report(str(rp), use_model=True)

    assert len(urlopen_calls) == 2  # one per finding
    assert result["explanation_source"]["model"] == 2
    assert result["explanation_source"]["deterministic"] == 0


# ── W10: real-report rendering — empty / malformed / unknown topology ─────────
# These cases exercise the server -> /report.json -> dashboard.html contract for
# inputs the December pipeline can actually produce.  No finding is invented
# here: the empty / malformed / unknown-topology cases carry no findings (or the
# clearly-labelled SYNTH- ones above), and the "real report" cases read the
# committed fixture ``docs/fixtures/report-fixture-demo.json`` verbatim (itself
# labelled as fixture-only, not project-dependency evidence).
#
# The page's JavaScript is not executed here (stdlib only, no browser); the
# page-side behaviour is pinned by asserting on the served script, and was
# checked manually in a browser (see docs/STATUS.md, W10 dashboard validation).

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_DEMO_FIXTURE = os.path.join(_REPO_ROOT, "docs", "fixtures", "report-fixture-demo.json")


def _serve_raw_and_read(raw: str) -> tuple[dict, str]:
    """Like ``_serve_and_read`` but writes ``raw`` text (possibly invalid JSON)."""
    with tempfile.TemporaryDirectory() as tmp:
        rp = os.path.join(tmp, "report.json")
        with open(rp, "w", encoding="utf-8") as f:
            f.write(raw)
        server = build_server("127.0.0.1", 0, rp, use_model=False)
        loop = threading.Thread(target=server.serve_forever, daemon=True)
        loop.start()
        try:
            base = f"http://127.0.0.1:{server.server_address[1]}"
            page_status, html_body = _get(base, "/")
            status, report_body = _get(base, "/report.json")
            assert page_status == 200 and status == 200
            return json.loads(report_body), html_body
        finally:
            server.shutdown()
            loop.join(timeout=5)
            server.server_close()


def _dashboard_script() -> str:
    with open(src.web.server._resolve_dashboard_path(), encoding="utf-8") as f:
        html = f.read()
    return html.split("<script>", 1)[1].split("</script>", 1)[0]


def test_empty_report_serves_no_data_without_crash() -> None:
    """An empty ``{}`` report is served (200) with no findings and a "no data" path.

    Before W10 the page crashed in ``render()`` on ``report.findings.length``
    when ``findings`` was absent ("Failed to load report: Cannot read properties
    of undefined"); the page now normalises a missing findings list to ``[]``
    and renders the "No findings in this report." message.
    """
    out, html = _serve_raw_and_read("{}")
    assert out.get("findings", []) == []
    assert out["ai_explanations"] == []
    assert out["explanation_source"]["total"] == 0
    assert "risk" not in out  # nothing is invented for a missing risk block
    script = _dashboard_script()
    assert "if(!Array.isArray(report.findings)) report.findings=[];" in script
    assert "No findings in this report." in script
    assert "RECON-DG" in html


def test_non_object_reports_fall_back_to_empty() -> None:
    """A JSON array / null / scalar report falls back to an empty report, not a crash."""
    for raw in ("[]", "[1, 2, 3]", "null", "42"):
        out, _ = _serve_raw_and_read(raw)
        assert out["findings"] == [], raw
        assert out["findings_count"] == 0, raw
        assert out["ai_explanations"] == [], raw


def test_malformed_report_serves_graceful_error() -> None:
    """Truncated/invalid JSON is served as an explicit error, never as findings."""
    out, _ = _serve_raw_and_read('{"findings": [ {"package_name": ')
    assert out["error"] == "report is not valid JSON"
    assert out.get("findings", []) == []
    assert out["ai_explanations"] == []
    assert out["explanation_source"]["total"] == 0
    # The page surfaces ``report.error`` instead of rendering an empty report
    # as if it were a clean scan.
    script = _dashboard_script()
    assert "if(report.error)" in script
    assert "Report could not be loaded: " in script


def test_unknown_topology_is_rendered_unavailable_not_fabricated() -> None:
    """``risk.status == "unavailable"`` (inventory-only) is served unchanged with no score.

    The page renders the PHEI card as unavailable with the red border and the
    "No score is fabricated" note, and does the same when the risk block is
    missing or carries no score (``topoKnown`` gate) — before W10 a report with
    no risk block was rendered as "Risk scoring uses the known dependency
    topology".
    """
    report = _sample_report()
    out, _ = _serve_and_read(report, use_model=False)
    assert out["risk"]["status"] == "unavailable"
    assert out["risk"]["score"] is None
    assert out["risk"] == report["risk"]

    # A report with no risk block must not gain one (or a score) on the way through.
    no_risk = _sample_report()
    del no_risk["risk"]
    out2, _ = _serve_and_read(no_risk, use_model=False)
    assert "risk" not in out2

    script = _dashboard_script()
    assert "const topoKnown=riskStatus!=='unavailable' && risk.score!=null;" in script
    assert "if(i===2 && !topoKnown) c.style.borderColor='#4a3a3f';" in script
    assert "if(!topoKnown){" in script
    assert "No score is fabricated; PHEI requires a known topology." in script


def test_real_fixture_report_served_in_insertion_order() -> None:
    """The committed demo report is served verbatim, in file order (no sort).

    Equivalent to ``python -m src.web --report docs/fixtures/report-fixture-demo.json``.
    """
    with open(_DEMO_FIXTURE, encoding="utf-8") as f:
        fixture = json.load(f)
    out, _ = _serve_and_read(fixture, use_model=False)
    assert out["findings_count"] == len(fixture["findings"]) == len(out["findings"])
    assert [(x["id"], x["package"], x["version"]) for x in out["findings"]] == \
        [(x["id"], x["package"], x["version"]) for x in fixture["findings"]]
    assert out["findings"] == fixture["findings"]  # explanation layer is additive
    assert len(out["ai_explanations"]) == len(fixture["findings"])
    # The page iterates report.findings in place and never re-orders it.
    script = _dashboard_script()
    assert "(report.findings||[]).forEach(" in script
    assert ".sort(" not in script


def test_demo_fixture_schema_gap_is_still_present() -> None:
    """Characterise the documented schema gap (docs/STATUS.md, W10 dashboard validation).

    ``report-fixture-demo.json`` uses ``id`` / ``package`` / ``severity``; the
    dashboard and ``src.web.osv_normalizer`` use ``vulnerability_id`` /
    ``package_name`` / ``severity_score``.  Rendered as-is, each finding header
    shows ``undefined@<version>``.  When the gap is resolved this test should be
    replaced by a positive rendering test.
    """
    with open(_DEMO_FIXTURE, encoding="utf-8") as f:
        fixture = json.load(f)
    first = fixture["findings"][0]
    assert {"id", "package", "severity"} <= set(first)
    assert "package_name" not in first
    assert "vulnerability_id" not in first
    assert "risk" not in fixture  # no risk block -> topology not known


def test_osv_normalizer_output_matches_dashboard_contract(tmp_path) -> None:
    """``osv_normalizer.normalize`` emits the keys ``dashboard.html`` reads.

    The OSV input is rebuilt from the first finding of the committed demo
    fixture (its real advisory ID / aliases / score), so no finding is invented.
    """
    from src.web.osv_normalizer import normalize

    with open(_DEMO_FIXTURE, encoding="utf-8") as f:
        f0 = json.load(f)["findings"][0]
    osv = {"results": [{
        "source": {"path": "tests/fixtures/requirements-before.txt"},
        "packages": [{
            "package": {"name": f0["package"], "version": f0["version"],
                        "ecosystem": f0["ecosystem"]},
            "groups": [{"ids": [f0["id"]], "aliases": f0["aliases"],
                        "max_severity": f0["severity"]}],
        }],
    }]}
    p = tmp_path / "osv.json"
    p.write_text(json.dumps(osv), encoding="utf-8")
    report = normalize(str(p))

    assert report["risk"] == {"status": "unavailable", "score": None}
    assert report["findings_count"] == 1
    finding = report["findings"][0]
    for key in ("package_name", "version", "vulnerability_id", "aliases",
                "ecosystem", "severity_score", "fixed_versions"):
        assert key in finding, key
    assert finding["package_name"] == f0["package"]
    assert finding["vulnerability_id"] == f0["id"]
    assert finding["severity_score"] == f0["severity"]

    # And it is served unchanged through the dashboard server.
    out, _ = _serve_and_read(report, use_model=False)
    assert out["findings"] == report["findings"]
    assert out["risk"]["status"] == "unavailable"
    assert f0["package"] in out["ai_explanations"][0]["text"]
