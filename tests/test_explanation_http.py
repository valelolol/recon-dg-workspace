"""Real-HTTP (loopback) verification for the OpenAI-compatible local model client.

``tests/test_explanation.py`` drives the client through an injected ``transport``
seam, so those tests never touch ``urllib``.  This module closes that gap: it
spins up a **real** local ``http.server`` implementing the OpenAI
``/v1/chat/completions`` endpoint, points ``LocalModelConfig.base_url`` at it,
and calls ``OpenAILocalClient.explain()`` with ``transport=None`` so the **real**
``urllib`` path issues the request.  All traffic is local loopback (127.0.0.1):
no external network is contacted and no live model is needed.

These tests verify item 1 of the task:
  * the client actually *sends* a POST to ``{base_url}/v1/chat/completions``
    (the configurable endpoint) with the model name, a grounded prompt, and the
    bearer key;
  * a 200 with a valid completion -> ``source='model'``;
  * non-2xx / malformed / empty body -> per-finding deterministic fallback
    (and the request still went out, so the failure is in the response);
  * no base_url / no api_key -> *zero* requests issued (immediate fallback);
  * the ``max_calls`` cap bounds the number of real requests.
"""
from __future__ import annotations

import json
import threading

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from src.explanation import LocalModelConfig, OpenAILocalClient


def _make_finding(idx: int = 0) -> dict:
    return {
        "package_name": f"pkg{idx + 1}",
        "version": "1.2.3",
        "vulnerability_id": f"SYNTH-2026-01{idx}",
        "aliases": [],
        "ecosystem": "python",
        "published": "2026-01-01",
        "vulnerability_spec": "< 2.0",
        "severity_score": None,
        "severity_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "severity_types": ["CVSS"],
        "fixed_versions": ["2.0"],
    }


class _CompletionsServer:
    """A loopback /v1/chat/completions stand-in that records every request."""

    def __init__(self, response_status: int = 200, response_body: bytes = b""):
        self.response_status = response_status
        self.response_body = response_body
        self.requests: list[dict] = []
        self.httpd: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    def start(self, port: int = 0) -> None:
        self.httpd = ThreadingHTTPServer(("127.0.0.1", port), self._handler_factory())
        self._thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self._thread.start()
        self.port = self.httpd.socket.getsockname()[1]

    def stop(self) -> None:
        if self.httpd is not None:
            self.httpd.shutdown()
            self.httpd.server_close()
            if self._thread is not None:
                self._thread.join(timeout=5)

    def _handler_factory(self):  # type: ignore[return-value]
        server = self  # handlers record into server.requests
        class _Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                length = int(self.headers.get("Content-Length", "0") or 0)
                body = self.rfile.read(length).decode("utf-8", "replace")
                parsed: dict
                try:
                    parsed = json.loads(body) if body else {}
                except json.JSONDecodeError:
                    parsed = {"_invalid_json": True}
                server.requests.append({
                    "path": self.path,
                    "method": self.command,
                    "headers": {k: v for k, v in self.headers.items()},
                    "body": body,
                    "json": parsed,
                })
                resp = server.response_body
                self.send_response(server.response_status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(resp)))
                self.end_headers()
                self.wfile.write(resp)

            def log_message(self, fmt: str, *args: object) -> None:
                pass

        return _Handler


def _cfg(base_url: str, api_key: str = "sk-LOOPBACK-TEST",
         max_calls: int | None = None) -> LocalModelConfig:
    if max_calls is None:
        return LocalModelConfig(base_url=base_url, api_key=api_key)
    return LocalModelConfig(base_url=base_url, api_key=api_key, max_calls=max_calls)


def _client(cfg: LocalModelConfig) -> OpenAILocalClient:
    # transport=None -> the real urllib path (no injected seam).
    return OpenAILocalClient(config=cfg)


def test_real_request_is_sent_to_configurable_endpoint() -> None:
    """The client issues a real POST to {base_url}/v1/chat/completions with model+prompt+key."""
    body = json.dumps({
        "choices": [{"message": {"content": "pkg1@1.2.3 is affected by SYNTH-2026-010; upgrade to 2.0."}}]
    }).encode("utf-8")
    srv = _CompletionsServer(response_status=200, response_body=body)
    srv.start()
    try:
        cfg = _cfg(base_url=f"http://127.0.0.1:{srv.port}", api_key="sk-LOOPBACK-TEST")
        entries = _client(cfg).explain([_make_finding(0), _make_finding(1)])
    finally:
        srv.stop()
    assert len(entries) == 2
    assert entries[0]["source"] == "model"
    assert entries[1]["source"] == "model"
    assert entries[0]["text"].strip()
    # A real request went out for each finding (transport=None => urllib).
    assert len(srv.requests) == 2
    r0 = srv.requests[0]
    assert r0["path"] == "/v1/chat/completions"
    assert r0["method"] == "POST"
    assert r0["json"]["model"] == "gpt-3.5-turbo"
    msgs = r0["json"]["messages"]
    assert any(m["role"] == "system" for m in msgs)
    assert any(m["role"] == "user" for m in msgs)
    # The user prompt is grounded in the finding (carries package/version/advisory).
    user_msg = [m for m in msgs if m["role"] == "user"][0]
    # The prompt is grounded in the finding (separate package_name / version lines).
    assert "pkg1" in user_msg["content"]
    assert "1.2.3" in user_msg["content"]
    assert "SYNTH-2026-010" in user_msg["content"]
    assert "do NOT invent" in user_msg["content"]  # grounded-prompt constraint
    # The bearer key is transmitted (and never echoed back in the response).
    assert r0["headers"]["Authorization"] == "Bearer sk-LOOPBACK-TEST"


def test_real_request_non2xx_falls_back_per_finding() -> None:
    """A 500 response means the request went out; each finding falls back deterministically."""
    srv = _CompletionsServer(
        response_status=500,
        response_body=json.dumps({"error": "server failed"}).encode("utf-8"),
    )
    srv.start()
    try:
        cfg = _cfg(base_url=f"http://127.0.0.1:{srv.port}", api_key="sk-LOOPBACK-TEST")
        entries = _client(cfg).explain([_make_finding(0), _make_finding(1)])
    finally:
        srv.stop()
    assert all(e["source"] == "deterministic" for e in entries)
    assert len(entries) == 2
    # Failures were real endpoint failures, not "no config" (requests actually went out).
    assert len(srv.requests) == 2
    # Two distinct findings -> two distinct deterministic fallbacks (grounded to each).
    assert entries[0]["text"] != entries[1]["text"]


def test_real_request_malformed_body_falls_back() -> None:
    """A 200 whose body is malformed / lacks choices -> deterministic fallback."""
    for body in (
        b"not json at all",
        json.dumps({"foo": "bar"}).encode(),            # valid JSON, no choices
        json.dumps({"choices": []}).encode(),            # choices empty
        json.dumps({"choices": [{"message": {}}]}).encode(),           # no content key
        json.dumps({"choices": [{"message": {"content": ""}}]}).encode(),  # empty string
        json.dumps({"choices": [{"message": {"content": "   "}}]}).encode(),  # whitespace only
        b"\x00\x01\x02",                                 # not valid UTF-8
    ):
        srv = _CompletionsServer(response_status=200, response_body=body)
        srv.start()
        try:
            cfg = _cfg(base_url=f"http://127.0.0.1:{srv.port}", api_key="sk-LOOPBACK-TEST")
            entries = _client(cfg).explain([_make_finding(0)])
        finally:
            srv.stop()
        assert entries[0]["source"] == "deterministic"
        assert len(srv.requests) == 1  # the malformed body was *received*
        assert srv.requests[0]["json"].get("_invalid_json") is not True or \
            not srv.requests[0]["json"].get("choices")


def test_real_request_no_configured_endpoint_issues_no_request() -> None:
    """No base_url/key -> immediate deterministic fallback, zero requests (no urllib call)."""
    srv = _CompletionsServer()
    srv.start()
    try:
        # base_url set, api_key empty -> not configured -> no request.
        cfg = _cfg(base_url=f"http://127.0.0.1:{srv.port}", api_key="")
        assert _client(cfg).explain([_make_finding(0)])[0]["source"] == "deterministic"
        assert len(srv.requests) == 0
        # base_url empty -> also no request.
        cfg = _cfg(base_url="", api_key="sk-LOOPBACK-TEST")
        assert _client(cfg).explain([_make_finding(0)])[0]["source"] == "deterministic"
        assert len(srv.requests) == 0
    finally:
        srv.stop()


def test_real_request_max_calls_cap_bounds_real_requests() -> None:
    """max_calls=1 with two findings -> exactly one real POST; the second is deterministic."""
    body = json.dumps({"choices": [{"message": {"content": "model says ok."}}]}).encode()
    srv = _CompletionsServer(response_status=200, response_body=body)
    srv.start()
    try:
        cfg = _cfg(base_url=f"http://127.0.0.1:{srv.port}", api_key="sk-LOOPBACK-TEST", max_calls=1)
        entries = _client(cfg).explain([_make_finding(0), _make_finding(1)])
    finally:
        srv.stop()
    assert len(entries) == 2
    assert [e["source"] for e in entries] == ["model", "deterministic"]
    assert len(srv.requests) == 1  # hard cap enforced on the real transport


def test_real_request_no_credentials_echoed() -> None:
    """The model response text never echoes the key or the endpoint."""
    body = json.dumps({"choices": [{"message": {"content": "pkg1 is affected; upgrade."}}]}).encode()
    srv = _CompletionsServer(response_status=200, response_body=body)
    srv.start()
    try:
        cfg = _cfg(base_url=f"http://127.0.0.1:{srv.port}", api_key="sk-LOOPBACK-SECRET")
        entries = _client(cfg).explain([_make_finding(0)])
        assert entries[0]["source"] == "model"
        assert "sk-LOOPBACK-SECRET" not in entries[0]["text"]
    finally:
        srv.stop()


def test_real_request_timeout_or_connrefused_falls_back() -> None:
    """A server that is already stopped (connection refused) -> deterministic fallback."""
    # A fresh ThreadingHTTPServer that we stop before any client request.
    srv = _CompletionsServer()
    srv.start()
    srv.stop()  # port is now free / closed
    cfg = _cfg(base_url=f"http://127.0.0.1:{srv.port}", api_key="sk-LOOPBACK-TEST")
    entries = _client(cfg).explain([_make_finding(0)])
    # Connection refused (or closed) -> the client must not raise; it falls back.
    assert entries[0]["source"] == "deterministic"
    assert len(srv.requests) == 0
