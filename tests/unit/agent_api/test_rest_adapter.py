"""REST adapter, OpenAPI generator and bind policy tests (stdlib server on an ephemeral port)."""

from __future__ import annotations

import http.client
import json
import threading

import pytest

from friTap.agent_api.adapters import openapi, rest_server
from friTap.agent_api.adapters.bind_policy import (
    bearer_matches,
    bind_error,
    is_loopback,
)
from friTap.agent_api.adapters.rest_server import (
    MAX_BODY_BYTES,
    RestApp,
    http_status,
    make_server,
)
from friTap.agent_api.context import ToolContext
from friTap.agent_api.errors import ToolError
from friTap.commands.serve import run_serve_cli
from tests.unit.agent_api.fake_registry import make_registry, make_reveal_registry


@pytest.fixture
def server(tmp_path, request):
    token = getattr(request, "param", None)
    app = RestApp(make_registry(), ToolContext(root=tmp_path, allow_capture=False), token=token)
    srv = make_server(app, "127.0.0.1", 0)
    thread = threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
    thread.start()
    yield srv.server_address[1]
    srv.shutdown()
    srv.server_close()


def _request(port, method, path, body=None, headers=None, raw=None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    payload = raw if raw is not None else (json.dumps(body).encode() if body is not None else None)
    conn.request(method, path, body=payload, headers=headers or {})
    resp = conn.getresponse()
    doc = json.loads(resp.read() or b"null")
    conn.close()
    return resp.status, doc


class TestRoutes:
    def test_list_tools(self, server):
        status, doc = _request(server, "GET", "/v1/tools")
        assert status == 200
        assert [t["name"] for t in doc["tools"]] == ["echo", "fail", "start_thing"]
        assert doc["tools"][0]["params_schema"]["required"] == ["text"]

    def test_healthz_and_openapi(self, server):
        assert _request(server, "GET", "/healthz") == (200, {"status": "ok"})
        status, doc = _request(server, "GET", "/openapi.json")
        assert status == 200 and doc["openapi"] == "3.1.0"

    def test_post_success_applies_defaults(self, server):
        status, doc = _request(server, "POST", "/v1/tools/echo", {"text": "ab", "times": 2})
        assert status == 200 and doc["echo"] == "abab"

    def test_context_is_passed(self, server):
        status, doc = _request(server, "POST", "/v1/tools/start_thing", raw=b"")
        assert status == 200 and doc["allow_capture"] is False

    def test_bad_param_is_400(self, server):
        status, doc = _request(server, "POST", "/v1/tools/echo", {"times": 0})
        assert status == 400 and doc["error_type"] == "bad_param"

    @pytest.mark.parametrize("body", [b"{not json", b"[1, 2]"])
    def test_bad_body_is_400(self, server, body):
        status, doc = _request(server, "POST", "/v1/tools/echo", raw=body)
        assert status == 400 and doc["error_type"] == "bad_request"

    def test_unknown_tool_is_404(self, server):
        status, doc = _request(server, "POST", "/v1/tools/ech", {})
        assert status == 404 and doc["error_type"] == "unknown_tool"
        assert "echo" in doc["hint"]

    def test_unknown_route_and_method(self, server):
        assert _request(server, "GET", "/nope")[0] == 404
        assert _request(server, "POST", "/v1/tools/echo/x", {})[0] == 404
        assert _request(server, "DELETE", "/v1/tools/echo")[0] == 405

    @pytest.mark.parametrize("error_type,status", [("forbidden", 403), ("not_found", 404),
                                                   ("capture_running", 409), ("runtime_error", 500)])
    def test_error_status_mapping(self, server, error_type, status):
        got, doc = _request(server, "POST", "/v1/tools/fail", {"error_type": error_type})
        assert got == status and doc["error_type"] == error_type

    def test_body_size_limit(self, server):
        # Declare an oversized body without sending it: the server must answer
        # 413 from the header alone instead of reading MAX_BODY_BYTES first.
        conn = http.client.HTTPConnection("127.0.0.1", server, timeout=10)
        conn.putrequest("POST", "/v1/tools/echo")
        conn.putheader("Content-Length", str(MAX_BODY_BYTES + 1))
        conn.endheaders()
        resp = conn.getresponse()
        doc = json.loads(resp.read())
        conn.close()
        assert resp.status == 413 and doc["error_type"] == "body_too_large"


def _serve_context(monkeypatch, argv):
    seen = {}
    monkeypatch.setattr(rest_server, "serve", lambda app, host, port: seen.update(ctx=app.context))
    assert run_serve_cli(argv) == 0
    return seen["ctx"]


class TestValueGating:
    def test_serve_denies_values_by_default(self, monkeypatch):
        assert _serve_context(monkeypatch, ["--port", "0"]).allow_values is False

    def test_serve_allow_values_flag(self, monkeypatch):
        assert _serve_context(monkeypatch, ["--port", "0", "--allow-values"]).allow_values is True

    def test_show_values_is_403_without_allow_values(self, tmp_path):
        app = RestApp(make_reveal_registry(), ToolContext(root=tmp_path, allow_values=False))
        srv = make_server(app, "127.0.0.1", 0)
        thread = threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.05},
                                  daemon=True)
        thread.start()
        try:
            port = srv.server_address[1]
            status, doc = _request(port, "POST", "/v1/tools/reveal", {"show_values": True})
            assert status == 403 and doc["error_type"] == "forbidden"
            assert "--allow-values" in doc["hint"]
            assert _request(port, "POST", "/v1/tools/reveal", {}) == (200, {"show_values": False})
        finally:
            srv.shutdown()
            srv.server_close()


class TestBrowserRequestsRefused:
    """Token-less server: web pages (CSRF, DNS rebinding) cannot drive the tools."""

    @pytest.mark.parametrize("origin", ["http://evil.example", "null", "http://127.0.0.1.evil.example"])
    def test_cross_origin_post_is_403(self, server, origin):
        status, doc = _request(server, "POST", "/v1/tools/echo", raw=b'{"text": "x"}',
                               headers={"Origin": origin, "Content-Type": "text/plain"})
        assert status == 403 and doc["error_type"] == "forbidden"

    def test_rebound_host_is_403(self, server):
        status, _doc = _request(server, "GET", "/v1/tools", headers={"Host": f"evil.example:{server}"})
        assert status == 403

    @pytest.mark.parametrize("headers", [
        {}, {"Origin": "http://localhost:1234"}, {"Host": "localhost"}, {"Host": "[::1]:8766"},
    ])
    def test_local_clients_allowed(self, server, headers):
        assert _request(server, "POST", "/v1/tools/echo", {"text": "x"}, headers=headers)[0] == 200


class TestToken:
    @pytest.mark.parametrize("server", ["s3cret"], indirect=True)
    def test_token_enforced(self, server):
        assert _request(server, "GET", "/v1/tools")[0] == 401
        assert _request(server, "GET", "/v1/tools", headers={"Authorization": "Bearer nope"})[0] == 401
        ok = _request(server, "POST", "/v1/tools/echo", {"text": "x"},
                      headers={"Authorization": "Bearer s3cret"})
        assert ok[0] == 200

    @pytest.mark.parametrize("server", ["s3cret"], indirect=True)
    def test_healthz_needs_no_token_and_leaks_nothing(self, server):
        assert _request(server, "GET", "/healthz") == (200, {"status": "ok"})
        assert _request(server, "GET", "/healthz/") == (200, {"status": "ok"})
        assert _request(server, "GET", "/healthz?x=1") == (200, {"status": "ok"})
        assert _request(server, "GET", "/openapi.json")[0] == 401
        assert _request(server, "POST", "/healthz")[0] == 401

    def test_bearer_matches(self):
        assert bearer_matches("Bearer t", "t")
        assert not bearer_matches("bearer t", "t") and not bearer_matches(None, "t")


class TestBindPolicy:
    @pytest.mark.parametrize("host", ["127.0.0.1", "localhost", "::1", "[::1]", "127.0.0.2"])
    def test_loopback(self, host):
        assert is_loopback(host) and bind_error(host, None) is None

    @pytest.mark.parametrize("host", ["0.0.0.0", "192.168.1.5", "example.com", "::"])
    def test_non_loopback_requires_token(self, host):
        assert not is_loopback(host)
        assert "--token" in bind_error(host, None)
        assert bind_error(host, "t") is None

    def test_serve_cli_refuses_non_loopback_without_token(self, monkeypatch, capsys):
        monkeypatch.delenv("FRITAP_API_TOKEN", raising=False)
        with pytest.raises(SystemExit) as info:
            run_serve_cli(["--host", "0.0.0.0", "--port", "0"])
        assert info.value.code == 2
        assert "without --token" in capsys.readouterr().err

    def test_status_mapping_by_exit_code(self):
        assert http_status(ToolError("x", "bad_filter")) == 400
        assert http_status(ToolError("x", "weird", exit_code=1)) == 500


def _resolve(doc, ref):
    node = doc
    for part in ref.removeprefix("#/").split("/"):
        node = node[part]
    return node


def _refs(node):
    if isinstance(node, dict):
        if "$ref" in node:
            yield node["$ref"]
        for value in node.values():
            yield from _refs(value)
    elif isinstance(node, list):
        for value in node:
            yield from _refs(value)


class TestOpenAPI:
    def test_structure(self):
        reg = make_registry()
        doc = openapi.build_openapi(reg, version="0")
        assert doc["openapi"] == "3.1.0"
        for name in reg.names():
            op = doc["paths"][f"/v1/tools/{name}"]["post"]
            assert op["operationId"] == name
            assert {"200", "400", "404", "500"} <= set(op["responses"])
        assert {"/v1/tools", "/openapi.json", "/healthz"} <= set(doc["paths"])
        for ref in _refs(doc):
            assert isinstance(_resolve(doc, ref), dict), ref

    def test_request_and_result_schemas(self):
        doc = openapi.build_openapi(make_registry(), version="0")
        schemas = doc["components"]["schemas"]
        echo = doc["paths"]["/v1/tools/echo"]["post"]
        assert _resolve(doc, echo["requestBody"]["content"]["application/json"]["schema"]["$ref"]) \
            == schemas["echo_params"]
        assert echo["responses"]["200"]["content"]["application/json"]["schema"]["$ref"].endswith("echo_result")
        fail = doc["paths"]["/v1/tools/fail"]["post"]
        assert fail["responses"]["200"]["content"]["application/json"]["schema"]["$ref"].endswith("GenericResult")

    def test_write_outputs_deterministic(self, tmp_path):
        reg = make_registry()
        out, schemas = tmp_path / "openapi.json", tmp_path / "schemas"
        openapi.write_outputs(reg, out, schemas)
        first = out.read_text()
        openapi.write_outputs(reg, out, schemas)
        assert out.read_text() == first
        assert sorted(p.name for p in schemas.iterdir()) == [
            "echo.params.json", "echo.result.json", "fail.params.json", "start_thing.params.json"]
        assert json.loads((schemas / "echo.params.json").read_text())["$schema"].endswith("2020-12/schema")

    def test_cli_main_on_real_registry(self, tmp_path):
        assert openapi.main(["--out", str(tmp_path / "o.json"), "--schemas", str(tmp_path / "s")]) == 0
        assert json.loads((tmp_path / "o.json").read_text())["openapi"] == "3.1.0"
