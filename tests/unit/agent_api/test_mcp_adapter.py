"""MCP adapter tests: registry parity, call results, stdio round trips and HTTP auth."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

pytest.importorskip("mcp")

import anyio  # noqa: E402
from mcp import ClientSession  # noqa: E402
from mcp.client.stdio import StdioServerParameters, stdio_client  # noqa: E402
from mcp.shared.memory import create_connected_server_and_client_session  # noqa: E402

from friTap.agent_api.adapters import mcp_server  # noqa: E402
from friTap.agent_api.context import ToolContext  # noqa: E402
from friTap.commands.mcp import run_mcp_cli  # noqa: E402
from tests.unit.agent_api.fake_registry import (  # noqa: E402
    make_registry,
    make_reveal_registry,
)

REPO_ROOT = Path(__file__).resolve().parents[3]
FAKE_STDIO_SCRIPT = (
    "from friTap.agent_api.adapters.mcp_server import serve_stdio\n"
    "from friTap.agent_api.context import ToolContext\n"
    "from tests.unit.agent_api.fake_registry import make_registry\n"
    "print('stray print must not reach the protocol stream')\n"
    "serve_stdio(make_registry(), ToolContext(allow_capture=False))\n"
)


def _in_memory(fn):
    """Run ``fn(session)`` against the fake registry over an in-memory MCP transport."""
    server = mcp_server.build_server(make_registry(), ToolContext(allow_capture=False))

    async def main():
        async with create_connected_server_and_client_session(server) as session:
            return await fn(session)

    return anyio.run(main)


def _over_stdio(args, fn):
    params = StdioServerParameters(command=sys.executable, args=args, cwd=str(REPO_ROOT),
                                   env={**os.environ, "PYTHONPATH": str(REPO_ROOT)})

    async def main():
        with anyio.fail_after(60):
            async with stdio_client(params) as (read, write):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    return await fn(session)

    return anyio.run(main)


def _payload(result):
    return json.loads(result.content[0].text)


class TestDefinitions:
    def test_list_tools_matches_registry(self):
        reg = make_registry()
        tools = _in_memory(lambda s: s.list_tools())
        assert [t.name for t in tools.tools] == reg.names()
        for tool, spec in zip(tools.tools, reg.specs()):
            assert tool.inputSchema == spec.params_schema
            assert tool.description == spec.summary

    def test_annotations_follow_kind(self):
        reg = make_registry()
        echo = mcp_server.tool_definition(reg.get("echo"))
        capture = mcp_server.tool_definition(reg.get("start_thing"))
        assert echo.annotations.readOnlyHint is True and echo.annotations.destructiveHint is False
        assert capture.annotations.readOnlyHint is False and capture.annotations.destructiveHint is True


class TestCallTool:
    def test_success_has_text_and_structured_content(self):
        result = _in_memory(lambda s: s.call_tool("echo", {"text": "hi", "times": 2}))
        assert not result.isError
        assert _payload(result)["echo"] == "hihi"
        assert result.structuredContent["echo"] == "hihi"

    def test_context_reaches_handler(self):
        result = _in_memory(lambda s: s.call_tool("start_thing", {}))
        assert _payload(result)["allow_capture"] is False

    def test_bad_param_is_error_json(self):
        result = _in_memory(lambda s: s.call_tool("echo", {"times": 0}))
        assert result.isError
        assert _payload(result)["error_type"] == "bad_param"

    def test_unknown_tool_and_runtime_error(self):
        unknown = _in_memory(lambda s: s.call_tool("ech", {}))
        assert unknown.isError and _payload(unknown)["error_type"] == "unknown_tool"
        failed = _in_memory(lambda s: s.call_tool("fail", {}))
        assert failed.isError and _payload(failed)["exit_code"] == 1


class TestValueGating:
    def test_mcp_denies_values_by_default(self, monkeypatch):
        seen = {}
        monkeypatch.setattr(mcp_server, "serve_stdio", lambda reg, ctx: seen.update(ctx=ctx))
        assert run_mcp_cli([]) == 0
        assert seen["ctx"].allow_values is False
        assert run_mcp_cli(["--allow-values"]) == 0
        assert seen["ctx"].allow_values is True

    def test_show_values_is_forbidden_error(self):
        server = mcp_server.build_server(make_reveal_registry(), ToolContext(allow_values=False))

        async def main():
            async with create_connected_server_and_client_session(server) as session:
                return await session.call_tool("reveal", {"show_values": True})

        result = anyio.run(main)
        assert result.isError
        assert _payload(result)["error_type"] == "forbidden"


class TestStdio:
    def test_fake_registry_round_trip(self):
        async def run(session):
            return await session.list_tools(), await session.call_tool("echo", {"text": "x"})

        tools, result = _over_stdio(["-c", FAKE_STDIO_SCRIPT], run)
        assert [t.name for t in tools.tools] == ["echo", "fail", "start_thing"]
        assert _payload(result)["echo"] == "x"

    def test_fritap_mcp_dispatch_round_trip(self):
        async def run(session):
            return await session.list_tools(), await session.call_tool("no_such_tool", {})

        tools, result = _over_stdio(["-m", "friTap.friTap", "mcp"], run)
        from friTap.agent_api import registry

        assert sorted(t.name for t in tools.tools) == registry.names()
        assert result.isError and _payload(result)["error_type"] == "unknown_tool"


class TestHttp:
    def _client(self, token):
        from starlette.testclient import TestClient

        app = mcp_server.build_http_app(make_registry(), ToolContext(), host="127.0.0.1", token=token)
        return TestClient(app, base_url="http://127.0.0.1:8765")

    def test_token_required(self):
        with self._client("s3cret") as client:
            resp = client.post("/mcp/", json={})
            assert resp.status_code == 401 and resp.json()["error_type"] == "unauthorized"

    def test_token_accepted_reaches_mcp(self):
        init = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": "2025-06-18", "capabilities": {},
            "clientInfo": {"name": "t", "version": "0"}}}
        headers = {"Authorization": "Bearer s3cret", "Accept": "application/json, text/event-stream"}
        with self._client("s3cret") as client:
            resp = client.post("/mcp/", json=init, headers=headers)
            assert resp.status_code == 200


class TestCli:
    def test_http_non_loopback_without_token_refused(self, monkeypatch, capsys):
        monkeypatch.delenv("FRITAP_API_TOKEN", raising=False)
        with pytest.raises(SystemExit) as info:
            run_mcp_cli(["--http", "--host", "0.0.0.0"])
        assert info.value.code == 2
        assert "without --token" in capsys.readouterr().err

    def test_missing_mcp_package(self, monkeypatch, capsys):
        monkeypatch.setattr(mcp_server, "mcp_available", lambda: False)
        assert run_mcp_cli([]) == 2
        err = json.loads(capsys.readouterr().err)
        assert err["error"] == "mcp package not installed" and err["exit_code"] == 2
