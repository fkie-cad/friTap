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

    def test_real_tools_have_no_top_level_combinators(self):
        """Claude rejects a top-level oneOf/anyOf/allOf and silently drops the tool."""
        from friTap.agent_api.registry import registry
        from friTap.agent_api.schema import TOP_LEVEL_COMBINATORS

        for spec in registry.specs():
            tool = mcp_server.tool_definition(spec)
            assert not set(TOP_LEVEL_COMBINATORS) & set(tool.inputSchema), spec.name

    def test_source_group_moves_into_description(self):
        from friTap.agent_api.registry import registry

        spec = registry.get("get_digest")
        tool = mcp_server.tool_definition(spec)
        assert "oneOf" in spec.params_schema  # the registry keeps validating it
        assert tool.description.startswith(spec.summary)
        assert tool.description.endswith("Give exactly one of: tap, session_id.")


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


@pytest.fixture
def fake_skills(tmp_path, monkeypatch):
    """Two fake skills patched in place of the packaged ones."""
    import friTap.skills as skills_pkg

    for name, description in (("zeta-skill", "Zeta does z."), ("alpha-skill", "Alpha does a.")):
        (tmp_path / name).mkdir()
        (tmp_path / name / "SKILL.md").write_text(
            f"---\nname: {name}\ndescription: {description}\n---\n# {name} body\n", encoding="utf-8")
    monkeypatch.setattr(skills_pkg, "skills_root", lambda: tmp_path)
    return tmp_path


class TestPrompts:
    def test_capability_is_advertised(self):
        from mcp.server.lowlevel import NotificationOptions

        server = mcp_server.build_server(make_registry(), ToolContext(allow_capture=False))
        assert server.get_capabilities(NotificationOptions(), {}).prompts is not None
        init = server.create_initialization_options()
        assert init.capabilities.prompts is not None and init.capabilities.tools is not None

    def test_list_prompts_mirrors_skills(self, fake_skills):
        prompts = _in_memory(lambda s: s.list_prompts()).prompts
        assert [p.name for p in prompts] == ["alpha-skill", "zeta-skill"]
        assert prompts[0].description == "Alpha does a."
        assert [(a.name, a.required) for a in prompts[0].arguments] == [("target", False), ("device", False)]

    def test_list_prompts_covers_packaged_skills(self):
        from friTap.skills import list_skills

        prompts = _in_memory(lambda s: s.list_prompts()).prompts
        assert [p.name for p in prompts] == [skill.name for skill in list_skills()]

    def test_get_prompt_without_arguments_is_skill_body(self, fake_skills):
        result = _in_memory(lambda s: s.get_prompt("alpha-skill"))
        assert len(result.messages) == 1
        message = result.messages[0]
        assert message.role == "user" and message.content.type == "text"
        assert message.content.text == "# alpha-skill body"
        assert result.description == "Alpha does a."

    def test_get_prompt_fills_target_and_device(self, fake_skills):
        result = _in_memory(lambda s: s.get_prompt("zeta-skill", {"target": "com.example", "device": "emu-1"}))
        text = result.messages[0].content.text
        first_line, _, body = text.partition("\n\n")
        assert "com.example" in first_line and "emu-1" in first_line
        assert body == "# zeta-skill body"

    def test_get_prompt_target_only(self, fake_skills):
        text = _in_memory(lambda s: s.get_prompt("zeta-skill", {"target": "1234"})).messages[0].content.text
        assert text.startswith("Apply this workflow to target `1234`.")
        assert "device" not in text.split("\n")[0]

    def test_unknown_prompt_is_invalid_params(self, fake_skills):
        from mcp import types
        from mcp.shared.exceptions import McpError

        async def request_unknown(session):
            try:
                await session.get_prompt("nope")
            except McpError as err:
                return err.error
            return None

        error = _in_memory(request_unknown)
        assert error is not None and error.code == types.INVALID_PARAMS
        assert "nope" in error.message

    def test_unknown_prompt_error_data(self, fake_skills):
        from mcp.shared.exceptions import McpError

        with pytest.raises(McpError) as caught:
            mcp_server.get_prompt_result("nope", None)
        assert caught.value.error.data["error_type"] == "unknown_prompt"

    def test_preamble_empty_without_values(self):
        assert mcp_server.prompt_preamble(None) == ""
        assert mcp_server.prompt_preamble({"target": "", "device": None}) == ""


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

    def test_fritap_mcp_prompts_round_trip(self):
        from mcp.shared.exceptions import McpError

        from friTap.skills import get_skill, list_skills

        prompt_args = {"target": "com.android.chrome", "device": "emulator-5556"}

        async def run(session):
            prompts = await session.list_prompts()
            rendered = await session.get_prompt("fritap-capture", prompt_args)
            try:
                await session.get_prompt("no-such-skill")
                unknown_error = None
            except McpError as err:
                unknown_error = err.error
            return prompts, rendered, unknown_error

        prompts, rendered, unknown_error = _over_stdio(["-m", "friTap.friTap", "mcp"], run)

        assert sorted(p.name for p in prompts.prompts) == sorted(s.name for s in list_skills())
        capture = next(p for p in prompts.prompts if p.name == "fritap-capture")
        assert [a.name for a in capture.arguments] == [name for name, _ in mcp_server.PROMPT_ARGUMENTS]
        text = rendered.messages[0].content.text
        assert get_skill("fritap-capture").body in text
        assert "com.android.chrome" in text and "emulator-5556" in text
        assert unknown_error is not None and "no-such-skill" in unknown_error.message


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
