"""Tests for the generated ``fritap q`` CLI, shared server options and dispatch."""

from __future__ import annotations

import argparse
import importlib
import io
import json
from pathlib import Path

import pytest

from friTap.agent_api.adapters import cli
from friTap.agent_api.adapters.server_options import (
    add_server_options,
    build_context,
    is_server_invocation,
    leading_option_count,
    option_takes_value,
)
from friTap.agent_api.errors import ToolError
from friTap.agent_api.registry import Registry, ToolSpec
from friTap.agent_api.schema import object_schema
from friTap.commands import mcp as mcp_command
from friTap.commands import serve as serve_command
from friTap.exit_codes import EXIT_RUNTIME_ERROR, EXIT_USAGE_ERROR

ALL_TYPES_SCHEMA = object_schema(
    {
        "tap": {"type": "string", "minLength": 1, "description": "Tap path (100% local)."},
        "max_bytes": {"type": "integer", "minimum": 1, "default": 10},
        "ratio": {"type": "number"},
        "show_values": {"type": "boolean", "default": False},
        "format": {"type": "string", "enum": ["md", "json"]},
        "fields": {"type": "array", "items": {"type": "string"}},
        "ports": {"type": "array", "items": {"type": "integer"}},
        "options": {"type": "object"},
    },
    required=("tap",),
)


def _echo(params, ctx):
    return {"params": params, "root": str(ctx.root), "allow_secrets": ctx.allow_secrets,
            "allow_capture": ctx.allow_capture, "allow_values": ctx.allow_values}


def _boom(params, ctx):
    raise RuntimeError("kaputt")


class _FakeCapture:
    """start_capture/capture_status/stop_capture with a scripted state sequence."""

    def __init__(self, states, interrupt_after=None):
        self.states = list(states)
        self.status_calls = 0
        self.stopped = False
        self.interrupt_after = interrupt_after

    def start(self, params, ctx):
        return {"session_id": "s1", "state": "starting"}

    def status(self, params, ctx):
        self.status_calls += 1
        if self.interrupt_after is not None and self.status_calls > self.interrupt_after:
            raise KeyboardInterrupt
        return {"session_id": params["session_id"], "state": self.states.pop(0)}

    def stop(self, params, ctx):
        self.stopped = True
        return {"session_id": params["session_id"], "state": "stopped", "by": "stop"}


def _session_schema():
    return object_schema({"session_id": {"type": "string"}}, required=("session_id",))


def make_registry(capture: _FakeCapture | None = None) -> Registry:
    reg = Registry()
    reg.register(ToolSpec("echo", "Echo params.", ALL_TYPES_SCHEMA, _echo, "read"))
    reg.register(ToolSpec("boom", "Always fails.", object_schema({}), _boom, "read"))
    if capture is not None:
        start_schema = object_schema({"target": {"type": "string"},
                                      "duration": {"type": "integer"}})
        reg.register(ToolSpec("start_capture", "Start.", start_schema, capture.start,
                              "capture", mutating=True))
        reg.register(ToolSpec("capture_status", "Status.", _session_schema(), capture.status,
                              "capture"))
        reg.register(ToolSpec("stop_capture", "Stop.", _session_schema(), capture.stop,
                              "capture", mutating=True))
    return reg


def run(tokens, reg=None):
    out, err = io.StringIO(), io.StringIO()
    runner = cli.QueryCli(reg or make_registry(), out, err, sleep=lambda _s: None)
    code = runner.run(tokens)
    return code, out.getvalue(), err.getvalue()


def run_json(tokens, reg=None):
    code, out, _ = run(tokens, reg)
    return code, json.loads(out)


# --- flag generation --------------------------------------------------------

def test_flags_cover_all_param_types():
    code, doc = run_json([
        "echo", "--tap", "a.tap", "--max-bytes", "5", "--ratio", "0.5", "--show-values",
        "--format", "md", "--fields", "a,b", "--fields", "c", "--ports", "1,2",
        "--options", '{"k": 1}',
    ])
    assert code == 0
    assert doc["params"] == {"tap": "a.tap", "max_bytes": 5, "ratio": 0.5, "show_values": True,
                             "format": "md", "fields": ["a", "b", "c"], "ports": [1, 2],
                             "options": {"k": 1}}


def test_underscore_alias_and_no_flag():
    _, doc = run_json(["echo", "--tap", "a.tap", "--max_bytes", "7", "--no-show-values"])
    assert doc["params"]["max_bytes"] == 7
    assert doc["params"]["show_values"] is False


def test_defaults_applied_when_flags_absent():
    _, doc = run_json(["echo", "--tap", "a.tap"])
    assert doc["params"] == {"tap": "a.tap", "max_bytes": 10, "show_values": False}


def test_json_and_flags_parity():
    payload = {"tap": "a.tap", "max_bytes": 3, "fields": ["x", "y"], "format": "json"}
    _, via_json = run_json(["echo", "--json", json.dumps(payload)])
    _, via_flags = run_json(["echo", "--tap", "a.tap", "--max-bytes", "3",
                             "--fields", "x,y", "--format", "json"])
    assert via_json == via_flags


def test_params_file_json_flags_precedence(tmp_path):
    params_file = tmp_path / "p.json"
    params_file.write_text(json.dumps({"tap": "file.tap", "max_bytes": 1, "ratio": 2.0}))
    _, doc = run_json(["echo", "--params-file", str(params_file),
                       "--json", '{"max_bytes": 2}', "--tap", "flag.tap"])
    assert doc["params"]["tap"] == "flag.tap"
    assert doc["params"]["max_bytes"] == 2
    assert doc["params"]["ratio"] == 2.0


def test_conflicting_param_name_is_skipped_not_crashing():
    reg = Registry()
    schema = object_schema({"root": {"type": "string"}, "compact": {"type": "boolean"}})
    reg.register(ToolSpec("clash", "Clash.", schema, _echo, "read"))
    parser = cli.build_tool_parser(reg.get("clash"), io.StringIO())
    assert isinstance(parser, argparse.ArgumentParser)
    _, doc = run_json(["clash", "--json", '{"root": "x"}'], reg)
    assert doc["params"]["root"] == "x"


def _secret_registry():
    reg = Registry()
    schema = object_schema({"format": {"type": "string"},
                            "confirm_secrets": {"type": "boolean", "default": False}})
    reg.register(ToolSpec("export", "Export.", schema, _echo, "export", mutating=True))
    return reg


def test_allow_secrets_switch_is_policy_only():
    """``--allow-secrets`` is the server policy; it never confirms the call by itself."""
    _, doc = run_json(["export", "--format", "keylog", "--allow-secrets"], _secret_registry())
    assert doc["allow_secrets"] is True
    assert doc["params"]["confirm_secrets"] is False


def test_confirm_secrets_is_a_generated_flag():
    _, doc = run_json(["export", "--format", "keylog", "--allow-secrets", "--confirm-secrets"],
                      _secret_registry())
    assert doc["allow_secrets"] is True
    assert doc["params"]["confirm_secrets"] is True


def test_query_cli_always_allows_values():
    _, doc = run_json(["echo", "--tap", "a", "--show-values"])
    assert doc["allow_values"] is True
    assert doc["params"]["show_values"] is True


# --- output -----------------------------------------------------------------

def test_compact_output_is_single_line():
    code, out, _ = run(["echo", "--tap", "a.tap", "--compact"])
    assert code == 0
    assert out.count("\n") == 1
    assert json.loads(out)["params"]["tap"] == "a.tap"


def test_pretty_output_is_default():
    _, out, _ = run(["echo", "--tap", "a.tap"])
    assert out.count("\n") > 1


def test_context_root_and_secrets(tmp_path):
    _, doc = run_json(["echo", "--tap", "a", "--root", str(tmp_path), "--allow-secrets"])
    assert doc["root"] == str(tmp_path.resolve())
    assert doc["allow_secrets"] is True
    assert doc["allow_capture"] is True
    _, doc = run_json(["echo", "--tap", "a"])
    assert doc["root"] == str(Path.cwd().resolve())
    assert doc["allow_secrets"] is False


# --- errors -----------------------------------------------------------------

@pytest.mark.parametrize("tokens,error_type,exit_code", [
    (["nope"], "unknown_tool", EXIT_USAGE_ERROR),
    (["echo"], "bad_param", EXIT_USAGE_ERROR),  # missing required tap
    (["echo", "--tap", "a", "--max-bytes", "x"], "bad_param", EXIT_USAGE_ERROR),
    (["echo", "--tap", "a", "--format", "xml"], "bad_param", EXIT_USAGE_ERROR),
    (["echo", "--tap", "a", "--ports", "1,z"], "bad_param", EXIT_USAGE_ERROR),
    (["echo", "--tap", "a", "--options", "{bad"], "bad_param", EXIT_USAGE_ERROR),
    (["echo", "--json", "[1]"], "bad_param", EXIT_USAGE_ERROR),
    (["echo", "--json", "{oops"], "bad_param", EXIT_USAGE_ERROR),
    (["echo", "--params-file", "/nonexistent/p.json"], "not_found", EXIT_USAGE_ERROR),
    (["echo", "--tap", "a", "--bogus"], "bad_param", EXIT_USAGE_ERROR),
    (["boom"], "runtime_error", EXIT_RUNTIME_ERROR),
])
def test_errors_are_json_on_stdout_with_exit_code(tokens, error_type, exit_code):
    code, doc = run_json(tokens)
    assert code == exit_code
    assert doc["error_type"] == error_type
    assert doc["exit_code"] == exit_code
    assert doc["error"]


# --- list / help ------------------------------------------------------------

def test_list_table_and_json():
    code, out, _ = run(["--list"])
    assert code == 0
    assert "echo" in out and "boom" in out and "KIND" in out
    _, docs = run_json(["--list", "--json"])
    assert [d["name"] for d in docs] == ["boom", "echo"]
    assert "params_schema" in docs[1] and "handler" not in docs[1]


def test_help_json_prints_spec():
    code, doc = run_json(["echo", "--help-json"])
    assert code == 0
    assert doc["name"] == "echo"
    assert doc["params_schema"] == ALL_TYPES_SCHEMA


def test_help_and_bare_q_print_usage():
    for tokens in ([], ["-h"]):
        code, out, _ = run(tokens)
        assert code == 0
        assert "usage: fritap q" in out and "echo" in out


def test_tool_help_lists_generated_flags():
    code, out, _ = run(["echo", "--help"])
    assert code == 0
    assert "--max-bytes" in out and "--no-show-values" in out


# --- start_capture wait loop ------------------------------------------------

def test_start_capture_waits_until_session_ends():
    capture = _FakeCapture(["running", "running", "stopped"])
    code, out, err = run(["start_capture", "--target", "app"], make_registry(capture))
    assert code == 0
    assert json.loads(out)["state"] == "stopped"
    assert capture.status_calls == 3
    assert "s1" in err


def test_start_capture_no_wait_returns_immediately():
    capture = _FakeCapture(["running"])
    _, doc = run_json(["start_capture", "--no-wait"], make_registry(capture))
    assert doc["state"] == "starting"
    assert capture.status_calls == 0


def test_start_capture_ctrl_c_stops_session():
    capture = _FakeCapture(["running"] * 5, interrupt_after=1)
    _, doc = run_json(["start_capture"], make_registry(capture))
    assert capture.stopped
    assert doc["by"] == "stop"


# --- server options ---------------------------------------------------------

def test_server_options_build_context(tmp_path):
    parser = argparse.ArgumentParser()
    add_server_options(parser)
    ns = parser.parse_args(["--root", str(tmp_path), "--allow-target", "com.*",
                            "--allow-target", "curl", "--max-response-bytes", "1000"])
    ctx = build_context(ns)
    assert ctx.root == tmp_path.resolve()
    assert ctx.allow_capture is False
    assert ctx.allow_targets == ("com.*", "curl")
    assert ctx.max_response_bytes == 1000
    assert ctx.allow_values is False
    ctx = build_context(parser.parse_args(["--allow-capture", "--allow-secrets",
                                           "--allow-values"]))
    assert ctx.allow_capture and ctx.allow_secrets and ctx.allow_values
    takes_value = option_takes_value(parser)
    assert {name for name, value in takes_value.items() if value} >= {
        "--root", "--allow-target", "--max-response-bytes"}
    assert not any(takes_value[name] for name in ("--allow-capture", "--allow-secrets",
                                                   "--allow-values", "-h"))


def test_build_context_overrides_win(tmp_path):
    parser = argparse.ArgumentParser()
    add_server_options(parser)
    ctx = build_context(parser.parse_args([]), allow_capture=True, allow_values=True)
    assert ctx.allow_capture and ctx.allow_values


@pytest.mark.parametrize("argv,expected", [
    (["fritap", "mcp"], True),
    (["fritap", "mcp", "--root", "x"], True),
    (["fritap", "mcp", "--root=x", "--allow-capture"], True),
    (["fritap", "serve", "--allow-values", "--root", "x"], True),
    (["fritap", "mcp", "--http", "--port", "8080", "--token", "t"], True),
    (["fritap", "mcp", "-m"], False),
    (["fritap", "mcp", "--allow-capture", "firefox"], False),
    (["fritap", "mcp", "-k", "k.log"], False),
])
def test_is_server_invocation(argv, expected):
    assert is_server_invocation(argv, mcp_command.build_parser()) is expected
    assert mcp_command.is_mcp_invocation(argv) is expected


def test_serve_has_no_http_flag():
    assert not serve_command.is_serve_invocation(["fritap", "serve", "--http"])
    assert serve_command.is_serve_invocation(["fritap", "serve", "--port", "1", "--token", "t"])


def test_server_invocation_follows_the_parser():
    """A new parser option is accepted without a second hand-kept list."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--level", type=int)
    parser.add_argument("--quiet", action="store_true")
    assert is_server_invocation(["fritap", "x", "--level", "3", "--quiet"], parser)
    assert not is_server_invocation(["fritap", "x", "--quiet", "firefox"], parser)
    assert leading_option_count(["--level", "--quiet", "t"], parser) == 2


# --- dispatch ---------------------------------------------------------------

def test_is_query_invocation_is_lazy_for_flags():
    def names():
        raise AssertionError("tool modules must not load")
    assert not cli.is_query_invocation(["fritap", "q", "-k", "k.log"], names)
    assert cli.is_query_invocation(["fritap", "q", "--list"], names)
    assert not cli.is_query_invocation(["fritap", "q"], names)
    assert cli.is_query_invocation(["fritap", "q", "echo"], lambda: ["echo"])
    assert not cli.is_query_invocation(["fritap", "q", "firefox"], lambda: ["echo"])


@pytest.fixture
def dispatch(monkeypatch):
    from friTap import friTap as main_module
    registry_module = importlib.import_module("friTap.agent_api.registry")

    monkeypatch.setattr(registry_module.registry, "names", lambda: ["get_digest"])
    return main_module._dispatch_special_mode


@pytest.mark.parametrize("argv,expected", [
    (["fritap", "q", "-k", "k.log"], None),
    (["fritap", "q", "firefox"], None),
    (["fritap", "q", "--list"], ("q", ["--list"])),
    (["fritap", "q", "get_digest", "--tap", "a.tap"], ("q", ["get_digest", "--tap", "a.tap"])),
    (["fritap", "mcp", "--root", "x"], ("mcp", ["--root", "x"])),
    (["fritap", "mcp"], ("mcp", [])),
    (["fritap", "mcp", "-k", "k.log"], None),
    (["fritap", "serve", "--port", "8000", "--allow-capture"],
     ("serve", ["--port", "8000", "--allow-capture"])),
    (["fritap", "serve", "-m"], None),
])
def test_dispatch_special_mode(dispatch, argv, expected):
    assert dispatch(argv) == expected


def test_main_runs_q_and_returns_exit_code(monkeypatch, capsys):
    from friTap import friTap as main_module
    registry_module = importlib.import_module("friTap.agent_api.registry")

    reg = make_registry()
    monkeypatch.setattr(registry_module, "registry", reg)
    monkeypatch.setattr("sys.argv", ["fritap", "q", "boom", "--compact"])
    assert main_module.main() == EXIT_RUNTIME_ERROR
    assert json.loads(capsys.readouterr().out)["error_type"] == "runtime_error"


def test_tool_error_hint_on_parser_error():
    with pytest.raises(ToolError) as info:
        cli.build_tool_parser(make_registry().get("echo"), io.StringIO()).parse_args(["--x"])
    assert "fritap q echo" in info.value.hint


# --- q-level options before the tool / unknown-tool dispatch -----------------

@pytest.mark.parametrize("tokens,expected", [
    (["--root", "X", "echo", "--tap", "a"], (["--root", "X"], ["echo", "--tap", "a"])),
    (["--root=X", "--compact", "echo"], (["--root=X", "--compact"], ["echo"])),
    (["--allow-secrets", "--max-response-bytes", "9", "echo"],
     (["--allow-secrets", "--max-response-bytes", "9"], ["echo"])),
    (["echo", "--root", "X"], ([], ["echo", "--root", "X"])),
    (["--root"], (["--root"], [])),
    (["-k", "k.log"], ([], ["-k", "k.log"])),
])
def test_split_leading_options(tokens, expected):
    assert cli.split_leading_options(tokens) == expected


def test_leading_q_options_apply_to_tool(tmp_path):
    code, out, _ = run(["--root", str(tmp_path), "--allow-secrets", "--compact",
                        "echo", "--tap", "a"])
    assert code == 0
    assert out.count("\n") == 1
    doc = json.loads(out)
    assert doc["root"] == str(tmp_path.resolve())
    assert doc["allow_secrets"] is True


def test_leading_compact_applies_to_list():
    code, out, _ = run(["--compact", "--list", "--json"])
    assert code == 0 and out.count("\n") == 1


def test_unknown_tool_after_leading_options_has_did_you_mean():
    code, doc = run_json(["--root", ".", "ecoh"])
    assert code == EXIT_USAGE_ERROR
    assert doc["error_type"] == "unknown_tool"
    assert "echo" in doc["hint"]


@pytest.mark.parametrize("argv,expected", [
    (["fritap", "q", "--root", "X", "echo"], True),
    (["fritap", "q", "--compact", "--list"], True),
    (["fritap", "q", "--max-response-bytes=5", "echo"], True),
    (["fritap", "q", "--allow-secrets"], True),
    (["fritap", "q", "ecoh"], True),              # close match of "echo"
    (["fritap", "q", "no_such_tool"], False),     # underscores alone are no tool
    (["fritap", "q", "com.example.my_app"], False),  # app id -> capture
    (["fritap", "q", "firefox"], False),          # capture target
    (["fritap", "q", "-k", "k.log"], False),
    (["fritap", "q", "firefox", "-k", "k.log"], False),
])
def test_is_query_invocation_rule(argv, expected):
    assert cli.is_query_invocation(argv, lambda: ["echo", "get_digest"]) is expected


def test_looks_like_tool_name():
    names = ["get_digest", "echo"]
    assert cli.looks_like_tool_name("get_digest", names)
    assert cli.looks_like_tool_name("get_digets", names)
    assert not cli.looks_like_tool_name("foo_bar", names)
    assert not cli.looks_like_tool_name("com.example.my_app", names)
    assert not cli.looks_like_tool_name("firefox", names)


@pytest.mark.parametrize("argv,expected", [
    (["fritap", "q", "--root", "x", "get_digest"], ("q", ["--root", "x", "get_digest"])),
    (["fritap", "q", "get_digets"], ("q", ["get_digets"])),
    (["fritap", "q", "com.example.my_app"], None),
    (["fritap", "q", "com.example.my_app", "-k", "k.log"], None),
])
def test_dispatch_special_mode_q_options_and_unknown_tools(dispatch, argv, expected):
    assert dispatch(argv) == expected
