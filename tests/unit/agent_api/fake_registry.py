"""A small in-memory tool registry shared by the adapter tests."""

from __future__ import annotations

from friTap.agent_api.errors import ToolError
from friTap.agent_api.registry import Registry, ToolSpec
from friTap.agent_api.schema import object_schema
from friTap.exit_codes import EXIT_RUNTIME_ERROR

ECHO_SCHEMA = object_schema(
    {"text": {"type": "string", "maxLength": 64}, "times": {"type": "integer", "minimum": 1, "default": 1}},
    required=("text",),
)
RESULT_SCHEMA = {"type": "object", "properties": {"echo": {"type": "string"}}}


def _echo(params, ctx):
    return {"schema": "test.echo/1", "echo": params["text"] * params["times"]}


def _fail(params, ctx):
    error_type = params.get("error_type", "runtime_error")
    exit_code = EXIT_RUNTIME_ERROR if error_type == "runtime_error" else 2
    raise ToolError(f"failed with {error_type}", error_type, exit_code=exit_code)


def _capture(params, ctx):
    return {"allow_capture": ctx.allow_capture, "root": str(ctx.root)}


REVEAL_SCHEMA = object_schema({"show_values": {"type": "boolean", "default": False}})


def _reveal(params, ctx):
    return {"show_values": params["show_values"]}


def make_reveal_registry() -> Registry:
    """A registry with one ``reveal`` tool taking ``show_values`` (for value gating)."""
    reg = Registry()
    reg.register(ToolSpec("reveal", "Reveal values.", REVEAL_SCHEMA, _reveal, "read"))
    return reg


def make_registry() -> Registry:
    reg = Registry()
    reg.register(ToolSpec("echo", "Echo text.", ECHO_SCHEMA, _echo, "read", result_schema=RESULT_SCHEMA))
    reg.register(ToolSpec("fail", "Always fails.", object_schema({"error_type": {"type": "string"}}),
                          _fail, "discover"))
    reg.register(ToolSpec("start_thing", "Mutating capture tool.", object_schema({}), _capture,
                          "capture", mutating=True))
    return reg
