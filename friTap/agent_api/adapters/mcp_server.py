"""
MCP adapter: exposes the tool registry over the Model Context Protocol.

Transports: stdio (default) and streamable HTTP (``serve_http``). The ``mcp``
package is an optional extra (``pip install 'fritap[mcp]'``) and is imported
only inside this module. With stdio, stdout belongs to the protocol: logging
goes to stderr and stray ``print`` calls are redirected there too.
"""

from __future__ import annotations

import logging
import sys
from contextlib import asynccontextmanager
from functools import partial

from friTap.agent_api.adapters.bind_policy import bearer_matches
from friTap.agent_api.context import ToolContext
from friTap.agent_api.envelope import dumps_compact
from friTap.agent_api.errors import ToolError
from friTap.agent_api.registry import Registry, ToolSpec
from friTap.agent_api.schema import split_top_level_groups

logger = logging.getLogger("friTap.agent_api.mcp")

DEFAULT_HTTP_PORT = 8765
MCP_PATH = "/mcp"
SERVER_NAME = "fritap"
MISSING_MCP_ERROR = {
    "error": "mcp package not installed",
    "error_type": "missing_dependency",
    "hint": "pip install 'fritap[mcp]'",
    "exit_code": 2,
}


def mcp_available() -> bool:
    """True if the optional ``mcp`` package can be imported."""
    try:
        import mcp.server.lowlevel  # noqa: F401
    except ImportError:
        return False
    return True


def tool_definition(spec: ToolSpec):
    """Build the ``mcp.types.Tool`` for ``spec``.

    A top-level ``oneOf`` (e.g. "``tap`` or ``session_id``") makes Claude clients
    drop the tool, so the group is stated in the description instead.
    """
    from mcp import types

    input_schema, group_note = split_top_level_groups(spec.params_schema)
    return types.Tool(
        name=spec.name,
        description=f"{spec.summary} {group_note}".strip(),
        inputSchema=input_schema,
        annotations=types.ToolAnnotations(
            readOnlyHint=not spec.mutating,
            destructiveHint=spec.mutating and spec.kind == "capture",
            openWorldHint=spec.kind == "capture",
        ),
    )


def call_tool_result(registry: Registry, context: ToolContext, name: str, arguments: dict | None):
    """Run a tool synchronously and wrap the outcome in ``CallToolResult``.

    The MCP spec (2025-06-18, "Structured Content") says a tool returning
    ``structuredContent`` SHOULD also return the serialized JSON in a text
    block for clients without structured-output support, so both are sent;
    the text is the compact JSON the size cap already produced (encoded once).
    """
    from mcp import types

    try:
        result, text = registry.call_json(name, arguments or {}, context=context)
    except ToolError as err:
        return types.CallToolResult(
            content=[types.TextContent(type="text", text=dumps_compact(err.to_dict()))], isError=True
        )
    return types.CallToolResult(
        content=[types.TextContent(type="text", text=text)],
        structuredContent=result,
        isError=False,
    )


PROMPT_ARGUMENTS = (
    ("target", "App or process to analyze (package name, process name or PID)."),
    ("device", "Device to use (e.g. a USB/adb serial); omit for the local host."),
)


def prompt_definition(skill):
    """Build the ``mcp.types.Prompt`` for a packaged ``friTap.skills.Skill``."""
    from mcp import types

    arguments = [types.PromptArgument(name=name, description=text, required=False)
                 for name, text in PROMPT_ARGUMENTS]
    return types.Prompt(name=skill.name, description=skill.description, arguments=arguments)


def list_prompt_definitions() -> list:
    """One MCP prompt per packaged skill, sorted by name."""
    from friTap.skills import list_skills

    return [prompt_definition(skill) for skill in list_skills()]


def prompt_preamble(arguments: dict | None) -> str:
    """Short first line naming the given target and device (empty when neither is set)."""
    given = [(name, (arguments or {}).get(name)) for name, _ in PROMPT_ARGUMENTS]
    parts = [f"{name} `{value}`" for name, value in given if value]
    return f"Apply this workflow to {' on '.join(parts)}.\n\n" if parts else ""


def get_prompt_result(name: str, arguments: dict | None):
    """Render skill ``name`` as a ``GetPromptResult``; unknown names raise ``McpError``."""
    from mcp import types

    skill = _skill_or_mcp_error(name)
    text = prompt_preamble(arguments) + skill.body
    message = types.PromptMessage(role="user", content=types.TextContent(type="text", text=text))
    return types.GetPromptResult(description=skill.description, messages=[message])


def _skill_or_mcp_error(name: str):
    """The skill called ``name``; an unknown name is a JSON-RPC invalid-params error."""
    from mcp import types
    from mcp.shared.exceptions import McpError

    from friTap.skills import get_skill

    try:
        return get_skill(name)
    except KeyError:
        error = ToolError(f"unknown prompt {name!r}", "unknown_prompt",
                          hint="list_prompts shows the available prompts")
        raise McpError(types.ErrorData(code=types.INVALID_PARAMS, message=error.error,
                                       data=error.to_dict())) from None


def build_server(registry: Registry, context: ToolContext):
    """Create the low-level MCP ``Server`` bound to ``registry`` and ``context``."""
    import anyio
    from mcp.server.lowlevel import Server

    from friTap.about import __version__

    server = Server(SERVER_NAME, version=__version__)

    @server.list_tools()
    async def _list_tools():
        return [tool_definition(spec) for spec in registry.specs()]

    # The registry validates params itself and returns better errors (hints).
    @server.call_tool(validate_input=False)
    async def _call_tool(name: str, arguments: dict):
        # Tools block (file IO, subprocess control): keep the event loop free.
        return await anyio.to_thread.run_sync(partial(call_tool_result, registry, context, name, arguments))

    _register_prompts(server)
    return server


def _register_prompts(server) -> None:
    """Expose the packaged skills as MCP prompts (this also advertises ``prompts``)."""

    @server.list_prompts()
    async def _list_prompts():
        return list_prompt_definitions()

    @server.get_prompt()
    async def _get_prompt(name: str, arguments: dict | None):
        return get_prompt_result(name, arguments)


def route_logging_to_stderr(level: int = logging.WARNING) -> None:
    """Send every log record to stderr (stdout is reserved for stdio MCP)."""
    root = logging.getLogger()
    for handler in list(root.handlers):
        if getattr(handler, "stream", None) is sys.stdout:
            root.removeHandler(handler)
    if not root.handlers:
        logging.basicConfig(stream=sys.stderr, level=level)


def serve_stdio(registry: Registry, context: ToolContext) -> None:
    """Run the MCP server on stdin/stdout until the client disconnects."""
    import anyio

    route_logging_to_stderr()
    server = build_server(registry, context)
    anyio.run(_run_stdio, server)


async def _run_stdio(server) -> None:
    from io import TextIOWrapper

    import anyio
    from mcp.server.stdio import stdio_server

    protocol_out = anyio.wrap_file(TextIOWrapper(sys.stdout.buffer, encoding="utf-8"))
    sys.stdout = sys.stderr  # stray prints must not corrupt the JSON-RPC stream
    async with stdio_server(stdout=protocol_out) as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


def build_http_app(registry: Registry, context: ToolContext, *, host: str, token: str | None = None):
    """Starlette ASGI app serving streamable-HTTP MCP at ``/mcp``."""
    from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
    from starlette.applications import Starlette
    from starlette.routing import Mount

    manager = StreamableHTTPSessionManager(
        app=build_server(registry, context), security_settings=_transport_security(host)
    )

    async def handle(scope, receive, send):
        await manager.handle_request(scope, receive, send)

    @asynccontextmanager
    async def lifespan(_app):
        async with manager.run():
            yield

    app = Starlette(routes=[Mount(MCP_PATH, app=handle)], lifespan=lifespan)
    return BearerAuth(app, token) if token else app


def _transport_security(host: str):
    """DNS-rebinding protection for loopback binds; token auth guards the rest."""
    from mcp.server.transport_security import TransportSecuritySettings

    from friTap.agent_api.adapters.bind_policy import is_loopback

    if not is_loopback(host):
        return TransportSecuritySettings(enable_dns_rebinding_protection=False)
    hosts = ["127.0.0.1:*", "localhost:*", "[::1]:*", "127.0.0.1", "localhost", "[::1]"]
    origins = [f"http://{h}" for h in hosts]
    return TransportSecuritySettings(allowed_hosts=hosts, allowed_origins=origins)


class BearerAuth:
    """ASGI middleware rejecting HTTP requests without the bearer token."""

    def __init__(self, app, token: str) -> None:
        self.app = app
        self.token = token

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] == "http" and not self._authorized(scope):
            await _send_unauthorized(send)
            return
        await self.app(scope, receive, send)

    def _authorized(self, scope) -> bool:
        headers = dict(scope.get("headers") or [])
        value = headers.get(b"authorization", b"").decode("latin-1")
        return bearer_matches(value, self.token)


async def _send_unauthorized(send) -> None:
    body = dumps_compact({"error": "missing or invalid bearer token", "error_type": "unauthorized",
                     "exit_code": 2}).encode()
    headers = [(b"content-type", b"application/json"), (b"www-authenticate", b"Bearer")]
    await send({"type": "http.response.start", "status": 401, "headers": headers})
    await send({"type": "http.response.body", "body": body})


def serve_http(registry: Registry, context: ToolContext, *, host: str, port: int,
               token: str | None = None) -> None:
    """Serve streamable-HTTP MCP with uvicorn until interrupted."""
    import uvicorn

    route_logging_to_stderr(logging.INFO)
    app = build_http_app(registry, context, host=host, token=token)
    logger.warning("friTap MCP (streamable HTTP) on http://%s:%s%s", host, port, MCP_PATH)
    uvicorn.run(app, host=host, port=port, log_level="warning")


__all__ = [
    "DEFAULT_HTTP_PORT", "MISSING_MCP_ERROR", "MCP_PATH", "mcp_available", "tool_definition",
    "call_tool_result", "PROMPT_ARGUMENTS", "prompt_definition", "list_prompt_definitions",
    "prompt_preamble", "get_prompt_result", "build_server", "serve_stdio", "build_http_app", "serve_http", "BearerAuth",
]
