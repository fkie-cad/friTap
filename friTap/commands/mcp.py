"""
``fritap mcp`` — serve the agent tools over MCP (stdio by default, ``--http`` optional).

    fritap mcp --root ./captures
    fritap mcp --http --port 8765 --allow-capture --allow-target 'com.example.*'
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Sequence

from friTap.agent_api.adapters import mcp_server
from friTap.agent_api.adapters.bind_policy import (
    add_network_options,
    enforce_bind_policy,
)
from friTap.agent_api.adapters.server_options import (
    add_server_options,
    build_context,
    is_server_invocation,
)
from friTap.agent_api.registry import registry
from friTap.exit_codes import EXIT_OK, EXIT_USAGE_ERROR


def build_parser() -> argparse.ArgumentParser:
    """The argparse parser of ``fritap mcp`` (also drives the dispatch guard)."""
    parser = argparse.ArgumentParser(prog="fritap mcp", description="friTap agent tools as an MCP server.")
    add_server_options(parser)
    parser.add_argument("--http", action="store_true", help="Use streamable HTTP instead of stdio.")
    add_network_options(parser, default_port=mcp_server.DEFAULT_HTTP_PORT)
    return parser


def is_mcp_invocation(argv: Sequence[str]) -> bool:
    """True when every token after ``mcp`` in ``argv`` (``sys.argv``) is a ``fritap mcp`` option."""
    return is_server_invocation(argv, build_parser())


def run_mcp_cli(argv: Sequence[str]) -> int:
    """Entry point; ``argv`` are the tokens after ``mcp``. Returns the exit code."""
    parser = build_parser()
    ns = parser.parse_args(list(argv))
    if ns.http:
        enforce_bind_policy(parser, ns)
    if not mcp_server.mcp_available():
        print(json.dumps(mcp_server.MISSING_MCP_ERROR), file=sys.stderr)
        return EXIT_USAGE_ERROR
    context = build_context(ns)
    if ns.http:
        mcp_server.serve_http(registry, context, host=ns.host, port=ns.port, token=ns.token)
    else:
        mcp_server.serve_stdio(registry, context)
    return EXIT_OK
