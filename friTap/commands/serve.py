"""
``fritap serve`` — serve the agent tools as a local REST/JSON API (stdlib only).

    fritap serve --root ./captures              # http://127.0.0.1:8766/v1/tools
    fritap serve --host 0.0.0.0 --token SECRET  # non-loopback needs a token
"""

from __future__ import annotations

import argparse
import logging
import sys
from typing import Sequence

from friTap.agent_api.adapters import rest_server
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
from friTap.exit_codes import EXIT_OK


def build_parser() -> argparse.ArgumentParser:
    """The argparse parser of ``fritap serve`` (also drives the dispatch guard)."""
    parser = argparse.ArgumentParser(prog="fritap serve", description="friTap agent tools as a REST API.")
    add_server_options(parser)
    add_network_options(parser, default_port=rest_server.DEFAULT_PORT)
    return parser


def is_serve_invocation(argv: Sequence[str]) -> bool:
    """True when every token after ``serve`` in ``argv`` (``sys.argv``) is a ``fritap serve`` option."""
    return is_server_invocation(argv, build_parser())


def run_serve_cli(argv: Sequence[str]) -> int:
    """Entry point; ``argv`` are the tokens after ``serve``. Returns the exit code."""
    parser = build_parser()
    ns = parser.parse_args(list(argv))
    enforce_bind_policy(parser, ns)
    if not logging.getLogger().handlers:
        logging.basicConfig(stream=sys.stderr, level=logging.WARNING)
    app = rest_server.RestApp(registry=registry, context=build_context(ns), token=ns.token)
    rest_server.serve(app, ns.host, ns.port)
    return EXIT_OK
