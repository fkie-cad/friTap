"""
Shared command-line options of the agent adapters (``fritap q``, ``mcp``, ``serve``).

``add_server_options(parser)`` adds the sandbox/permission flags and
``build_context(ns)`` turns the parsed namespace into a :class:`ToolContext`.
Servers (MCP/REST) deny capture unless ``--allow-capture`` is given and
redact finding values unless ``--allow-values`` is given.

``is_server_invocation(argv, parser)`` is the pre-argparse dispatch guard (same
idea as :func:`friTap.commands.devices.is_listing_invocation`): ``fritap mcp``
/ ``fritap serve`` is only the subcommand when EVERY following token is one of
its options, so ``fritap serve -m`` still captures a process named ``serve``.
Option names and whether they take a value are read from the command's real
argparse parser, so a new option needs no second list.
"""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Sequence

from friTap.agent_api.context import DEFAULT_MAX_RESPONSE_BYTES, ToolContext


def add_context_options(parser: argparse.ArgumentParser) -> None:
    """Options every adapter shares: ``--root``, ``--allow-secrets``, ``--max-response-bytes``."""
    parser.add_argument("--root", default=None, metavar="DIR",
                        help="Sandbox root for .tap paths and exports (default: cwd).")
    parser.add_argument("--allow-secrets", action="store_true",
                        help="Allow tools to produce key material (keylog export).")
    parser.add_argument("--max-response-bytes", type=int, metavar="N",
                        default=DEFAULT_MAX_RESPONSE_BYTES,
                        help=f"Cap on a JSON response (default {DEFAULT_MAX_RESPONSE_BYTES}).")


def add_server_options(parser: argparse.ArgumentParser) -> None:
    """Add the shared MCP/REST sandbox and permission options to ``parser``."""
    add_context_options(parser)
    parser.add_argument("--allow-capture", action="store_true",
                        help="Allow capture tools to start live captures (off by default).")
    parser.add_argument("--allow-target", action="append", default=[], metavar="PATTERN",
                        help="fnmatch pattern of an allowed capture target (repeatable).")
    parser.add_argument("--allow-values", action="store_true",
                        help="Allow show_values=true to return unredacted finding values "
                             "(off by default).")


def _option_or(ns: argparse.Namespace, name: str, override: bool | None) -> bool:
    """``override`` when given, else the parsed switch ``ns.<name>`` (False if absent)."""
    return bool(getattr(ns, name, False)) if override is None else override


def build_context(ns: argparse.Namespace, *, allow_capture: bool | None = None,
                  allow_values: bool | None = None) -> ToolContext:
    """Build the :class:`ToolContext` from parsed options.

    ``allow_capture`` / ``allow_values`` override the parsed switches (the
    ``fritap q`` CLI always allows both: the local user owns the data).
    """
    root = Path(ns.root).expanduser() if ns.root else Path.cwd()
    return ToolContext(
        root=root.resolve(),
        allow_capture=_option_or(ns, "allow_capture", allow_capture),
        allow_targets=tuple(getattr(ns, "allow_target", None) or ()),
        allow_secrets=bool(ns.allow_secrets),
        allow_values=_option_or(ns, "allow_values", allow_values),
        max_response_bytes=ns.max_response_bytes,
    )


def option_takes_value(parser: argparse.ArgumentParser) -> dict[str, bool]:
    """``{option string: takes a value}`` for every option of ``parser``."""
    return {name: action.nargs != 0 for name, action in parser._option_string_actions.items()}


def leading_option_count(tokens: Sequence[str], parser: argparse.ArgumentParser) -> int:
    """How many leading ``tokens`` are options of ``parser`` (with their values).

    ``--opt=value`` is accepted; a value option consumes the next token unless
    that token is itself an option. Stops at the first other token.
    """
    takes_value = option_takes_value(parser)
    index = 0
    while index < len(tokens):
        token = tokens[index]
        name = token.split("=", 1)[0]
        if name not in takes_value:
            break
        index += 1
        if takes_value[name] and "=" not in token and index < len(tokens) \
                and not tokens[index].startswith("-"):
            index += 1
    return index


def is_server_invocation(argv: Sequence[str], parser: argparse.ArgumentParser) -> bool:
    """True when every token after ``argv[1]`` is an option of ``parser`` (or its value)."""
    tokens = list(argv[2:])
    return leading_option_count(tokens, parser) == len(tokens)


__all__ = [
    "add_context_options",
    "add_server_options",
    "build_context",
    "option_takes_value",
    "leading_option_count",
    "is_server_invocation",
]
