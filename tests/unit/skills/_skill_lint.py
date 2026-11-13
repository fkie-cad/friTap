"""
Helpers that check SKILL.md text against friTap's real CLI and tool registry.

Conventions the skill authors follow (and these helpers rely on):

* CLI commands sit in fenced code blocks, one command per line, starting with
  ``fritap `` (optionally after ``$ `` and/or ``sudo ``). A line containing
  ``# noqa-flag`` is skipped.
* Agent tools are written as ``fritap q <tool> --param value``.
"""

from __future__ import annotations

import argparse
import io
import re
import shlex
from typing import Iterable, Iterator

from friTap.skills import Traversable

NOQA_FLAG = "# noqa-flag"
_FENCE = re.compile(r"^\s*(```|~~~)")
_COMMAND_PREFIX = re.compile(r"^\s*(?:\$\s+)?(?:sudo\s+(?:-\S+\s+)*)?fritap\s+(?P<args>.*)$")
_Q_INVOCATION = re.compile(r"\bfritap\s+q\s+(?P<rest>[^`\n]*)")
_LONG_OPTION = re.compile(r"^--[A-Za-z0-9][\w-]*$")
_TRAILING_COMMENT = re.compile(r"\s+#.*$")

# Dispatch-level flags handled before the capture parser (friTap.friTap.main).
_ANALYZE_FLAG = "--analyze"
_FROM_PCAP_FLAG = "--from-pcap"
_REPLAY_FLAGS = ("-r", "--replay")
_LISTING_OPTIONS = {"--json", "--running", "--mobile", "--device", "--host", "--help"}
_Q_LIST_OPTIONS = {"--list", "--json", "--compact", "--help"}


# ---------------------------------------------------------------------------
# Markdown scanning
# ---------------------------------------------------------------------------

def markdown_files(skill_dir: Traversable) -> Iterator[Traversable]:
    """``SKILL.md`` and every ``*.md`` below the skill directory (e.g. references/)."""
    for entry in skill_dir.iterdir():
        if entry.is_dir() and entry.name != "__pycache__":
            yield from markdown_files(entry)
        elif entry.name.endswith(".md"):
            yield entry


def fenced_lines(text: str) -> Iterator[str]:
    """Lines inside fenced code blocks, with ``\\`` continuations joined."""
    inside, pending = False, ""
    for line in text.splitlines():
        if _FENCE.match(line):
            inside, pending = not inside, ""
            continue
        if not inside:
            continue
        if line.rstrip().endswith("\\"):
            pending += line.rstrip()[:-1] + " "
            continue
        yield pending + line
        pending = ""


def fritap_command_args(line: str) -> list[str] | None:
    """Tokens after ``fritap`` for a command line, or None (not a command / noqa)."""
    if NOQA_FLAG in line:
        return None
    match = _COMMAND_PREFIX.match(line)
    if not match:
        return None
    args = _TRAILING_COMMENT.sub("", match.group("args"))
    try:
        return shlex.split(args)
    except ValueError:
        return args.split()


def command_lines(text: str) -> Iterator[list[str]]:
    """Token lists of every ``fritap ...`` command line in fenced blocks."""
    for line in fenced_lines(text):
        args = fritap_command_args(line)
        if args is not None:
            yield args


def long_options(tokens: Iterable[str]) -> list[str]:
    """``--name`` tokens (``=value`` stripped), stopping at a bare ``--``."""
    found = []
    for token in tokens:
        if token == "--":
            break
        option = token.split("=", 1)[0]
        if _LONG_OPTION.match(option):
            found.append(option)
    return found


# ---------------------------------------------------------------------------
# Tool references
# ---------------------------------------------------------------------------

def _tool_after_leading_options(tokens: list[str]) -> str | None:
    from friTap.agent_api.adapters.cli import split_leading_options

    _, rest = split_leading_options(tokens)
    if not rest or rest[0].startswith("-"):
        return None
    return rest[0]


def referenced_tools(text: str) -> set[str]:
    """Tool names written as ``fritap q <tool>`` anywhere in ``text``."""
    tools = set()
    for match in _Q_INVOCATION.finditer(text):
        name = _tool_after_leading_options(match.group("rest").split())
        if name and re.fullmatch(r"[A-Za-z_][\w]*", name):
            tools.add(name)
    return tools


# ---------------------------------------------------------------------------
# Known options per command
# ---------------------------------------------------------------------------

def parser_long_options(parser: argparse.ArgumentParser) -> set[str]:
    """Long option strings of ``parser`` and of all its subparsers."""
    options = {o for o in parser._option_string_actions if o.startswith("--")}
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            for sub in action.choices.values():
                options |= parser_long_options(sub)
    return options


def _q_options(args: list[str]) -> set[str]:
    from friTap.agent_api.adapters.cli import build_tool_parser, leading_options_parser
    from friTap.agent_api.registry import registry

    allowed = parser_long_options(leading_options_parser()) | _Q_LIST_OPTIONS
    tool = _tool_after_leading_options(args)
    if tool in registry.names():
        allowed |= parser_long_options(build_tool_parser(registry.get(tool), io.StringIO()))
    return allowed


def _subcommand_parser(name: str) -> argparse.ArgumentParser | None:
    if name == "mcp":
        from friTap.commands.mcp import build_parser
    elif name == "serve":
        from friTap.commands.serve import build_parser
    elif name == "skills":
        from friTap.commands.skills import build_parser
    elif name in ("analyze", _ANALYZE_FLAG):
        from friTap.commands.analyze import _build_parser as build_parser
    elif name == "report":
        from friTap.commands.report import _build_parser as build_parser
    else:
        return None
    return build_parser()


def known_options(args: list[str]) -> set[str]:
    """Long options the ``fritap <args>`` invocation accepts."""
    head = args[0] if args else ""
    if head == "q":
        return _q_options(args[1:])
    if head in ("devices", "apps"):
        return set(_LISTING_OPTIONS)
    if _FROM_PCAP_FLAG in args:
        from friTap.offline.cli import _build_parser
        return parser_long_options(_build_parser()) | {_FROM_PCAP_FLAG}
    if head in _REPLAY_FLAGS or head == "install-backend":
        return {"--replay"}
    parser = _subcommand_parser(head)
    if parser is not None:
        return parser_long_options(parser) | {_ANALYZE_FLAG}
    from friTap.friTap import build_capture_parser
    return parser_long_options(build_capture_parser())


def unknown_options(text: str) -> list[tuple[str, str]]:
    """(command, option) pairs for every unknown long option in ``text``."""
    problems = []
    for args in command_lines(text):
        allowed = known_options(args)
        for option in long_options(args):
            if option not in allowed:
                problems.append(("fritap " + " ".join(args), option))
    return problems
