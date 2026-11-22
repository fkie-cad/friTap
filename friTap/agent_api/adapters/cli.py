"""``fritap q``: run any agent tool from the shell, generated from the registry.

    fritap q --list [--json] [--compact]
    fritap q <tool> --help-json
    fritap q <tool> [--json '{...}' | --params-file f.json | --<param> value ...] [--compact]

Flags are generated from each tool's JSON-Schema; sources merge as ``--params-file`` < ``--json`` < flags.
Results and errors are JSON on stdout; an error exits with its ``exit_code``. A keylog export needs
``--allow-secrets`` plus the per-call ``--confirm-secrets``. ``start_capture`` blocks until the session
ends (Ctrl+C stops it); ``--no-wait`` returns at once and the capture stops when this process exits.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from typing import Any, Callable, TextIO

from friTap.agent_api.adapters.server_options import (
    add_context_options,
    build_context,
    leading_option_count,
)
from friTap.agent_api.context import ToolContext
from friTap.agent_api.errors import ToolError
from friTap.agent_api.json_input import load_json, load_json_object
from friTap.agent_api.registry import Registry, ToolSpec
from friTap.exit_codes import EXIT_OK
from friTap.suggest import close_matches

PROG = "fritap q"
LIST_FLAG = "--list"
HELP_JSON_FLAG = "--help-json"
HELP_FLAGS = ("-h", "--help")
#: First tokens after ``q`` that select the query CLI without naming a tool.
ENTRY_FLAGS = frozenset({LIST_FLAG, *HELP_FLAGS})
#: difflib ratio above which an unknown word is taken as a mistyped tool name.
TOOL_NAME_CUTOFF = 0.75

#: Tool whose CLI call waits for the session to end, and its status/stop tools.
WAIT_TOOL = "start_capture"
STATUS_TOOL = "capture_status"
STOP_TOOL = "stop_capture"
ACTIVE_STATES = frozenset({"starting", "running"})
DEFAULT_POLL_INTERVAL = 1.0

_PARAM_DEST_PREFIX = "param__"
_SCALAR_PARSERS: dict[str, Callable[[str], Any]] = {"string": str, "integer": int, "number": float}

USAGE = (
    f"usage: {PROG} --list [--json] [--compact]\n"
    f"       {PROG} <tool> --help-json\n"
    f"       {PROG} <tool> [--json '{{...}}' | --params-file FILE | --<param> VALUE ...] [--compact]\n"
)


class _ToolArgumentParser(argparse.ArgumentParser):
    """argparse parser that raises ``ToolError(bad_param)`` and prints help to ``out``."""

    def __init__(self, *args: Any, out: TextIO, **kwargs: Any) -> None:
        kwargs.setdefault("allow_abbrev", False)
        super().__init__(*args, **kwargs)
        self._out = out

    def error(self, message: str) -> None:  # type: ignore[override]
        raise ToolError(message, "bad_param", hint=f"see: {self.prog} --help")

    def print_help(self, file: TextIO | None = None) -> None:
        super().print_help(file or self._out)


def _json_value(text: str) -> Any:
    try:
        return load_json(text, "value")
    except ToolError as exc:
        raise argparse.ArgumentTypeError(exc.error) from None


_json_value.__name__ = "JSON"


def base_type(prop: dict[str, Any]) -> str:
    """The JSON type of ``prop`` (first non-null of a type list; default string)."""
    kind = prop.get("type", "string")
    if isinstance(kind, list):
        kind = next((k for k in kind if k != "null"), "string")
    return kind


def items_allow_objects(items: dict[str, Any]) -> bool:
    """True when an array's ``items`` schema accepts objects (directly or via ``anyOf``)."""
    branches = items.get("anyOf", [items])
    return any(base_type(branch) == "object" for branch in branches)


def option_strings(name: str) -> list[str]:
    """``--max-bytes`` plus the literal ``--max_bytes`` alias when they differ."""
    dashed = "--" + name.replace("_", "-")
    literal = "--" + name
    return [dashed] if dashed == literal else [dashed, literal]


def _argument_kwargs(prop: dict[str, Any]) -> dict[str, Any]:
    kind = base_type(prop)
    if kind == "boolean":
        return {"action": argparse.BooleanOptionalAction}
    if kind == "array":
        object_items = items_allow_objects(prop.get("items", {}))
        return {"action": "append", "metavar": "ITEM" if object_items else "A,B"}
    if kind == "object":
        return {"type": _json_value, "metavar": "JSON"}
    kwargs: dict[str, Any] = {"type": _SCALAR_PARSERS.get(kind, str)}
    if "enum" in prop:
        kwargs["choices"] = prop["enum"]
    else:
        kwargs["metavar"] = kind.upper()
    return kwargs


def _param_help(name: str, prop: dict[str, Any], required: set[str]) -> str:
    text = prop.get("description", "")
    if base_type(prop) == "array" and items_allow_objects(prop.get("items", {})):
        text += " Repeat the flag, one item each (no comma splitting); a JSON object is accepted."
    if name in required:
        text += " (required)"
    if "default" in prop:
        text += f" [default: {json.dumps(prop['default'])}]"
    return text.replace("%", "%%")


def add_param_flags(parser: argparse.ArgumentParser, schema: dict[str, Any]) -> list[str]:
    """Add one flag per schema property; returns the names that got a flag.

    A property whose flag would clash with an existing option is skipped (it
    can still be passed with ``--json``).
    """
    required = set(schema.get("required", ()))
    flagged = []
    for name, prop in schema.get("properties", {}).items():
        flags = option_strings(name)
        if any(flag in parser._option_string_actions for flag in flags):
            continue
        parser.add_argument(*flags, dest=_PARAM_DEST_PREFIX + name, default=argparse.SUPPRESS,
                            help=_param_help(name, prop, required), **_argument_kwargs(prop))
        flagged.append(name)
    return flagged


def _object_items(name: str, values: list[str]) -> list[Any]:
    """One item per flag occurrence: a ``{...}`` token is a JSON object, else a string.

    Commas are not split (a GPS fix ``48.1,11.5`` is one value); the tool interprets strings.
    """
    items = []
    for value in values:
        text = value.strip()
        items.append(load_json_object(text, f"--{name}") if text.startswith("{") else text)
    return [item for item in items if item != ""]


def _split_array(name: str, values: list[str], items: dict[str, Any]) -> list[Any]:
    if items_allow_objects(items):
        return _object_items(name, values)
    convert = _SCALAR_PARSERS.get(base_type(items), str)
    parts = [part.strip() for value in values for part in value.split(",")]
    try:
        return [convert(part) for part in parts if part]
    except ValueError as exc:
        raise ToolError(f"--{name}: {exc}", "bad_param", param=name) from exc


def flag_params(ns: argparse.Namespace, schema: dict[str, Any]) -> dict[str, Any]:
    """Collect the parameter values given as generated flags."""
    params = {}
    for name, prop in schema.get("properties", {}).items():
        dest = _PARAM_DEST_PREFIX + name
        if not hasattr(ns, dest):
            continue
        value = getattr(ns, dest)
        if base_type(prop) == "array":
            value = _split_array(name, value, prop.get("items", {}))
        params[name] = value
    return params


def _read_params_file(path: str) -> str:
    if path == "-":
        return sys.stdin.read()
    try:
        with open(path, encoding="utf-8") as handle:
            return handle.read()
    except OSError as exc:
        raise ToolError(f"--params-file: {exc}", "not_found") from exc


def collect_params(ns: argparse.Namespace, schema: dict[str, Any]) -> dict[str, Any]:
    """Merge ``--params-file`` < ``--json`` < generated flags."""
    params: dict[str, Any] = {}
    if ns.params_file:
        params.update(load_json_object(_read_params_file(ns.params_file), "--params-file"))
    if ns.json_params:
        params.update(load_json_object(ns.json_params, "--json"))
    params.update(flag_params(ns, schema))
    return params


def build_tool_parser(spec: ToolSpec, out: TextIO) -> argparse.ArgumentParser:
    """The argparse parser of ``fritap q <tool>`` (control options + generated flags)."""
    parser = _ToolArgumentParser(prog=f"{PROG} {spec.name}", description=spec.summary, out=out)
    parser.add_argument("--json", dest="json_params", metavar="JSON",
                        help="Parameters as a JSON object.")
    parser.add_argument("--params-file", metavar="FILE",
                        help="Read the parameters JSON object from FILE ('-' = stdin).")
    parser.add_argument(HELP_JSON_FLAG, action="store_true",
                        help="Print the tool spec and parameter schema as JSON.")
    add_query_options(parser)
    if spec.name == WAIT_TOOL:
        parser.add_argument("--wait", dest="cli_wait", action=argparse.BooleanOptionalAction,
                            default=True, help="Block until the capture session ends (default).")
    add_param_flags(parser, spec.params_schema)
    return parser


def add_query_options(parser: argparse.ArgumentParser) -> None:
    """q-level options: the shared context options plus ``--compact``."""
    parser.add_argument("--compact", action="store_true", help="Print single-line JSON.")
    add_context_options(parser)


def leading_options_parser() -> argparse.ArgumentParser:
    """Parser of the q-level options that may precede the tool name."""
    parser = argparse.ArgumentParser(add_help=False, allow_abbrev=False)
    add_query_options(parser)
    return parser


def render_json(doc: Any, compact: bool) -> str:
    if compact:
        return json.dumps(doc, ensure_ascii=False, default=str)
    return json.dumps(doc, ensure_ascii=False, default=str, indent=2)


def render_table(specs: list[ToolSpec]) -> str:
    width = max([len(spec.name) for spec in specs] + [4])
    lines = [f"{'TOOL':<{width}}  {'KIND':<8} SUMMARY"]
    for spec in specs:
        marker = " *" if spec.mutating else ""
        lines.append(f"{spec.name:<{width}}  {spec.kind:<8} {spec.summary}{marker}")
    lines.append("(* = mutating)")
    return "\n".join(lines) + "\n"


class QueryCli:
    """Runs ``fritap q`` against a registry; I/O and sleeping are injectable for tests."""

    def __init__(self, registry: Registry, out: TextIO, err: TextIO,
                 sleep: Callable[[float], None] = time.sleep,
                 poll_interval: float = DEFAULT_POLL_INTERVAL) -> None:
        self.registry = registry
        self.out = out
        self.err = err
        self.sleep = sleep
        self.poll_interval = poll_interval

    def run(self, tokens: list[str]) -> int:
        """Execute ``fritap q <tokens>``; returns the process exit code."""
        compact = "--compact" in tokens
        try:
            return self._dispatch(tokens)
        except ToolError as error:
            self._emit(error.to_dict(), compact)
            return error.exit_code
        except SystemExit as exit_:  # argparse -h
            return int(exit_.code or 0)

    def _dispatch(self, tokens: list[str]) -> int:
        leading, tokens = split_leading_options(tokens)
        if not tokens or tokens[0] in HELP_FLAGS:
            self.out.write(USAGE + "\n" + render_table(self.registry.specs()))
            return EXIT_OK
        if tokens[0] == LIST_FLAG:
            list_leading = [token for token in leading if token == "--compact"]
            return self._list(list_leading + tokens[1:])
        return self._run_tool(self.registry.get(tokens[0]), leading + tokens[1:])

    def _list(self, tokens: list[str]) -> int:
        parser = _ToolArgumentParser(prog=f"{PROG} {LIST_FLAG}", out=self.out)
        parser.add_argument("--json", action="store_true", help="Print the tools as JSON.")
        parser.add_argument("--compact", action="store_true", help="Print single-line JSON.")
        ns = parser.parse_args(tokens)
        specs = self.registry.specs()
        if ns.json:
            self._emit([spec.describe(include_result=True) for spec in specs], ns.compact)
        else:
            self.out.write(render_table(specs))
        return EXIT_OK

    def _run_tool(self, spec: ToolSpec, tokens: list[str]) -> int:
        ns = build_tool_parser(spec, self.out).parse_args(tokens)
        if ns.help_json:
            self._emit(spec.describe(include_result=True), ns.compact)
            return EXIT_OK
        context = build_context(ns, allow_capture=True, allow_values=True)
        params = collect_params(ns, spec.params_schema)
        result = self.registry.call(spec.name, params, context=context)
        if getattr(ns, "cli_wait", False):
            result = self.wait_for_session(result, context)
        self._emit(result, ns.compact)
        return EXIT_OK

    def wait_for_session(self, started: dict[str, Any], context: ToolContext) -> dict[str, Any]:
        """Poll ``capture_status`` until the session leaves starting/running.

        Ctrl+C stops the session via ``stop_capture`` and returns its result.
        """
        session_id = started.get("session_id")
        if not session_id:
            return started
        self.err.write(f"{PROG}: waiting for capture session {session_id} (Ctrl+C stops it)\n")
        params = {"session_id": session_id}
        status = started
        try:
            while status.get("state", "starting") in ACTIVE_STATES:
                self.sleep(self.poll_interval)
                status = self.registry.call(STATUS_TOOL, params, context=context)
        except KeyboardInterrupt:
            status = self.registry.call(STOP_TOOL, params, context=context)
        return status

    def _emit(self, doc: Any, compact: bool) -> None:
        self.out.write(render_json(doc, compact) + "\n")


def run_query_cli(tokens: list[str], *, registry: Registry | None = None,
                  out: TextIO | None = None, err: TextIO | None = None) -> int:
    """Entry point of ``fritap q`` (``tokens`` = arguments after ``q``)."""
    if registry is None:
        from friTap.agent_api.registry import registry as default_registry
        registry = default_registry
    return QueryCli(registry, out or sys.stdout, err or sys.stderr).run(tokens)


def split_leading_options(tokens: list[str]) -> tuple[list[str], list[str]]:
    """Split the q-level options that precede the tool name from the rest.

    ``["--root", "X", "--compact", "get_digest", "--tap", "t"]`` ->
    ``(["--root", "X", "--compact"], ["get_digest", "--tap", "t"])``.
    The option names come from :func:`leading_options_parser`.
    """
    index = leading_option_count(tokens, leading_options_parser())
    return tokens[:index], tokens[index:]


def looks_like_tool_name(word: str, names: list[str]) -> bool:
    """True when ``word`` is a registered tool or a close (mistyped) match of one."""
    return word in names or bool(close_matches(word, names, limit=1, cutoff=TOOL_NAME_CUTOFF))


def is_query_invocation(argv: list[str], tool_names: Callable[[], list[str]]) -> bool:
    """True when ``argv`` (``sys.argv``) selects ``fritap q`` rather than a capture.

    After the leading q-level options (``--root``, ``--max-response-bytes``, ``--allow-secrets``,
    ``--compact``) it is the query CLI when one of those was given (no capture flag shares their
    names), the next token is ``--list``/``-h``/``--help``, or it is a registered tool or a close
    misspelling (so a typo gets an ``unknown_tool`` error with a hint). Rule: ``docs/api/cli.md``.
    Anything else (``fritap q -k keys.log``, ``fritap q firefox``) falls through to capture mode.
    ``tool_names`` loads the tool modules, so it is called only for a bare word.
    """
    if len(argv) < 3 or argv[1] != "q":
        return False
    leading, rest = split_leading_options(list(argv[2:]))
    if leading or rest[0] in ENTRY_FLAGS:
        return True
    first = rest[0]
    return not first.startswith("-") and looks_like_tool_name(first, tool_names())


__all__ = [
    "QueryCli",
    "run_query_cli",
    "is_query_invocation",
    "split_leading_options",
    "looks_like_tool_name",
    "add_param_flags",
    "build_tool_parser",
    "collect_params",
    "flag_params",
]
