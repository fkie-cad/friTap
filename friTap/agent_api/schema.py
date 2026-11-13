"""
Tool parameter schemas and a minimal in-house validator.

Schemas are plain JSON-Schema (draft 2020-12 compatible) dicts so MCP and
OpenAPI adapters can publish them unchanged. :func:`validate` implements the
subset the tools use (type, enum, minimum/maximum, minLength/maxLength,
items, required, default, additionalProperties=false, property-level
``anyOf`` alternatives and ``oneOf``/``anyOf`` groups of ``required`` lists) -- no ``jsonschema`` dependency.

Property fragments (``TAP_SOURCE_PARAMS`` ...) are ``{name: schema}`` dicts
meant to be merged into :func:`object_schema`::

    object_schema({**TAP_SOURCE_PARAMS, **SLICE_PARAMS, **page_params()},
                  one_of_required=TAP_SOURCE_KEYS)
"""

from __future__ import annotations

import re
from typing import Any, Iterable

from friTap.agent_api.errors import ToolError
from friTap.suggest import did_you_mean

MAX_PAGE_LIMIT = 200
DEFAULT_PAGE_LIMIT = 50
#: Default page for row-heavy listings (endpoints, findings): ~50 rows of a real
#: tap cost ~5k tokens, so these start small and page on demand.
COMPACT_PAGE_LIMIT = 20

TAP_SOURCE_KEYS = ("tap", "session_id")

TAP_SOURCE_PARAMS: dict[str, dict] = {
    "tap": {"type": "string", "minLength": 1,
            "description": "Path to a .tap capture file (inside the sandbox root)."},
    "session_id": {"type": "string", "minLength": 1,
                   "description": "Id of a capture session started with start_capture."},
}

SLICE_PARAMS: dict[str, dict] = {
    "protocol": {"type": "string", "minLength": 1,
                 "description": "Only flows carrying this protocol (e.g. tls, http2, mtproto)."},
    "app_protocol": {"type": "string", "minLength": 1,
                     "description": "Only flows of this application protocol group."},
    "filter": {"type": "string", "minLength": 1,
               "description": "Display filter expression (Wireshark-like syntax)."},
}

SHOW_VALUES: dict[str, dict] = {
    "show_values": {"type": "boolean", "default": False,
                    "description": "Show raw captured values instead of redacting them."},
}

def page_params(default: int = DEFAULT_PAGE_LIMIT) -> dict[str, dict]:
    """``limit``/``cursor`` pagination params with the given default page size."""
    assert 1 <= default <= MAX_PAGE_LIMIT, f"default page size {default} outside 1..{MAX_PAGE_LIMIT}"
    return {
        "limit": {"type": "integer", "minimum": 1, "maximum": MAX_PAGE_LIMIT,
                  "default": default, "description": "Maximum rows per page."},
        "cursor": {"type": "string", "pattern": "^[0-9]+$",
                   "description": "Opaque cursor from a previous page's next_cursor."},
    }

_PYTHON_TYPES: dict[str, tuple[type, ...]] = {
    "string": (str,),
    "integer": (int,),
    "number": (int, float),
    "boolean": (bool,),
    "array": (list, tuple),
    "object": (dict,),
}


def object_schema(
    properties: dict[str, dict],
    required: Iterable[str] = (),
    one_of_required: Iterable[str] = (),
) -> dict[str, Any]:
    """Build a closed object schema (``additionalProperties: false``).

    ``one_of_required`` names keys of which exactly one must be given; it is
    emitted as standard ``oneOf: [{"required": [k]}, ...]``.
    """
    schema: dict[str, Any] = {
        "type": "object",
        "properties": dict(properties),
        "additionalProperties": False,
    }
    if required:
        schema["required"] = list(required)
    group = list(one_of_required)
    if group:
        schema["oneOf"] = [{"required": [key]} for key in group]
    return schema


#: Top-level keywords LLM tool APIs reject (the Anthropic API refuses the tool,
#: so Claude clients silently drop it); :func:`split_top_level_groups` moves them.
TOP_LEVEL_COMBINATORS = ("oneOf", "anyOf", "allOf")


def split_top_level_groups(schema: dict[str, Any]) -> tuple[dict[str, Any], str]:
    """Return ``schema`` without top-level combinators, plus a sentence stating them.

    Only ``required``-list groups (from :func:`object_schema`) are described; the
    registry's :func:`validate` still enforces the original schema on every call.
    """
    flat = {key: value for key, value in schema.items() if key not in TOP_LEVEL_COMBINATORS}
    notes = [_describe_required_group(word, schema[key])
             for key, word in (("oneOf", "exactly one"), ("anyOf", "at least one"))
             if schema.get(key)]
    return flat, " ".join(notes)


def _describe_required_group(word: str, group: list[dict[str, Any]]) -> str:
    """``"Give exactly one of: tap, session_id."`` for ``[{"required": ["tap"]}, ...]``."""
    keys = [key for option in group for key in option.get("required", [])]
    return f"Give {word} of: {', '.join(keys)}."


def validate(schema: dict[str, Any], params: dict[str, Any] | None) -> dict[str, Any]:
    """Validate ``params`` against an object ``schema``; return a new dict.

    ``None`` values count as absent. Defaults are filled in for absent keys.

    Raises:
        ToolError: ``bad_param`` describing the first violation.
    """
    if params is None:
        params = {}
    if not isinstance(params, dict):
        raise ToolError("params must be a JSON object", "bad_param")
    given = {key: value for key, value in params.items() if value is not None}
    properties = schema.get("properties", {})
    _check_unknown_keys(schema, given, properties)
    for name, value in given.items():
        if name in properties:
            check_value(name, value, properties[name])
    _check_required(schema, given)
    return _with_defaults(given, properties)


def check_value(name: str, value: Any, prop: dict[str, Any]) -> None:
    """Validate one value against its property schema (raises ``bad_param``)."""
    _check_any_of(name, value, prop.get("anyOf"))
    _check_type(name, value, prop.get("type"))
    _check_enum(name, value, prop.get("enum"))
    _check_bounds(name, value, prop)
    if isinstance(value, (list, tuple)) and "items" in prop:
        for index, item in enumerate(value):
            check_value(f"{name}[{index}]", item, prop["items"])


def _check_any_of(name: str, value: Any, branches: list | None) -> None:
    """A property-level ``anyOf``: the value must satisfy at least one branch."""
    if not branches:
        return
    for branch in branches:
        try:
            check_value(name, value, branch)
        except ToolError:
            continue
        return
    allowed = " or ".join(base for base in dict.fromkeys(
        branch.get("type", "any") for branch in branches))
    raise ToolError(f"{name}: expected {allowed}, got {type(value).__name__}", "bad_param",
                    param=name)


def _check_type(name: str, value: Any, expected: str | None) -> None:
    if expected is None:
        return
    is_bool = isinstance(value, bool)
    ok = isinstance(value, _PYTHON_TYPES[expected]) and (expected == "boolean" or not is_bool)
    if not ok:
        raise ToolError(
            f"{name}: expected {expected}, got {type(value).__name__}", "bad_param",
            param=name,
        )


def _check_enum(name: str, value: Any, allowed: list | None) -> None:
    if allowed is not None and value not in allowed:
        raise ToolError(
            f"{name}: {value!r} is not one of the allowed values", "bad_param",
            hint=did_you_mean(str(value), [str(a) for a in allowed], show_all=True),
            param=name,
        )


def _check_bounds(name: str, value: Any, prop: dict[str, Any]) -> None:
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        _check_limit(name, value, prop.get("minimum"), prop.get("maximum"), "")
    if isinstance(value, str):
        _check_limit(name, len(value), prop.get("minLength"), prop.get("maxLength"), "length ")
        _check_pattern(name, value, prop.get("pattern"))


def _check_limit(name: str, value: float, low: Any, high: Any, what: str) -> None:
    if low is not None and value < low:
        raise ToolError(f"{name}: {what}must be >= {low}", "bad_param", param=name)
    if high is not None and value > high:
        raise ToolError(f"{name}: {what}must be <= {high}", "bad_param", param=name)


def _check_pattern(name: str, value: str, pattern: str | None) -> None:
    if pattern is not None and re.search(pattern, value) is None:
        raise ToolError(f"{name}: {value!r} does not match {pattern}", "bad_param", param=name)


def _check_unknown_keys(schema: dict, given: dict, properties: dict) -> None:
    if schema.get("additionalProperties", True) is not False:
        return
    for key in given:
        if key not in properties:
            raise ToolError(
                f"unknown parameter {key!r}", "bad_param",
                hint=did_you_mean(key, list(properties), show_all=True), param=key,
            )


def _check_required(schema: dict, given: dict) -> None:
    for key in schema.get("required", ()):
        if key not in given:
            raise ToolError(f"missing required parameter {key!r}", "bad_param", param=key)
    _check_required_group(schema.get("oneOf"), given, exactly_one=True)
    _check_required_group(schema.get("anyOf"), given, exactly_one=False)


def _check_required_group(group: list | None, given: dict, *, exactly_one: bool) -> None:
    if not group:
        return
    keys = [key for branch in group for key in branch.get("required", ())]
    matched = sum(all(k in given for k in branch.get("required", ())) for branch in group)
    names = ", ".join(keys)
    if matched == 0:
        raise ToolError(f"one of {names} is required", "bad_param", hint=f"pass one of: {names}")
    if exactly_one and matched > 1:
        raise ToolError(f"pass only one of {names}", "bad_param")


def _with_defaults(given: dict, properties: dict) -> dict[str, Any]:
    result = dict(given)
    for name, prop in properties.items():
        if name not in result and "default" in prop:
            result[name] = prop["default"]
    return result


__all__ = [
    "TAP_SOURCE_KEYS",
    "TAP_SOURCE_PARAMS",
    "SLICE_PARAMS",
    "SHOW_VALUES",
    "MAX_PAGE_LIMIT",
    "DEFAULT_PAGE_LIMIT",
    "COMPACT_PAGE_LIMIT",
    "page_params",
    "object_schema",
    "validate",
    "check_value",
]
