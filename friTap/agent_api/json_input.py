"""
Parsing of untrusted JSON input: REST request bodies and CLI ``--json`` / ``--params-file``.

Same contract as :func:`friTap.analysis._limits.safe_json_loads` (size cap,
``RecursionError``/``ValueError`` caught) plus the iterative
:func:`friTap.analysis._json_walk.exceeds_depth` guard: since CPython 3.14
``json.loads`` accepts arbitrarily deep input, which would only fail later in
recursive code (schema validation, the response cap, ``json.dumps``). Unlike
``safe_json_loads`` it raises a :class:`ToolError` naming the problem.
"""

from __future__ import annotations

import json
from typing import Any

from friTap.agent_api.errors import ToolError
from friTap.analysis._json_walk import MAX_JSON_DEPTH, exceeds_depth
from friTap.analysis._limits import MAX_JSON_BYTES


def load_json(text: str | bytes, source: str, *, error_type: str = "bad_param",
              max_bytes: int = MAX_JSON_BYTES) -> Any:
    """Parse untrusted JSON ``text``; ``source`` prefixes error messages.

    Raises:
        ToolError: ``error_type`` when ``text`` is too large, not JSON, or
            nested deeper than ``MAX_JSON_DEPTH``.
    """
    if len(text) > max_bytes:
        raise ToolError(f"{source}: JSON larger than {max_bytes} bytes", error_type)
    try:
        value = json.loads(text)
    except (RecursionError, ValueError) as exc:
        raise ToolError(f"{source}: invalid JSON: {exc}", error_type) from None
    if exceeds_depth(value):
        raise ToolError(f"{source}: JSON nested deeper than {MAX_JSON_DEPTH} levels", error_type)
    return value


def load_json_object(text: str | bytes, source: str, *, error_type: str = "bad_param",
                     max_bytes: int = MAX_JSON_BYTES) -> dict[str, Any]:
    """:func:`load_json` that also requires a JSON object."""
    value = load_json(text, source, error_type=error_type, max_bytes=max_bytes)
    if not isinstance(value, dict):
        raise ToolError(f"{source}: expected a JSON object", error_type)
    return value


__all__ = ["load_json", "load_json_object"]
