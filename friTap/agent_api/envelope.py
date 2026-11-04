"""
Response envelope helpers: schema tag, pagination and size capping.

Every successful tool result is ``{"schema": "<name>/<version>", ...}``;
read tools that copy captured text add ``notice`` (the digest's
UNTRUSTED_NOTICE). Lists are paginated with a decimal-offset cursor and the
whole document is capped to the context's ``max_response_bytes``.
"""

from __future__ import annotations

import json
from typing import Any

from friTap.agent_api.errors import ToolError


def ok(schema: str, data: dict[str, Any], *, notice: bool = False) -> dict[str, Any]:
    """Wrap ``data`` in the envelope (``schema`` first, optional ``notice`` last)."""
    doc: dict[str, Any] = {"schema": schema, **data}
    if notice:
        from friTap.analysis.digest import UNTRUSTED_NOTICE

        doc["notice"] = UNTRUSTED_NOTICE
    return doc


def paginate(rows: list, limit: int, cursor: str | None) -> tuple[list, str | None]:
    """Return ``(page, next_cursor)``; ``next_cursor`` is ``None`` on the last page."""
    offset = _parse_cursor(cursor, len(rows))
    end = offset + limit
    next_cursor = str(end) if end < len(rows) else None
    return rows[offset:end], next_cursor


def _parse_cursor(cursor: str | None, total: int) -> int:
    if cursor is None or cursor == "":
        return 0
    if not (isinstance(cursor, str) and cursor.isdigit() and cursor.isascii()):
        raise ToolError(f"invalid cursor {cursor!r}", "bad_param",
                        hint="pass next_cursor from the previous page unchanged")
    offset = int(cursor)
    if offset > total:
        raise ToolError(f"cursor {cursor} is past the end ({total} rows)", "bad_param",
                        hint="start again without a cursor")
    return offset


def dumps_compact(doc: Any) -> str:
    """``doc`` as compact JSON (no spaces, UTF-8 kept, unknown types via ``str``).

    The one wire serializer of the agent API: the size cap, REST and MCP all
    use it, so a result that fits :func:`cap_response` always serializes.
    """
    return json.dumps(doc, ensure_ascii=False, separators=(",", ":"), default=str)


def _utf8_len(text: str) -> int:
    return len(text.encode("utf-8"))


def json_size(doc: Any) -> int:
    """Size in bytes of ``doc`` serialized as compact UTF-8 JSON."""
    return _utf8_len(dumps_compact(doc))


def cap_response(doc: dict[str, Any], max_bytes: int) -> dict[str, Any]:
    """Return ``doc`` if it fits ``max_bytes``, else a trimmed copy (see :func:`capped_json`)."""
    return capped_json(doc, max_bytes)[0]


def capped_json(doc: dict[str, Any], max_bytes: int) -> tuple[dict[str, Any], str]:
    """``(document, compact_json)`` with the document trimmed to fit ``max_bytes``.

    The largest list (searched through nested dicts) is halved until the
    document fits or no list is left; the copy gets ``"truncated": true`` and
    ``"truncated_fields"`` (dotted paths of the trimmed lists). The JSON text
    is returned so callers never serialize the result a second time.
    """
    text = dumps_compact(doc)
    size = _utf8_len(text)
    if size <= max_bytes:
        return doc, text
    trimmed = json.loads(text)
    fields = _trim_lists(trimmed, size, max_bytes)
    trimmed["truncated"] = True
    trimmed["truncated_fields"] = fields
    return trimmed, dumps_compact(trimmed)


def _trim_lists(doc: dict[str, Any], size: int, max_bytes: int) -> list[str]:
    """Halve the largest list until ``size`` fits; returns the trimmed dotted paths.

    Each list is serialized once up front and again only after it is halved:
    in compact JSON the document size changes by exactly the list's change.
    """
    sizes = {path: [json_size(lst), lst] for path, lst in _lists_in(doc, ())}
    fields: list[str] = []
    while size > max_bytes:
        candidates = [(entry[0], path) for path, entry in sizes.items() if entry[1]]
        if not candidates:
            break
        _, path = max(candidates, key=lambda c: c[0])
        entry = sizes[path]
        del entry[1][len(entry[1]) // 2:]
        new_size = json_size(entry[1])
        size -= entry[0] - new_size
        entry[0] = new_size
        dotted = ".".join(path)
        if dotted not in fields:
            fields.append(dotted)
    return fields


def _lists_in(node: dict[str, Any], path: tuple[str, ...]):
    for key, value in node.items():
        if isinstance(value, list):
            yield path + (key,), value
        elif isinstance(value, dict):
            yield from _lists_in(value, path + (key,))


__all__ = ["ok", "paginate", "cap_response", "capped_json", "dumps_compact", "json_size"]
