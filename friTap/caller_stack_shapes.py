"""Bounded, escaped shapes of a ``caller_stack`` backtrace.

Every frame string, thread name and module name of a caller stack comes from
the target process, so it is untrusted (AGENTS.md): it is escaped with
:func:`~friTap.text_safety.safe_terminal_text` and length-capped before it
leaves the host. Two shapes exist:

* :func:`untrusted_caller_stack` -- the router's ``CallerStackEvent.untrusted``
  dict: frames only (16 per kind, 120 characters per string); the thread and
  module names travel as the event's own capped top-level fields.
* :func:`compact_caller_stack` -- the collector's per-flow ``flow.caller_stack``
  (8 frames per kind, 80 characters per string), small enough to repeat on
  every HTTP/2 stream flow of a connection.

:func:`sanitize_caller_stack` re-applies the compact bounds to a value read
back from a ``.tap`` file, which may be hand-crafted.
:func:`caller_stack_lookup_keys` extracts the raw (unescaped) classifier keys.
"""

from __future__ import annotations

import math
from itertools import islice
from typing import Any, Iterator, Optional

from .text_safety import safe_terminal_text

#: Per-string cap of the router's ``untrusted`` dict.
UNTRUSTED_TEXT_LIMIT = 120
#: Frames per kind (native / java) kept in the router's ``untrusted`` dict.
UNTRUSTED_FRAME_LIMIT = 16
#: Per-string cap of the collector's compact ``flow.caller_stack``.
COMPACT_TEXT_LIMIT = 80
#: Frames per kind kept in the collector's compact ``flow.caller_stack``.
COMPACT_FRAME_LIMIT = 8
#: Cap of a ``request_context`` URL (kept in full, query included, up to this length).
REQUEST_CONTEXT_URL_LIMIT = 2048
#: Java frames kept per ``request_context`` (router event and ``.tap`` record).
REQUEST_CONTEXT_FRAME_LIMIT = 32
#: Per-frame cap of a ``request_context`` Java frame.
REQUEST_CONTEXT_FRAME_TEXT_LIMIT = UNTRUSTED_TEXT_LIMIT
#: Per-field caps of a ``request_context``'s text fields (``RequestContextEvent``
#: names), shared by the router and the ``.tap`` record so both cut the same way.
REQUEST_CONTEXT_TEXT_LIMITS = {
    "req_id": COMPACT_TEXT_LIMIT,
    "url": REQUEST_CONTEXT_URL_LIMIT,
    "stack_kind": COMPACT_TEXT_LIMIT,
    "method": 16,
    "thread": COMPACT_TEXT_LIMIT,
    "negotiated_protocol": COMPACT_TEXT_LIMIT,
    "error": COMPACT_TEXT_LIMIT,
    "webview_id": COMPACT_TEXT_LIMIT,
}


def capped_text(value: Any, limit: int) -> str:
    """*value* escaped for a terminal and cut to *limit* characters.

    Non-strings (``None``, numbers, dicts from a hostile agent) become ``""``.
    """
    if not isinstance(value, str):
        return ""
    return safe_terminal_text(value)[:limit]


def non_negative_int(value: Any) -> int:
    """*value* (an int or numeric string) as a non-negative int; bools and junk become 0."""
    if isinstance(value, bool):
        return 0
    if isinstance(value, str):
        try:
            value = int(value.strip())
        except ValueError:
            return 0
    return max(value, 0) if isinstance(value, int) else 0


def strict_int(value: Any) -> Optional[int]:
    """*value* when it is a real int; bools, numeric strings and junk become ``None``."""
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def optional_bool(value: Any) -> Optional[bool]:
    """*value* when it is a real bool, else ``None``."""
    return value if isinstance(value, bool) else None


def finite_float(value: Any) -> Optional[float]:
    """*value* (an int or float) as a finite float; bools, NaN/inf and junk become ``None``."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    try:
        as_float = float(value)
    except OverflowError:  # an int too large for a float
        return None
    return as_float if math.isfinite(as_float) else None


def _entries_of_type(frames: Any, kind: type, limit: int) -> Iterator:
    """The first *limit* entries of *frames* that are of *kind* (none when not a list)."""
    if not isinstance(frames, list):
        return iter(())
    return islice((frame for frame in frames if isinstance(frame, kind)), limit)


def _native_frames(frames: Any, frame_limit: int, text_limit: int) -> list[dict]:
    """``[{module, symbol}]`` from the dict entries of *frames*, bounded.

    Frames are cut to *frame_limit* before any escaping work.
    """
    return [{"module": capped_text(frame.get("module"), text_limit),
             "symbol": capped_text(frame.get("symbol"), text_limit)}
            for frame in _entries_of_type(frames, dict, frame_limit)]


def bounded_strings(values: Any, max_entries: int, text_limit: int) -> list[str]:
    """The first *max_entries* string entries of *values*, escaped and capped.

    Non-string entries are skipped; a non-list *values* gives ``[]``. Entries
    are cut to *max_entries* before any escaping work.
    """
    return [capped_text(value, text_limit)
            for value in _entries_of_type(values, str, max_entries)]


def untrusted_caller_stack(payload: dict) -> dict:
    """The router's ``untrusted`` dict (frames only) for a raw ``caller_stack`` payload."""
    return {
        "native_frames": _native_frames(
            payload.get("native_frames"), UNTRUSTED_FRAME_LIMIT, UNTRUSTED_TEXT_LIMIT),
        "java_frames": bounded_strings(
            payload.get("java_frames"), UNTRUSTED_FRAME_LIMIT, UNTRUSTED_TEXT_LIMIT),
    }


def caller_stack_lookup_keys(payload: dict) -> tuple[list[str], list[str]]:
    """``(java_frames, native_modules)`` of a raw payload: the SDK classifier's keys.

    Unescaped and unbounded on purpose: they are only matched against the
    bundled signature table, never echoed.
    """
    java_frames = [f for f in (payload.get("java_frames") or []) if isinstance(f, str)]
    native_modules = [
        frame.get("module")
        for frame in (payload.get("native_frames") or [])
        if isinstance(frame, dict) and isinstance(frame.get("module"), str) and frame.get("module")
    ]
    return java_frames, native_modules


def _compact(source: dict) -> dict:
    """The compact flow shape of a dict carrying the caller-stack fields."""
    return {
        "transport_module": capped_text(source.get("transport_module"), COMPACT_TEXT_LIMIT),
        "thread_name": capped_text(source.get("thread_name"), COMPACT_TEXT_LIMIT),
        "tid": non_negative_int(source.get("tid")),
        "pid": non_negative_int(source.get("pid")),
        "native_frames": _native_frames(
            source.get("native_frames"), COMPACT_FRAME_LIMIT, COMPACT_TEXT_LIMIT),
        "java_frames": bounded_strings(
            source.get("java_frames"), COMPACT_FRAME_LIMIT, COMPACT_TEXT_LIMIT),
    }


def compact_caller_stack(event) -> dict:
    """The compact ``flow.caller_stack`` for a ``CallerStackEvent``.

    Frames come from ``event.untrusted``; identity from the event's own
    ``tid``/``pid``/``thread_name``/``transport_module``.
    """
    untrusted = getattr(event, "untrusted", None)
    frames = untrusted if isinstance(untrusted, dict) else {}
    return _compact({
        "transport_module": getattr(event, "transport_module", ""),
        "thread_name": getattr(event, "thread_name", ""),
        "tid": getattr(event, "tid", 0),
        "pid": getattr(event, "pid", 0),
        "native_frames": frames.get("native_frames"),
        "java_frames": frames.get("java_frames"),
    })


def sanitize_caller_stack(value: Any) -> Optional[dict]:
    """A ``.tap`` meta ``caller_stack`` re-bounded, or ``None`` when not a dict."""
    if not isinstance(value, dict):
        return None
    return _compact(value)
