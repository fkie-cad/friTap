"""Searchable-content index for the ``frame`` display-filter field.

``frame contains "hello"`` searches a flow's decrypted content. Flow summaries
carry no bytes, so the evaluator asks an evaluation context for them:
:class:`FlowContentIndex` loads the full flow through an injected lookup,
builds its lowercased searchable bytes (:func:`build_searchable_bytes`) and
caches them in a byte-budgeted LRU keyed on ``flow_id`` (each entry
remembers the ``total_bytes`` it was built at) so a live flow that grows is
rebuilt automatically.
"""

from __future__ import annotations

import logging
import threading
from collections import OrderedDict
from typing import TYPE_CHECKING, Any, Callable, Iterator, Optional

if TYPE_CHECKING:
    from friTap.flow.models import Flow

logger = logging.getLogger(__name__)

MiB = 1024 * 1024
DEFAULT_MAX_BYTES = 256 * MiB
DEFAULT_PER_FLOW_CAP = 16 * MiB

FlowLookup = Callable[[str], "Flow | None"]

_SEPARATOR = b"\n"


# -- Content builder (pure) --------------------------------------------------

def build_searchable_bytes(flow: Any, cap: int = DEFAULT_PER_FLOW_CAP) -> bytes:
    """Return the flow's searchable content: lowercased, joined by newlines.

    Covers both chunk directions, request/response headers and already-present
    bodies, OHTTP inner payloads, trailing bytes, owned layer bytes/parsed
    results and every layer message ``body``. Nothing is decompressed or
    re-parsed. The result is capped at *cap* bytes. Never raises.
    """
    try:
        parts: list[bytes] = []
        size = 0
        for part in _iter_lowered_parts(flow, cap):
            if not part:
                continue
            parts.append(part)
            size += len(part) + 1
            if size >= cap:
                break
        return _SEPARATOR.join(parts)[:cap]
    except Exception:
        logger.debug("build_searchable_bytes failed", exc_info=True)
        return b""


def _iter_lowered_parts(flow: Any, cap: int) -> Iterator[bytes]:
    """Every content fragment of *flow*, each capped at *cap* and lowercased."""
    yield from _chunk_parts(flow, cap)
    for part in _iter_content_parts(flow):
        yield _lowercase(part[:cap])


def _iter_content_parts(flow: Any) -> Iterator[bytes]:
    """Yield every raw non-chunk content fragment of *flow* (unlowered).

    Chunk directions are handled by :func:`_chunk_parts`, which lowercases
    and caps them while accumulating.
    """
    for attr in ("request", "response", "ohttp_inner_request",
                 "ohttp_inner_response", "trailing_parse", "response_trailing_parse"):
        yield from _parse_result_parts(getattr(flow, attr, None))
    for attr in ("trailing_bytes", "response_trailing_bytes"):
        yield _to_bytes(getattr(flow, attr, None))
    for layer in list(getattr(flow, "layers", None) or ()):
        yield from _layer_parts(layer)


def _chunk_parts(flow: Any, cap: int) -> Iterator[bytes]:
    """Both directions of the flow's raw chunks (write first, then read).

    Each direction is joined from per-chunk lowercased data and stops
    accumulating once *cap* bytes are collected, so a large or growing live
    flow never materializes its full byte stream. Lowercasing per chunk keeps
    UTF-8 text case-folded even when other chunks of the direction are binary.
    """
    chunks = list(getattr(flow, "chunks", None) or ())
    for direction in ("write", "read"):
        yield _join_direction(chunks, direction, cap)


def _join_direction(chunks: list, direction: str, cap: int) -> bytes:
    """Lowercased data of *direction*'s chunks, joined, at most *cap* bytes."""
    # Not Flow.get_direction_bytes(): lowercasing its joined result in one pass
    # would stop UTF-8 case folding for the whole direction at one binary chunk.
    parts: list[bytes] = []
    remaining = cap
    for chunk in chunks:
        if remaining <= 0:
            break
        if getattr(chunk, "direction", "") != direction:
            continue
        data = _to_bytes(getattr(chunk, "data", b""))[:remaining]
        if data:
            data = _lowercase(data)
            parts.append(data)
            remaining -= len(data)
    return b"".join(parts)[:cap]


def _parse_result_parts(result: Any) -> Iterator[bytes]:
    """``k: v`` header lines and the already-present body of a ParseResult."""
    if result is None:
        return
    headers = getattr(result, "headers", None)
    if isinstance(headers, dict) and headers:
        yield _to_bytes("\n".join(f"{k}: {v}" for k, v in headers.items()))
    yield _to_bytes(getattr(result, "body", b""))


def _layer_parts(layer: Any) -> Iterator[bytes]:
    """Owned layer bytes, an owned parsed result, and message bodies."""
    data = getattr(layer, "data", None)
    if getattr(data, "data_source", "") == "owned":
        yield _to_bytes(data.write)
        yield _to_bytes(data.read)
    yield from _parse_result_parts(getattr(layer, "_inner_parsed", None))
    for message in getattr(layer, "messages", None) or ():
        if isinstance(message, dict):
            yield _to_bytes(message.get("body"))


def _lowercase(part: bytes) -> bytes:
    """Lowercase like the parser lowercases the needle (``str.lower``).

    Valid UTF-8 is case-folded as text so non-ASCII letters (``Ü``) match;
    binary data falls back to ASCII-only ``bytes.lower``. Callers apply it per
    fragment/chunk so one binary chunk never disables folding for the rest.
    """
    try:
        return part.decode("utf-8").lower().encode("utf-8")
    except UnicodeDecodeError:
        return part.lower()


def _to_bytes(value: Any) -> bytes:
    """Coerce str (UTF-8) / bytes-like to bytes; anything else to ``b""``."""
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value)
    if isinstance(value, str):
        return value.encode("utf-8", errors="replace")
    return b""


# -- Cache -------------------------------------------------------------------

class FlowContentIndex:
    """Thread-safe, byte-budgeted LRU of searchable flow content.

    Satisfies the evaluator's context contract: ``text_for(obj)`` returns the
    flow's content as lowercased bytes, or None when the flow can't be loaded.
    """

    def __init__(
        self,
        flow_lookup: Optional[FlowLookup] = None,
        max_bytes: int = DEFAULT_MAX_BYTES,
        per_flow_cap: int = DEFAULT_PER_FLOW_CAP,
    ) -> None:
        self._flow_lookup = flow_lookup
        self._max_bytes = max_bytes
        self._per_flow_cap = per_flow_cap
        # flow_id -> (total_bytes the text was built at, text); LRU order.
        self._entries: OrderedDict[str, tuple[int, bytes]] = OrderedDict()
        self._used_bytes = 0
        self._lock = threading.Lock()

    def set_flow_lookup(self, flow_lookup: Optional[FlowLookup]) -> None:
        """Replace the flow lookup; cached content is dropped."""
        self._flow_lookup = flow_lookup
        self.clear()

    @property
    def used_bytes(self) -> int:
        return self._used_bytes

    def __len__(self) -> int:
        return len(self._entries)

    def text_for(self, obj: Any) -> Optional[bytes]:
        """Lowercased searchable bytes for *obj* (a Flow or FlowSummary)."""
        key = self._key_for(obj)
        if key is None:
            return None
        flow_id, size = key
        with self._lock:
            cached = self._entries.get(flow_id)
            if cached is not None and cached[0] == size:
                self._entries.move_to_end(flow_id)
                return cached[1]
        flow = self._load_flow(obj, flow_id)
        if flow is None:
            return None
        text = build_searchable_bytes(flow, self._per_flow_cap)
        self._store(flow_id, size, text)
        return text

    def invalidate(self, flow_id: str) -> None:
        """Drop the cached entry of *flow_id* (any size)."""
        with self._lock:
            self._drop(flow_id)

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()
            self._used_bytes = 0

    # -- internals -----------------------------------------------------------

    @staticmethod
    def _key_for(obj: Any) -> Optional[tuple[str, int]]:
        flow_id = getattr(obj, "flow_id", "") or ""
        if not flow_id:
            return None
        try:
            size = int(getattr(obj, "_total_bytes", 0) or 0)
        except (TypeError, ValueError):
            size = 0
        return flow_id, size

    def _load_flow(self, obj: Any, flow_id: str) -> Any:
        """A full Flow for *obj*: itself if it carries chunks, else the lookup."""
        if getattr(obj, "chunks", None) is not None:
            return obj
        if self._flow_lookup is None:
            return None
        try:
            return self._flow_lookup(flow_id)
        except Exception:
            logger.debug("flow lookup failed for %s", flow_id, exc_info=True)
            return None

    def _store(self, flow_id: str, size: int, text: bytes) -> None:
        if len(text) > self._max_bytes:
            return
        with self._lock:
            self._drop(flow_id)
            self._entries[flow_id] = (size, text)
            self._used_bytes += len(text)
            while self._used_bytes > self._max_bytes and self._entries:
                _, (_, evicted) = self._entries.popitem(last=False)
                self._used_bytes -= len(evicted)

    def _drop(self, flow_id: str) -> None:
        """Remove *flow_id*'s entry, if any; caller holds ``_lock``."""
        entry = self._entries.pop(flow_id, None)
        if entry is not None:
            self._used_bytes -= len(entry[1])
