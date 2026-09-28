"""Immutable result tree of :func:`friTap.offline.mtproto.tl.decode_tl`.

A decoded object is a :class:`TlNode` whose ``fields`` hold plain Python values
(int, float, str, bytes, bool), nested :class:`TlNode` objects, :class:`TlVector`
summaries or :class:`TlRaw` byte runs the decoder could not interpret.

Offsets are byte offsets into the buffer the node was read from: the input to
``decode_tl`` or, below a ``gzip_packed`` node, its inflated payload.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterator, Optional, Tuple

#: Values a node's ``kind`` may take.
NODE_KINDS = frozenset({"constructor", "function", "unknown", "gzip"})


@dataclass(frozen=True)
class TlRaw:
    """Bytes left uninterpreted, with the *reason* decoding stopped."""

    data: bytes
    reason: str


@dataclass(frozen=True)
class TlField:
    """One decoded parameter; ``flag_bit`` is e.g. ``"flags.10"`` for ``flags.10?T``."""

    name: str
    type: str
    value: Any
    flag_bit: Optional[str] = None


@dataclass(frozen=True)
class TlVector:
    """A vector summary: the first kept ``items`` of ``total`` elements."""

    elem_type: str
    items: Tuple[Any, ...]
    total: int
    offset: int
    note: str = ""


@dataclass(frozen=True)
class TlNode:
    """A decoded constructor/function call, an unknown id, or a gzip wrapper."""

    name: str
    ctor_id: Optional[int]
    kind: str
    fields: Tuple[TlField, ...]
    offset: int
    length: int
    note: str = ""

    def field(self, name: str) -> Optional[TlField]:
        """The first field called *name*, or ``None``."""
        return next((f for f in self.fields if f.name == name), None)

    def value(self, name: str, default: Any = None) -> Any:
        """The value of field *name*, or *default* when absent."""
        found = self.field(name)
        return default if found is None else found.value

    def to_jsonable(self) -> dict:
        """A JSON-serialisable dict of this node and everything below it."""
        return to_jsonable(self)


def _node_jsonable(node: TlNode) -> dict:
    return {
        "name": node.name,
        "ctor_id": None if node.ctor_id is None else f"0x{node.ctor_id:08x}",
        "kind": node.kind,
        "offset": node.offset,
        "length": node.length,
        "note": node.note,
        "fields": [_field_jsonable(f) for f in node.fields],
    }


def _field_jsonable(tl_field: TlField) -> dict:
    out = {"name": tl_field.name, "type": tl_field.type, "value": to_jsonable(tl_field.value)}
    if tl_field.flag_bit:
        out["flag_bit"] = tl_field.flag_bit
    return out


def to_jsonable(value: Any) -> Any:
    """Convert any decoder value to JSON-friendly data (bytes become hex)."""
    if isinstance(value, TlNode):
        return _node_jsonable(value)
    if isinstance(value, TlVector):
        return {
            "vector": value.elem_type,
            "total": value.total,
            "offset": value.offset,
            "note": value.note,
            "items": [to_jsonable(item) for item in value.items],
        }
    if isinstance(value, TlRaw):
        return {"raw": value.data.hex(), "length": len(value.data), "reason": value.reason}
    if isinstance(value, (bytes, bytearray)):
        return value.hex()
    return value


def iter_nodes(value: Any) -> Iterator[TlNode]:
    """Yield every :class:`TlNode` in *value*, depth first, parents first."""
    if isinstance(value, TlNode):
        yield value
        for tl_field in value.fields:
            yield from iter_nodes(tl_field.value)
    elif isinstance(value, TlVector):
        for item in value.items:
            yield from iter_nodes(item)


def iter_raws(value: Any) -> Iterator[TlRaw]:
    """Yield every :class:`TlRaw` remainder in *value*."""
    if isinstance(value, TlRaw):
        yield value
    elif isinstance(value, TlNode):
        for tl_field in value.fields:
            yield from iter_raws(tl_field.value)
    elif isinstance(value, TlVector):
        for item in value.items:
            yield from iter_raws(item)


def stopped_early(node: TlNode) -> bool:
    """True when decoding left any bytes uninterpreted below *node*."""
    return any(True for _ in iter_raws(node))
