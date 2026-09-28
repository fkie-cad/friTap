"""Generic, tolerant, schema-driven TL decoder.

:func:`decode_tl` turns one TL-serialized MTProto/Secret-Chat payload into a
:class:`~friTap.offline.mtproto.tl.nodes.TlNode` tree using the vendored schema
(:mod:`friTap.offline.mtproto.tl.registry`). It **never raises**:

* an unknown constructor id becomes an ``unknown`` node holding the rest of the
  enclosing buffer as a :class:`TlRaw`; everything decoded before it is kept;
* a length-delimited child (a ``msg_container`` message body, a ``gzip_packed``
  payload) is a boundary: a stop inside it does not stop its siblings;
* ``gzip_packed`` is inflated inline (gzip or zlib header, bounded by
  :attr:`TlLimits.max_inflate`);
* nesting beyond :attr:`TlLimits.max_depth` stops cleanly; beyond
  :attr:`TlLimits.max_nodes` built nodes the decoder switches to advance-only
  mode (bytes are still walked, so offsets stay right, but no nodes are built);
* vectors keep only their first :attr:`TlLimits.keep_vector_items` items.
"""

from __future__ import annotations

import dataclasses
import struct
import zlib
from dataclasses import dataclass
from functools import lru_cache
from typing import Any, List, Optional

from .nodes import TlField, TlNode, TlRaw, TlVector
from .registry import load_schema
from .schema import TlCombinator, TlSchema, TlType, parse_type

VECTOR_ID = 0x1CB5C415
GZIP_PACKED_ID = 0x3072CFA1
RPC_RESULT_ID = 0xF35C6D01
MSG_CONTAINER_ID = 0x73F1F8DC
BOOL_TRUE_ID = 0x997275B5
BOOL_FALSE_ID = 0xBC799737
#: CRC32 id of the bare ``message msg_id:long seqno:int bytes:int body:Object``.
MESSAGE_BARE_ID = 0x5BB8E511

#: Default cap on the INFLATED size of a ``gzip_packed`` body. The packed bytes
#: are peer-supplied, so an unbounded inflate is a decompression bomb; 16 MiB is
#: far above any real Telegram TL payload while keeping a hostile record cheap.
MAX_INFLATE = 16 * 1024 * 1024

_FIXED_PRIMS = {"int": ("<i", 4), "long": ("<q", 8), "double": ("<d", 8), "#": ("<I", 4)}
_WIDE_PRIMS = {"int128": 16, "int256": 32}
_OBJECT = parse_type("Object")


@dataclass(frozen=True)
class TlLimits:
    """Resource bounds for one :func:`decode_tl` call."""

    max_depth: int = 32
    max_nodes: int = 20000
    keep_vector_items: int = 20
    max_inflate: int = MAX_INFLATE


class InflateLimitError(ValueError):
    """A ``gzip_packed`` body would inflate beyond the allowed size."""


def inflate_bounded(packed: bytes, limit: int = MAX_INFLATE) -> bytes:
    """Inflate a gzip- or zlib-framed ``gzip_packed`` body to at most *limit* bytes.

    ``MAX_WBITS | 32`` auto-detects the header (Telegram sends real gzip members,
    which a plain zlib ``decompressobj()`` rejects). Raises ``zlib.error`` on a
    corrupt stream and :class:`InflateLimitError` when the output would exceed
    *limit* (input left unconsumed) instead of inflating it unbounded.
    """
    inflater = zlib.decompressobj(zlib.MAX_WBITS | 32)
    inflated = inflater.decompress(packed, limit)
    if inflater.unconsumed_tail:
        raise InflateLimitError(f"inflate exceeds {limit} B limit")
    return inflated


class _Abort(Exception):
    """Decoding cannot continue in this buffer; ``partial`` is what was built."""

    def __init__(self, partial: Any) -> None:
        super().__init__()
        self.partial = partial


class _Reader:
    """Little-endian cursor over ``data[pos:end]``."""

    __slots__ = ("data", "pos", "end")

    def __init__(self, data: bytes, pos: int = 0, end: Optional[int] = None) -> None:
        self.data = data
        self.pos = pos
        self.end = len(data) if end is None else end

    @property
    def remaining(self) -> int:
        return self.end - self.pos

    def rest(self) -> bytes:
        return bytes(self.data[self.pos:self.end])

    def _need(self, count: int) -> None:
        if count < 0 or count > self.remaining:
            raise _Abort(TlRaw(
                self.rest(),
                f"truncated: need {count} B at offset {self.pos}, {self.remaining} B left",
            ))

    def take(self, count: int) -> bytes:
        self._need(count)
        start = self.pos
        self.pos += count
        return bytes(self.data[start:self.pos])

    def unpack(self, fmt: str, size: int) -> Any:
        self._need(size)
        value = struct.unpack_from(fmt, self.data, self.pos)[0]
        self.pos += size
        return value

    def uint32(self) -> int:
        return self.unpack("<I", 4)

    def peek_uint32(self) -> Optional[int]:
        if self.remaining < 4:
            return None
        return struct.unpack_from("<I", self.data, self.pos)[0]

    def tl_bytes(self) -> bytes:
        """A TL ``bytes``/``string``: 1-byte (<254) or 0xFE + 3-byte length, 4-aligned."""
        first = self.take(1)[0]
        if first == 255:
            raise _Abort(TlRaw(self.rest(), f"invalid TL string prefix 0xff at offset {self.pos - 1}"))
        if first == 254:
            length = int.from_bytes(self.take(3), "little")
            header = 4
        else:
            length, header = first, 1
        value = self.take(length)
        self.take((-(header + length)) % 4)
        return value


def _decode_string(raw: bytes) -> Any:
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw


def _flag_label(param) -> Optional[str]:
    return None if param.flag_field is None else f"{param.flag_field}.{param.flag_bit}"


class _TlDecoder:
    """One decode run: schema, limits, node budget and advance-only state."""

    def __init__(self, schema: TlSchema, limits: TlLimits, expect: Optional[str]) -> None:
        self.schema = schema
        self.limits = limits
        self.expect = parse_type(expect) if expect else None
        self.nodes = 0
        self.exhausted = False
        self.skip = 0

    # -- budget ------------------------------------------------------------ #
    def _enter(self, reader: _Reader, depth: int) -> bool:
        """Account one node; return whether it should be built."""
        if depth > self.limits.max_depth:
            raise _Abort(TlRaw(reader.rest(), f"max depth {self.limits.max_depth} exceeded"))
        if self.exhausted or self.skip:
            return False
        self.nodes += 1
        if self.nodes > self.limits.max_nodes:
            self.exhausted = True
            return False
        return True

    # -- typed values -------------------------------------------------------- #
    def read_value(self, reader: _Reader, tl_type: TlType, depth: int) -> Any:
        kind = tl_type.kind
        if kind == "prim":
            return self._read_prim(reader, tl_type.name)
        if kind == "bool":
            return self._read_bool(reader, depth)
        if kind == "vector":
            return self._read_boxed_vector(reader, tl_type, depth)
        if kind == "bare_vector":
            return self._read_vector_body(reader, tl_type.elem, depth)
        if kind == "bare":
            return self._read_bare(reader, tl_type, depth)
        return self.read_boxed(reader, depth, expected=tl_type,
                               prefer_function=kind == "function")

    def _read_prim(self, reader: _Reader, name: str) -> Any:
        fixed = _FIXED_PRIMS.get(name)
        if fixed is not None:
            return reader.unpack(*fixed)
        if name in _WIDE_PRIMS:
            return reader.take(_WIDE_PRIMS[name])
        if name == "true":
            return True
        raw = reader.tl_bytes()
        return _decode_string(raw) if name == "string" else raw

    def _read_bool(self, reader: _Reader, depth: int) -> Any:
        start = reader.pos
        ctor_id = reader.uint32()
        if ctor_id == BOOL_TRUE_ID:
            return True
        if ctor_id == BOOL_FALSE_ID:
            return False
        return self._read_by_id(reader, ctor_id, start, depth, None, False)

    def _read_boxed_vector(self, reader: _Reader, tl_type: TlType, depth: int) -> Any:
        start = reader.pos
        ctor_id = reader.uint32()
        if ctor_id != VECTOR_ID:
            return self._read_by_id(reader, ctor_id, start, depth, tl_type, False)
        return self._read_vector_body(reader, tl_type.elem, depth)

    def _resolve_bare(self, name: str) -> Optional[TlCombinator]:
        combinator = self.schema.by_name.get(name)
        if combinator is not None:
            return combinator
        candidates = self.schema.by_type.get(name) or []
        return candidates[0] if candidates else None

    def _read_bare(self, reader: _Reader, tl_type: TlType, depth: int) -> Any:
        combinator = self._resolve_bare(tl_type.name)
        if combinator is None:
            return self.read_boxed(reader, depth, expected=None)
        if combinator.id == MESSAGE_BARE_ID:
            return self._read_message(reader, depth)
        return self._read_combinator(reader, combinator, reader.pos, depth)

    # -- boxed objects -------------------------------------------------------- #
    def read_boxed(self, reader: _Reader, depth: int, *, expected: Optional[TlType] = None,
                   prefer_function: bool = False) -> Any:
        start = reader.pos
        ctor_id = reader.uint32()
        return self._read_by_id(reader, ctor_id, start, depth, expected, prefer_function)

    def _lookup(self, ctor_id: int, prefer_function: bool) -> Optional[TlCombinator]:
        first, second = self.schema.constructors, self.schema.functions
        if prefer_function:
            first, second = second, first
        return first.get(ctor_id) or second.get(ctor_id)

    def _read_by_id(self, reader: _Reader, ctor_id: int, start: int, depth: int,
                    expected: Optional[TlType], prefer_function: bool) -> Any:
        if ctor_id == GZIP_PACKED_ID:
            return self._read_gzip(reader, start, depth, expected)
        if ctor_id == VECTOR_ID:
            elem = expected.elem if expected is not None and expected.kind == "vector" else None
            return self._read_vector_body(reader, elem, depth)
        if ctor_id == MSG_CONTAINER_ID:
            return self._read_container(reader, start, depth)
        if ctor_id == RPC_RESULT_ID:
            return self._read_rpc_result(reader, start, depth)
        combinator = self._lookup(ctor_id, prefer_function)
        if combinator is None:
            raise _Abort(self._unknown_node(reader, ctor_id, start))
        return self._read_combinator(reader, combinator, start, depth)

    def _unknown_node(self, reader: _Reader, ctor_id: int, start: int) -> TlNode:
        reason = f"unknown constructor 0x{ctor_id:08x}"
        remainder = TlRaw(reader.rest(), reason)
        return TlNode("unknown", ctor_id, "unknown", (TlField("remainder", "bytes", remainder),),
                      start, reader.end - start, note=reason)

    def _read_combinator(self, reader: _Reader, combinator: TlCombinator, start: int,
                         depth: int) -> Optional[TlNode]:
        build = self._enter(reader, depth)
        fields: List[TlField] = []
        flags: dict = {}
        omitted = False
        for param in combinator.params:
            if param.flag_field is not None and not (flags.get(param.flag_field, 0) >> param.flag_bit) & 1:
                continue
            try:
                value = self._read_param(reader, combinator, param, depth)
            except _Abort as abort:
                if not build:
                    raise
                fields.append(TlField(param.name, param.type, abort.partial, _flag_label(param)))
                raise _Abort(self._node(combinator, fields, start, reader,
                                        f"stopped at field {param.name!r}")) from None
            if param.type == "#":
                flags[param.name] = value
            if not build:
                continue
            if value is None:
                omitted = True
                continue
            fields.append(TlField(param.name, param.type, value, _flag_label(param)))
        if not build:
            return None
        note = "node budget exhausted: some fields omitted" if omitted else ""
        return self._node(combinator, fields, start, reader, note)

    def _read_param(self, reader: _Reader, combinator: TlCombinator, param, depth: int) -> Any:
        if param.type in combinator.generics:
            return self.read_boxed(reader, depth + 1)
        return self.read_value(reader, parse_type(param.type), depth + 1)

    @staticmethod
    def _node(combinator: TlCombinator, fields: List[TlField], start: int, reader: _Reader,
              note: str) -> TlNode:
        kind = "function" if combinator.is_function else "constructor"
        return TlNode(combinator.name, combinator.id, kind, tuple(fields), start,
                      reader.pos - start, note)

    # -- vectors -------------------------------------------------------------- #
    def _guess_elem(self, reader: _Reader, count: int) -> Optional[TlType]:
        """Element type of a vector whose type the schema does not give."""
        head = reader.peek_uint32()
        if head is not None and (head in self.schema.constructors or head == GZIP_PACKED_ID):
            return _OBJECT
        if reader.remaining == count * 8:
            return parse_type("long")
        if reader.remaining == count * 4:
            return parse_type("int")
        return None

    def _read_vector_body(self, reader: _Reader, elem: Optional[TlType], depth: int) -> Any:
        start = reader.pos
        count = reader.unpack("<i", 4)
        if count < 0 or count > reader.remaining:
            raise _Abort(TlRaw(reader.rest(), f"implausible vector count {count} at offset {start}"))
        if elem is None:
            elem = self._guess_elem(reader, count) if count else parse_type("long")
            if elem is None:
                raw = TlRaw(reader.rest(), "vector of unknown element type")
                raise _Abort(TlVector("?", (raw,), count, start, "element type unknown"))
        fixed = _FIXED_PRIMS.get(elem.name) if elem.kind == "prim" else None
        if fixed is not None:
            return self._read_fixed_vector(reader, fixed, count, start)
        return self._read_object_vector(reader, elem, count, start, depth)

    def _elem_label(self, elem: TlType) -> str:
        return elem.name if elem.elem is None else f"{elem.name}<{self._elem_label(elem.elem)}>"

    def _vector_note(self, count: int) -> str:
        extra = count - self.limits.keep_vector_items
        return f"… {extra} more" if extra > 0 else ""

    def _read_fixed_vector(self, reader: _Reader, fixed, count: int, start: int) -> Any:
        fmt, size = fixed
        reader._need(count * size)
        keep = min(count, self.limits.keep_vector_items)
        items = struct.unpack_from(f"<{keep}{fmt[1]}", reader.data, reader.pos) if keep else ()
        reader.pos += count * size
        if self.exhausted or self.skip:
            return None
        label = {"<i": "int", "<q": "long", "<d": "double", "<I": "#"}[fmt]
        return TlVector(label, tuple(items), count, start, self._vector_note(count))

    def _read_object_vector(self, reader: _Reader, elem: TlType, count: int, start: int,
                            depth: int) -> Any:
        building = not (self.exhausted or self.skip)
        keep = self.limits.keep_vector_items
        items: List[Any] = []
        label = self._elem_label(elem)
        for index in range(count):
            overflow = index >= keep
            self.skip += overflow
            try:
                value = self.read_value(reader, elem, depth + 1)
            except _Abort as abort:
                if not building:
                    raise
                items.append(abort.partial)
                raise _Abort(TlVector(label, tuple(items), count, start,
                                      f"stopped at item {index} of {count}")) from None
            finally:
                self.skip -= overflow
            if building and not overflow and value is not None:
                items.append(value)
        if not building:
            return None
        return TlVector(label, tuple(items), count, start, self._vector_note(count))

    # -- MTProto service objects --------------------------------------------- #
    def _read_gzip(self, reader: _Reader, start: int, depth: int,
                   inner_type: Optional[TlType]) -> Any:
        build = self._enter(reader, depth)
        packed = reader.tl_bytes()
        inflated, error = self._inflate(packed)
        if error:
            if not build:
                return None
            field = TlField("packed_data", "bytes", TlRaw(packed, error))
            return TlNode("gzip_packed", GZIP_PACKED_ID, "gzip", (field,), start,
                          reader.pos - start, error)
        inner, stopped = self._decode_bounded(_Reader(inflated), depth, inner_type)
        if not build:
            return None
        note = f"inflated {len(packed)} B → {len(inflated)} B"
        if stopped:
            note += "; inner decode stopped early"
        field = TlField("packed_data", "Object" if inner_type is None else inner_type.name, inner)
        return TlNode("gzip_packed", GZIP_PACKED_ID, "gzip", (field,), start,
                      reader.pos - start, note)

    def _inflate(self, packed: bytes):
        """``(inflated, "")`` or ``(b"", error)``; bounded by ``max_inflate``."""
        try:
            return inflate_bounded(packed, self.limits.max_inflate), ""
        except zlib.error as exc:
            return b"", f"inflate failed: {exc}"
        except InflateLimitError:
            return b"", f"inflate exceeds {self.limits.max_inflate} B limit"

    def _decode_bounded(self, sub: _Reader, depth: int, expected: Optional[TlType]):
        """Decode one object filling *sub*; ``(value, stopped)``. A boundary: never raises."""
        try:
            if expected is None:
                value = self.read_boxed(sub, depth + 1)
            else:
                value = self.read_value(sub, expected, depth + 1)
        except _Abort as abort:
            return abort.partial, True
        return value, False

    def _read_container(self, reader: _Reader, start: int, depth: int) -> Any:
        build = self._enter(reader, depth)
        count = reader.unpack("<i", 4)
        if count < 0 or count * 16 > reader.remaining:
            raise _Abort(TlRaw(reader.rest(), f"implausible msg_container count {count}"))
        messages: List[Any] = []
        for index in range(count):
            try:
                message = self._read_message(reader, depth + 1)
            except _Abort as abort:
                if not build:
                    raise
                messages.append(abort.partial)
                vector = TlVector("%Message", tuple(messages), count, start + 4,
                                  f"stopped at message {index} of {count}")
                raise _Abort(self._container_node(vector, start, reader)) from None
            if build and message is not None:
                messages.append(message)
        if not build:
            return None
        return self._container_node(TlVector("%Message", tuple(messages), count, start + 4),
                                    start, reader)

    @staticmethod
    def _container_node(vector: TlVector, start: int, reader: _Reader) -> TlNode:
        field = TlField("messages", "vector<%Message>", vector)
        return TlNode("msg_container", MSG_CONTAINER_ID, "constructor", (field,), start,
                      reader.pos - start, vector.note)

    def _read_message(self, reader: _Reader, depth: int) -> Any:
        """A bare container child ``message msg_id:long seqno:int bytes:int body:Object``."""
        start = reader.pos
        build = self._enter(reader, depth)
        msg_id = reader.unpack("<q", 8)
        seqno = reader.unpack("<i", 4)
        length = reader.unpack("<i", 4)
        reader._need(length)
        sub = _Reader(reader.data, reader.pos, reader.pos + length)
        reader.pos += length
        body, stopped = self._decode_bounded(sub, depth, None)
        if not build:
            return None
        fields = [TlField("msg_id", "long", msg_id), TlField("seqno", "int", seqno),
                  TlField("bytes", "int", length), TlField("body", "Object", body)]
        fields.extend(_trailing_fields(sub, stopped))
        return TlNode("message", None, "constructor", tuple(fields), start, reader.pos - start,
                      "body stopped early" if stopped else "")

    def _read_rpc_result(self, reader: _Reader, start: int, depth: int) -> Any:
        build = self._enter(reader, depth)
        req_msg_id = reader.unpack("<q", 8)
        expected, self.expect = self.expect, None
        head = [TlField("req_msg_id", "long", req_msg_id)]
        try:
            if expected is None:
                result = self.read_boxed(reader, depth + 1)
            else:
                result = self.read_value(reader, expected, depth + 1)
        except _Abort as abort:
            if not build:
                raise
            node = self._rpc_node(head, abort.partial, start, reader, "stopped at field 'result'")
            raise _Abort(node) from None
        if not build:
            return None
        return self._rpc_node(head, result, start, reader, "")

    @staticmethod
    def _rpc_node(head: List[TlField], result: Any, start: int, reader: _Reader,
                  note: str) -> TlNode:
        fields = tuple(head) + (TlField("result", "Object", result),)
        return TlNode("rpc_result", RPC_RESULT_ID, "constructor", fields, start,
                      reader.pos - start, note)

    # -- top level ------------------------------------------------------------ #
    def decode(self, data: bytes) -> TlNode:
        reader = _Reader(data)
        stopped = False
        try:
            value = self._read_top(reader)
        except _Abort as abort:
            value, stopped = abort.partial, True
        extra = list(_trailing_fields(reader, stopped))
        return self._finish(_as_node(value, len(data)), extra)

    def _read_top(self, reader: _Reader) -> Any:
        head = reader.peek_uint32()
        if self.expect is not None and head != RPC_RESULT_ID:
            expected, self.expect = self.expect, None
            return self.read_value(reader, expected, 0)
        start = reader.pos
        ctor_id = reader.uint32()
        return self._read_by_id(reader, ctor_id, start, 0, None, False)

    def _finish(self, node: TlNode, extra: List[TlField]) -> TlNode:
        note = node.note
        if self.exhausted:
            budget = f"node budget {self.limits.max_nodes} exhausted: rest walked in advance-only mode"
            note = f"{note}; {budget}" if note else budget
        if not extra and note == node.note:
            return node
        return dataclasses.replace(node, fields=node.fields + tuple(extra), note=note)


def _trailing_fields(reader: _Reader, stopped: bool):
    """A ``<trailing>`` raw field when a fully decoded buffer has bytes left."""
    if stopped or reader.pos >= reader.end:
        return ()
    raw = TlRaw(reader.rest(), f"{reader.remaining} trailing bytes after the object")
    return (TlField("<trailing>", "bytes", raw),)


def _as_node(value: Any, total: int) -> TlNode:
    """Wrap a non-node top-level value so ``decode_tl`` always returns a node."""
    if isinstance(value, TlNode):
        return value
    if isinstance(value, TlVector):
        field = TlField("items", f"Vector<{value.elem_type}>", value)
        return TlNode("vector", VECTOR_ID, "constructor", (field,), 0, total, value.note)
    if isinstance(value, TlRaw):
        field = TlField("remainder", "bytes", value)
        return TlNode("unknown", None, "unknown", (field,), 0, total, value.reason)
    return TlNode("value", None, "constructor", (TlField("value", type(value).__name__, value),),
                  0, total)


def _error_node(data: bytes, exc: BaseException) -> TlNode:
    reason = f"decoder error: {type(exc).__name__}: {exc}"
    field = TlField("remainder", "bytes", TlRaw(bytes(data), reason))
    return TlNode("unknown", None, "unknown", (field,), 0, len(data), reason)


def decode_tl(data: bytes, *, domain: str = "mtproto", expect: Optional[str] = None,
              limits: TlLimits = TlLimits()) -> TlNode:
    """Decode one TL payload into a :class:`TlNode` tree. Never raises.

    *domain* picks the schema stack (``"mtproto"`` or ``"secret"``). *expect*
    is an optional TL type (e.g. ``"messages.StickerSet"``): the type of an
    ``rpc_result``'s result when the payload is one, otherwise the type of the
    payload itself. Without it, objects are decoded boxed (constructor first,
    then function - client writes are RPC function calls).
    """
    try:
        return _TlDecoder(load_schema(domain), limits, expect).decode(bytes(data))
    except Exception as exc:  # noqa: BLE001 - the contract is "never raises"
        return _error_node(data, exc)


def rpc_result_ctor_id(data: bytes) -> Optional[int]:
    """Constructor id of a top-level ``rpc_result``'s result, seen through ``gzip_packed``.

    A cheap, name-only peek (no tree is built): ``None`` when *data* is not an
    ``rpc_result`` or is truncated / fails to inflate - exactly the cases in which
    :func:`decode_tl` yields no named result object.
    """
    reader = _Reader(bytes(data))
    try:
        if reader.uint32() != RPC_RESULT_ID:
            return None
        reader.take(8)  # req_msg_id:long
        ctor_id = reader.uint32()
        if ctor_id != GZIP_PACKED_ID:
            return ctor_id
        return _Reader(inflate_bounded(reader.tl_bytes())).uint32()
    except (_Abort, zlib.error, InflateLimitError):
        return None


@lru_cache(maxsize=256)
def decode_tl_cached(data: bytes, domain: str = "mtproto",
                     expect: Optional[str] = None) -> TlNode:
    """:func:`decode_tl` with default limits, memoised on the arguments."""
    return decode_tl(data, domain=domain, expect=expect)
