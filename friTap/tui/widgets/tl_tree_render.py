"""Render decoded TL trees, MTProto envelopes and cross-references as Rich markup.

Pure functions (no Textual widgets): each returns a ``list[str]`` of Rich
markup lines ready for ``RichLog.write``. Everything derived from captured data
is escaped with :func:`rich.markup.escape`, so a string such as ``"[bold]"``
inside a message renders literally.

Colours come from a *color* callable mapping a semantic role (``"primary"``,
``"accent"``, ``"warning"``, ``"success"``) to a Rich colour; it defaults to the
running TUI theme (:func:`friTap.tui.themes.c`).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Iterable, List, Mapping, Optional

from rich.markup import escape

from friTap.offline.mtproto.crossref import msg_id_hex
from friTap.offline.mtproto.packet_meta import msg_id_time
from friTap.offline.mtproto.tl import TlField, TlNode, TlRaw, TlVector

ColorFn = Callable[[str], str]
RefLabelFn = Callable[[int], Optional[str]]
RowOfFn = Callable[[Any], Optional[int]]
#: ``(ref item, method) -> tail`` used when a ref item's row is not resolvable.
RefFallbackFn = Callable[[Mapping, str], str]

MAX_STRING_CHARS = 512
BYTES_PREVIEW = 32
RAW_PREVIEW = 64
RAW_HEX_WIDTH = 16
MAX_FLAG_NAMES = 16
TRUNCATED_LINE = "… truncated — press h for raw hex"

_GLYPH_MID, _GLYPH_LAST = "├─ ", "└─ "
_PIPE_MID, _PIPE_LAST = "│  ", "   "

#: Plausible Unix time window for date-like ints and msg_id timestamps.
_MIN_EPOCH, _MAX_EPOCH = 1_000_000_000, 4_102_444_800  # 2001 .. 2100
_DATE_NAMES = frozenset({
    "date", "expires", "was_online", "until_date", "expires_at", "valid_since",
    "valid_until", "last_seen",
})
#: Mask reducing a (possibly signed) msg_id to its unsigned 64-bit value.
U64_MASK = (1 << 64) - 1
_U64 = U64_MASK


def _default_color(role: str) -> str:
    from friTap.tui.themes import c

    return c(role)


# --------------------------------------------------------------------------- #
# Scalar formatting
# --------------------------------------------------------------------------- #

def local_datetime(seconds: float) -> Optional[datetime]:
    """Local ``datetime`` for epoch *seconds*, or ``None`` when out of range."""
    try:
        return datetime.fromtimestamp(seconds)
    except (OverflowError, OSError, ValueError):
        return None


def local_time(seconds: float, *, millis: bool = False) -> str:
    """Local ``YYYY-MM-DD HH:MM:SS[.mmm]`` for epoch *seconds* ("" if invalid)."""
    stamp = local_datetime(seconds)
    if stamp is None:
        return ""
    text = stamp.strftime("%Y-%m-%d %H:%M:%S")
    return f"{text}.{stamp.microsecond // 1000:03d}" if millis else text


_local_time = local_time  # backwards-compatible private name


def _escape_char(char: str) -> str:
    if char == "\n":
        return "\\n"
    if char == "\r":
        return "\\r"
    if char == "\t":
        return "\\t"
    if char in '\\"':
        return "\\" + char
    if ord(char) < 0x20 or ord(char) == 0x7F:
        return f"\\x{ord(char):02x}"
    return char


def format_tl_string(text: str, limit: int = MAX_STRING_CHARS) -> str:
    """Quoted, control-char-escaped, markup-escaped *text*, truncated to *limit* chars."""
    shown = "".join(_escape_char(ch) for ch in text[:limit])
    quoted = escape(f'"{shown}"')
    if len(text) <= limit:
        return quoted
    return f"{quoted}… [dim]({len(text)} chars)[/]"


def format_tl_bytes(data: bytes, preview: int = BYTES_PREVIEW) -> str:
    """``bytes[len] <hex of the first *preview* bytes>…``."""
    if not data:
        return "bytes[0]"
    more = "…" if len(data) > preview else ""
    return f"bytes[{len(data)}] {data[:preview].hex()}{more}"


def is_date_field(name: str) -> bool:
    """True for field names that carry a Unix timestamp (``date``, ``*_date``, ``until*``…)."""
    return name in _DATE_NAMES or name.endswith("_date") or name.startswith("until")


def is_msg_id_field(name: str) -> bool:
    """True for field names holding an MTProto msg_id (``msg_id``, ``req_msg_id``…)."""
    return name.endswith("msg_id") or name == "msg_ids"


def format_date_value(value: int) -> str:
    """``1790358548 (2026-09-25 19:49:08)`` for plausible timestamps, else the number."""
    if _MIN_EPOCH < value <= _MAX_EPOCH:
        when = _local_time(value)
        if when:
            return f"{value} [dim]({when})[/]"
    return str(value)


def format_msg_id(msg_id: int, ref_label: Optional[RefLabelFn] = None) -> str:
    """Hex msg_id, its derived local time (with ms) and an optional row reference."""
    unsigned = msg_id & _U64
    text = msg_id_hex(unsigned)
    if _MIN_EPOCH < unsigned >> 32 <= _MAX_EPOCH:
        text += f" [dim]({local_time(msg_id_time(unsigned), millis=True)})[/]"
    label = ref_label(msg_id) if ref_label is not None else None
    if label:
        text += f" {escape(label)}"
    return text


def _format_int(name: str, value: int, ref_label: Optional[RefLabelFn]) -> str:
    if is_msg_id_field(name):
        return format_msg_id(value, ref_label)
    if is_date_field(name):
        return format_date_value(value)
    return str(value)


def format_scalar(name: str, tl_type: str, value: Any,
                  ref_label: Optional[RefLabelFn] = None) -> str:
    """Markup for one primitive TL value of field *name* / type *tl_type*."""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return _format_int(name, value, ref_label)
    if isinstance(value, str):
        return format_tl_string(value)
    if isinstance(value, (bytes, bytearray)):
        if tl_type in ("int128", "int256"):
            return f"0x{bytes(value).hex()}"
        suffix = " [dim](invalid UTF-8)[/]" if tl_type == "string" else ""
        return format_tl_bytes(bytes(value)) + suffix
    return escape(repr(value) if isinstance(value, float) else str(value))


def _flag_names(node: TlNode, flags_field: str) -> List[str]:
    prefix = f"{flags_field}."
    return [f.name for f in node.fields if f.flag_bit and f.flag_bit.startswith(prefix)]


def format_flags(node: TlNode, tl_field: TlField) -> str:
    """``0x02000457 (self, contact, …)``: the set bits named by the node's flag params."""
    value = tl_field.value if isinstance(tl_field.value, int) else 0
    names = _flag_names(node, tl_field.name)
    text = f"0x{value & 0xFFFFFFFF:08x}"
    if not names:
        return text
    shown = ", ".join(names[:MAX_FLAG_NAMES])
    if len(names) > MAX_FLAG_NAMES:
        shown += ", …"
    return f"{text} ({escape(shown)})"


def _type_label(tl_field: TlField) -> str:
    return f"{tl_field.flag_bit}?{tl_field.type}" if tl_field.flag_bit else tl_field.type


# --------------------------------------------------------------------------- #
# Tree rendering
# --------------------------------------------------------------------------- #

class _LineCapReached(Exception):
    """Raised by :meth:`_TreeWriter.emit` once ``max_lines`` lines exist."""


@dataclass
class _TreeWriter:
    color: ColorFn
    ref_label: Optional[RefLabelFn]
    max_lines: int
    base: str
    lines: List[str] = field(default_factory=list)
    gzip_depth: int = 0

    def emit(self, prefix: str, text: str) -> None:
        if len(self.lines) >= self.max_lines:
            raise _LineCapReached()
        self.lines.append(f"{self.base}{prefix}{text}")

    def styled(self, role: str, text: str, *, bold: bool = False) -> str:
        weight = "bold " if bold else ""
        return f"[{weight}{self.color(role)}]{text}[/]"


def _children_prefixes(prefix: str, last: bool):
    return prefix + (_GLYPH_LAST if last else _GLYPH_MID), prefix + (_PIPE_LAST if last else _PIPE_MID)


def _node_header(writer: _TreeWriter, node: TlNode) -> str:
    if node.kind == "unknown":
        label = f"unknown constructor 0x{node.ctor_id:08x}" if node.ctor_id is not None else "undecodable"
        return writer.styled("warning", escape(label), bold=True)
    if node.kind == "gzip":
        return _gzip_header(writer, node)
    ident = f"[dim]#{node.ctor_id:08x}[/]" if node.ctor_id is not None else ""
    header = f"[bold]{escape(node.name)}[/]{ident}"
    if node.note:
        header += "  " + writer.styled("warning", f"({escape(node.note)})")
    return header


def _gzip_header(writer: _TreeWriter, node: TlNode) -> str:
    name = f"[bold]{escape(node.name)}[/]"
    if node.note.startswith("inflated"):
        return f"{name} [dim]({escape(node.note)})[/]"
    return f"{name} " + writer.styled("warning", f"({escape(node.note)})")


def _raw_offset(parent: Optional[TlNode], name: str, raw: TlRaw) -> Optional[int]:
    """Best-effort offset of *raw* (always the rest of its buffer) within that buffer."""
    if parent is None:
        return None
    if parent.kind == "gzip":
        if not parent.note.startswith("inflated") and name == "packed_data":
            return parent.offset + 4 + (1 if len(raw.data) < 254 else 4)
        return None
    if parent.kind == "unknown" or parent.name == "message":
        return parent.offset + parent.length - len(raw.data)
    return parent.offset + parent.length


def _raw_summary(writer: _TreeWriter, raw: TlRaw, offset: Optional[int]) -> str:
    where = f" at +0x{offset:x}" if offset is not None else ""
    if writer.gzip_depth and offset is not None:
        where += " (inflated data)"
    text = f"undecoded remainder ({len(raw.data)} bytes){where}"
    return writer.styled("warning", text) + f"  [dim]{escape(raw.reason)}[/]"


def _write_raw(writer: _TreeWriter, raw: TlRaw, prefix: str, lead: str,
               offset: Optional[int]) -> None:
    writer.emit(lead, _raw_summary(writer, raw, offset))
    preview = raw.data[:RAW_PREVIEW]
    rows = [preview[i:i + RAW_HEX_WIDTH] for i in range(0, len(preview), RAW_HEX_WIDTH)]
    for index, row in enumerate(rows):
        more = "…" if index == len(rows) - 1 and len(raw.data) > RAW_PREVIEW else ""
        writer.emit(prefix + _PIPE_LAST, f"[dim]{row.hex(' ')}{more}[/]")


def _write_node_children(writer: _TreeWriter, node: TlNode, prefix: str) -> None:
    if node.kind == "gzip":
        writer.gzip_depth += 1
    try:
        for index, tl_field in enumerate(node.fields):
            _write_field(writer, node, tl_field, prefix, index == len(node.fields) - 1)
    finally:
        if node.kind == "gzip":
            writer.gzip_depth -= 1


def _write_field(writer: _TreeWriter, node: TlNode, tl_field: TlField, prefix: str,
                 last: bool) -> None:
    lead, child_prefix = _children_prefixes(prefix, last)
    label = f"{escape(tl_field.name)}: "
    value = tl_field.value
    if node.kind == "unknown" and tl_field.name == "remainder" and isinstance(value, TlRaw):
        label = ""
    _write_value(writer, label, tl_field.name, tl_field.type, value, lead, child_prefix,
                 parent=node, type_label=_type_label(tl_field), flags_of=(node, tl_field))


def _write_value(writer: _TreeWriter, label: str, name: str, tl_type: str, value: Any,
                 lead: str, child_prefix: str, *, parent: Optional[TlNode] = None,
                 type_label: str = "", flags_of=None) -> None:
    if isinstance(value, TlNode):
        writer.emit(lead, label + _node_header(writer, value))
        _write_node_children(writer, value, child_prefix)
    elif isinstance(value, TlVector):
        _write_vector(writer, label, name, value, lead, child_prefix)
    elif isinstance(value, TlRaw):
        _write_raw(writer, value, child_prefix, lead + label, _raw_offset(parent, name, value))
    elif value is None:
        writer.emit(lead, label + "[dim](omitted)[/]")
    else:
        if tl_type == "#" and flags_of is not None:
            text = format_flags(*flags_of)
        else:
            text = format_scalar(name, tl_type, value, writer.ref_label)
        suffix = f"  [dim]{escape(type_label)}[/]" if type_label else ""
        writer.emit(lead, f"{label}{text}{suffix}")


def _vector_header(vector: TlVector) -> str:
    header = escape(f"Vector<{vector.elem_type}> [{vector.total}]")
    if vector.note and not vector.note.startswith("…"):
        header += f"  [dim]({escape(vector.note)})[/]"
    return header


def _write_vector(writer: _TreeWriter, label: str, name: str, vector: TlVector,
                  lead: str, child_prefix: str) -> None:
    writer.emit(lead, label + _vector_header(vector))
    hidden = max(vector.total - len(vector.items), 0)
    item_name = name if is_msg_id_field(name) else ""
    for index, item in enumerate(vector.items):
        last = index == len(vector.items) - 1 and not hidden
        item_lead, item_prefix = _children_prefixes(child_prefix, last)
        offset = vector.offset + 4 if vector.elem_type == "?" else None
        if isinstance(item, TlRaw):
            _write_raw(writer, item, item_prefix, item_lead + f"[{index}] ", offset)
            continue
        _write_value(writer, f"\\[{index}] ", item_name, vector.elem_type, item,
                     item_lead, item_prefix)
    if hidden:
        writer.emit(child_prefix + _GLYPH_LAST, f"[dim]… {hidden} more[/]")


def render_tl_tree(node: TlNode, *, ref_label: Optional[RefLabelFn] = None,
                   max_lines: int = 4000, indent: str = "  ",
                   color: Optional[ColorFn] = None) -> List[str]:
    """Rich markup lines drawing *node* as a tree (``├─``/``└─``/``│``).

    *ref_label* maps a msg_id to a row reference such as ``"→ #12
    messages.getDialogs"`` (or ``None``). *indent* prefixes every line. Output
    stops after *max_lines* lines with a final "press h for raw hex" hint.
    """
    writer = _TreeWriter(color or _default_color, ref_label, max(max_lines, 1), indent)
    try:
        writer.emit("", _node_header(writer, node))
        _write_node_children(writer, node, "")
    except _LineCapReached:
        writer.lines.append(f"{indent}" + writer.styled("warning", TRUNCATED_LINE, bold=True))
    return writer.lines


# --------------------------------------------------------------------------- #
# Envelope
# --------------------------------------------------------------------------- #

def _fmt_msg_time(value: Any) -> str:
    if isinstance(value, (int, float)) and not isinstance(value, bool) and value > 0:
        return _local_time(float(value), millis=True) or str(value)
    return escape(str(value))


def _fmt_seq_no(value: Any, envelope: Mapping) -> str:
    related = envelope.get("content_related")
    if related is None and isinstance(value, int):
        related = bool(value & 1)
    return f"{value} ({'content-related' if related else 'service'})"


def _fmt_bytes_len(value: Any) -> str:
    return f"{value} B"


def _fmt_bool(value: Any) -> str:
    return "yes" if value else "no"


def _fmt_plain(value: Any) -> str:
    return escape(str(value))


# (key, label, formatter taking (value, envelope)); the order is the display order.
_ENVELOPE_ROWS = (
    ("msg_id", "msg_id", lambda v, e: _fmt_plain(v)),
    ("msg_time", "msg time", lambda v, e: _fmt_msg_time(v)),
    ("msg_id_kind", "msg_id kind", lambda v, e: _fmt_plain(v).replace("_", " ")),
    ("seq_no", "seq_no", _fmt_seq_no),
    ("auth_key_id", "auth_key_id", lambda v, e: _fmt_plain(v)),
    ("salt", "salt", lambda v, e: _fmt_plain(v)),
    ("session_id", "session_id", lambda v, e: _fmt_plain(v)),
    ("msg_len", "msg_len", lambda v, e: _fmt_bytes_len(v)),
    ("padding_len", "padding", lambda v, e: _fmt_bytes_len(v)),
    ("frame_len", "frame", lambda v, e: _fmt_bytes_len(v)),
    ("transport", "transport", lambda v, e: _fmt_plain(v)),
    ("obfuscated", "obfuscated", lambda v, e: _fmt_bool(v)),
    ("dc_id", "DC", lambda v, e: _fmt_plain(v)),
    ("dc", "DC", lambda v, e: _fmt_plain(v)),
    ("dc_addr", "DC address", lambda v, e: _fmt_plain(v)),
    ("key_fingerprint", "key fingerprint", lambda v, e: _fmt_plain(v)),
    ("msg_key", "msg_key", lambda v, e: _fmt_plain(v)),
    ("chat_id", "chat_id", lambda v, e: _fmt_plain(v)),
    ("carrier_msg_id", "carrier msg_id", lambda v, e: _fmt_plain(v)),
    ("carrier_auth_key_id", "carrier auth_key_id", lambda v, e: _fmt_plain(v)),
)
_ENVELOPE_HIDDEN = frozenset({"content_related"})
_LABEL_WIDTH = 20


def _envelope_line(label: str, text: str, indent: str) -> str:
    return f"{indent}[dim]{escape(label).ljust(_LABEL_WIDTH)}[/] {text}"


def _is_blank(value: Any) -> bool:
    return value is None or value == ""


def render_envelope(envelope: Optional[Mapping], *, indent: str = "  ") -> List[str]:
    """One ``label  value`` line per envelope key present (unknown keys last)."""
    if not envelope:
        return []
    lines: List[str] = []
    known = set(_ENVELOPE_HIDDEN)
    for key, label, formatter in _ENVELOPE_ROWS:
        known.add(key)
        value = envelope.get(key)
        if _is_blank(value):
            continue
        lines.append(_envelope_line(label, formatter(value, envelope), indent))
    for key, value in envelope.items():
        if key not in known and not _is_blank(value):
            lines.append(_envelope_line(str(key), _fmt_plain(value), indent))
    return lines


# --------------------------------------------------------------------------- #
# Cross-references
# --------------------------------------------------------------------------- #

def ref_items(value: Any) -> List[Mapping]:
    """The mapping item(s) of one ``refs`` value (a single item or a list)."""
    if isinstance(value, Mapping):
        return [value]
    if isinstance(value, (list, tuple)):
        return [item for item in value if isinstance(item, Mapping)]
    return []


_as_items = ref_items  # backwards-compatible private name


def _ref_msg_id(value: Any) -> str:
    if isinstance(value, int) and not isinstance(value, bool):
        return msg_id_hex(value)
    return escape(str(value)) if not _is_blank(value) else ""


def ref_target_text(item: Mapping, row_of: Optional[RowOfFn] = None,
                    fallback: Optional[RefFallbackFn] = None) -> str:
    """Unescaped ``#12 messages.getDialogs`` target of one cross-reference *item*.

    When *row_of* yields no row for an item that names a flow, *fallback*
    (``(item, method) -> tail``) builds the text instead (default: the method).
    """
    flow_id = item.get("flow_id")
    row = row_of(flow_id) if row_of is not None and flow_id is not None else None
    method = str(item.get("method") or "")
    if row is None and flow_id and fallback is not None:
        return fallback(item, method)
    return " ".join(p for p in (f"#{row}" if row is not None else "", method) if p)


def format_ref_item(item: Mapping, row_of: Optional[RowOfFn] = None,
                    fallback: Optional[RefFallbackFn] = None) -> str:
    """``msg 0x… → #12 messages.getDialogs`` for one cross-reference *item*."""
    parts = []
    msg_id = _ref_msg_id(item.get("msg_id"))
    if msg_id:
        parts.append(f"msg {msg_id}")
    tail = ref_target_text(item, row_of, fallback)
    if tail:
        parts.append(f"→ {escape(tail)}")
    return " ".join(parts) or "[dim](unresolved)[/]"


# (key, label); list-valued keys render one indented line per item.
_REF_ROWS = (
    ("answers", "answers"),
    ("answered_by", "answered by"),
    ("request_method", "request method"),
    # ``container`` lists the record's OWN children (crossref.py); a child
    # record carries no back-reference, so the heading is always "contains".
    ("container", "contains"),
    ("acks", "acks"),
    ("acked_by", "acked by"),
    ("carried_in", "carried in"),
    ("carries", "carries"),
)


def _ref_label(key: str, label: str, items: List[Mapping], refs: Mapping) -> str:
    if key == "acks":
        total = refs.get("acks_total")
        if isinstance(total, int) and total > len(items):
            return f"{label} ({len(items)} of {total})"
    return label


def _ref_lines(key: str, label: str, refs: Mapping, row_of: Optional[RowOfFn],
               indent: str, fallback: Optional[RefFallbackFn] = None) -> Iterable[str]:
    value = refs.get(key)
    if _is_blank(value) or value == [] or value == {}:
        return []
    if isinstance(value, str):
        return [_envelope_line(label, escape(value), indent)]
    items = ref_items(value)
    if not items:
        return []
    heading = _ref_label(key, label, items, refs)
    if len(items) == 1 and key != "acks":
        return [_envelope_line(heading, format_ref_item(items[0], row_of, fallback), indent)]
    lines = [f"{indent}[dim]{escape(heading)}:[/]"]
    lines.extend(f"{indent}  {format_ref_item(item, row_of, fallback)}" for item in items)
    return lines


def render_refs(refs: Optional[Mapping], row_of: Optional[RowOfFn] = None, *,
                indent: str = "  ", fallback: Optional[RefFallbackFn] = None) -> List[str]:
    """Cross-reference lines (answers, acks, container, carrier…); missing keys are skipped.

    *row_of* maps a flow id to its row number, rendered as ``#N``; *fallback*
    labels items whose row is unknown (see :func:`ref_target_text`).
    """
    if not refs:
        return []
    lines: List[str] = []
    for key, label in _REF_ROWS:
        lines.extend(_ref_lines(key, label, refs, row_of, indent, fallback))
    return lines
