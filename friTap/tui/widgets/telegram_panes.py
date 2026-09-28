"""Pure helpers for the forensic Telegram / MTProto panes of the flow detail view.

No Textual widgets: every function returns data or ``list[str]`` of Rich
markup lines ready for ``RichLog.write``. Everything derived from captured data
is escaped with :func:`rich.markup.escape`.

The TL tree / envelope / cross-reference drawing lives in
:mod:`friTap.tui.widgets.tl_tree_render`; this module adapts a flow and its
``mtproto`` / ``telegram_e2e`` layer to those renderers (records of one
direction, the right schema domain, the ``expect`` type of an ``rpc_result``,
a msg_id -> row label resolver, the users and Secret-Chat peer blocks).
"""

from __future__ import annotations

from functools import lru_cache
from typing import Any, Dict, List, Mapping, Optional

from rich.markup import escape

from friTap.tui.widgets.tl_tree_render import (  # noqa: F401  (RowOfFn/RefLabelFn re-exported)
    U64_MASK,
    RefLabelFn,
    RowOfFn,
    format_date_value,
    ref_items,
    ref_target_text,
    render_envelope,
    render_refs,
    render_tl_tree,
)

RPC_RESULT_ID = 0xF35C6D01
_U64 = U64_MASK
_SHORT_FLOW_ID = 18
_LABEL_WIDTH = 13
_PRIMITIVE_RESULTS = frozenset({"int", "long", "double", "string", "bytes", "Bool", "true"})
# Keys of ``layer.refs`` whose items point at another record by msg_id.
_REF_ITEM_KEYS = ("answers", "answered_by", "acks", "acked_by", "container",
                  "carried_in", "carries")
# Container children live in the same record, so the tree does not label them.
_TREE_REF_KEYS = tuple(key for key in _REF_ITEM_KEYS if key != "container")


# --------------------------------------------------------------------------- #
# Records and decoding
# --------------------------------------------------------------------------- #

def tl_domain_for(flow: Any) -> str:
    """TL schema domain of *flow*: ``"secret"`` for Secret-Chat, else ``"mtproto"``."""
    return "secret" if getattr(flow, "transport", "") == "telegram_e2e" else "mtproto"


def tl_records_for(flow: Any, direction: str) -> List[bytes]:
    """Decrypted TL record bytes of *direction* ("write"/"read"), one per chunk.

    Per-packet taps carry exactly one chunk; old grouped taps may carry several
    records per direction (rendered as "Record k/N").
    """
    return [bytes(ch.data) for ch in getattr(flow, "chunks", None) or []
            if ch.direction == direction and ch.data]


@lru_cache(maxsize=1)
def _function_result_types() -> Dict[str, str]:
    from friTap.offline.mtproto.tl import load_schema

    schema = load_schema("mtproto")
    return {fn.name: fn.result_type for fn in schema.functions.values()}


def _is_decodable_type(result_type: str) -> bool:
    from friTap.offline.mtproto.tl import load_schema

    if result_type in _PRIMITIVE_RESULTS or result_type.startswith("Vector<"):
        return True
    return result_type in load_schema("mtproto").by_type


def result_type_for(request_method: Optional[str]) -> Optional[str]:
    """Result type of the RPC function *request_method* (``expect`` for its rpc_result).

    ``None`` when the method is unknown or its result is a generic (``X``).
    """
    if not request_method:
        return None
    try:
        result_type = _function_result_types().get(str(request_method))
    except Exception:
        return None
    if result_type and _is_decodable_type(result_type):
        return result_type
    return None


def _is_rpc_result(data: bytes) -> bool:
    return len(data) >= 4 and int.from_bytes(data[:4], "little") == RPC_RESULT_ID


def decode_record(data: bytes, domain: str = "mtproto",
                  request_method: Optional[str] = None):
    """Decode one TL record; a top-level ``rpc_result`` is typed by its request.

    The typed decode is only kept when it does not stop early; otherwise the
    boxed (schema-guessing) decode is used.
    """
    from friTap.offline.mtproto.tl import decode_tl_cached, stopped_early

    expect = result_type_for(request_method) if domain == "mtproto" else None
    if expect and _is_rpc_result(data):
        typed = decode_tl_cached(data, domain, expect)
        if not stopped_early(typed):
            return typed
    return decode_tl_cached(data, domain)


# --------------------------------------------------------------------------- #
# Row references
# --------------------------------------------------------------------------- #

def short_flow_id(flow_id: Any) -> str:
    """Tail of a (long) flow id, used when the referenced row is not visible."""
    text = str(flow_id)
    return text if len(text) <= _SHORT_FLOW_ID else "…" + text[-_SHORT_FLOW_ID:]


def _safe_row(row_of: Optional[RowOfFn], flow_id: Any) -> Optional[int]:
    if row_of is None or flow_id is None:
        return None
    try:
        return row_of(flow_id)
    except Exception:
        return None


def _parse_msg_id(value: Any) -> Optional[int]:
    if isinstance(value, int) and not isinstance(value, bool):
        return value & _U64
    try:
        return int(str(value), 16) & _U64
    except (TypeError, ValueError):
        return None


def _iter_ref_items(refs: Mapping, keys=_REF_ITEM_KEYS):
    for key in keys:
        yield from ref_items(refs.get(key))


def ref_index(refs: Optional[Mapping], keys=_REF_ITEM_KEYS) -> Dict[int, Mapping]:
    """msg_id (int) -> cross-reference item, over the ref kinds *keys* of *refs*."""
    index: Dict[int, Mapping] = {}
    for item in _iter_ref_items(refs or {}, keys):
        msg_id = _parse_msg_id(item.get("msg_id"))
        if msg_id is not None and (msg_id not in index or item.get("flow_id")):
            index[msg_id] = item
    return index


def ref_target_label(item: Mapping, row_of: Optional[RowOfFn]) -> Optional[str]:
    """``→ #12 account.getPrivacy`` (row, else short flow id) for one ref item."""
    tail = ref_target_text(item, _safe_row_fn(row_of), _flow_prefix_target)
    return f"→ {tail}" if tail else None


def _flow_prefix_target(item: Mapping, method: str) -> str:
    """``flow …<id> method``: the target of a ref whose row is not visible."""
    return " ".join(p for p in (f"flow {short_flow_id(item['flow_id'])}", method) if p)


def _flow_suffix_target(item: Mapping, method: str) -> str:
    """``method (flow …<id>)``: a cross-reference row whose target is not visible."""
    return f"{method} (flow {short_flow_id(item['flow_id'])})".strip()


def make_ref_label(refs: Optional[Mapping], row_of: Optional[RowOfFn]) -> RefLabelFn:
    """A ``ref_label`` callback for :func:`render_tl_tree` (msg_id -> row label)."""
    index = ref_index(refs, _TREE_REF_KEYS)

    def label(msg_id: int) -> Optional[str]:
        item = index.get(msg_id & _U64)
        return ref_target_label(item, row_of) if item is not None else None

    return label


# --------------------------------------------------------------------------- #
# Section blocks
# --------------------------------------------------------------------------- #

def envelope_lines(layer: Any) -> List[str]:
    """Envelope rows of an ``mtproto`` / ``telegram_e2e`` layer (``[]`` if absent)."""
    envelope = dict(getattr(layer, "envelope", None) or {})
    envelope.pop("record_seq", None)
    return render_envelope(envelope)


def _with_fallback_targets(refs: Mapping, row_of: Optional[RowOfFn]) -> Dict[str, Any]:
    """Copy of *refs* where items without a visible row name their flow instead.

    No longer used by :func:`refs_lines` (which passes :func:`_flow_suffix_target`
    to the renderer instead of copying the refs); kept for API compatibility.
    """
    def patch(item: Any) -> Any:
        if not isinstance(item, Mapping) or not item.get("flow_id"):
            return item
        if _safe_row(row_of, item["flow_id"]) is not None:
            return item
        method = str(item.get("method") or "")
        suffix = f"(flow {short_flow_id(item['flow_id'])})"
        return {**item, "flow_id": None, "method": f"{method} {suffix}".strip()}

    patched: Dict[str, Any] = {}
    for key, value in refs.items():
        if isinstance(value, (list, tuple)):
            patched[key] = [patch(item) for item in value]
        else:
            patched[key] = patch(value)
    return patched


def refs_lines(layer: Any, row_of: Optional[RowOfFn] = None) -> List[str]:
    """Cross-reference rows (answers, acks, container, carrier…) with ``#row`` targets."""
    refs = getattr(layer, "refs", None) or {}
    if not refs:
        return []
    return render_refs(refs, _safe_row_fn(row_of), fallback=_flow_suffix_target)


def _safe_row_fn(row_of: Optional[RowOfFn]) -> Optional[RowOfFn]:
    if row_of is None:
        return None
    return lambda flow_id: _safe_row(row_of, flow_id)


def _user_title(user: Mapping) -> str:
    name = " ".join(str(user.get(k) or "") for k in ("first_name", "last_name")).strip()
    title = escape(name or "(no name)")
    flags = [str(f) for f in user.get("flags") or []]
    badge = f"  [dim]\\[{escape(', '.join(flags))}][/]" if flags else ""
    return f"[bold]{title}[/]  [dim](id {escape(str(user.get('id', '?')))})[/]{badge}"


def format_user_status(status: Any) -> str:
    """``offline, was_online 1790… (2026-…)`` for a status dict (dates resolved)."""
    if not isinstance(status, Mapping):
        return escape(str(status))
    parts = [escape(str(status.get("kind") or "?"))]
    for key, value in status.items():
        if key == "kind":
            continue
        shown = format_date_value(value) if isinstance(value, int) else escape(str(value))
        parts.append(f"{escape(str(key))} {shown}")
    return ", ".join(parts)


def _user_field_value(key: str, value: Any) -> str:
    if key == "status":
        return format_user_status(value)
    if key == "username":
        return "@" + escape(str(value))
    if key == "has_photo":
        return "yes" if value else "no"
    return escape(str(value))


# (key, label) in display order; any other non-empty key is shown after these.
_USER_FIELDS = (
    ("username", "username"), ("phone", "phone"), ("status", "status"),
    ("access_hash", "access_hash"), ("lang_code", "lang_code"),
    ("has_photo", "photo"), ("ctor", "constructor"),
)
_USER_SKIP = frozenset({"id", "first_name", "last_name", "flags"})


def _user_rows(user: Mapping) -> List[str]:
    known = {key for key, _ in _USER_FIELDS} | _USER_SKIP
    pairs = [(label, user.get(key), key) for key, label in _USER_FIELDS]
    pairs += [(str(key), value, key) for key, value in user.items() if key not in known]
    return [f"      [dim]{escape(label).ljust(_LABEL_WIDTH)}[/] {_user_field_value(key, value)}"
            for label, value, key in pairs if value not in (None, "", [], {})]


def users_lines(users: Any) -> List[str]:
    """One block per user: name, id, flags, then every non-empty field."""
    lines: List[str] = []
    for user in users or []:
        if isinstance(user, Mapping):
            lines.append("    " + _user_title(user))
            lines.extend(_user_rows(user))
    return lines


def peer_lines(peer: Any) -> List[str]:
    """Secret-Chat peer rows: label, user id, chat id (``[]`` when unknown)."""
    if not isinstance(peer, Mapping) or not peer:
        return []
    rows = [("peer", peer.get("label")), ("user_id", peer.get("user_id") or None),
            ("chat_id", peer.get("chat_id"))]
    return [f"  [dim]{label.ljust(_LABEL_WIDTH)}[/] {escape(str(value))}"
            for label, value in rows if value not in (None, "")]


def decoded_tree_lines(records: List[bytes], domain: str, *,
                       request_method: Optional[str] = None,
                       ref_label: Optional[RefLabelFn] = None) -> List[str]:
    """TL tree lines of every record; several records get "Record k/N" headings."""
    lines: List[str] = []
    total = len(records)
    for index, data in enumerate(records, 1):
        if total > 1:
            lines.append(f"  [bold]Record {index}/{total}[/]  [dim]({len(data)} B)[/]")
        node = decode_record(data, domain, request_method)
        lines.extend(render_tl_tree(node, ref_label=ref_label))
    return lines
