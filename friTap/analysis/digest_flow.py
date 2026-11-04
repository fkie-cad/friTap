"""
Flow drill-down for digest refs (``fritap report <file.tap> --flow f12``).

Resolves a ``f<N>`` / ``f<N>#m<k>`` ref emitted by :mod:`friTap.analysis.digest`
(or a full flow id) to one flow's metadata — full flow id, endpoints, protocol
stack, timestamps — and its decoded content: the HTTP request/response (headers
and a body preview) and the E2E transcript messages (signal / telegram_e2e /
mtproto layers; ``#m<k>`` selects one).

Safety contract (same as the digest):

* Payload-derived strings live under ``untrusted``: control-char escaped, keylog
  lines and long hex runs (possible key material) scrubbed, every body / message
  preview capped at ``max_bytes``.
* Only the FLOW record is read; the keylog and TLS secrets never are.
* Unless ``show_values``: URLs keep their keys but lose query/fragment values,
  header values outside a small benign allowlist become shapes
  (``<str(bearer-auth)>``), JSON/form bodies and message fields are rendered
  with every value replaced by its shape, and free text (text bodies, message
  texts) is pattern-masked (e-mails, query values, digit runs).
"""

from __future__ import annotations

import json
import os
from typing import TYPE_CHECKING, Any
from urllib.parse import parse_qsl

from friTap.analysis._digest_shapes import classify_body, safe_untrusted, value_shape
from friTap.analysis._limits import safe_json_loads
from friTap.analysis.digest import (
    UNTRUSTED_NOTICE,
    _flow_bytes,
    _flow_host,
    _iso,
    _iter_messages,
    _server_endpoint,
    flow_group,
    flow_ref,
    ordered_flow_ids,
    parse_ref,
)
from friTap.analysis.redaction import (
    DIGIT_RUN_IN_TEXT_RE,
    PLUMBING_HEADERS,
    REDACTED,
    scrub_key_material,
    scrub_values,
)
from friTap.analysis.reporters import _sanitize_text

if TYPE_CHECKING:
    from friTap.flow.models import Flow

SCHEMA = "fritap.flow/1"
DEFAULT_MAX_BYTES = 2048
MAX_MESSAGES = 50
MAX_HEADERS = 60
_MAX_SHAPE_DEPTH = 8
_MAX_SHAPE_ITEMS = 50

# Header values shown verbatim (still scrubbed) when values are redacted:
# protocol plumbing that describes software / format, never the user.
_BENIGN_HEADERS = PLUMBING_HEADERS | frozenset({
    ":authority", ":method", ":scheme", ":status", "accept-ranges",
    "access-control-allow-methods", "age", "alt-svc", "date", "expires",
    "grpc-encoding", "grpc-status", "last-modified", "server", "transfer-encoding",
    "user-agent", "vary", "via", "x-content-type-options",
})
# Header values that are URLs: shown with query/fragment values masked.
_URL_HEADERS = frozenset({":path", "location", "origin", "referer", "content-location"})
_VERBATIM_HEADERS = _BENIGN_HEADERS | _URL_HEADERS
# Message fields carrying free text (pattern-masked, not shape-only).
_TEXT_FIELDS = frozenset({"body", "text", "message", "caption"})
# Message fields naming the protocol operation (shown like ``kind``).
_PROTOCOL_FIELDS = frozenset({"method"})


class FlowRefError(ValueError):
    """A ``--flow`` ref is malformed or names no flow/message of the capture."""


# ---------------------------------------------------------------------------
# Value rendering (redacted unless show_values)
# ---------------------------------------------------------------------------

def _cap(text: str, max_bytes: int) -> tuple[str, bool]:
    encoded = text.encode("utf-8", errors="replace")
    if len(encoded) <= max_bytes:
        return text, False
    return encoded[:max_bytes].decode("utf-8", errors="ignore"), True


def _untrusted_block(text: str, max_bytes: int) -> tuple[str, bool]:
    """Multi-line payload text: control chars escaped, key material scrubbed, capped."""
    return _cap(scrub_key_material(_sanitize_text(text)), max_bytes)


def _mask_free_text(text: str) -> str:
    """Best-effort PII masking of unstructured text (values hidden, words kept)."""
    return DIGIT_RUN_IN_TEXT_RE.sub("<digits>", scrub_values(text, placeholder=REDACTED))


def _shape_tag(value: Any) -> str:
    return f"<{value_shape(value)}>"


def _shape_json(node: Any, depth: int = 0) -> Any:
    """Replace every JSON leaf by its shape; keep keys and nesting (bounded)."""
    if depth >= _MAX_SHAPE_DEPTH and isinstance(node, (dict, list)):
        return _shape_tag(node)
    if isinstance(node, dict):
        items = list(node.items())[:_MAX_SHAPE_ITEMS]
        return {str(key): _shape_json(value, depth + 1) for key, value in items}
    if isinstance(node, list):
        return [_shape_json(item, depth + 1) for item in node[:_MAX_SHAPE_ITEMS]]
    return None if node is None else _shape_tag(node)


def _printable(data: bytes) -> str:
    """UTF-8 text with undecodable bytes and non-printables shown as ``.``."""
    text = data.decode("utf-8", errors="replace").replace("\r\n", "\n")
    return "".join(ch if (ch.isprintable() and ch != "\ufffd") or ch in "\n\t" else "."
                   for ch in text)


def _shaped_structured_body(body: bytes, kind: str) -> str | None:
    """Keys/nesting of a JSON or form body with every value as its shape."""
    if kind == "json":
        parsed = safe_json_loads(body)
        if isinstance(parsed, (dict, list)):
            shaped = json.dumps(_shape_json(parsed), ensure_ascii=False, separators=(",", ":"))
            return scrub_values(shaped, placeholder=REDACTED)
    if kind == "form":
        pairs = parse_qsl(body.decode("utf-8", errors="replace"), keep_blank_values=True)
        return "&".join(f"{key}={_shape_tag(value)}" for key, value in pairs[:_MAX_SHAPE_ITEMS])
    return None


def _body_preview(body: bytes, kind: str, max_bytes: int, show_values: bool) -> tuple[str, bool]:
    """Return ``(preview, truncated)`` for a body (shape-only / masked unless revealing)."""
    shaped = None if show_values else _shaped_structured_body(body, kind)
    if shaped is not None:
        return _untrusted_block(shaped, max_bytes)
    text = _printable(body[:max_bytes])
    preview, cut = _untrusted_block(text if show_values else _mask_free_text(text), max_bytes)
    return preview, cut or len(body) > max_bytes


def _header_value(name: str, value: Any, show_values: bool) -> str:
    text = str(value)
    if show_values:
        return safe_untrusted(text, 512)
    if name in _VERBATIM_HEADERS:
        return safe_untrusted(scrub_values(text, placeholder=REDACTED), 512)
    return _shape_tag(text)


def _headers(headers: dict, show_values: bool) -> dict[str, str]:
    shown: dict[str, str] = {}
    for name, value in list((headers or {}).items())[:MAX_HEADERS]:
        key = safe_untrusted(str(name).lower(), 64)
        shown[key] = _header_value(key, value, show_values)
    return shown


# ---------------------------------------------------------------------------
# Sections
# ---------------------------------------------------------------------------

def _endpoint(addr: str, port: int) -> str:
    if not addr:
        return ""
    return safe_untrusted(f"{addr}:{port}" if port else addr, 80)


def _flow_meta(flow: "Flow", ordinal: int) -> dict:
    stack = [safe_untrusted(getattr(layer, "name", "") or "?", 32)
             for layer in getattr(flow, "layers", []) or []]
    return {
        "ref": flow_ref(ordinal),
        "flow_id": safe_untrusted(flow.flow_id, 200),
        "src": _endpoint(flow.src_addr, flow.src_port),
        "dst": _endpoint(flow.dst_addr, flow.dst_port),
        "server": safe_untrusted(_server_endpoint(flow), 80),
        "group": flow_group(flow),
        "transport": safe_untrusted(flow.transport or "", 32),
        "stack": stack,
        "state": safe_untrusted(getattr(flow.state, "value", flow.state), 16),
        "started": _iso(float(flow.started or 0.0)),
        "ended": _iso(float(flow.ended or 0.0)),
        "bytes": _flow_bytes(flow, 0),
        "untrusted": {"host": _flow_host(flow)},
    }


def _add_body(out: dict, untrusted: dict, body: bytes, content_type: str,
              max_bytes: int, show_values: bool) -> None:
    if not body:
        return
    kind, _keys = classify_body(body, content_type)
    preview, truncated = _body_preview(body, kind, max_bytes, show_values)
    out.update({"body_kind": kind, "body_bytes": len(body)})
    if truncated:
        out["body_truncated"] = True
    untrusted["body"] = preview


def _exchange_part(flow: "Flow", is_request: bool, max_bytes: int, show_values: bool) -> dict | None:
    """The HTTP request (``is_request``) or response of *flow*, or ``None``."""
    part = flow.request if is_request else flow.response
    if part is None or getattr(part, "is_control_frame", False):
        return None
    out: dict[str, Any] = {"direction": "write" if is_request else "read",
                           "protocol": safe_untrusted(part.protocol or "", 32)}
    untrusted: dict[str, Any] = {}
    if is_request:
        url = part.url or ""
        untrusted["method"] = safe_untrusted(part.method or "", 40)
        untrusted["url"] = safe_untrusted(url if show_values else scrub_values(url), 512)
    else:
        out["status"] = int(part.status_code or 0)
        untrusted["status_text"] = safe_untrusted(part.status_text or "", 80)
    untrusted["headers"] = _headers(part.headers, show_values)
    side = "request" if is_request else "response"
    body = _safe_call(getattr(flow, f"get_decompressed_{side}_body"), b"")
    content_type = _safe_call(lambda: getattr(flow, f"{side}_content_type"), "")
    _add_body(out, untrusted, body, content_type, max_bytes, show_values)
    out["untrusted"] = untrusted
    return out


def _safe_call(getter, default: Any) -> Any:
    try:
        return getter() or default
    except Exception:  # noqa: BLE001 - attacker-controlled flow, never raise
        return default


def _message_field(key: str, value: Any, max_bytes: int, show_values: bool) -> Any:
    if key in _PROTOCOL_FIELDS and isinstance(value, str):
        return safe_untrusted(value, 80)
    if key in _TEXT_FIELDS and isinstance(value, str):
        text = value if show_values else _mask_free_text(value)
        return _untrusted_block(text, max_bytes)[0]
    if not show_values:
        return None if value is None else _shape_tag(value)
    if isinstance(value, (dict, list)):
        value = json.dumps(value, ensure_ascii=False, default=str)
    return _untrusted_block(str(value), max_bytes)[0]


def _message_row(ordinal: int, index: int, layer: str, msg: dict,
                 max_bytes: int, show_values: bool) -> dict:
    fields = {
        safe_untrusted(key, 48): _message_field(str(key), value, max_bytes, show_values)
        for key, value in msg.items() if key not in ("direction", "kind")
    }
    return {
        "ref": flow_ref(ordinal, index),
        "layer": layer,
        "direction": safe_untrusted(str(msg.get("direction", "")), 16),
        "untrusted": {"kind": safe_untrusted(str(msg.get("kind") or msg.get("method") or "?"), 48),
                      "fields": fields},
    }


def _messages(flow: "Flow", ordinal: int, msg_index: int | None,
              max_bytes: int, show_values: bool) -> tuple[list[dict], int]:
    rows, total = [], 0
    for index, layer, msg in _iter_messages(flow):
        total += 1
        wanted = index == msg_index if msg_index is not None else len(rows) < MAX_MESSAGES
        if wanted:
            rows.append(_message_row(ordinal, index, layer, msg, max_bytes, show_values))
    if msg_index is not None and not rows:
        valid = f"m0..m{total - 1}" if total else f"use {flow_ref(ordinal, None)}"
        raise FlowRefError(f"{flow_ref(ordinal, msg_index)}: flow has {total} messages "
                           f"({valid})")
    return rows, total


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def _resolve(ids: list[str], ref: str) -> tuple[int, int | None]:
    """Return ``(ordinal, msg_index)`` for *ref* (``f<N>[#m<k>]`` or a full flow id)."""
    parsed = parse_ref(ref)
    if parsed is None:
        if ref in ids:
            return ids.index(ref) + 1, None
        raise FlowRefError(f"malformed flow ref {ref!r}; expected f<N> or f<N>#m<k>")
    ordinal, msg_index = parsed
    if ordinal > len(ids):
        raise FlowRefError(f"unknown flow ref {ref!r}: capture has {len(ids)} flows "
                           f"(f1..f{len(ids)})")
    return ordinal, msg_index


def build_flow_detail(
    tap_path: str,
    ref: str,
    *,
    max_bytes: int = DEFAULT_MAX_BYTES,
    show_values: bool = False,
) -> dict:
    """Resolve *ref* in the capture at *tap_path* to a flow-detail dict.

    Raises:
        FlowRefError: malformed ref, unknown flow, or unknown message index.
        ValueError: non-positive ``max_bytes``.
    """
    from friTap.flow.tap_reader import TapReader

    if max_bytes <= 0:
        raise ValueError("max_bytes must be positive")
    with TapReader(tap_path) as reader:
        return flow_detail_from(reader, ordered_flow_ids(reader), ref,
                                source_file=os.path.basename(tap_path),
                                max_bytes=max_bytes, show_values=show_values)


def flow_detail_from(
    reader: Any,
    ids: list[str],
    ref: str,
    *,
    source_file: str,
    max_bytes: int = DEFAULT_MAX_BYTES,
    show_values: bool = False,
) -> dict:
    """:func:`build_flow_detail` on an open reader (``ids`` from :func:`ordered_flow_ids`).

    Lets callers rendering many refs open and index the capture once.
    """
    ordinal, msg_index = _resolve(ids, ref)
    flow = reader.read_flow(ids[ordinal - 1])
    if flow is None:
        raise FlowRefError(f"flow {flow_ref(ordinal)} could not be decoded")
    detail: dict[str, Any] = {
        "schema": SCHEMA,
        "source": {"file": source_file},
        "params": {"ref": safe_untrusted(ref, 64), "max_bytes": max_bytes,
                   "show_values": show_values},
        "notice": UNTRUSTED_NOTICE,
        "flow": _flow_meta(flow, ordinal),
    }
    if msg_index is None:
        detail["request"] = _exchange_part(flow, True, max_bytes, show_values)
        detail["response"] = _exchange_part(flow, False, max_bytes, show_values)
    messages, total = _messages(flow, ordinal, msg_index, max_bytes, show_values)
    detail["messages"] = messages
    detail["messages_total"] = total
    return detail


__all__ = ["SCHEMA", "DEFAULT_MAX_BYTES", "FlowRefError", "build_flow_detail", "flow_detail_from"]
