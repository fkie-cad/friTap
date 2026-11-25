"""
.tap file format constants, structs, and encode/decode functions.

The .tap format stores friTap flow captures for offline replay in the TUI.
It uses a binary envelope with JSON metadata + raw binary blobs per record.

Layout:
    [HEADER 64 bytes]
    [RECORD]*             -- streamed during capture
    [FLOW_INDEX record]   -- written at close (optional for partial captures)
    [FOOTER 16 bytes]     -- written at close
"""

from __future__ import annotations

import json
import struct
import zlib
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Optional

from friTap.caller_stack_shapes import (
    REQUEST_CONTEXT_FRAME_LIMIT,
    REQUEST_CONTEXT_FRAME_TEXT_LIMIT,
    REQUEST_CONTEXT_TEXT_LIMITS,
    REQUEST_CONTEXT_URL_LIMIT,
    bounded_strings,
    capped_text,
    finite_float,
    optional_bool,
    sanitize_caller_stack,
    strict_int,
)
from friTap.flow.attribution import KIND_PATTERN, sanitize_attribution

if TYPE_CHECKING:
    from friTap.flow.models import Flow
    from friTap.parsers.base import ParseResult

MAGIC = b"TAP\x01"
FORMAT_VERSION = 1

# Header flags (u16).
FLAG_HAS_INDEX = 0x0001
# Set at close() when a REC_FINDING record was written, so a reader can skip the
# scan. Additive: old files lack it, so absence means "unknown", not "no findings".
FLAG_HAS_FINDINGS = 0x0002
# Set at close() when a REC_REQUEST_CONTEXT record was written, so a reader of an
# indexed file can skip the scan; an indexed file without it has none.
FLAG_HAS_REQUEST_CONTEXTS = 0x0004

# Record types (u8).
REC_FLOW = 0x01
REC_KEYLOG = 0x02
REC_META = 0x03
REC_FINDING = 0x04
# Per-request Java context that may match no flow; see encode_request_context.
REC_REQUEST_CONTEXT = 0x05
REC_FLOW_INDEX = 0x10

# Precedes every record; a reader rescans for it to recover from corruption.
SYNC_MARKER = b"\xF7\xA9\x00\x00"

# Distinct from the header magic so a truncated file (no footer) is detectable.
FOOTER_MAGIC = b"TAP_END\x00"  # 8 bytes

# Struct formats are compiled once at module level for speed.
# Header: magic(4) + version(2) + flags(2) + capture_start(8) + flow_count(4)
#        + ext_header_len(4) + reserved(8) + capture_target(32) = 64 bytes
_HEADER_STRUCT = struct.Struct("<4sHHdII8s32s")
assert _HEADER_STRUCT.size == 64

# Record envelope: sync(4) + type(1) + reserved_u8(1) + reserved_u16(2) + payload_len(4) + crc32(4) = 16
_RECORD_ENVELOPE = struct.Struct("<4sBBHII")
assert _RECORD_ENVELOPE.size == 16

# JSON metadata length prefix inside FLOW payload
_META_LEN = struct.Struct("<I")

# Footer: footer_magic(8) + index_offset(8) = 16
_FOOTER_STRUCT = struct.Struct("<8sQ")
assert _FOOTER_STRUCT.size == 16

# Flow schema version embedded in every FLOW record's JSON.
# v2 adds optional enrichment keys (tls, tags, notes, local/remote, process_name,
# hook_*) and the body-from-chunks de-duplication flag; v3 adds meta["layers"].
# All additive: readers use ``.get`` with defaults, so older records still decode.
# Optional keys written only when set (``stream_id``, ``truncated``,
# ``total_size``) need no version bump: older readers ignore them.
FLOW_SCHEMA_VERSION = 3


@dataclass
class TapHeader:
    """Parsed .tap file header."""
    format_version: int = FORMAT_VERSION
    flags: int = 0
    capture_start: float = 0.0
    flow_count: int = 0
    ext_header_len: int = 0
    capture_target: str = ""
    ext_data: dict | None = None


@dataclass
class TapMeta:
    """File-level metadata from the META record."""
    schema_version: int = 1
    flow_fields_version: int = FLOW_SCHEMA_VERSION
    parse_result_version: int = 1
    fritap_version: str = ""


@dataclass
class FlowSummary:
    """Lightweight flow metadata for the flow list table (no chunks/bodies)."""
    flow_id: str = ""
    connection_id: str = ""
    src_addr: str = ""
    src_port: int = 0
    dst_addr: str = ""
    dst_port: int = 0
    ssl_session_id: str = ""
    state: str = "complete"
    started: float = 0.0
    ended: float = 0.0
    # Mirrors Flow.transport ("tls", "quic", "signal", "mtproto", ...) for grouping
    # without decoding the full Flow. Persisted in FLOW meta when non-default.
    transport: str = "tls"
    # From ParseResult (request)
    protocol: str = "unknown"
    method: str = ""
    url: str = ""
    host: str = ""
    # From ParseResult (response)
    status_code: int = 0
    status_text: str = ""
    body_size: int = 0
    total_size: int = 0  # Sum of all chunk blob sizes (for display when no parsed response)
    # Record offset for on-demand full loading
    file_offset: int = 0
    # Protocol detected by the parser registry even without a request/response (e.g. HTTP/2 control-only).
    detected_protocol: str = ""
    # HTTP/2 control frame (SETTINGS, PING, etc.) with no request/response payload.
    is_control_frame: bool = False
    # Schema v2 enrichment scalars (read from FLOW meta; cheap, no blobs).
    process_name: str = ""
    tls_sni: str = ""
    tls_alpn: str = ""
    tag_count: int = 0
    finding_count: int = 0
    has_notes: bool = False
    # Layered protocol-display scalars (parity with models.FlowSummary).
    outer_app_protocol: str = ""
    inner_e2e_protocol: str = ""
    inner_summary: str = ""
    # Primary TL operation from message-bearing layers (display.method_from_messages).
    flow_method: str = ""
    # Which halves were parsed (from FLOW meta ``request``/``response``, so old taps work too).
    has_request: bool = False
    has_response: bool = False
    # OHTTP inner request/response present (from ``ohttp_inner_*``), for the replay filter preset.
    has_ohttp: bool = False
    # Real transport stream id of a single-stream flow: meta ``stream_id``, else derived from chunk ids.
    stream_id: Optional[int] = None
    # Precomputed display-filter inputs (parity with models.FlowSummary), derived from
    # ``meta["layers"]`` on decode and never persisted; plain dict (picklable), read-only.
    filter_attrs: Mapping[str, tuple] = field(default_factory=dict)
    protocols: frozenset[str] = frozenset()

    @property
    def display_method(self) -> str:
        """Method-column string: the derived TL method, else the HTTP method."""
        from friTap.flow import display as _display
        return _display.display_method_layered(self)

    @property
    def display_protocol_layered(self) -> str:
        """Layered ``outer-app[inner-E2E]`` protocol string (display imported locally: import cycle)."""
        from friTap.flow import display as _display
        return _display.display_protocol_layered(self)

    @staticmethod
    def from_flow(flow: "Flow") -> "FlowSummary":
        """Build this summary shape from a live/full Flow, matching the offline :meth:`to_dict` key set.

        Uses the non-mutating ``flow.layer()`` lookup so the layer stack never grows.
        """
        from friTap.flow.models import shared_summary_fields
        req = flow.request
        resp = flow.response
        total = getattr(flow, "_total_bytes", 0) or sum(len(c.data) for c in flow.chunks)
        state = flow.state.value if hasattr(flow.state, "value") else str(flow.state)
        return FlowSummary(
            **shared_summary_fields(flow),
            state=state,
            protocol=(req.protocol if req else "") or (resp.protocol if resp else "") or "unknown",
            method=req.method if req else "",
            url=req.url if req else "",
            host=req.host if req else "",
            status_code=resp.status_code if resp else 0,
            status_text=resp.status_text if resp else "",
            body_size=(resp.body_size if resp else (req.body_size if req else 0)),
            total_size=total,
            file_offset=0,
            detected_protocol=getattr(flow, "detected_protocol", "") or "",
            is_control_frame=(req.is_control_frame if req else False),
            process_name=getattr(flow, "process_name", "") or "",
            has_request=req is not None,
            has_response=resp is not None,
        )

    def to_dict(self) -> dict:
        """Return a JSON-safe, body-free overview dict; key set must match :meth:`friTap.flow.models.FlowSummary.to_dict`."""
        duration = (self.ended - self.started) if self.ended > 0 else 0.0
        out = {
            "flow_id": self.flow_id,
            "connection_id": self.connection_id,
            "src_addr": self.src_addr,
            "src_port": self.src_port,
            "dst_addr": self.dst_addr,
            "dst_port": self.dst_port,
            "ssl_session_id": self.ssl_session_id,
            "state": str(self.state),
            "started": self.started,
            "ended": self.ended,
            "duration": duration,
            "transport": self.transport,
            "protocol": self.detected_protocol or self.protocol or "unknown",
            "method": self.method,
            "url": self.url,
            "host": self.host,
            "status_code": self.status_code,
            "total_bytes": self.total_size,
            "detected_protocol": self.detected_protocol,
            "process_name": self.process_name,
            "tls_sni": self.tls_sni,
            "tls_alpn": self.tls_alpn,
            "tag_count": self.tag_count,
            "finding_count": self.finding_count,
            "has_notes": self.has_notes,
            "outer_app_protocol": self.outer_app_protocol,
            "inner_e2e_protocol": self.inner_e2e_protocol,
            "inner_summary": self.inner_summary,
            "flow_method": self.flow_method,
        }
        from friTap.flow.models import put_stream_id
        # Omitted when unknown, in parity with models.FlowSummary.to_dict.
        return put_stream_id(out, self.stream_id)


def encode_header(
    capture_start: float = 0.0,
    flow_count: int = 0,
    flags: int = 0,
    capture_target: str = "",
    ext_data: dict | None = None,
) -> bytes:
    """Encode a 64-byte .tap file header, optionally followed by ext data."""
    target_bytes = _truncate_utf8(capture_target, 32)

    ext_bytes = b""
    ext_len = 0
    if ext_data:
        ext_bytes = json.dumps(ext_data, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        ext_len = len(ext_bytes)

    header = _HEADER_STRUCT.pack(
        MAGIC,
        FORMAT_VERSION,
        flags,
        capture_start,
        flow_count,
        ext_len,
        b"\x00" * 8,
        target_bytes,
    )
    return header + ext_bytes


def encode_record(record_type: int, payload: bytes) -> bytes:
    """Wrap a payload in a record envelope with sync marker and CRC32."""
    crc = zlib.crc32(payload) & 0xFFFFFFFF
    envelope = _RECORD_ENVELOPE.pack(
        SYNC_MARKER,
        record_type,
        0,  # reserved byte
        0,  # reserved u16
        len(payload),
        crc,
    )
    return envelope + payload


def encode_footer(index_offset: int) -> bytes:
    """Encode the 16-byte footer pointing to the FLOW_INDEX record."""
    return _FOOTER_STRUCT.pack(FOOTER_MAGIC, index_offset)


def encode_meta(meta: TapMeta) -> bytes:
    """Encode a META record payload."""
    d = {
        "schema_version": meta.schema_version,
        "flow_fields_version": meta.flow_fields_version,
        "parse_result_version": meta.parse_result_version,
        "fritap_version": meta.fritap_version,
    }
    return json.dumps(d, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def encode_keylog(key_data: str, timestamp: float) -> bytes:
    """Encode a KEYLOG record payload."""
    d = {"key_data": key_data, "timestamp": timestamp}
    return json.dumps(d, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


# Cap on string-valued evidence fields persisted in a finding record, to keep
# REC_FINDING records small (analysts get a snippet, not whole bodies).
_MAX_EVIDENCE_STR = 512


def _bound_finding_dict(d: dict) -> dict:
    """Copy of a serialized finding with evidence strings capped and bytes hex-encoded."""
    evidence = d.get("evidence")
    if not isinstance(evidence, dict):
        return d
    bounded = {}
    for k, v in evidence.items():
        if isinstance(v, str) and len(v) > _MAX_EVIDENCE_STR:
            bounded[k] = v[:_MAX_EVIDENCE_STR] + "…[truncated]"
        elif isinstance(v, (bytes, bytearray)):
            # Hex-encode all bytes: raw bytes would make json.dumps abort the whole REC_FINDING write.
            if len(v) > _MAX_EVIDENCE_STR:
                bounded[k] = bytes(v[:_MAX_EVIDENCE_STR]).hex() + "…[truncated]"
            else:
                bounded[k] = bytes(v).hex()
        else:
            bounded[k] = v
    out = dict(d)
    out["evidence"] = bounded
    return out


def encode_finding_record(flow_id: str, finding_dicts: list[dict]) -> bytes:
    """Encode a REC_FINDING payload binding already-serialized findings (``Finding.to_dict()``) to a flow_id.

    Taking dicts keeps tap_format free of an ``analysis`` import (cycle). Evidence strings are bounded via :func:`_bound_finding_dict`.
    """
    d = {
        "flow_id": flow_id,
        "findings": [_bound_finding_dict(fd) for fd in finding_dicts],
    }
    # default=str: one odd non-JSON evidence value from a custom analyzer must never abort persisting.
    return json.dumps(
        d, ensure_ascii=False, separators=(",", ":"), default=str
    ).encode("utf-8")


def decode_finding_record(payload: bytes) -> tuple[str, list[dict]]:
    """Decode a REC_FINDING payload. Returns (flow_id, list[finding_dict])."""
    d = json.loads(payload.decode("utf-8", errors="replace"))
    return d.get("flow_id", ""), d.get("findings", [])


# REC_REQUEST_CONTEXT: one per-request Java context.

#: Bounds of a request-context record. Everything in it comes from the target
#: process (or a hand-crafted .tap), so it is re-bounded on write AND on read.
#: Text and frame bounds are shared with the router (:mod:`friTap.caller_stack_shapes`).
MAX_REQUEST_CONTEXT_REDIRECTS = 16
MAX_REQUEST_CONTEXT_FLOW_IDS = 64
#: Flow ids are host-generated but an IPv6 5-tuple id exceeds the compact cap.
MAX_REQUEST_CONTEXT_FLOW_ID_LEN = 256
#: Accepted HTTP status range (-1 = unknown, as Java stacks report it).
_REQUEST_CONTEXT_STATUS_RANGE = range(-1, 1000)

#: Escaped/capped string fields -> character limit. The record stores the event's
#: ``negotiated_protocol`` as ``protocol``; ``stack_kind`` is slug-checked instead.
_REQUEST_CONTEXT_TEXT_FIELDS = {
    ("protocol" if name == "negotiated_protocol" else name): limit
    for name, limit in REQUEST_CONTEXT_TEXT_LIMITS.items() if name != "stack_kind"
}
#: List-of-string fields -> (max entries, per-entry character limit).
_REQUEST_CONTEXT_LIST_FIELDS = {
    "frames": (REQUEST_CONTEXT_FRAME_LIMIT, REQUEST_CONTEXT_FRAME_TEXT_LIMIT),
    "redirects": (MAX_REQUEST_CONTEXT_REDIRECTS, REQUEST_CONTEXT_URL_LIMIT),
    "matched_flow_ids": (MAX_REQUEST_CONTEXT_FLOW_IDS, MAX_REQUEST_CONTEXT_FLOW_ID_LEN),
}
_REQUEST_CONTEXT_TIME_FIELDS = ("t_start", "t_end")
_REQUEST_CONTEXT_BOOL_FIELDS = ("cached", "main_frame")
#: Originator-claim keys bounded by friTap.flow.attribution.sanitize_attribution.
_REQUEST_CONTEXT_ATTRIBUTION_KEYS = ("originator", "confidence", "source", "bucket")


def _bounded_status(value: Any) -> Optional[int]:
    """*value* when it is an int HTTP status in range (bools are rejected)."""
    status = strict_int(value)
    return status if status in _REQUEST_CONTEXT_STATUS_RANGE else None


def _request_context_scalars(value: Mapping) -> dict:
    """The text, time, status, bool and slug fields of *value*, bounded."""
    clean: dict = {}
    for key, limit in _REQUEST_CONTEXT_TEXT_FIELDS.items():
        if isinstance(value.get(key), str):
            clean[key] = capped_text(value[key], limit)
    stack_kind = value.get("stack_kind")
    if isinstance(stack_kind, str) and KIND_PATTERN.fullmatch(stack_kind):
        clean["stack_kind"] = stack_kind
    for key in _REQUEST_CONTEXT_TIME_FIELDS:
        bounded_time = finite_float(value.get(key))
        if bounded_time is not None:
            clean[key] = bounded_time
    status = _bounded_status(value.get("status"))
    if status is not None:
        clean["status"] = status
    for key in _REQUEST_CONTEXT_BOOL_FIELDS:
        flag = optional_bool(value.get(key))
        if flag is not None:
            clean[key] = flag
    return clean


def sanitize_request_context(value: Any) -> Optional[dict]:
    """Re-bound an untrusted request-context dict: known keys only, strings escaped
    and capped, lists capped, claim bounded like ``Flow.attribution``. ``None``
    without a ``req_id``."""
    if not isinstance(value, Mapping):
        return None
    clean = _request_context_scalars(value)
    if not clean.get("req_id"):
        return None
    for key, (max_entries, text_limit) in _REQUEST_CONTEXT_LIST_FIELDS.items():
        if isinstance(value.get(key), list):
            clean[key] = bounded_strings(value[key], max_entries, text_limit)
    claim = sanitize_attribution(
        {key: value.get(key) for key in _REQUEST_CONTEXT_ATTRIBUTION_KEYS}
    ) or {}
    clean.update({key: claim[key] for key in _REQUEST_CONTEXT_ATTRIBUTION_KEYS if key in claim})
    return clean


def encode_request_context(record: Mapping) -> bytes:
    """Encode a REC_REQUEST_CONTEXT payload (JSON, bounded by :func:`sanitize_request_context`); ``ValueError`` without a ``req_id``."""
    clean = sanitize_request_context(record)
    if clean is None:
        raise ValueError("request context needs a non-empty string req_id")
    return json.dumps(clean, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def decode_request_context(payload: bytes) -> Optional[dict]:
    """Decode a REC_REQUEST_CONTEXT payload, re-bounded as untrusted input; ``None`` for undecodable JSON (incl. deep nesting) or a record failing :func:`sanitize_request_context`."""
    try:
        value = json.loads(payload.decode("utf-8", errors="replace"))
    except (ValueError, RecursionError):
        return None
    return sanitize_request_context(value)


def encode_flow(flow: "Flow") -> bytes:
    """Encode a Flow into a FLOW record payload: ``[json_meta_len u32 LE][json_meta][blobs]``.

    Blobs (chunk data, bodies) are concatenated; the JSON meta references them by blob_offset/blob_len.
    """
    # Meta key order and blob registration order define the output bytes, so
    # the steps below must keep their sequence.
    blob_table = _BlobTable()
    register_blob = blob_table.register
    chunks_meta = _encode_chunks(flow, register_blob)
    meta = _encode_core_meta(flow, chunks_meta, register_blob)
    _encode_trailing(flow, meta, register_blob)
    _encode_response_trailing(flow, meta, register_blob)
    _encode_size_and_stream_id(flow, meta, chunks_meta)
    _encode_enrichment(flow, meta)
    _encode_layers_meta(flow, meta, register_blob)
    _encode_display_scalars(flow, meta)

    meta_bytes = json.dumps(meta, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return _META_LEN.pack(len(meta_bytes)) + meta_bytes + blob_table.joined()


class _BlobTable:
    """Blob section of one FLOW record; ``register`` returns (offset, length)."""

    __slots__ = ("_blobs", "_offset", "_registered")

    def __init__(self) -> None:
        self._blobs: list[bytes] = []
        self._offset = 0
        # Identical payloads within one flow share one blob region (e.g. an MTProto body IS its chunk's bytes).
        self._registered: dict[bytes, tuple[int, int]] = {}

    def register(self, data: bytes) -> tuple[int, int]:
        if not data:
            return self._offset, 0
        key = data if isinstance(data, bytes) else bytes(data)
        known = self._registered.get(key)
        if known is not None:
            return known
        self._registered[key] = (self._offset, len(key))
        self._blobs.append(key)
        self._offset += len(key)
        return self._registered[key]

    def joined(self) -> bytes:
        return b"".join(self._blobs)


def _encode_chunks(flow: "Flow", register_blob) -> list[dict]:
    """Per-chunk meta dicts; chunk bytes go to the blob section."""
    chunks_meta = []
    for chunk in flow.chunks:
        off, ln = register_blob(chunk.data)
        chunk_meta = {
            "direction": chunk.direction,
            "timestamp": chunk.timestamp,
            "function": chunk.function,
            "blob_offset": off,
            "blob_len": ln,
        }
        # Additive, written only when set so id-less records stay byte-identical.
        if chunk.stream_id is not None:
            chunk_meta["stream_id"] = chunk.stream_id
        chunks_meta.append(chunk_meta)
    return chunks_meta


def _encode_core_meta(flow: "Flow", chunks_meta: list, register_blob) -> dict:
    """Identity, endpoints, state, chunks and the request/response results."""
    return {
        "_v": FLOW_SCHEMA_VERSION,
        "flow_id": flow.flow_id,
        "connection_id": flow.connection_id,
        "src_addr": flow.src_addr,
        "src_port": flow.src_port,
        "dst_addr": flow.dst_addr,
        "dst_port": flow.dst_port,
        "ssl_session_id": flow.ssl_session_id,
        "state": flow.state.value if hasattr(flow.state, "value") else str(flow.state),
        "started": flow.started,
        "ended": flow.ended,
        "chunks": chunks_meta,
        "request": _encode_parse_result(flow.request, register_blob, flow=flow),
        "response": _encode_parse_result(flow.response, register_blob, flow=flow),
        "ohttp_inner_request": _encode_parse_result(
            getattr(flow, "ohttp_inner_request", None), register_blob
        ),
        "ohttp_inner_response": _encode_parse_result(
            getattr(flow, "ohttp_inner_response", None), register_blob
        ),
    }


def _encode_trailing(flow: "Flow", meta: dict, register_blob) -> None:
    """``trailing_*`` keys: unconsumed bytes after valid protocol frames."""
    if not flow.trailing_bytes:
        return
    t_off, t_len = register_blob(flow.trailing_bytes)
    meta["trailing_blob_offset"] = t_off
    meta["trailing_blob_len"] = t_len
    meta["trailing_protocol"] = flow.trailing_protocol
    if flow.trailing_parse is not None:
        meta["trailing_parse"] = _encode_parse_result(flow.trailing_parse, register_blob)


def _encode_size_and_stream_id(flow: "Flow", meta: dict, chunks_meta: list) -> None:
    """``detected_protocol``, ``truncated``, ``stream_id`` and ``total_size``."""
    if flow.detected_protocol:
        meta["detected_protocol"] = flow.detected_protocol
    # Additive, written only when set: older readers ignore the key.
    if getattr(flow, "truncated", False):
        meta["truncated"] = True
    from friTap.flow.models import put_stream_id
    # Derived from chunks on decode; the copy lets the summary path skip the chunk scan.
    put_stream_id(meta, flow.stream_id)
    # Additive, written only when non-zero: the summary path reads it instead of summing chunk ``blob_len``.
    # Caches the sum of retained chunk blob lengths (what readers would compute); not the live byte counter.
    total_size = sum(cm["blob_len"] for cm in chunks_meta)
    if total_size:
        meta["total_size"] = total_size


def _encode_enrichment(flow: "Flow", meta: dict) -> None:
    """Schema v2 additive enrichment, written only when non-default.

    Findings go in separate REC_FINDING records so the summary fast path stays lean.
    """
    if getattr(flow, "local_addr", "") or getattr(flow, "local_port", 0):
        meta["local_addr"] = flow.local_addr
        meta["local_port"] = flow.local_port
        meta["remote_addr"] = flow.remote_addr
        meta["remote_port"] = flow.remote_port
    if getattr(flow, "process_name", ""):
        meta["process_name"] = flow.process_name
    if getattr(flow, "package_name", ""):
        meta["package_name"] = flow.package_name
    # Process origin (multi-process captures): additive, written only when set.
    if getattr(flow, "pid", None) is not None:
        meta["pid"] = flow.pid
    if getattr(flow, "process_role", ""):
        meta["process_role"] = flow.process_role
    # Omitted when None so a flow without it is byte-identical to a pre-attribution record.
    if getattr(flow, "sdk", None):
        meta["sdk"] = flow.sdk
    # Caller stack and option-5 synthetic-endpoint flag: additive, written only when set.
    if getattr(flow, "caller_stack", None):
        meta["caller_stack"] = flow.caller_stack
    if getattr(flow, "endpoints_synthetic", False):
        meta["endpoints_synthetic"] = True
    # Transport vs originator attribution: additive, written only when set.
    if getattr(flow, "attribution", None):
        meta["attribution"] = flow.attribution
    _encode_tls_scalars(flow, meta)
    if getattr(flow, "hook_function", ""):
        meta["hook_function"] = flow.hook_function
    if getattr(flow, "hook_stack", ""):
        meta["hook_stack"] = flow.hook_stack
    if getattr(flow, "tags", None):
        meta["tags"] = list(flow.tags)
    if getattr(flow, "notes", ""):
        meta["notes"] = flow.notes
    # Transport hint, written only when non-default.
    if getattr(flow, "transport", "tls") and flow.transport != "tls":
        meta["transport"] = flow.transport


def _encode_tls_scalars(flow: "Flow", meta: dict) -> None:
    """``tls`` key from a non-empty TLS layer."""
    # Non-mutating: layer() returns None rather than attaching an empty TLS layer.
    tls = flow.layer("tls")
    if tls is not None and not tls.is_empty():
        meta["tls"] = {
            "library": tls.library, "version": tls.version, "sni": tls.sni,
            "alpn": tls.alpn, "cipher": tls.cipher,
        }


def _encode_layers_meta(flow: "Flow", meta: dict, register_blob) -> None:
    """Schema v3 ordered protocol layer stack (``layers`` key).

    Additive: the fields above stay the source of truth and layers mirror them.
    Transport/app layers carry no bytes (``data_from_chunks`` + a ``parsed_field``
    tag), so nothing is duplicated; only owned inner layers serialize their bytes,
    once, via register_blob. Empty layers are skipped except metadata-only markers
    (e.g. HTTP/2 or WebSocket encapsulation on an offline Signal flow).
    """
    layers_meta = [
        _encode_layer(ly, register_blob)
        for ly in getattr(flow, "layers", [])
        if not ly.is_empty() or ly.metadata_only or _has_owned_bytes(ly)
    ]
    if layers_meta:
        meta["layers"] = layers_meta


def _encode_display_scalars(flow: "Flow", meta: dict) -> None:
    """Layered protocol-display scalars, written only when non-empty (computed from the full layer stack so decode_flow_summary needn't re-walk layers)."""
    from friTap.flow import display as _display
    outer_app, inner_e2e, inner_summary = _display.layered_scalars_from_flow(flow)
    if outer_app:
        meta["outer_app_protocol"] = outer_app
    if inner_e2e:
        meta["inner_e2e_protocol"] = inner_e2e
    if inner_summary:
        meta["inner_summary"] = inner_summary
    flow_method = getattr(flow, "flow_method", "") or _display.method_from_messages(flow)
    if flow_method:
        meta["flow_method"] = flow_method


def _encode_response_trailing(flow: "Flow", meta: dict, register_blob) -> None:
    """Additive ``resp_trailing_*`` meta keys for read-direction trailing data."""
    data = getattr(flow, "response_trailing_bytes", None)
    if not data:
        return
    r_off, r_len = register_blob(data)
    meta["resp_trailing_blob_offset"] = r_off
    meta["resp_trailing_blob_len"] = r_len
    meta["resp_trailing_protocol"] = flow.response_trailing_protocol
    if flow.response_trailing_parse is not None:
        meta["resp_trailing_parse"] = _encode_parse_result(
            flow.response_trailing_parse, register_blob)


def _decode_response_trailing(flow: "Flow", meta: dict, read_blob) -> None:
    """Restore ``resp_trailing_*``; taps written before it keep the defaults."""
    r_len = meta.get("resp_trailing_blob_len", 0)
    if not r_len:
        return
    flow.response_trailing_bytes = read_blob(
        meta.get("resp_trailing_blob_offset", 0), r_len)
    flow.response_trailing_protocol = meta.get("resp_trailing_protocol", "")
    flow.response_trailing_parse = _decode_parse_result(
        meta.get("resp_trailing_parse"), read_blob)


def encode_flow_index(entries: list[dict]) -> bytes:
    """Encode a FLOW_INDEX record payload from ``{"flow_id", "offset"}`` entries."""
    d = {"version": 1, "entries": entries}
    return json.dumps(d, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def decode_header(data: bytes) -> tuple[TapHeader, int]:
    """Decode a .tap header; returns ``(TapHeader, total_header_bytes)`` (fixed 64 bytes plus extension data)."""
    if len(data) < _HEADER_STRUCT.size:
        raise ValueError(f"Header too short: {len(data)} bytes, need {_HEADER_STRUCT.size}")

    magic, version, flags, capture_start, flow_count, ext_len, _reserved, target_raw = (
        _HEADER_STRUCT.unpack(data[:_HEADER_STRUCT.size])
    )

    if magic != MAGIC:
        raise ValueError(f"Invalid magic: {magic!r}, expected {MAGIC!r}")

    if version > FORMAT_VERSION:
        raise ValueError(
            f"Format version {version} is newer than supported ({FORMAT_VERSION}). "
            "Please update friTap."
        )

    header = TapHeader(
        format_version=version,
        flags=flags,
        capture_start=capture_start,
        flow_count=flow_count,
        ext_header_len=ext_len,
        capture_target=target_raw.rstrip(b"\x00").decode("utf-8", errors="replace"),
    )

    total = _HEADER_STRUCT.size
    if ext_len > 0:
        ext_raw = data[total : total + ext_len]
        if len(ext_raw) < ext_len:
            raise ValueError(f"Extension header truncated: got {len(ext_raw)}, expected {ext_len}")
        header.ext_data = json.loads(ext_raw.decode("utf-8", errors="replace"))
        total += ext_len

    return header, total


def decode_record_envelope(data: bytes) -> tuple[int, int, int, int]:
    """Decode a 16-byte record envelope: ``(record_type, payload_len, stored_crc, envelope_size)``; ``ValueError`` on a bad sync marker."""
    if len(data) < _RECORD_ENVELOPE.size:
        raise ValueError(f"Record envelope too short: {len(data)} bytes")

    sync, rec_type, _res1, _res2, payload_len, stored_crc = _RECORD_ENVELOPE.unpack(
        data[:_RECORD_ENVELOPE.size]
    )

    if sync != SYNC_MARKER:
        raise ValueError(f"Invalid sync marker: {sync!r}")

    return rec_type, payload_len, stored_crc, _RECORD_ENVELOPE.size


def verify_payload_crc(payload: bytes, stored_crc: int) -> bool:
    """Verify CRC32 of a record payload."""
    computed = zlib.crc32(payload) & 0xFFFFFFFF
    return computed == stored_crc


def decode_meta(payload: bytes) -> TapMeta:
    """Decode a META record payload.

    Defaults mirror ``TapMeta`` so an encode/decode round-trip is a fixed point;
    a missing ``flow_fields_version`` is ``FLOW_SCHEMA_VERSION``, not ``1``.
    """
    d = json.loads(payload.decode("utf-8", errors="replace"))
    return TapMeta(
        schema_version=d.get("schema_version", 1),
        flow_fields_version=d.get("flow_fields_version", FLOW_SCHEMA_VERSION),
        parse_result_version=d.get("parse_result_version", 1),
        fritap_version=d.get("fritap_version", ""),
    )


def resolve_flow_schema_version(flow_meta: dict) -> int:
    """A flow's effective schema version from its JSON meta (v1 records have no ``_v``); the only place to branch on per-flow version."""
    return int(flow_meta.get("_v", 1))


def decode_keylog(payload: bytes) -> tuple[str, float]:
    """Decode a KEYLOG record payload. Returns (key_data, timestamp)."""
    d = json.loads(payload.decode("utf-8", errors="replace"))
    return d.get("key_data", ""), d.get("timestamp", 0.0)


def decode_flow(payload: bytes) -> "Flow":
    """Decode a FLOW record payload into a Flow with chunks and ParseResults."""
    from friTap.flow.models import Flow, FlowChunk, FlowState

    if len(payload) < 4:
        raise ValueError(f"FLOW payload too short: {len(payload)} bytes")

    meta_len = _META_LEN.unpack(payload[:4])[0]
    if 4 + meta_len > len(payload):
        raise ValueError(f"FLOW meta_len ({meta_len}) exceeds payload size ({len(payload)})")

    meta_bytes = payload[4 : 4 + meta_len]
    blob_section = payload[4 + meta_len :]

    meta = json.loads(meta_bytes.decode("utf-8", errors="replace"))

    def read_blob(offset: int, length: int) -> bytes:
        if length == 0:
            return b""
        return blob_section[offset : offset + length]

    chunks = []
    for cm in meta.get("chunks", []):
        chunks.append(FlowChunk(
            data=read_blob(cm.get("blob_offset", 0), cm.get("blob_len", 0)),
            direction=cm.get("direction", "read"),
            timestamp=cm.get("timestamp", 0.0),
            function=cm.get("function", ""),
            stream_id=cm.get("stream_id"),
        ))

    state_str = meta.get("state", "complete")
    try:
        state = FlowState(state_str)
    except ValueError:
        state = FlowState.COMPLETE

    flow = Flow(
        flow_id=meta.get("flow_id", ""),
        connection_id=meta.get("connection_id", ""),
        src_addr=meta.get("src_addr", ""),
        src_port=meta.get("src_port", 0),
        dst_addr=meta.get("dst_addr", ""),
        dst_port=meta.get("dst_port", 0),
        ssl_session_id=meta.get("ssl_session_id", ""),
        state=state,
        started=meta.get("started", 0.0),
        ended=meta.get("ended", 0.0),
        request=_decode_parse_result(meta.get("request"), read_blob),
        response=_decode_parse_result(meta.get("response"), read_blob),
        chunks=chunks,
    )

    flow.ohttp_inner_request = _decode_parse_result(
        meta.get("ohttp_inner_request"), read_blob
    )
    flow.ohttp_inner_response = _decode_parse_result(
        meta.get("ohttp_inner_response"), read_blob
    )

    # Trailing data (unconsumed bytes after valid protocol frames)
    t_len = meta.get("trailing_blob_len", 0)
    if t_len:
        flow.trailing_bytes = read_blob(
            meta.get("trailing_blob_offset", 0), t_len
        )
        flow.trailing_protocol = meta.get("trailing_protocol", "")
        flow.trailing_parse = _decode_parse_result(
            meta.get("trailing_parse"), read_blob
        )
    _decode_response_trailing(flow, meta, read_blob)

    flow.detected_protocol = meta.get("detected_protocol", "")
    flow.truncated = bool(meta.get("truncated", False))
    flow.transport = meta.get("transport", "tls")

    # Schema v2 additive enrichment; v1 files fall back to defaults.
    flow.local_addr = meta.get("local_addr", "")
    flow.local_port = meta.get("local_port", 0)
    flow.remote_addr = meta.get("remote_addr", "")
    flow.remote_port = meta.get("remote_port", 0)
    flow.process_name = meta.get("process_name", "")
    flow.package_name = meta.get("package_name", "")
    pid = meta.get("pid")
    flow.pid = pid if isinstance(pid, int) and not isinstance(pid, bool) else None
    flow.process_role = str(meta.get("process_role") or "")
    flow.sdk = meta.get("sdk", None)
    # Hand-crafted .tap files may carry junk: re-bound the stack, coerce the flag.
    flow.caller_stack = sanitize_caller_stack(meta.get("caller_stack"))
    flow.endpoints_synthetic = meta.get("endpoints_synthetic") is True
    # Untrusted like caller_stack: whitelist keys/enums and cap strings.
    flow.attribution = sanitize_attribution(meta.get("attribution"))
    flow.hook_function = meta.get("hook_function", "")
    flow.hook_stack = meta.get("hook_stack", "")
    flow.tags = list(meta.get("tags", []))
    flow.notes = meta.get("notes", "")

    # Rebuild the protocol layer stack. v3 records carry an explicit
    # meta["layers"]; v1/v2 records pre-date it and rebuild from the legacy
    # meta["tls"] + request/response fields (so old .tap files still open).
    _rebuild_layers(flow, meta, read_blob)

    return flow


def _rebuild_layers(flow: "Flow", meta: dict, read_blob) -> None:
    """Reconstruct ``flow.layers`` after the scalar fields are populated.

    v3 rebuilds the stack from ``meta["layers"]`` (the only path restoring owned
    inner-layer bytes); v1/v2 seed TLS from ``meta["tls"]`` and let LayerPipeline rebuild the rest.
    """
    layers_meta = meta.get("layers")
    if layers_meta is not None:
        _decode_layers(flow, layers_meta, read_blob)
        return

    tls_meta = meta.get("tls")
    if tls_meta:
        # flow.tls lazily creates the layer; mutate in place (assigning would shadow the layer-stack lookup).
        tls_layer = flow.tls
        tls_layer.library = tls_meta.get("library", "")
        tls_layer.version = tls_meta.get("version", "")
        tls_layer.sni = tls_meta.get("sni", "")
        tls_layer.alpn = tls_meta.get("alpn", "")
        tls_layer.cipher = tls_meta.get("cipher", "")
    from friTap.flow.layer_pipeline import LayerPipeline
    LayerPipeline().finalize(flow)


def _decode_layers(flow: "Flow", layers_meta: list, read_blob) -> None:
    """Rebuild ``flow.layers`` from a v3 ``meta["layers"]`` list.

    Added in ascending depth so ``add_layer`` relinks parent/child contiguously
    (tolerating gaps from skipped empty layers). Mirrored layers rebind their chunks
    view / parsed_field; owned layers restore their bytes from blobs.
    """
    from friTap.flow.layer_registry import get_registry
    from friTap.flow.layers import AppLayer, LayerData

    registry = get_registry()
    flow.layers = []
    for lm in sorted(layers_meta, key=lambda d: d.get("depth", 0)):
        name = lm.get("name", "")
        desc = registry.get(name)
        layer_cls = desc.layer_cls if desc is not None else AppLayer
        layer = layer_cls.from_dict(lm)
        layer._name = name
        if lm.get("metadata_only"):
            # Metadata-only marker: keep empty (data_source="none") LayerData and re-flag it for re-encode.
            layer.metadata_only = True
        elif lm.get("data_from_chunks"):
            layer.data = LayerData(data_source="chunks", _owner=flow)
        elif "data_owned" in lm:
            owned = lm["data_owned"]
            data = LayerData()
            data.set_owned(
                read=read_blob(owned.get("r_off", 0), owned.get("r_len", 0)),
                write=read_blob(owned.get("w_off", 0), owned.get("w_len", 0)),
            )
            layer.data = data
        parsed_field = lm.get("parsed_field")
        if parsed_field:
            layer._parsed_field = parsed_field
        elif lm.get("parsed") is not None:
            layer.set_parsed(_decode_parse_result(lm["parsed"], read_blob))
        flow.add_layer(layer)


def _flow_meta_stream_id(meta: dict, chunks_meta: list) -> Optional[int]:
    """The meta's ``stream_id``, else the one id its chunks share (older records)."""
    stream_id = meta.get("stream_id")
    if stream_id is not None:
        return stream_id
    from friTap.flow.models import single_stream_id
    return single_stream_id(cm.get("stream_id") for cm in chunks_meta)


def _flow_meta_total_size(meta: dict, chunks_meta: list) -> int:
    """The meta's ``total_size`` when a valid int >= 0, else the sum of chunk ``blob_len`` (older records)."""
    stored = strict_int(meta.get("total_size"))
    if stored is not None and stored >= 0:
        return stored
    return sum(cm.get("blob_len", 0) for cm in chunks_meta)


def decode_flow_summary(payload: bytes, file_offset: int = 0) -> FlowSummary:
    """Decode only the JSON meta of a FLOW record (no blobs): the fast path for the flow list."""
    if len(payload) < 4:
        raise ValueError(f"FLOW payload too short: {len(payload)} bytes")

    meta_len = _META_LEN.unpack(payload[:4])[0]
    if 4 + meta_len > len(payload):
        raise ValueError(f"FLOW meta_len ({meta_len}) exceeds payload size ({len(payload)})")

    meta_bytes = payload[4 : 4 + meta_len]
    meta = json.loads(meta_bytes.decode("utf-8", errors="replace"))

    req = meta.get("request")
    resp = meta.get("response")
    chunks_meta = meta.get("chunks", [])
    total_size = _flow_meta_total_size(meta, chunks_meta)

    detected = meta.get("detected_protocol", "")
    if req and req.get("protocol"):
        protocol = req["protocol"]
    elif resp and resp.get("protocol"):
        protocol = resp["protocol"]
    elif detected:
        protocol = detected
    else:
        protocol = "unknown"

    summary = FlowSummary(
        flow_id=meta.get("flow_id", ""),
        connection_id=meta.get("connection_id", ""),
        src_addr=meta.get("src_addr", ""),
        src_port=meta.get("src_port", 0),
        dst_addr=meta.get("dst_addr", ""),
        dst_port=meta.get("dst_port", 0),
        ssl_session_id=meta.get("ssl_session_id", ""),
        state=meta.get("state", "complete"),
        started=meta.get("started", 0.0),
        ended=meta.get("ended", 0.0),
        transport=meta.get("transport", "tls"),
        protocol=protocol,
        method=req.get("method", "") if req else "",
        url=req.get("url", "") if req else "",
        host=req.get("host", "") if req else "",
        status_code=resp.get("status_code", 0) if resp else 0,
        status_text=resp.get("status_text", "") if resp else "",
        body_size=resp.get("body_size", 0) if resp else 0,
        total_size=total_size,
        file_offset=file_offset,
        detected_protocol=detected,
        is_control_frame=req.get("is_control_frame", False) if req else False,
        process_name=meta.get("process_name", ""),
        tls_sni=(meta.get("tls") or {}).get("sni", ""),
        tls_alpn=(meta.get("tls") or {}).get("alpn", ""),
        tag_count=len(meta.get("tags", [])),
        finding_count=0,  # findings live in separate REC_FINDING records; TapReader fills this in
        has_notes=bool(meta.get("notes", "")),
        outer_app_protocol=meta.get("outer_app_protocol", ""),
        inner_e2e_protocol=meta.get("inner_e2e_protocol", ""),
        inner_summary=meta.get("inner_summary", ""),
        flow_method=meta.get("flow_method", ""),
        has_request=req is not None,
        has_response=resp is not None,
        has_ohttp=(meta.get("ohttp_inner_request") is not None
                   or meta.get("ohttp_inner_response") is not None),
        stream_id=_flow_meta_stream_id(meta, chunks_meta),
    )
    _attach_filter_inputs(summary, meta.get("layers"))
    return summary


def _attach_filter_inputs(summary: FlowSummary, layers_meta: Any) -> None:
    """Derive ``filter_attrs`` / ``protocols`` for a decoded summary from ``meta["layers"]`` (v1/v2 use scalar labels alone); never raises."""
    # Local imports: friTap.filter's package __init__ pulls in the evaluator, which must stay free to import friTap.flow (cycle).
    from friTap.filter.layer_fields import LAYER_NAME_KEY, extract_filter_attrs
    from friTap.filter.protocols import canonical_protocols

    layers = layers_meta if isinstance(layers_meta, list) else []
    summary.filter_attrs = dict(extract_filter_attrs(layers))
    # A flat summary exposes neither layer names nor the request/response ``protocol`` to
    # canonical_protocols(), so pass them as extra labels (they join implied protocols: bhttp -> ohttp).
    labels = [summary.protocol] + [
        lm.get(LAYER_NAME_KEY, "") for lm in layers if isinstance(lm, dict)
    ]
    summary.protocols = canonical_protocols(summary, labels)


def decode_flow_index(payload: bytes) -> list[dict]:
    """Decode a FLOW_INDEX payload: list of ``{"flow_id", "offset"}``."""
    d = json.loads(payload.decode("utf-8", errors="replace"))
    return d.get("entries", [])


def find_sync_marker(data: bytes, start: int = 0) -> int:
    """Offset of the next sync marker in *data*, or -1 (corruption recovery)."""
    return data.find(SYNC_MARKER, start)


def _has_owned_bytes(layer) -> bool:
    """True when a layer carries its own bytes (e.g. an RC4-in-TLS carrier); metadata ``is_empty()`` checks would drop its plaintext."""
    data = getattr(layer, "data", None)
    return (data is not None and data.data_source == "owned"
            and not data.is_empty())


def _encode_layer(layer, register_blob) -> dict:
    """Encode one ProtocolLayer for ``meta["layers"]``.

    Mirrored layers store no bytes (``data_from_chunks`` + ``parsed_field``); owned
    inner layers store bytes once via *register_blob* and inline their parsed result.
    """
    from friTap.flow.layer_registry import get_registry

    d = layer.to_dict()  # name, depth, + typed metadata fields
    if layer.metadata_only:
        # Metadata-only marker (e.g. encapsulation layers on an offline Signal flow): opt out of
        # the chunks-view default so a round-trip never rebinds it to the inner protocol's plaintext.
        d["metadata_only"] = True
    else:
        # The registry decides whether data is a chunks view (never serialized as bytes); an
        # instance that owns bytes (e.g. TLS of an RC4-in-TLS flow) overrides it.
        desc = get_registry().get(layer.name)
        owns_data = layer.data.data_source == "owned"
        if not owns_data and (
                (desc is not None and desc.data_source == "chunks")
                or layer.data.data_source == "chunks"):
            d["data_from_chunks"] = True
        elif owns_data:
            read = layer.data.read
            write = layer.data.write
            r_off, r_len = register_blob(read) if read else (0, 0)
            w_off, w_len = register_blob(write) if write else (0, 0)
            d["data_owned"] = {
                "r_off": r_off, "r_len": r_len, "w_off": w_off, "w_len": w_len,
            }
    if layer._parsed_field:
        d["parsed_field"] = layer._parsed_field
    elif layer._inner_parsed is not None:
        d["parsed"] = _encode_parse_result(layer._inner_parsed, register_blob)
    return d


def _encode_parse_result(
    pr: "Optional[ParseResult]",
    register_blob,
    flow=None,
) -> dict | None:
    """Encode a ParseResult into a JSON dict with blob references; ``raw`` is omitted (rebuilt from chunks).

    With *flow* and an empty ``pr.body`` no body blob is stored (``body_from_chunks`` is set,
    the body is rebuilt from ``flow.chunks``); otherwise (no *flow*, or e.g. WebSocket) it is a blob.
    """
    if pr is None:
        return None

    body = pr.body
    body_from_chunks = False
    if not body and flow is not None:
        body_from_chunks = True
        body = b""
    body_off, body_len = register_blob(body) if body else (0, 0)

    return {
        "protocol": pr.protocol,
        "method": pr.method,
        "url": pr.url,
        "host": pr.host,
        "status_code": pr.status_code,
        "status_text": pr.status_text,
        "headers": pr.headers,
        "body_blob_offset": body_off,
        "body_blob_len": body_len,
        "body_from_chunks": body_from_chunks,
        "body_size": pr.body_size,
        "is_complete": pr.is_complete,
        "is_request": pr.is_request,
        "content_encoding": pr.content_encoding,
        "content_type": pr.content_type,
        "error": pr.error,
        "stream_id": pr.stream_id,
        "is_control_frame": pr.is_control_frame,
    }


def _decode_parse_result(
    meta: dict | None,
    read_blob,
) -> "Optional[ParseResult]":
    """Decode a ParseResult from JSON metadata dict + blob reader."""
    if meta is None:
        return None

    from friTap.parsers.base import ParseResult

    body = read_blob(
        meta.get("body_blob_offset", 0),
        meta.get("body_blob_len", 0),
    )

    pr = ParseResult(
        protocol=meta.get("protocol", "unknown"),
        method=meta.get("method", ""),
        url=meta.get("url", ""),
        host=meta.get("host", ""),
        status_code=meta.get("status_code", 0),
        status_text=meta.get("status_text", ""),
        headers=meta.get("headers", {}),
        body=body,
        body_size=meta.get("body_size", 0),
        is_complete=meta.get("is_complete", False),
        is_request=meta.get("is_request", True),
        content_encoding=meta.get("content_encoding", ""),
        content_type=meta.get("content_type", ""),
        error=meta.get("error", ""),
        raw=b"",  # Omitted — reconstructible from chunks
        stream_id=meta.get("stream_id", 0),
        is_control_frame=meta.get("is_control_frame", False),
    )
    # Stash the writer's hint to tell "no body" from "body lives in Flow.chunks" (v1 records yield False).
    pr.body_from_chunks = bool(meta.get("body_from_chunks", False))
    return pr


def _truncate_utf8(text: str, max_bytes: int) -> bytes:
    """Truncate to at most *max_bytes* of UTF-8 on a character boundary, null-padded."""
    encoded = text.encode("utf-8")
    if len(encoded) <= max_bytes:
        return encoded.ljust(max_bytes, b"\x00")

    # Slice bytes then decode with 'ignore' to drop a partial trailing sequence; O(1).

    truncated = encoded[:max_bytes].decode("utf-8", errors="ignore").encode("utf-8")
    return truncated.ljust(max_bytes, b"\x00")
