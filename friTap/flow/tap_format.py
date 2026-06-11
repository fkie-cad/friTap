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
from dataclasses import dataclass
from typing import Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from friTap.flow.models import Flow
    from friTap.parsers.base import ParseResult

# ---------------------------------------------------------------------------
# Magic & version
# ---------------------------------------------------------------------------

MAGIC = b"TAP\x01"
FORMAT_VERSION = 1

# ---------------------------------------------------------------------------
# Flags (u16 in header)
# ---------------------------------------------------------------------------

FLAG_HAS_INDEX = 0x0001
# Set at close() when at least one REC_FINDING record was written. Lets a reader
# decide cheaply (header-only) whether the findings scan is worth running.
# Additive: old files lack it, so absence means "unknown", not "no findings".
FLAG_HAS_FINDINGS = 0x0002

# ---------------------------------------------------------------------------
# Record types (u8)
# ---------------------------------------------------------------------------

REC_FLOW = 0x01
REC_KEYLOG = 0x02
REC_META = 0x03
REC_FINDING = 0x04
REC_FLOW_INDEX = 0x10

# ---------------------------------------------------------------------------
# Sync marker (4 bytes) — enables corruption recovery
# ---------------------------------------------------------------------------

SYNC_MARKER = b"\xF7\xA9\x00\x00"

# ---------------------------------------------------------------------------
# Footer magic (separate from header magic so we can detect truncation)
# ---------------------------------------------------------------------------

FOOTER_MAGIC = b"TAP_END\x00"  # 8 bytes

# ---------------------------------------------------------------------------
# Pre-compiled struct formats (module-level for performance)
# ---------------------------------------------------------------------------

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
# hook_*) and the body-from-chunks de-duplication flag. All additive — readers
# use ``.get`` with defaults, so v1 and v2 records decode identically.
FLOW_SCHEMA_VERSION = 3


# ---------------------------------------------------------------------------
# Header dataclass
# ---------------------------------------------------------------------------

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
    # Protocol detected by parser registry even when no request/response
    # was ever produced (e.g. HTTP/2 control-frame-only flows).
    detected_protocol: str = ""
    # HTTP/2 control frame (SETTINGS, PING, etc.) — no request/response payload
    is_control_frame: bool = False
    # Schema v2 enrichment scalars (read from FLOW meta; cheap, no blobs).
    process_name: str = ""
    tls_sni: str = ""
    tls_alpn: str = ""
    tag_count: int = 0
    finding_count: int = 0
    has_notes: bool = False

    @staticmethod
    def from_flow(flow: "Flow") -> "FlowSummary":
        """Build this (flat, public) summary shape from a live/full Flow.

        Mirrors :meth:`friTap.flow.models.FlowSummary.from_flow` but produces
        the publicly exported ``tap_format`` shape, so the live capture path
        (``FlowSummary.from_flow(event.flow)``) and the offline path
        (``TapReader.read_flow_summaries()``) yield the *same* summary type
        with a matching :meth:`to_dict` key set. Uses the non-mutating
        ``flow.layer()`` lookup so it never grows the flow's layer stack.
        """
        req = flow.request
        resp = flow.response
        tls = flow.layer("tls")
        total = getattr(flow, "_total_bytes", 0) or sum(len(c.data) for c in flow.chunks)
        state = flow.state.value if hasattr(flow.state, "value") else str(flow.state)
        return FlowSummary(
            flow_id=flow.flow_id,
            connection_id=flow.connection_id,
            src_addr=flow.src_addr,
            src_port=flow.src_port,
            dst_addr=flow.dst_addr,
            dst_port=flow.dst_port,
            ssl_session_id=flow.ssl_session_id,
            state=state,
            started=flow.started,
            ended=flow.ended,
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
            tls_sni=(tls.sni if tls is not None else ""),
            tls_alpn=(tls.alpn if tls is not None else ""),
            tag_count=len(getattr(flow, "tags", []) or []),
            finding_count=len(getattr(flow, "findings", []) or []),
            has_notes=bool(getattr(flow, "notes", "")),
        )

    def to_dict(self) -> dict:
        """Return a JSON-safe, body-free dict for a high-level flow overview.

        Emits the canonical FlowSummary key set shared with
        :meth:`friTap.flow.models.FlowSummary.to_dict` so live and offline
        summaries render identically for web/TUI/CLI consumers.
        """
        duration = (self.ended - self.started) if self.ended > 0 else 0.0
        return {
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
        }


# ---------------------------------------------------------------------------
# Encode helpers
# ---------------------------------------------------------------------------

def encode_header(
    capture_start: float = 0.0,
    flow_count: int = 0,
    flags: int = 0,
    capture_target: str = "",
    ext_data: dict | None = None,
) -> bytes:
    """Encode a 64-byte .tap file header, optionally followed by ext data."""
    # Truncate target at Unicode char level to fit 32 bytes of UTF-8
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
    """Return a copy of a serialized finding with oversized evidence strings
    truncated, so findings never bloat the .tap file."""
    evidence = d.get("evidence")
    if not isinstance(evidence, dict):
        return d
    bounded = {}
    for k, v in evidence.items():
        if isinstance(v, str) and len(v) > _MAX_EVIDENCE_STR:
            bounded[k] = v[:_MAX_EVIDENCE_STR] + "…[truncated]"
        elif isinstance(v, (bytes, bytearray)):
            # bytes are not JSON-serializable, so ALWAYS hex-encode them — not
            # only when oversized. A short raw-bytes evidence value (e.g. a
            # matched binary token) would otherwise reach json.dumps unchanged
            # and raise TypeError, aborting the whole REC_FINDING write.
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
    """Encode a REC_FINDING payload binding findings to a flow_id.

    *finding_dicts* are already-serialized findings (``Finding.to_dict()``);
    keeping tap_format free of an ``analysis`` import avoids a cycle. Evidence
    string values are bounded via :func:`_bound_finding_dict`.
    """
    d = {
        "flow_id": flow_id,
        "findings": [_bound_finding_dict(fd) for fd in finding_dicts],
    }
    # default=str is a safety net for any other non-JSON evidence value a
    # custom analyzer might emit (sets, paths, arbitrary objects) so a single
    # odd value can never abort persisting the findings.
    return json.dumps(
        d, ensure_ascii=False, separators=(",", ":"), default=str
    ).encode("utf-8")


def decode_finding_record(payload: bytes) -> tuple[str, list[dict]]:
    """Decode a REC_FINDING payload. Returns (flow_id, list[finding_dict])."""
    d = json.loads(payload.decode("utf-8", errors="replace"))
    return d.get("flow_id", ""), d.get("findings", [])


def encode_flow(flow: "Flow") -> bytes:
    """Encode a Flow object into a FLOW record payload.

    Layout: [json_meta_len (4 bytes LE)][json_meta bytes][blob bytes]

    Binary blobs (chunk data, request/response bodies) are concatenated
    in the blob section.  The JSON metadata contains blob_offset/blob_len
    references instead of inline binary data.
    """
    blobs: list[bytes] = []
    blob_offset = 0

    def register_blob(data: bytes) -> tuple[int, int]:
        nonlocal blob_offset
        offset = blob_offset
        length = len(data)
        blobs.append(data)
        blob_offset += length
        return offset, length

    # Encode chunks
    chunks_meta = []
    for chunk in flow.chunks:
        off, ln = register_blob(chunk.data)
        chunks_meta.append({
            "direction": chunk.direction,
            "timestamp": chunk.timestamp,
            "function": chunk.function,
            "blob_offset": off,
            "blob_len": ln,
        })

    meta: dict = {
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

    # Trailing data (unconsumed bytes after valid protocol frames)
    if flow.trailing_bytes:
        t_off, t_len = register_blob(flow.trailing_bytes)
        meta["trailing_blob_offset"] = t_off
        meta["trailing_blob_len"] = t_len
        meta["trailing_protocol"] = flow.trailing_protocol
        if flow.trailing_parse is not None:
            meta["trailing_parse"] = _encode_parse_result(flow.trailing_parse, register_blob)

    if flow.detected_protocol:
        meta["detected_protocol"] = flow.detected_protocol

    # --- Schema v2 additive enrichment (write only when non-default to keep
    # records compact; findings are intentionally NOT inlined here — they are
    # persisted as separate REC_FINDING records so the summary fast path
    # (decode_flow_summary) stays lean). ---
    if getattr(flow, "local_addr", "") or getattr(flow, "local_port", 0):
        meta["local_addr"] = flow.local_addr
        meta["local_port"] = flow.local_port
        meta["remote_addr"] = flow.remote_addr
        meta["remote_port"] = flow.remote_port
    if getattr(flow, "process_name", ""):
        meta["process_name"] = flow.process_name
    if getattr(flow, "package_name", ""):
        meta["package_name"] = flow.package_name
    # Non-mutating lookup (encoding is a pure read): layer() returns None when
    # absent rather than attaching an empty TLS layer to every serialized flow.
    tls = flow.layer("tls")
    if tls is not None and not tls.is_empty():
        meta["tls"] = {
            "library": tls.library, "version": tls.version, "sni": tls.sni,
            "alpn": tls.alpn, "cipher": tls.cipher,
        }
    if getattr(flow, "hook_function", ""):
        meta["hook_function"] = flow.hook_function
    if getattr(flow, "hook_stack", ""):
        meta["hook_stack"] = flow.hook_stack
    if getattr(flow, "tags", None):
        meta["tags"] = list(flow.tags)
    if getattr(flow, "notes", ""):
        meta["notes"] = flow.notes

    # Transport hint (Phase 1b) — only when non-default to keep records compact.
    if getattr(flow, "transport", "tls") and flow.transport != "tls":
        meta["transport"] = flow.transport

    # --- Schema v3: ordered protocol layer stack. ADDITIVE — every legacy field
    # above stays the source of truth; layers MIRROR them. Transport/app layers
    # carry NO bytes of their own (``data_from_chunks`` + a ``parsed_field`` tag
    # pointing at request/response, which are already in meta), so no transport
    # bytes and no ParseResult JSON are duplicated. Only genuinely owned inner
    # layers (decryptor output) serialize their directional bytes, once, via
    # register_blob. Empty layers are skipped (mirrors the meta["tls"] discipline
    # and avoids persisting the lazily-created never-None stubs). ---
    layers_meta = [
        _encode_layer(ly, register_blob)
        for ly in getattr(flow, "layers", [])
        if not ly.is_empty()
    ]
    if layers_meta:
        meta["layers"] = layers_meta

    meta_bytes = json.dumps(meta, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    blob_bytes = b"".join(blobs)

    return _META_LEN.pack(len(meta_bytes)) + meta_bytes + blob_bytes


def encode_flow_index(entries: list[dict]) -> bytes:
    """Encode a FLOW_INDEX record payload.

    entries: list of {"flow_id": str, "offset": int}
    """
    d = {"version": 1, "entries": entries}
    return json.dumps(d, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


# ---------------------------------------------------------------------------
# Decode helpers
# ---------------------------------------------------------------------------

def decode_header(data: bytes) -> tuple[TapHeader, int]:
    """Decode a .tap file header from raw bytes.

    Returns (TapHeader, total_header_bytes) where total_header_bytes
    includes the fixed 64 bytes plus any extension data.
    """
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
    """Decode a 16-byte record envelope.

    Returns (record_type, payload_len, stored_crc, envelope_size).
    Raises ValueError if sync marker is invalid.
    """
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

    Defaults mirror the ``TapMeta`` dataclass exactly so an encode/decode
    round-trip of an unset field is a fixed point: ``flow_fields_version``
    falls back to ``FLOW_SCHEMA_VERSION`` (the same baseline ``encode_meta``
    writes), keeping the versioning coherent rather than silently downgrading
    a missing key to ``1``.
    """
    d = json.loads(payload.decode("utf-8", errors="replace"))
    return TapMeta(
        schema_version=d.get("schema_version", 1),
        flow_fields_version=d.get("flow_fields_version", FLOW_SCHEMA_VERSION),
        parse_result_version=d.get("parse_result_version", 1),
        fritap_version=d.get("fritap_version", ""),
    )


def resolve_flow_schema_version(flow_meta: dict) -> int:
    """Resolve a single flow's effective schema version from its JSON meta.

    Contract: every FLOW record written by current friTap stamps ``_v`` with
    ``FLOW_SCHEMA_VERSION``. Legacy/v1 records pre-date that key and carry no
    ``_v``; they are treated as schema version 1 (the first release, before the
    additive enrichment keys existed). This is the single place to branch on the
    per-flow schema version so future readers can adapt decoding by version
    without scattering ``meta.get("_v", ...)`` calls across the codebase.
    """
    return int(flow_meta.get("_v", 1))


def decode_keylog(payload: bytes) -> tuple[str, float]:
    """Decode a KEYLOG record payload. Returns (key_data, timestamp)."""
    d = json.loads(payload.decode("utf-8", errors="replace"))
    return d.get("key_data", ""), d.get("timestamp", 0.0)


def decode_flow(payload: bytes) -> "Flow":
    """Decode a FLOW record payload into a Flow object.

    Reconstructs Flow with chunks (including binary data) and ParseResults.
    """
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

    # Reconstruct chunks
    chunks = []
    for cm in meta.get("chunks", []):
        chunks.append(FlowChunk(
            data=read_blob(cm.get("blob_offset", 0), cm.get("blob_len", 0)),
            direction=cm.get("direction", "read"),
            timestamp=cm.get("timestamp", 0.0),
            function=cm.get("function", ""),
        ))

    # Parse state enum
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

    flow.detected_protocol = meta.get("detected_protocol", "")
    flow.transport = meta.get("transport", "tls")

    # --- Schema v2 additive enrichment (absent in v1 files → defaults) ---
    flow.local_addr = meta.get("local_addr", "")
    flow.local_port = meta.get("local_port", 0)
    flow.remote_addr = meta.get("remote_addr", "")
    flow.remote_port = meta.get("remote_port", 0)
    flow.process_name = meta.get("process_name", "")
    flow.package_name = meta.get("package_name", "")
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
    """Reconstruct ``flow.layers`` after the legacy scalar fields are populated.

    v3: rebuild the full ordered stack from ``meta["layers"]`` — the only path
    that restores owned inner-layer bytes. v1/v2: seed the TLS layer from
    ``meta["tls"]`` and let the LayerPipeline rebuild the transport+app layers
    from the (mirrored, source-of-truth) request/response/detected_protocol
    fields — a free-bonus reconstruction so pre-v3 captures still expose the
    layer stack.
    """
    layers_meta = meta.get("layers")
    if layers_meta is not None:
        _decode_layers(flow, layers_meta, read_blob)
        return

    tls_meta = meta.get("tls")
    if tls_meta:
        # flow.tls lazily resolves/creates the tls layer; mutate in place
        # (assigning a new object would shadow the layer-stack lookup).
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

    Layers are added in ascending depth so ``add_layer`` relinks parent/child
    contiguously (tolerating gaps left by skipped empty layers at encode time).
    Mirrored layers rebind their chunks view / parsed_field; owned inner layers
    restore their directional bytes from blobs and their inline parsed result.
    """
    from friTap.flow.layers import AppLayer, LayerData
    from friTap.flow.layer_registry import get_registry

    registry = get_registry()
    flow.layers = []
    for lm in sorted(layers_meta, key=lambda d: d.get("depth", 0)):
        name = lm.get("name", "")
        desc = registry.get(name)
        layer_cls = desc.layer_cls if desc is not None else AppLayer
        layer = layer_cls.from_dict(lm)
        layer._name = name
        if lm.get("data_from_chunks"):
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


def decode_flow_summary(payload: bytes, file_offset: int = 0) -> FlowSummary:
    """Decode only the JSON metadata portion of a FLOW record (no blobs).

    This is the fast path for populating the flow list table without
    loading chunk data or HTTP bodies into memory.
    """
    if len(payload) < 4:
        raise ValueError(f"FLOW payload too short: {len(payload)} bytes")

    meta_len = _META_LEN.unpack(payload[:4])[0]
    if 4 + meta_len > len(payload):
        raise ValueError(f"FLOW meta_len ({meta_len}) exceeds payload size ({len(payload)})")

    meta_bytes = payload[4 : 4 + meta_len]
    meta = json.loads(meta_bytes.decode("utf-8", errors="replace"))

    req = meta.get("request")
    resp = meta.get("response")
    total_size = sum(cm.get("blob_len", 0) for cm in meta.get("chunks", []))

    detected = meta.get("detected_protocol", "")
    if req and req.get("protocol"):
        protocol = req["protocol"]
    elif resp and resp.get("protocol"):
        protocol = resp["protocol"]
    elif detected:
        protocol = detected
    else:
        protocol = "unknown"

    return FlowSummary(
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
    )


def decode_flow_index(payload: bytes) -> list[dict]:
    """Decode a FLOW_INDEX record payload.

    Returns list of {"flow_id": str, "offset": int}.
    """
    d = json.loads(payload.decode("utf-8", errors="replace"))
    return d.get("entries", [])


def find_sync_marker(data: bytes, start: int = 0) -> int:
    """Scan for the next sync marker in a byte buffer.

    Returns the offset of the sync marker, or -1 if not found.
    Used for corruption recovery.
    """
    return data.find(SYNC_MARKER, start)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _encode_layer(layer, register_blob) -> dict:
    """Encode one ProtocolLayer for ``meta["layers"]``.

    Mirrored transport/app layers store NO bytes: ``data_from_chunks`` marks the
    data as a chunks view and ``parsed_field`` names the flow attribute
    (``request``/``response``) the layer mirrors — both already in meta, so
    nothing is duplicated. Owned inner layers (decryptor output) store their
    directional bytes once via *register_blob* and inline their own parsed
    result (which is NOT one of the flow's mirrored fields).
    """
    from friTap.flow.layer_registry import get_registry

    d = layer.to_dict()  # name, depth, + typed metadata fields
    # The registry is the authority on whether a protocol's data is a chunks
    # view (transport tls/quic + app layers) — mark it so regardless of how the
    # instance was built, so the view is never serialized as bytes. Only genuine
    # owned-data layers (decryptor output, unregistered names) blob their bytes.
    desc = get_registry().get(layer.name)
    if (desc is not None and desc.data_source == "chunks") \
            or layer.data.data_source == "chunks":
        d["data_from_chunks"] = True
    elif layer.data.data_source == "owned":
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
    """Encode a ParseResult into a JSON-serializable dict with blob references.

    The ``raw`` field is omitted (reconstructible from chunks). Body storage:
    when *flow* is provided (request/response) and ``pr.body`` is empty, the body
    is reconstructable from ``flow.chunks`` on read, so we store **no** body blob
    and set ``body_from_chunks`` — this avoids the historical double-storage
    (chunks + a duplicated reconstructed-body blob). When *flow* is absent
    (ohttp/trailing) or ``pr.body`` is set (e.g. WebSocket, where the payload is
    not separately recoverable from chunks), the body is stored as before.
    """
    if pr is None:
        return None

    body = pr.body
    body_from_chunks = False
    if not body and flow is not None:
        # Reconstructable from chunks on read (Flow.reconstruct_body /
        # request_body / response_body fall back to chunks when pr.body is
        # empty). Do not duplicate it in a blob.
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
    # Consume the writer's body-storage hint. When ``body_from_chunks`` is set,
    # ``pr.body`` was intentionally left empty at encode time (the de-dup path)
    # and the real body must be recovered from ``Flow.chunks`` via
    # ``request_body``/``response_body``/``reconstruct_body``. Stash it on the
    # instance (ParseResult has no such field; dataclass instances allow it) so
    # callers can distinguish "no body" from "body lives in chunks" instead of
    # the flag being write-only. Absent in legacy/v1 records -> False.
    pr.body_from_chunks = bool(meta.get("body_from_chunks", False))
    return pr


def _truncate_utf8(text: str, max_bytes: int) -> bytes:
    """Truncate a string to fit within max_bytes of UTF-8, null-padded.

    Truncates at Unicode character boundaries to avoid splitting
    multi-byte sequences.
    """
    encoded = text.encode("utf-8")
    if len(encoded) <= max_bytes:
        return encoded.ljust(max_bytes, b"\x00")

    # Slice at byte boundary, then decode with 'ignore' to drop any
    # partial multi-byte sequence at the end — O(1) instead of O(n).
    truncated = encoded[:max_bytes].decode("utf-8", errors="ignore").encode("utf-8")
    return truncated.ljust(max_bytes, b"\x00")
