"""Flow data models for SSL/TLS flow collection."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, TYPE_CHECKING
import time

from friTap.flow import display as _display
from friTap.flow.layers import (
    ProtocolLayer, LayerData, TlsLayer,
)
from friTap.flow.layer_registry import get_registry

if TYPE_CHECKING:
    from friTap.parsers.base import ParseResult


def format_byte_size(size_bytes: int) -> str:
    """Format a byte count as a human-readable string. Returns '-' for zero."""
    if size_bytes == 0:
        return "-"
    size = float(size_bytes)
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024:
            if unit == "B":
                return f"{int(size)} B"
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"


class FlowState(Enum):
    ACTIVE = "active"
    COMPLETE = "complete"
    ERROR = "error"


class FlowEventType(str, Enum):
    """Type of flow lifecycle event."""
    CREATED = "created"
    UPDATED = "updated"
    COMPLETED = "completed"
    REMOVED = "removed"


@dataclass
class FlowChunk:
    data: bytes
    direction: str  # "read" or "write"
    timestamp: float
    function: str = ""


# TLS handshake metadata is now the ``tls`` protocol LAYER (TlsLayer in
# friTap/flow/layers.py), carrying the same library/version/sni/alpn/cipher
# fields plus the shared layer facets (.data/.parsed/.depth). ``TlsMetadata``
# remains as an alias so existing imports/constructions keep working; a Flow
# exposes it via ``flow.tls`` (resolved from ``flow.layers`` by __getattr__).
TlsMetadata = TlsLayer


_OHTTP_SENTINEL = object()  # Truthy sentinel for FlowSummary OHTTP filter compat


@dataclass(frozen=True, slots=True)
class _ParseStub:
    """Minimal stand-in for ParseResult in FlowSummary.

    Holds only the fields read by the filter engine and display widgets.
    """
    protocol: str = ""
    method: str = ""
    url: str = ""
    host: str = ""
    status_code: int = 0
    status_text: str = ""
    content_type: str = ""
    content_encoding: str = ""
    body_size: int = 0
    stream_id: int = 0
    is_control_frame: bool = False


@dataclass(frozen=True, slots=True)
class FlowSummary:
    """Lightweight snapshot of a Flow for list display and filtering.

    Contains only scalar metadata (~200 bytes) — no chunks, no body bytes.
    Compatible with the filter engine (has ``request``/``response`` stubs
    with the same attribute names as ParseResult).
    """
    flow_id: str = ""
    connection_id: str = ""
    src_addr: str = ""
    src_port: int = 0
    dst_addr: str = ""
    dst_port: int = 0
    ssl_session_id: str = ""
    state: FlowState = FlowState.ACTIVE
    started: float = 0.0
    ended: float = 0.0
    request: Optional[_ParseStub] = None
    response: Optional[_ParseStub] = None
    has_ohttp: bool = False
    has_trailing_data: bool = False
    trailing_protocol: str = ""
    total_bytes: int = 0
    detected_protocol: str = ""
    # Schema v2 additive enrichment scalars (cheap to surface in list/filter views)
    process_name: str = ""
    tls_sni: str = ""
    tls_alpn: str = ""
    tag_count: int = 0
    finding_count: int = 0
    has_notes: bool = False

    @property
    def duration(self) -> float:
        if self.ended > 0:
            return self.ended - self.started
        return time.time() - self.started

    @property
    def display_protocol(self) -> str:
        return _display.display_protocol(self)

    @property
    def display_method(self) -> str:
        return _display.display_method(self.request)

    @property
    def display_host(self) -> str:
        return _display.display_host(self.request, self.dst_addr, self.dst_port)

    @property
    def display_status(self) -> str:
        return _display.display_status(self.response)

    @property
    def display_size(self) -> str:
        return _display.display_size(self.response, self.total_bytes)

    @property
    def display_source(self) -> str:
        return _display.display_source(self.src_addr, self.src_port)

    @property
    def display_connection(self) -> str:
        return _display.display_connection(
            self.request, self.response,
            self.src_addr, self.src_port, self.dst_addr, self.dst_port,
        )

    # Aliases for filter engine compatibility
    @property
    def _total_bytes(self) -> int:
        return self.total_bytes

    @property
    def ohttp_inner_request(self):
        # Filter engine checks `is not None` — return a truthy sentinel
        return _OHTTP_SENTINEL if self.has_ohttp else None

    @property
    def ohttp_inner_response(self):
        return _OHTTP_SENTINEL if self.has_ohttp else None

    @staticmethod
    def from_flow(flow: "Flow") -> "FlowSummary":
        """Create a summary snapshot from a full Flow."""
        req_stub = None
        if flow.request is not None:
            r = flow.request
            req_stub = _ParseStub(
                protocol=r.protocol, method=r.method, url=r.url,
                host=r.host, status_code=r.status_code, status_text=r.status_text,
                content_type=r.content_type, content_encoding=r.content_encoding,
                body_size=r.body_size, stream_id=r.stream_id,
                is_control_frame=r.is_control_frame,
            )
        resp_stub = None
        if flow.response is not None:
            r = flow.response
            resp_stub = _ParseStub(
                protocol=r.protocol, method=r.method, url=r.url,
                host=r.host, status_code=r.status_code, status_text=r.status_text,
                content_type=r.content_type, content_encoding=r.content_encoding,
                body_size=r.body_size, stream_id=r.stream_id,
                is_control_frame=r.is_control_frame,
            )
        # Non-mutating lookup: a summary is a pure read, so use layer() (None if
        # absent) rather than flow.tls, which would attach an empty layer.
        tls_layer = flow.layer("tls")
        return FlowSummary(
            flow_id=flow.flow_id,
            connection_id=flow.connection_id,
            src_addr=flow.src_addr,
            src_port=flow.src_port,
            dst_addr=flow.dst_addr,
            dst_port=flow.dst_port,
            ssl_session_id=flow.ssl_session_id,
            state=flow.state,
            started=flow.started,
            ended=flow.ended,
            request=req_stub,
            response=resp_stub,
            has_ohttp=(flow.ohttp_inner_request is not None
                       or flow.ohttp_inner_response is not None),
            has_trailing_data=flow.trailing_bytes is not None,
            trailing_protocol=flow.trailing_protocol,
            total_bytes=flow._total_bytes,
            detected_protocol=flow.detected_protocol,
            process_name=flow.process_name,
            tls_sni=(tls_layer.sni if tls_layer is not None else ""),
            tls_alpn=(tls_layer.alpn if tls_layer is not None else ""),
            tag_count=len(flow.tags),
            finding_count=len(flow.findings),
            has_notes=bool(flow.notes),
        )

    def to_dict(self) -> dict:
        """Return a JSON-safe, body-free dict for a high-level flow overview.

        Emits the canonical FlowSummary key set shared with
        :meth:`friTap.flow.tap_format.FlowSummary.to_dict` so that live
        summaries (built via :meth:`from_flow`) and offline summaries (read
        from a .tap) render identically in a web UI / TUI / CLI overview.
        """
        req, resp = self.request, self.response
        return {
            "flow_id": self.flow_id,
            "connection_id": self.connection_id,
            "src_addr": self.src_addr,
            "src_port": self.src_port,
            "dst_addr": self.dst_addr,
            "dst_port": self.dst_port,
            "ssl_session_id": self.ssl_session_id,
            "state": self.state.value if isinstance(self.state, FlowState) else str(self.state),
            "started": self.started,
            "ended": self.ended,
            # Deterministic and parity-matched with tap_format.FlowSummary.to_dict:
            # the `duration` property returns wall-clock `time.time() - started`
            # for in-progress flows (ended == 0), which is non-deterministic and
            # would diverge from the offline summary shape. A serialized snapshot
            # uses 0.0 until the flow completes.
            "duration": (self.ended - self.started) if self.ended > 0 else 0.0,
            "protocol": (self.detected_protocol
                         or (req.protocol if req else "")
                         or (resp.protocol if resp else "")
                         or "unknown"),
            "method": req.method if req else "",
            "url": req.url if req else "",
            "host": req.host if req else "",
            "status_code": resp.status_code if resp else 0,
            "total_bytes": self.total_bytes,
            "detected_protocol": self.detected_protocol,
            "process_name": self.process_name,
            "tls_sni": self.tls_sni,
            "tls_alpn": self.tls_alpn,
            "tag_count": self.tag_count,
            "finding_count": self.finding_count,
            "has_notes": self.has_notes,
        }


@dataclass
class Flow:
    # Identity
    flow_id: str = ""
    connection_id: str = ""
    src_addr: str = ""
    src_port: int = 0
    dst_addr: str = ""
    dst_port: int = 0
    ssl_session_id: str = ""

    # Transport/encryption protocol of the underlying connection: "tls"
    # (TLS-over-TCP, the default) or "quic" (QUIC-over-UDP). Stamped from
    # ``event.protocol`` at flow creation (FlowCollector._stamp_metadata). The
    # Flow itself stores no other transport hint, so the LayerPipeline reads
    # this to decide whether the layer-0 transport is a TlsLayer or QuicLayer.
    transport: str = "tls"

    # State
    state: FlowState = FlowState.ACTIVE
    started: float = field(default_factory=time.time)
    ended: float = 0.0

    # Parsed (from parsers module)
    request: Optional[ParseResult] = None
    response: Optional[ParseResult] = None

    # OHTTP inner payloads (decrypted bhttp, from NSS HPKE hooks)
    ohttp_inner_request: Optional[ParseResult] = None
    ohttp_inner_response: Optional[ParseResult] = None

    # Trailing data (unconsumed bytes after valid WebSocket/protocol frames)
    trailing_bytes: Optional[bytes] = None
    trailing_protocol: str = ""
    trailing_parse: Optional[ParseResult] = None

    # Raw
    chunks: list[FlowChunk] = field(default_factory=list)

    # Cached byte total (incremented by FlowCollector when appending chunks)
    _total_bytes: int = 0

    # Protocol detected by the parser registry, populated even when no
    # ``request``/``response`` is produced yet (e.g. HTTP/2 control-frame-only
    # flows). Used as a display fallback before showing "unknown".
    detected_protocol: str = ""

    # ------------------------------------------------------------------
    # Schema v2 additive enrichment fields (all optional, back-compat safe)
    # ------------------------------------------------------------------

    # Explicit endpoint-role labeling (v2-reserved). ``src_*``/``dst_*`` remain
    # the canonical transport endpoints (used across display/collector/filters);
    # these name the same two ends by *role* — local (instrumented process) and
    # remote (peer). They are stored fields (not properties) because both the
    # FLOW decode path (tap_format.decode_flow) and the collector assign them,
    # and they are persisted as their own keys in the .tap meta. They are
    # populated from src/dst in exactly ONE place — FlowCollector._enrich_flow —
    # which is the single source of truth for the local==src / remote==dst
    # mapping; everything else only reads them. Kept as a v2 hook so a future
    # capture source that distinguishes role from src/dst order (e.g. inbound
    # server flows) can set them without changing readers.
    local_addr: str = ""
    local_port: int = 0
    remote_addr: str = ""
    remote_port: int = 0

    # Process / package identity (from the capture target / agent).
    process_name: str = ""
    package_name: str = ""

    # Ordered protocol layer stack (outermost transport -> innermost), e.g.
    # [tls, http2] or [quic, http3]. Per-flow LINEAR (HTTP/2-3 streams are
    # already separate flows). Resolved by name via __getattr__: ``flow.tls``,
    # ``flow.quic``, ``flow.ssh`` each return their typed layer (lazily created
    # empty if absent, so e.g. ``flow.tls.sni`` is never None — matching the
    # old TlsMetadata value-object ergonomics). Whole-layer writes go through
    # add_layer/set_layer; field mutation (``flow.tls.sni = ...``) works on the
    # cached instance returned by __getattr__.
    layers: list[ProtocolLayer] = field(default_factory=list, repr=False)

    # Hook origin. ``hook_function`` mirrors the dominant chunk.function;
    # ``hook_stack`` is reserved for full backtraces (NICE-later).
    hook_function: str = ""
    hook_stack: str = ""

    # Mutable analyst annotations.
    tags: list[str] = field(default_factory=list)
    notes: str = ""
    # Attached analysis findings. Typed loosely as ``list`` to avoid importing
    # ``friTap.analysis`` here (it imports ``flow.models`` under TYPE_CHECKING);
    # elements are ``friTap.analysis.Finding`` instances.
    findings: list = field(default_factory=list)

    # ------------------------------------------------------------------
    # Protocol layer access (flow.<protocol> -> typed ProtocolLayer)
    # ------------------------------------------------------------------

    def __getattr__(self, name: str):
        # Only invoked when normal attribute lookup fails — real dataclass
        # fields/methods never reach here. Resolve a registered protocol name
        # to its layer (lazily creating an empty one so flow.tls/flow.quic are
        # never-None, matching the old TlsMetadata ergonomics). Anything else
        # raises AttributeError so getattr(flow, x, default) (filter engine,
        # copy/pickle dunder probing) keeps working.
        #
        # This materializes-and-attaches by design: it is the writable
        # never-None ergonomic (``flow.tls.version = ...`` persists). PURE-READ
        # probes that must NOT grow the stack (serializers, snapshots) must use
        # the non-mutating :meth:`layer` instead of attribute access.
        if name.startswith("_"):
            raise AttributeError(name)
        layers = self.__dict__.get("layers")
        if layers is None:
            # Half-constructed (e.g. during copy/unpickle before fields set).
            raise AttributeError(name)
        desc = get_registry().get(name)
        if desc is None:
            raise AttributeError(name)
        for ly in layers:
            if ly.name == name:
                return ly
        return self._create_layer(name, desc)

    def _create_layer(self, name: str, desc) -> ProtocolLayer:
        layer = desc.layer_cls()
        # Stamp the per-instance name so generic layers (AppLayer, registered
        # under several names against one class) report the right ``name``.
        # Harmless for typed layers (their ``NAME`` already equals ``name``).
        layer._name = name
        layer.depth = len(self.layers)
        layer._flow = self
        if desc.data_source == "chunks":
            layer.data = LayerData(data_source="chunks", _owner=self)
        self.layers.append(layer)
        return layer

    def layer(self, name: str) -> Optional[ProtocolLayer]:
        """Return the layer named *name*, or None if not present."""
        for ly in self.layers:
            if ly.name == name:
                return ly
        return None

    def add_layer(self, layer: ProtocolLayer) -> ProtocolLayer:
        """Append *layer* to the stack, linking parent/child + binding data."""
        layer.depth = len(self.layers)
        if self.layers:
            parent = self.layers[-1]
            parent.child = layer
            layer.parent = parent
        layer._flow = self
        if layer.data.data_source == "chunks" and layer.data._owner is None:
            layer.data._owner = self
        self.layers.append(layer)
        return layer

    def set_layer(self, layer: ProtocolLayer) -> ProtocolLayer:
        """Replace an existing same-name layer in place, else append it."""
        for i, existing in enumerate(self.layers):
            if existing.name == layer.name:
                layer.depth = existing.depth
                layer.parent, layer.child = existing.parent, existing.child
                layer._flow = self
                if layer.data.data_source == "chunks" and layer.data._owner is None:
                    layer.data._owner = self
                self.layers[i] = layer
                return layer
        return self.add_layer(layer)

    def __copy__(self) -> "Flow":
        # Shallow copy that re-lists the mutable containers (chunks, layers) so
        # appending to a live flow does not mutate a snapshot's lists. Element
        # objects are shared, matching the pre-existing snapshot semantics
        # (the collector already shared the TlsMetadata/FlowChunk objects).
        new = Flow.__new__(Flow)
        new.__dict__.update(self.__dict__)
        new.chunks = list(self.chunks)
        new.layers = list(self.layers)
        return new

    @property
    def has_trailing_data(self) -> bool:
        return self.trailing_bytes is not None

    @property
    def segments(self) -> list[dict]:
        """Return segment descriptors for multi-protocol rendering.

        Each segment is a dict with keys: type ('parsed'|'raw'), protocol,
        parse_result (or None), data (raw bytes for 'raw' type), source.
        """
        segs: list[dict] = []
        if self.request is not None:
            segs.append({
                "type": "parsed",
                "protocol": self.display_protocol,
                "parse_result": self.request,
                "source": "primary",
            })
        if self.trailing_parse is not None:
            segs.append({
                "type": "parsed",
                "protocol": self.trailing_protocol,
                "parse_result": self.trailing_parse,
                "source": "trailing",
            })
        elif self.trailing_bytes:
            segs.append({
                "type": "raw",
                "protocol": self.trailing_protocol or "unknown",
                "data": self.trailing_bytes,
                "source": "trailing",
            })
        return segs

    @property
    def duration(self) -> float:
        if self.ended > 0:
            return self.ended - self.started
        return time.time() - self.started

    @property
    def display_method(self) -> str:
        return _display.display_method(self.request)

    @property
    def display_host(self) -> str:
        return _display.display_host(self.request, self.dst_addr, self.dst_port)

    @property
    def display_status(self) -> str:
        return _display.display_status(self.response)

    @property
    def display_size(self) -> str:
        total_bytes = self._total_bytes
        if total_bytes == 0 and self.chunks:
            total_bytes = sum(len(c.data) for c in self.chunks)
        return _display.display_size(self.response, total_bytes)

    @property
    def display_protocol(self) -> str:
        return _display.display_protocol(self)

    @property
    def has_request_data(self) -> bool:
        if self.request is not None:
            return True
        return any(c.direction == "write" for c in self.chunks)

    @property
    def has_response_data(self) -> bool:
        if self.response is not None:
            return True
        return any(c.direction == "read" for c in self.chunks)

    def get_direction_bytes(self, direction: str, max_bytes: int = 0) -> bytes:
        """Get concatenated raw bytes for a given direction ('read' or 'write').

        If *max_bytes* > 0, stop accumulating after that many bytes.
        """
        if max_bytes <= 0:
            return b"".join(c.data for c in self.chunks if c.direction == direction)
        parts: list[bytes] = []
        total = 0
        for c in self.chunks:
            if c.direction != direction:
                continue
            parts.append(c.data)
            total += len(c.data)
            if total >= max_bytes:
                break
        return b"".join(parts)

    @property
    def display_source(self) -> str:
        return _display.display_source(self.src_addr, self.src_port)

    @property
    def display_connection(self) -> str:
        """Directional connection string: src -> dst, src <- dst, or src <-> dst."""
        return _display.display_connection(
            self.request if self.has_request_data else None,
            self.response if self.has_response_data else None,
            self.src_addr, self.src_port, self.dst_addr, self.dst_port,
        )

    def to_dict(self, include_bodies: bool = False) -> dict:
        """Return a JSON-safe dict view of this flow for API/web consumers.

        Covers identity, transport/timing, parsed request/response (via
        :meth:`ParseResult.to_dict`), the protocol layer names, analyst
        annotations and attached findings. Raw chunk bytes are never included;
        request/response bodies are included (hex-encoded) only when
        *include_bodies* is True. Uses the non-mutating :meth:`layer` lookup so
        serializing never grows the layer stack.
        """
        tls = self.layer("tls")
        total_bytes = self._total_bytes or sum(len(c.data) for c in self.chunks)
        return {
            "flow_id": self.flow_id,
            "connection_id": self.connection_id,
            "src_addr": self.src_addr,
            "src_port": self.src_port,
            "dst_addr": self.dst_addr,
            "dst_port": self.dst_port,
            "ssl_session_id": self.ssl_session_id,
            "transport": self.transport,
            "state": self.state.value if isinstance(self.state, FlowState) else str(self.state),
            "started": self.started,
            "ended": self.ended,
            # Deterministic: avoid the wall-clock `duration` property for an
            # in-progress flow so the serialized snapshot is stable across calls.
            "duration": (self.ended - self.started) if self.ended > 0 else 0.0,
            "protocol": self.display_protocol,
            "detected_protocol": self.detected_protocol,
            "total_bytes": total_bytes,
            "process_name": self.process_name,
            "package_name": self.package_name,
            "tls_sni": tls.sni if tls is not None else "",
            "tls_alpn": tls.alpn if tls is not None else "",
            "layers": [ly.name for ly in self.layers],
            "tags": list(self.tags),
            "notes": self.notes,
            "request": self.request.to_dict(include_body=include_bodies) if self.request else None,
            "response": self.response.to_dict(include_body=include_bodies) if self.response else None,
            "findings": [f.to_dict() for f in self.findings],
        }

    # ------------------------------------------------------------------
    # On-demand body reconstruction from raw chunks
    # ------------------------------------------------------------------

    # Cache for reconstructed bodies: {direction: bytes}
    _body_cache: dict = field(default_factory=dict, repr=False)

    def reconstruct_body(self, direction: str) -> bytes:
        """Reconstruct the body for *direction* ('read' or 'write') from raw chunks.

        Bodies are no longer accumulated in parsers — this method extracts
        them on demand from ``self.chunks``.  The result is cached so repeated
        calls are cheap.
        """
        if direction in self._body_cache:
            return self._body_cache[direction]

        proto = self.display_protocol.lower()
        if "http/2" in proto:
            body = self._extract_h2_body(direction)
        elif "http/3" in proto:
            body = self._extract_h3_body(direction)
        elif "http/1" in proto:
            body = self._extract_h1_body(direction)
        elif "websocket" in proto:
            body = self._extract_ws_body(direction)
        else:
            body = b""

        self._body_cache[direction] = body
        return body

    def invalidate_body_cache(self) -> None:
        """Clear cached body data (call when chunks change)."""
        self._body_cache.clear()

    def _extract_h1_body(self, direction: str) -> bytes:
        """Extract HTTP/1 body by re-parsing raw bytes with h11."""
        try:
            import h11
        except ImportError:
            return b""
        raw = self.get_direction_bytes(direction)
        if not raw:
            return b""
        conn = h11.Connection(
            h11.CLIENT if direction == "read" else h11.SERVER
        )
        conn.receive_data(raw)
        body_parts: list[bytes] = []
        while True:
            event = conn.next_event()
            if event is h11.NEED_DATA or event is h11.PAUSED:
                break
            if isinstance(event, h11.Data):
                body_parts.append(bytes(event.data))
            elif isinstance(event, h11.EndOfMessage):
                break
        return b"".join(body_parts)

    def _extract_h2_body(self, direction: str) -> bytes:
        """Extract HTTP/2 DATA frame payloads from raw chunks.

        Stateless scan — no HPACK needed for body-only extraction.
        """
        import struct
        stream_id = 0
        msg = self.request if direction == "write" else self.response
        if msg is not None:
            stream_id = msg.stream_id

        body_parts: list[bytes] = []
        buf = bytearray()
        for chunk in self.chunks:
            if chunk.direction != direction:
                continue
            buf.extend(chunk.data)

        offset = 0
        while offset + 9 <= len(buf):
            length = (buf[offset] << 16) | (buf[offset + 1] << 8) | buf[offset + 2]
            frame_type = buf[offset + 3]
            flags = buf[offset + 4]
            sid = struct.unpack_from("!I", buf, offset + 5)[0] & 0x7FFFFFFF
            offset += 9
            if offset + length > len(buf):
                break
            if frame_type == 0x00 and (stream_id == 0 or sid == stream_id):
                payload = buf[offset:offset + length]
                # Strip padding if PADDED flag (0x08) is set
                if flags & 0x08 and len(payload) >= 1:
                    pad_len = payload[0]
                    end = len(payload) - pad_len
                    payload = payload[1:end] if end > 1 else b""
                body_parts.append(bytes(payload))
            offset += length

        return b"".join(body_parts)

    def _extract_h3_body(self, direction: str) -> bytes:
        """Extract HTTP/3 DATA frame payloads using varint framing."""
        from friTap.parsers.varint import decode_varint

        body_parts: list[bytes] = []
        buf = bytearray()
        for chunk in self.chunks:
            if chunk.direction != direction:
                continue
            buf.extend(chunk.data)

        offset = 0
        while offset < len(buf):
            try:
                frame_type, type_len = decode_varint(buf, offset)
                frame_length, len_len = decode_varint(buf, offset + type_len)
            except (ValueError, IndexError):
                break
            header_size = type_len + len_len
            payload_start = offset + header_size
            payload_end = payload_start + frame_length
            if payload_end > len(buf):
                break
            if frame_type == 0x00:  # DATA frame
                body_parts.append(bytes(buf[payload_start:payload_end]))
            offset = payload_end

        return b"".join(body_parts)

    def _extract_ws_body(self, direction: str) -> bytes:
        """Extract WebSocket payload — body is already in ParseResult for WS."""
        msg = self.request if direction == "write" else self.response
        if msg is not None and msg.body:
            return msg.body
        return b""

    # ------------------------------------------------------------------
    # Header / body / content-type access
    # ------------------------------------------------------------------

    @staticmethod
    def _get_header(msg: "Optional[ParseResult]", name: str, default: str = "") -> str:
        if msg is None:
            return default
        lower_name = name.lower()
        for key, value in msg.headers.items():
            if key.lower() == lower_name:
                return value
        return default

    def _get_decompressed_body(self, msg: "Optional[ParseResult]", direction: str, encoding_override: str = "") -> bytes:
        if msg is None:
            return b""
        body = msg.body if msg.body else self.reconstruct_body(direction)
        if not body:
            return b""
        encoding = encoding_override or msg.content_encoding
        if not encoding:
            lower = "content-encoding"
            for key, value in msg.headers.items():
                if key.lower() == lower:
                    encoding = value
                    break
        if not encoding:
            return body
        from friTap.parsers.decompress import decompress_body
        data, _err = decompress_body(body, encoding)
        return data

    def get_request_header(self, name: str, default: str = "") -> str:
        """Get a request header value by name (case-insensitive)."""
        return self._get_header(self.request, name, default)

    def get_response_header(self, name: str, default: str = "") -> str:
        """Get a response header value by name (case-insensitive)."""
        return self._get_header(self.response, name, default)

    @property
    def request_body(self) -> bytes:
        """The request body (possibly compressed), or ``b""``."""
        if self.request and self.request.body:
            return self.request.body
        return self.reconstruct_body("write")

    @property
    def response_body(self) -> bytes:
        """The response body (possibly compressed), or ``b""``."""
        if self.response and self.response.body:
            return self.response.body
        return self.reconstruct_body("read")

    def get_decompressed_request_body(self) -> bytes:
        """Return the request body after decompressing (gzip/br/zstd/deflate)."""
        return self._get_decompressed_body(self.request, "write")

    def get_decompressed_response_body(self) -> bytes:
        """Return the response body after decompressing (gzip/br/zstd/deflate)."""
        return self._get_decompressed_body(self.response, "read")

    @property
    def response_content_type(self) -> str:
        """The response Content-Type, or ``""`` if unavailable."""
        if self.response is not None and self.response.content_type:
            return self.response.content_type
        return self.get_response_header("content-type")

    @property
    def request_content_type(self) -> str:
        """The request Content-Type, or ``""`` if unavailable."""
        if self.request is not None and self.request.content_type:
            return self.request.content_type
        return self.get_request_header("content-type")

    def decode_request_protobuf(
        self, schema_path: Optional[str] = None, force: bool = False
    ) -> Optional[list]:
        """Decode the request body as protobuf.

        Returns a dict of ``{field_number: [ProtoField, ...]}`` or ``None``
        if the body is not protobuf or decoding fails.

        Args:
            schema_path: Optional path to a compiled ``.desc`` file.
            force: If ``True``, attempt decoding regardless of content type.
        """
        return self._decode_protobuf(
            self.get_decompressed_request_body(),
            self.request_content_type,
            schema_path=schema_path,
            force=force,
        )

    def decode_response_protobuf(
        self, schema_path: Optional[str] = None, force: bool = False
    ) -> Optional[list]:
        """Decode the response body as protobuf.

        Returns a dict of ``{field_number: [ProtoField, ...]}`` or ``None``
        if the body is not protobuf or decoding fails.

        Args:
            schema_path: Optional path to a compiled ``.desc`` file.
            force: If ``True``, attempt decoding regardless of content type.
        """
        return self._decode_protobuf(
            self.get_decompressed_response_body(),
            self.response_content_type,
            schema_path=schema_path,
            force=force,
        )

    def _decode_protobuf(
        self,
        body: bytes,
        content_type: str,
        schema_path: Optional[str] = None,
        force: bool = False,
    ) -> Optional[list]:
        """Internal: decode protobuf body with auto gRPC framing detection."""
        if not body:
            return None

        from friTap.parsers.protobuf import (
            decode_raw,
            extract_grpc_messages,
            is_grpc_content_type,
            is_likely_protobuf,
            is_protobuf_content_type,
        )

        # Check if we should attempt decoding
        is_proto_ct = is_grpc_content_type(content_type) or is_protobuf_content_type(content_type)
        if not force and not is_proto_ct and not is_likely_protobuf(body):
            return None

        try:
            payloads = extract_grpc_messages(body, content_type)
            results = []
            for payload in payloads:
                if not payload:
                    continue
                msg = decode_raw(payload)
                results.append(msg)
            return results if results else None
        except Exception:
            return None
