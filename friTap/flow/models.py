"""Flow data models for SSL/TLS flow collection."""

from __future__ import annotations

import time
from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from enum import Enum
from typing import TYPE_CHECKING, Any, Optional

from friTap.flow import display as _display
from friTap.flow.layer_registry import get_registry
from friTap.flow.layers import (
    LayerData,
    ProtocolLayer,
    TlsLayer,
)

if TYPE_CHECKING:
    from friTap.parsers.base import ParseResult
    from friTap.parsers.protobuf.view import ProtobufView


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


def single_stream_id(stream_ids) -> Optional[int]:
    """The one id shared by all non-None *stream_ids*; None if none or mixed."""
    found: Optional[int] = None
    for sid in stream_ids:
        if sid is None:
            continue
        if found is None:
            found = sid
        elif sid != found:
            return None
    return found


# Terminal Flow.stream_id cache state: chunk ids disagree (multi-stream).
_MIXED_STREAMS = object()


def put_stream_id(out: dict, stream_id: Optional[int]) -> dict:
    """Add ``stream_id`` to the serialized *out* only when known."""
    if stream_id is not None:
        out["stream_id"] = stream_id
    return out


def shared_summary_fields(
    flow: "Flow", filter_attrs: Optional[Mapping[str, tuple]] = None,
) -> dict[str, Any]:
    """Summary fields both FlowSummary shapes (here and tap_format) derive the same way from *flow*, as constructor kwargs.

    A pure read (``flow.layer()`` never grows the stack). *filter_attrs* goes to ``filter_inputs_from_flow``.
    """
    # Local imports: friTap.filter's package __init__ pulls in the evaluator, which must stay free to import friTap.flow (cycle).
    from friTap.filter.layer_fields import filter_inputs_from_flow
    from friTap.filter.protocols import flow_has_ohttp

    tls = flow.layer("tls")
    outer_app, inner_e2e, inner_summary = _display.layered_scalars_from_flow(flow)
    flow_method = getattr(flow, "flow_method", "") or _display.method_from_messages(flow)
    filter_attrs, protocols = filter_inputs_from_flow(flow, filter_attrs)
    return {
        "flow_id": flow.flow_id,
        "connection_id": flow.connection_id,
        "src_addr": flow.src_addr,
        "src_port": flow.src_port,
        "dst_addr": flow.dst_addr,
        "dst_port": flow.dst_port,
        "ssl_session_id": flow.ssl_session_id,
        "started": flow.started,
        "ended": flow.ended,
        "transport": getattr(flow, "transport", "tls") or "tls",
        "has_ohttp": flow_has_ohttp(flow),
        "tls_sni": tls.sni if tls is not None else "",
        "tls_alpn": tls.alpn if tls is not None else "",
        "tag_count": len(getattr(flow, "tags", []) or []),
        "finding_count": len(getattr(flow, "findings", []) or []),
        "has_notes": bool(getattr(flow, "notes", "")),
        "outer_app_protocol": outer_app,
        "inner_e2e_protocol": inner_e2e,
        "inner_summary": inner_summary,
        "flow_method": flow_method,
        "stream_id": flow.stream_id,
        "filter_attrs": filter_attrs,
        "protocols": protocols,
    }


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
    # Real transport stream id (QUIC/HTTP/2) when known; persisted per chunk only when set.
    stream_id: Optional[int] = None


# TLS handshake metadata is the ``tls`` layer (TlsLayer); ``flow.tls`` resolves it via __getattr__.
TlsMetadata = TlsLayer


_OHTTP_SENTINEL = object()  # Truthy sentinel for FlowSummary OHTTP filter compat


@dataclass(frozen=True, slots=True)
class _ParseStub:
    """Minimal ParseResult stand-in for FlowSummary: only the fields the filter engine and display read."""
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


def _parse_stub(result: "Optional[ParseResult]") -> Optional[_ParseStub]:
    """The summary stub of a request/response *result*, or None."""
    if result is None:
        return None
    return _ParseStub(
        protocol=result.protocol, method=result.method, url=result.url,
        host=result.host, status_code=result.status_code,
        status_text=result.status_text, content_type=result.content_type,
        content_encoding=result.content_encoding, body_size=result.body_size,
        stream_id=result.stream_id, is_control_frame=result.is_control_frame,
    )


@dataclass(frozen=True, slots=True)
class FlowSummary:
    """Lightweight scalar snapshot of a Flow (~200 bytes, no chunks/bodies) for list display and filtering.

    ``request``/``response`` stubs use ParseResult's attribute names for the filter engine.
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
    # Mirrors Flow.transport ("tls", "quic", "signal", ...) for grouping without the full Flow.
    transport: str = "tls"
    request: Optional[_ParseStub] = None
    response: Optional[_ParseStub] = None
    has_ohttp: bool = False
    has_trailing_data: bool = False
    trailing_protocol: str = ""
    has_response_trailing_data: bool = False
    response_trailing_protocol: str = ""
    total_bytes: int = 0
    detected_protocol: str = ""
    # Schema v2 additive enrichment scalars (cheap to surface in list/filter views)
    process_name: str = ""
    tls_sni: str = ""
    tls_alpn: str = ""
    tag_count: int = 0
    finding_count: int = 0
    has_notes: bool = False
    # Layered protocol-display scalars (display.display_protocol_layered).
    outer_app_protocol: str = ""
    inner_e2e_protocol: str = ""
    inner_summary: str = ""
    # Primary TL operation from message-bearing layers (display.method_from_messages), shown in the Method column.
    flow_method: str = ""
    # Real transport stream id of a single-stream flow (see Flow.stream_id).
    stream_id: Optional[int] = None
    # Precomputed display-filter inputs so filtering matches on a live flow and on a row rebuilt
    # from a .tap (no layer stack): ``filter_attrs`` maps per-protocol fields (friTap.filter.layer_fields)
    # to values, ``protocols`` holds canonical names (friTap.filter.protocols). Plain dict (pickles,
    # survives asdict) and READ-ONLY; unhashable, so excluded from hash().
    filter_attrs: Mapping[str, tuple] = field(default_factory=dict, hash=False)
    protocols: frozenset[str] = frozenset()

    @property
    def duration(self) -> float:
        if self.ended > 0:
            return self.ended - self.started
        return time.time() - self.started

    @property
    def display_protocol(self) -> str:
        return _display.display_protocol(self)

    @property
    def display_protocol_layered(self) -> str:
        return _display.display_protocol_layered(self)

    @property
    def display_method(self) -> str:
        return _display.display_method_layered(self)

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
            literal_direction=_display.is_message_transport(self),
        )

    # Aliases for filter engine compatibility
    @property
    def _total_bytes(self) -> int:
        return self.total_bytes

    @property
    def ohttp_inner_request(self):
        # Filter engine only checks `is not None`: return a truthy sentinel.
        return _OHTTP_SENTINEL if self.has_ohttp else None

    @property
    def ohttp_inner_response(self):
        return _OHTTP_SENTINEL if self.has_ohttp else None

    @staticmethod
    def from_flow(
        flow: "Flow", filter_attrs: Optional[Mapping[str, tuple]] = None,
    ) -> "FlowSummary":
        """Summary snapshot of a full Flow; *filter_attrs* reuses attributes already extracted for an unchanged layer stack (live rebuilds)."""
        fields = shared_summary_fields(flow, filter_attrs)
        # Prefer a scalar already set on the flow (a layerless flow rebuilt from a .tap summary),
        # since layered_scalars_from_flow returns "" without a layer stack.
        for name in ("outer_app_protocol", "inner_e2e_protocol", "inner_summary"):
            fields[name] = getattr(flow, name, "") or fields[name]
        return FlowSummary(
            **fields,
            state=flow.state,
            request=_parse_stub(flow.request),
            response=_parse_stub(flow.response),
            has_trailing_data=flow.trailing_bytes is not None,
            trailing_protocol=flow.trailing_protocol,
            has_response_trailing_data=flow.response_trailing_bytes is not None,
            response_trailing_protocol=flow.response_trailing_protocol,
            total_bytes=flow._total_bytes,
            detected_protocol=flow.detected_protocol,
            process_name=flow.process_name,
        )

    @staticmethod
    def from_tap_summary(tap_summary: Any, flow: "Flow") -> "FlowSummary":
        """Summary for a replay row: *flow* is the layerless synthetic Flow rebuilt from *tap_summary*.

        It has no layer stack or OHTTP payloads, so the filter inputs decoded from the tap's
        ``meta["layers"]`` are taken over; only protocols of a re-parsed request/response are added.
        """
        summary = FlowSummary.from_flow(flow, filter_attrs=tap_summary.filter_attrs)
        return replace(
            summary,
            protocols=tap_summary.protocols | summary.protocols,
            has_ohttp=summary.has_ohttp or tap_summary.has_ohttp,
            # The synthetic flow has no chunks to derive the stream id from.
            stream_id=(summary.stream_id if summary.stream_id is not None
                       else tap_summary.stream_id),
        )

    def to_dict(self) -> dict:
        """Return a JSON-safe, body-free overview dict.

        Same key set as :meth:`friTap.flow.tap_format.FlowSummary.to_dict`, so live and offline summaries render identically.
        """
        req, resp = self.request, self.response
        out = {
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
            "transport": self.transport,
            # Deterministic, parity with the offline shape: the ``duration`` property uses
            # wall-clock time for in-progress flows, so a snapshot uses 0.0 until completion.
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
            "outer_app_protocol": self.outer_app_protocol,
            "inner_e2e_protocol": self.inner_e2e_protocol,
            "inner_summary": self.inner_summary,
            "flow_method": self.flow_method,
        }
        # Omitted when unknown, in parity with tap_format.FlowSummary.to_dict.
        return put_stream_id(out, self.stream_id)


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

    # Transport of the connection: "tls" (default) or "quic"; stamped from ``event.protocol``
    # at creation (FlowCollector._stamp_metadata). LayerPipeline reads it to pick TlsLayer vs QuicLayer.
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
    # Trailing data left in the READ (response) direction; the trailing_* slot above keeps
    # write-direction / direction-less leftovers so direction-less parsers are unchanged.
    response_trailing_bytes: Optional[bytes] = None
    response_trailing_protocol: str = ""
    response_trailing_parse: Optional[ParseResult] = None

    # Raw
    chunks: list[FlowChunk] = field(default_factory=list)

    # Cached byte total (incremented by FlowCollector when appending chunks).
    _total_bytes: int = 0

    # True once the flow exceeded the per-flow retained-payload cap (MAX_FLOW_CHUNK_BYTES):
    # ``_total_bytes`` keeps counting but later chunks are not retained.
    truncated: bool = False

    # Protocol detected by the parser registry even without a request/response yet; display fallback before "unknown".
    detected_protocol: str = ""

    # Schema v2 additive enrichment fields (all optional).

    # Role labels for the endpoints: ``src_*``/``dst_*`` stay the canonical transport endpoints;
    # these name the same ends as local (instrumented process) / remote (peer). Stored fields
    # (set by tap_format.decode_flow and the collector, persisted as their own meta keys),
    # derived from src/dst in ONE place, FlowCollector._enrich_flow; everything else only reads them.
    local_addr: str = ""
    local_port: int = 0
    remote_addr: str = ""
    remote_port: int = 0

    # Process / package identity (from the capture target / agent).
    process_name: str = ""
    package_name: str = ""
    # Origin of the flow's first event when friTap follows several processes
    # (FriTapEvent.process_origin): pid and role ("target", "child", "spawn").
    # Persisted into the .tap meta only when set.
    pid: Optional[int] = None
    process_role: str = ""

    # Resolved SDK attribution (``--attribute-sdk``): the trusted ``{"sdk", "vendor", "category"}``
    # dict from the bundled signature table (friTap/analysis/attribution/sdk.py), or ``None``.
    # Persisted into the .tap meta only when set.
    sdk: Optional[dict] = None

    # Compact caller stack of the flow's connection (``--attribute-sdk``), stored whether or not it
    # matched an SDK: ``{transport_module, thread_name, tid, pid, native_frames[:8], java_frames[:8]}``,
    # strings escaped and capped at 80 chars (friTap/caller_stack_shapes.py). Target-controlled
    # text; ``None`` when no stack was joined. Persisted only when set.
    caller_stack: Optional[dict] = None

    # Transport vs originator attribution (friTap/flow/attribution.py): ``{"transport": {module, kind},
    # "originator": {sdk, vendor, category}, "confidence", "source", "bucket", "mixed": True}``, every
    # key optional. Transport is stamped on every TLS/QUIC flow with a known library; originator only
    # when a classified caller stack joined.
    attribution: Optional[dict] = None

    # True while src/dst (and local/remote) are a synthetic 198.18.0.0/15 pin for an fd-less
    # connection (option 5, friTap/endpoint_pinner.py); cleared when the real tuple is observed.
    # Persisted only when True.
    endpoints_synthetic: bool = False

    # Ordered layer stack (outermost transport -> innermost), e.g. [tls, http2]; per-flow LINEAR
    # (HTTP/2-3 streams are separate flows). ``flow.tls`` / ``flow.quic`` / ``flow.ssh`` resolve
    # by name via __getattr__ (lazily created empty, so ``flow.tls.sni`` is never None). Whole-layer
    # writes go through add_layer/set_layer; field mutation works on the cached instance.
    layers: list[ProtocolLayer] = field(default_factory=list, repr=False)

    # Hook origin: ``hook_function`` mirrors the dominant chunk.function; ``hook_stack`` is reserved.
    hook_function: str = ""
    hook_stack: str = ""

    # Mutable analyst annotations.
    tags: list[str] = field(default_factory=list)
    notes: str = ""
    # Attached findings, typed loosely to avoid importing ``friTap.analysis`` here (it imports models under TYPE_CHECKING).
    findings: list = field(default_factory=list)

    # (chunks list, scanned length, id so far or _MIXED_STREAMS) backing
    # ``stream_id``.
    _stream_id_cache: Optional[tuple] = field(
        default=None, init=False, repr=False, compare=False)

    @property
    def stream_id(self) -> Optional[int]:
        """Real transport stream id when every id-carrying chunk agrees (None if none or mixed).

        Chunks are append-only, so the cache is keyed on the list object (held, so its id
        cannot be reused) and only the new tail is scanned.
        """
        chunks = self.chunks
        # Snapshot the length first: chunks appended concurrently after this
        # point stay unscanned for the next call.
        end = len(chunks)
        cache = self._stream_id_cache
        if cache is not None and cache[0] is chunks and cache[1] <= end:
            scanned, found = cache[1], cache[2]
        else:
            scanned, found = 0, None
        if found is not _MIXED_STREAMS:
            for index in range(scanned, end):
                sid = chunks[index].stream_id
                if sid is None:
                    continue
                if found is None:
                    found = sid
                elif sid != found:
                    found = _MIXED_STREAMS
                    break
        if end != scanned:
            self._stream_id_cache = (chunks, end, found)
        return None if found is _MIXED_STREAMS else found

    # ------------------------------------------------------------------
    # Protocol layer access (flow.<protocol> -> typed ProtocolLayer)
    # ------------------------------------------------------------------

    def __getattr__(self, name: str):
        # Only invoked when normal lookup fails. Resolves a registered protocol name to its
        # layer, lazily creating an empty one (so flow.tls/flow.quic are never None); anything
        # else raises AttributeError so getattr(flow, x, default) (filter engine, copy/pickle
        # probing) keeps working. This attaches by design (``flow.tls.version = ...`` persists):
        # PURE-READ probes (serializers, snapshots) must use the non-mutating :meth:`layer`.
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
        # Per-instance name so generic layers (AppLayer, one class under several names) report the right ``name``.
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
        # Shallow copy that re-lists the mutable containers (chunks, layers) so appends to a live
        # flow do not mutate a snapshot; elements are shared.
        new = Flow.__new__(Flow)
        new.__dict__.update(self.__dict__)
        new.chunks = list(self.chunks)
        new.layers = list(self.layers)
        return new

    @property
    def has_trailing_data(self) -> bool:
        return self.trailing_bytes is not None

    @property
    def has_response_trailing_data(self) -> bool:
        return self.response_trailing_bytes is not None

    @property
    def segments(self) -> list[dict]:
        """Segment descriptors for multi-protocol rendering.

        Each is a dict with keys type ('parsed'|'raw'), protocol, parse_result (or None),
        data (raw bytes for 'raw'), source. The response-direction trailing segment
        (source ``"response_trailing"``) is last. The TUI addresses segments PER PANE:
        segment 1 is that pane's own trailing segment (see ``pane_segments``).
        """
        segs: list[dict] = []
        if self.request is not None:
            segs.append({
                "type": "parsed",
                "protocol": self.display_protocol,
                "parse_result": self.request,
                "source": "primary",
            })
        segs.extend(self._trailing_segments(
            self.trailing_bytes, self.trailing_protocol,
            self.trailing_parse, "trailing"))
        segs.extend(self._trailing_segments(
            self.response_trailing_bytes, self.response_trailing_protocol,
            self.response_trailing_parse, "response_trailing"))
        return segs

    def pane_segments(self, pane: str) -> list[dict]:
        """Segments shown on one detail pane: primary plus that pane's trailing.

        *pane* is ``"request"`` or ``"response"``; index 0 is the primary
        message, index 1 (when present) the pane's trailing segment.
        """
        trailing_source = "response_trailing" if pane == "response" else "trailing"
        return [s for s in self.segments
                if s["source"] in ("primary", trailing_source)]

    @staticmethod
    def _trailing_segments(data: Optional[bytes], protocol: str,
                           parse: Optional[ParseResult], source: str) -> list[dict]:
        """0 or 1 segment descriptor for one trailing slot."""
        if parse is not None:
            return [{"type": "parsed", "protocol": protocol,
                     "parse_result": parse, "source": source}]
        if data:
            return [{"type": "raw", "protocol": protocol or "unknown",
                     "data": data, "source": source}]
        return []

    @property
    def duration(self) -> float:
        if self.ended > 0:
            return self.ended - self.started
        return time.time() - self.started

    @property
    def display_method(self) -> str:
        return _display.display_method_layered(self)

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
            literal_direction=_display.is_message_transport(self),
        )

    def to_dict(self, include_bodies: bool = False) -> dict:
        """Return a JSON-safe dict view of this flow for API/web consumers.

        Covers identity, transport/timing, parsed request/response, layer names, annotations
        and findings. Chunk bytes are never included; bodies only (hex) when *include_bodies*.
        Uses the non-mutating :meth:`layer` so serializing never grows the layer stack.
        """
        tls = self.layer("tls")
        total_bytes = self._total_bytes or sum(len(c.data) for c in self.chunks)
        out = {
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
            # Deterministic: avoid the wall-clock ``duration`` for in-progress flows.
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
        return put_stream_id(out, self.stream_id)


        # Cache for reconstructed bodies: {direction: bytes}.
    _body_cache: dict = field(default_factory=dict, repr=False)

    def reconstruct_body(self, direction: str) -> bytes:
        """Reconstruct the body for *direction* from raw chunks, cached per direction."""
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
            try:
                event = conn.next_event()
            except h11.ProtocolError:
                # Malformed (attacker-controlled) framing: keep what parsed.
                break
            if event is h11.NEED_DATA or event is h11.PAUSED:
                break
            if isinstance(event, h11.Data):
                body_parts.append(bytes(event.data))
            elif isinstance(event, h11.EndOfMessage):
                break
        return b"".join(body_parts)

    def _extract_h2_body(self, direction: str) -> bytes:
        """Extract HTTP/2 DATA payloads from raw chunks (stateless scan, no HPACK).

        Without a parsed message the flow's own stream is used; stream id 0 (unknown) keeps every stream's DATA.
        """
        from friTap.parsers.http2_dataframe import http2_data_for_stream

        msg = self.request if direction == "write" else self.response
        if msg is not None:
            stream_id = msg.stream_id
        else:
            stream_id = self.stream_id or 0
        body, _degraded = http2_data_for_stream(
            self.get_direction_bytes(direction), stream_id
        )
        return body

    def _extract_h3_body(self, direction: str) -> bytes:
        """Extract HTTP/3 DATA frame payloads using varint framing."""
        from friTap.parsers.http3 import iter_h3_data_frames

        return b"".join(iter_h3_data_frames(self.get_direction_bytes(direction)))

    def _extract_ws_body(self, direction: str) -> bytes:
        """Extract WebSocket payload — body is already in ParseResult for WS."""
        msg = self.request if direction == "write" else self.response
        if msg is not None and msg.body:
            return msg.body
        return b""


    @staticmethod
    def _get_header(msg: "Optional[ParseResult]", name: str, default: str = "") -> str:
        if msg is None:
            return default
        lower_name = name.lower()
        for key, value in msg.headers.items():
            if key.lower() == lower_name:
                return value
        return default

    def _get_decompressed_body(
        self,
        msg: "Optional[ParseResult]",
        direction: str,
        encoding_override: str = "",
        max_out: Optional[int] = None,
    ) -> bytes:
        """Decompressed body of *msg*, output bounded by *max_out*.

        Defaults to ``MAX_DECOMPRESSED_BODY`` (explicit saves); the automatic paths pass the smaller
        ``MAX_AUTO_DECOMPRESS``. Cached in ``_body_cache`` per (direction, encoding, max_out).
        """
        if msg is None:
            return b""
        body = msg.body if msg.body else self.reconstruct_body(direction)
        if not body:
            return b""
        encoding = encoding_override or msg.content_encoding or self._content_encoding_header(msg)
        if not encoding:
            return body
        from friTap.parsers.decompress import MAX_DECOMPRESSED_BODY, decompress_body
        limit = MAX_DECOMPRESSED_BODY if max_out is None else max_out
        key = ("decompressed", direction, encoding, limit)
        cached = self._body_cache.get(key)
        if cached is not None and cached[0] is msg and cached[1] is body:
            return cached[2]
        data, _err = decompress_body(body, encoding, limit)
        self._body_cache[key] = (msg, body, data)
        return data

    @staticmethod
    def _content_encoding_header(msg: "ParseResult") -> str:
        """The message's Content-Encoding header value, or ``""``."""
        for key, value in msg.headers.items():
            if key.lower() == "content-encoding":
                return value
        return ""

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
        from friTap.parsers.decompress import MAX_AUTO_DECOMPRESS
        return self._get_decompressed_body(self.request, "write", max_out=MAX_AUTO_DECOMPRESS)

    def get_decompressed_response_body(self) -> bytes:
        """Return the response body after decompressing (gzip/br/zstd/deflate)."""
        from friTap.parsers.decompress import MAX_AUTO_DECOMPRESS
        return self._get_decompressed_body(self.response, "read", max_out=MAX_AUTO_DECOMPRESS)

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
        self,
        schema_path: Optional[str] = None,
        force: bool = False,
        message_type: Optional[str] = None,
    ) -> Optional["ProtobufView"]:
        """Decode the request body as protobuf (gRPC framing auto-detected).

        Returns a :class:`~friTap.parsers.protobuf.view.ProtobufView`, or ``None`` when the
        body is empty or not protobuf-like. A view may hold no decoded message: check
        ``view.ok``, ``view.notes`` / ``view.error``.

        Args:
            schema_path: Optional ``.proto`` or compiled ``.desc`` descriptor set, used with *message_type*.
                Without both, the wire decoder runs and a note says why.
            force: If ``True``, decode regardless of content type.
            message_type: Fully qualified message type for *schema_path*.
        """
        return self._decode_protobuf(
            self.get_decompressed_request_body(),
            self.request_content_type,
            self.get_request_header("grpc-encoding"),
            schema_path=schema_path,
            force=force,
            message_type=message_type,
        )

    def decode_response_protobuf(
        self,
        schema_path: Optional[str] = None,
        force: bool = False,
        message_type: Optional[str] = None,
    ) -> Optional["ProtobufView"]:
        """Decode the response body as protobuf (gRPC framing auto-detected).

        Same contract as :meth:`decode_request_protobuf`, for the response.
        """
        return self._decode_protobuf(
            self.get_decompressed_response_body(),
            self.response_content_type,
            self.get_response_header("grpc-encoding"),
            schema_path=schema_path,
            force=force,
            message_type=message_type,
        )

    @staticmethod
    def _decode_protobuf(
        body: bytes,
        content_type: str,
        grpc_encoding: str,
        schema_path: Optional[str] = None,
        force: bool = False,
        message_type: Optional[str] = None,
    ) -> Optional["ProtobufView"]:
        """Internal: gate on content type, then delegate to the shared view decoder."""
        if not body:
            return None

        from friTap.parsers.protobuf import (
            decode_protobuf_view,
            is_grpc_content_type,
            is_likely_protobuf,
            is_protobuf_content_type,
        )

        is_proto_ct = is_grpc_content_type(content_type) or is_protobuf_content_type(content_type)
        if not force and not is_proto_ct and not is_likely_protobuf(body):
            return None

        return decode_protobuf_view(
            body,
            content_type=content_type,
            grpc_encoding=grpc_encoding,
            schema_path=schema_path or "",
            message_type=message_type or "",
        )
