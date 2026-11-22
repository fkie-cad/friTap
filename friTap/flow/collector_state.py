"""Per-connection state and helper records of :class:`FlowCollector`.

Kept apart from ``collector.py`` so the collector mixins can use them without
importing the collector module; ``friTap.flow.collector`` re-exports them.
"""

import sys
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Callable, NamedTuple, Optional

from .attribution import sdk_name
from .models import Flow, FlowChunk, FlowEventType


def collector_module():
    """``friTap.flow.collector``, looked up at call time so tests patching its constants take effect."""
    return sys.modules["friTap.flow.collector"]


def _merge_pop(table: dict, old_id: str, new_id: str, merge) -> None:
    """Move ``table[old_id]`` to *new_id*, merging with an existing entry via ``merge(new_value, old_value)``."""
    if old_id not in table:
        return
    old_value = table.pop(old_id)
    table[new_id] = merge(table[new_id], old_value) if new_id in table else old_value


def _merge_session_meta(target: dict, update: dict) -> dict:
    """Overwrite *target* with *update*'s non-empty fields (a partial update never blanks a set field); returns *target*."""
    for key, value in update.items():
        if value:
            target[key] = value
    return target


def _merge_connection_attribution(new: '_ConnectionAttribution',
                                  old: '_ConnectionAttribution') -> '_ConnectionAttribution':
    new.adopt_missing(old)
    new.sdk_names |= old.sdk_names
    return new


@dataclass(slots=True)
class _ConnectionAttribution:
    """What a live connection's originators resolved to (``FlowCollector._connection_attributions``).

    ``caller_stack`` stays ``None`` until a stack is joined (a per-request originator may create the record first).
    """

    sdk: Optional[dict] = None  # first caller stack's {sdk, vendor, category}
    caller_stack: Optional[dict] = None  # first joined compact caller stack
    sdk_names: set = field(default_factory=set)

    @property
    def mixed(self) -> bool:
        """True when the originators named more than one SDK."""
        return len(self.sdk_names) > 1

    def adopt_missing(self, other) -> None:
        """Take *other*'s caller stack and SDK where this record has none."""
        if self.caller_stack is None:
            self.caller_stack = other.caller_stack
        if other.sdk and not self.sdk:
            self.sdk = other.sdk

    def add_originator(self, sdk: Optional[dict]) -> None:
        """Note *sdk*'s name (an unnamed or missing SDK is ignored)."""
        name = sdk_name(sdk)
        if name is not None:
            self.sdk_names.add(name)


class _Publication(NamedTuple):
    """Staged under the lock by ``_stage_publication``, delivered by ``_publish``."""

    events: list
    request_records: list = []
    request_sink: Optional[Callable[[dict], object]] = None


class _PendingEvents:
    """A pending ``(event_type, flow)`` list plus its flow ids, so each flow gets at most one extra UPDATED."""

    __slots__ = ("events", "_ids")

    def __init__(self, events: list) -> None:
        self.events = events
        self._ids = {id(flow) for _, flow in events}

    def flows(self) -> list:
        """The distinct flows in *events*, in first-seen order."""
        return list({id(flow): flow for _, flow in self.events}.values())

    def add_updated(self, flow: Flow) -> None:
        if id(flow) not in self._ids:
            self.events.append((FlowEventType.UPDATED, flow))
            self._ids.add(id(flow))


class _ConnectionState:
    """Internal per-connection tracking."""
    def __init__(self, conn_id: str, transport: str = ""):
        self.conn_id = conn_id
        # Flow.transport of this connection's events; selects a registry-pinned parser.
        self.transport = transport
        self.parser = None  # BaseParser instance
        self.active_flow_id: Optional[str] = None
        # First client_random seen on this connection ("" until stamped).
        self.client_random: str = ""
        # Synthetic -> real endpoint map (option 5), learned from the first record with
        # observed_* or the first real record after provisional ones.
        self.real_endpoint_map: Optional[dict] = None
        # (local, peer) tuples the agent guessed (QUIC before its peer was readable).
        self.provisional_sides: list = []
        # Flow ids come from FlowCollector._flow_seq: this state is rebuilt on idle-reset and would re-mint ids.
        self.last_activity: float = 0.0
        self.pending_chunks: list[FlowChunk] = []  # buffered before parser committed
        self.pending_bytes: int = 0  # total bytes in pending_chunks
        # detected_protocol stamp deferred until the parser recognizes something.
        self.protocol_stamp_pending: bool = False
        # Raw decrypted bytes per direction for live Signal decoding (flow chunks do not preserve the full stream).
        self.signal_raw: dict[str, bytearray] = {"read": bytearray(), "write": bytearray()}
        # Directions whose signal_raw exceeded MAX_SIGNAL_RAW_BYTES (decoding off).
        self.signal_capped: set[str] = set()
        # Real QUIC stream id -> dense positive synthetic id (stream_id 0 means "no stream", but QUIC's first bidi stream is 0).
        self._qsid_map: dict[int, int] = {}
        self._qsid_next: int = 1
        # QUIC stream plumbing (QuicStreamFlowMixin): HTTP/3 control flow, stream id -> flow_id, newest stream event.
        self.h3_control_flow_id: Optional[str] = None
        # Flow of de-framed QUIC bodies that arrived without a stream id.
        self.quic_unattributed_flow_id: Optional[str] = None
        self.quic_stream_flows: dict[int, str] = {}
        self.quic_last_event = None
        # Agent flag: the connection predates the capture (no SETTINGS/QPACK).
        self.quic_midstream = False
        # Weakref to the parser already told about quic_midstream (weak so replaced parsers are freed).
        self.quic_midstream_parser = None
        # HTTP/2 plumbing (Http2StreamFlowMixin): stream id -> flow_id routes (LRU, outlive flow completion), newest control flow, newest record per direction.
        self.h2_stream_flows: OrderedDict[int, str] = OrderedDict()
        self.h2_control_flow_id: Optional[str] = None
        self.h2_last_chunk: dict[str, FlowChunk] = {}
        # Late-payload flows (not active); completed with the control flow on finalize.
        self.h2_late_stream_flow_ids: list[str] = []

    def map_qsid(self, real_qsid: int) -> int:
        """Return the dense positive synthetic id for a real QUIC stream id."""
        sid = self._qsid_map.get(real_qsid)
        if sid is None:
            sid = self._qsid_next
            self._qsid_next += 1
            self._qsid_map[real_qsid] = sid
        return sid
