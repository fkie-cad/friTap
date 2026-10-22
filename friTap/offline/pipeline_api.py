"""Public API for offline-decryptor plugins (the pcap -> .tap pipeline surface).

Offline-decryptor plugins (Signal, RC4, Schannel, ...) drive the same writer,
event and TLS single-pass machinery as :mod:`friTap.offline.pcap_to_tap`. This
module is the supported surface for that: plugins import from here instead of
reaching into ``pcap_to_tap`` private names. ``pcap_to_tap`` imports what it
uses from here (keeping a few historical private aliases such as
``_WriterState``).

It must not import ``pcap_to_tap`` or any offline protocol package (see
``tests/unit/test_architecture_layering.py``, rule R2).
"""

from __future__ import annotations

import contextlib
import copy
import logging
from collections.abc import Mapping
from dataclasses import asdict, dataclass, field
from typing import Callable, Iterable, Sequence

from friTap.connection_index import canonical_4tuple, resolve_connection_key
from friTap.events import SESSION_STARTED, DatalogEvent, EventBus, SessionEvent
from friTap.flow.tap_writer import TapWriter
from friTap.offline.keylog_paths import canonical_keylog_path
from friTap.offline.result_schema import V1_BUCKET_DEFAULTS, V1_FLAT_COUNTERS
from friTap.offline.tls_spans import record_tls_span

from .tshark import (
    TLS_APP_DATA_COUNT_FIELD,
    TlsMetadataAccumulator,
    build_combined_command,
    decode_hex,
    ek_as_list,
    ek_field,
    ek_first,
    is_tls_app_data_row,
    is_tls_handshake_row,
    stream_packets,
    tls_app_data_marker,
    tshark_version,
)

# Kept under the historical module name so the moved code logs exactly as it
# did inside pcap_to_tap (same logger object, same record names).
logger = logging.getLogger("friTap.offline.pcap_to_tap")


# ---------------------------------------------------------------------------
# Conversion summary
# ---------------------------------------------------------------------------

@dataclass
class ConvertResult:
    """Summary of a pcap-to-tap conversion."""
    tap_path: str
    flow_count: int = 0
    decrypted_packet_count: int = 0
    stream_count: int = 0
    # QUIC per-packet drops (e.g. misaligned stream id/payload lists). Kept
    # distinct from dropped TLS streams below so the two are not conflated.
    dropped_packet_count: int = 0
    # TLS streams that could not be followed/decoded (whole-stream drops).
    dropped_stream_count: int = 0
    findings_count: int = 0
    # Streams skipped during a keyless (plaintext) conversion because they were
    # encrypted (TLS/QUIC) and therefore need keys. Drives the "looks encrypted —
    # pass --keylog" hint in the offline CLI.
    encrypted_streams_skipped: int = 0
    # Protocol-generic counters keyed by counter_prefix, e.g.
    # ``{"<prefix>": {"messages": 6, "streams": 2, "undecryptable": 0, ...}}``.
    # Every registry-driven protocol (built-in or plugin) needs only this dict
    # (no new dataclass field). Populated via :meth:`record_protocol`. The frozen
    # v1 flat counters (:data:`~friTap.offline.result_schema.V1_FLAT_COUNTERS`)
    # are read-only property views of it, attached below the class.
    per_protocol: dict = field(default_factory=dict)

    def record_protocol(self, prefix: str, **counters) -> None:
        """Accumulate one protocol decryptor's counters into ``per_protocol[prefix]``.

        A new bucket starts as a deep copy of the frozen v1 defaults
        (:data:`~friTap.offline.result_schema.V1_BUCKET_DEFAULTS`), so every
        bucket carries the same keys whether or not the protocol reports them.
        Each counter then merges by type (see :func:`_merge_counter`): booleans
        latch (OR), numbers add, mappings merge-add per key, ``None`` is skipped
        and anything else raises :class:`TypeError`. A counter name outside the
        v1 defaults simply becomes a new bucket key.
        """
        bucket = self.per_protocol.get(prefix)
        if bucket is None:
            bucket = self.per_protocol[prefix] = copy.deepcopy(V1_BUCKET_DEFAULTS)
        for name, value in counters.items():
            _merge_counter(bucket, name, value)

    def to_dict(self) -> dict:
        """Return a JSON-safe dict view of this conversion summary.

        Lets web/API callers serialize the result of a pcap-to-tap conversion
        without reaching into the dataclass fields by hand. The key order is the
        frozen v1 layout: the dataclass fields, with the legacy flat counters
        re-inserted right before ``per_protocol``.
        """
        data = asdict(self)
        per_protocol = data.pop("per_protocol")
        for flat_name, _prefix, _key in V1_FLAT_COUNTERS:
            data[flat_name] = getattr(self, flat_name)
        data["per_protocol"] = per_protocol
        return data


def _flat_counter_property(prefix: str, key: str, flat_name: str) -> property:
    """Read-only view of ``per_protocol[prefix][key]`` (0 when absent)."""
    def getter(self: ConvertResult):
        return (self.per_protocol.get(prefix) or {}).get(key, 0)

    getter.__name__ = flat_name
    return property(getter, doc=f"Read-only view of ``per_protocol[{prefix!r}][{key!r}]``.")


for _flat_name, _prefix, _key in V1_FLAT_COUNTERS:
    setattr(ConvertResult, _flat_name, _flat_counter_property(_prefix, _key, _flat_name))
del _flat_name, _prefix, _key


def _merge_counter(bucket: dict, name: str, value) -> None:
    """Merge one ``record_protocol`` counter *value* into *bucket[name]*.

    Dispatches on the bucket's existing value (on *value* for a new key) so the
    v1 semantics hold exactly: a boolean is checked BEFORE int (``bool`` is an
    ``int`` subclass) and latches with OR; numbers add; a mapping merge-adds per
    key (preserving first-seen order); ``None`` is skipped. Anything else raises
    :class:`TypeError` rather than silently corrupting the summary.
    """
    if value is None:
        return
    if name not in bucket:
        bucket[name] = _initial_counter(name, value)
        return
    current = bucket[name]
    if isinstance(current, bool) and isinstance(value, (bool, int, float)):
        bucket[name] = current or bool(value)
    elif isinstance(current, (int, float)) and isinstance(value, (int, float)):
        bucket[name] = current + value
    elif isinstance(current, dict) and isinstance(value, Mapping):
        for item_key, item_value in value.items():
            current[item_key] = current.get(item_key, 0) + item_value
    else:
        raise TypeError(
            f"record_protocol: cannot merge {type(value).__name__} counter "
            f"{name!r} into {type(current).__name__}"
        )


def _initial_counter(name: str, value):
    """First value of a counter key outside the v1 defaults (mappings copied)."""
    if isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, Mapping):
        return dict(value)
    raise TypeError(
        f"record_protocol: unsupported counter type {type(value).__name__} for {name!r}"
    )

# ---------------------------------------------------------------------------
# tshark `-T ek` field helpers
# ---------------------------------------------------------------------------

# ``ek_field`` / ``ek_as_list`` / ``ek_first`` live in friTap.offline.tshark next
# to the `-T ek` producers and are re-exported here (same objects).


def coerce_int(value, default: int | None = 0):
    """Coerce a tshark field value to int, or *default* on failure."""
    if value is None:
        return default
    try:
        return int(str(value))
    except (ValueError, TypeError):
        return default


def coerce_float(value, default: float = 0.0) -> float:
    """Coerce a tshark field value to float, or *default* on failure."""
    if value is None:
        return default
    try:
        return float(str(value))
    except (ValueError, TypeError):
        return default


def extract_addrs(layers: dict) -> tuple[str, str, str]:
    """Return ``(src_addr, dst_addr, ss_family)`` from a `-T ek` layers dict.

    Prefers IPv6 endpoints when present, else IPv4. Shared by every
    packet->events translator so the address/family logic lives in one place.
    """
    ip6_src = ek_first(ek_field(layers, "ipv6.src"))
    ip6_dst = ek_first(ek_field(layers, "ipv6.dst"))
    if ip6_src or ip6_dst:
        return ip6_src or "", ip6_dst or "", "AF_INET6"
    return (
        ek_first(ek_field(layers, "ip.src")) or "",
        ek_first(ek_field(layers, "ip.dst")) or "",
        "AF_INET",
    )

# ---------------------------------------------------------------------------
# Direction tracking and the lazily-opened writer
# ---------------------------------------------------------------------------

class StreamDirectionTracker:
    """Map each packet to "write" (client->server) or "read" (server->client).

    The client endpoint for a stream is chosen by SERVER PORT when possible: the
    endpoint that is NOT the well-known server port is the client. This mirrors
    how :func:`~friTap.offline.tshark._server_node_index` picks the server side
    on the TLS follow path, and it labels direction correctly even when the
    capture starts mid-flow or the first datagram is server-originated.

    Only when NEITHER endpoint matches a known server port do we fall back to
    the original first-packet-is-client order, so behaviour is unchanged for
    captures that hit a known port (the common case).
    """

    def __init__(self, server_ports: tuple[int, ...] = ()) -> None:
        self._client_endpoint: dict[str, tuple[str, int]] = {}
        # 443 is QUIC's well-known port; merge in any configured --quic-port(s).
        self._server_ports: set[int] = {443, *server_ports}

    @property
    def stream_count(self) -> int:
        """Number of distinct streams observed so far."""
        return len(self._client_endpoint)

    def direction_for(
        self,
        stream_key: str,
        src_ip: str,
        src_port: int,
        dst_ip: str | None = None,
        dst_port: int | None = None,
    ) -> str:
        """Return "write" or "read" for a packet on *stream_key*.

        When *dst_port* is a known server port the source is the client, and
        vice versa, regardless of which datagram arrived first. Falls back to
        the first-packet-is-client heuristic only when neither endpoint port is
        a known server port.
        """
        client = self._client_endpoint.get(stream_key)
        if client is None:
            client = self._derive_client_endpoint(
                src_ip, src_port, dst_ip, dst_port)
            self._client_endpoint[stream_key] = client
        return "write" if client == (src_ip, src_port) else "read"

    def _derive_client_endpoint(
        self,
        src_ip: str,
        src_port: int,
        dst_ip: str | None,
        dst_port: int | None,
    ) -> tuple[str, int]:
        """Pick the client endpoint for a stream's first observed packet.

        Prefer the server port: if the destination is a known server port the
        SOURCE is the client; if the SOURCE is a known server port this first
        packet is server-originated and the DESTINATION is the client. When
        neither matches, keep the legacy assumption that the first packet's
        source is the client.
        """
        if dst_port in self._server_ports:
            return (src_ip, src_port)
        if src_port in self._server_ports and dst_ip is not None and dst_port is not None:
            # Server-originated first packet: the destination is the client.
            return (dst_ip, dst_port)
        return (src_ip, src_port)


def _copy_keylog_into_tap(writer: TapWriter, keylog_path: str) -> None:
    """Copy each NSS keylog line into the .tap so it is self-describing."""
    try:
        with open(keylog_path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if line and not line.startswith("#"):
                    writer.write_keylog(line)
    except OSError:
        logger.warning("Could not read keylog %s for embedding", keylog_path, exc_info=True)


# Per-conversion protocol state namespaces: a protocol package registers a
# factory (and the legacy WriterState attribute names it owns) once at import;
# each WriterState then creates that namespace lazily on first access.
_PROTOCOL_STATE_FACTORIES: dict = {}
_LEGACY_ATTR_OWNERS: dict = {}
# Public attributes WriterState sets on ITSELF in __init__. A namespace may never
# claim one: routing e.g. ``opened`` would silently hijack the writer's own state.
_WRITER_STATE_OWN_ATTRS = frozenset({"opened", "inner_meta", "tls_spans"})


def _is_writer_state_attr(attr: str) -> bool:
    """True when *attr* is a real WriterState attribute, method or property."""
    return attr in _WRITER_STATE_OWN_ATTRS or hasattr(WriterState, attr)


def register_protocol_state(name: str, factory: Callable[[], object],
                            legacy_attrs: Iterable[str] = ()) -> None:
    """Register the per-conversion state namespace *name* built by *factory*.

    *legacy_attrs* are historical ``WriterState`` attribute names that now live
    on the namespace; ``state.<attr>`` reads and writes keep working by being
    routed to ``state.protocol_state(name).<attr>``. Re-registering *name*
    replaces its factory (idempotent for package re-imports); claiming an
    attribute another namespace already owns, a private ``_``-name, or a name
    that is a real ``WriterState`` attribute/method (e.g. ``opened``,
    ``protocol_state``) raises :class:`ValueError`.
    """
    legacy_attrs = tuple(legacy_attrs)
    for attr in legacy_attrs:
        if attr.startswith("_"):
            raise ValueError(f"private attribute {attr!r} cannot be routed")
        if _is_writer_state_attr(attr):
            raise ValueError(
                f"attribute {attr!r} is a WriterState attribute and cannot be routed")
        owner = _LEGACY_ATTR_OWNERS.get(attr)
        if owner not in (None, name):
            raise ValueError(f"attribute {attr!r} is already owned by {owner!r}")
    _PROTOCOL_STATE_FACTORIES[name] = factory
    _LEGACY_ATTR_OWNERS.update(dict.fromkeys(legacy_attrs, name))


def protocol_state_of(state, name: str):
    """The *name* protocol-state namespace of *state*.

    A real :class:`WriterState` (anything whose TYPE defines ``protocol_state``)
    returns its lazily created namespace; a minimal writer-state stand-in
    resolves to itself, so code written against the namespace keeps working on
    stand-ins that carry the attributes directly.
    """
    accessor = getattr(type(state), "protocol_state", None)
    if accessor is None:
        return state
    return accessor(state, name)


class WriterState:
    """Lazily open the TapWriter on first use, embedding the keylog once.

    Offline reconstruction may produce no events at all; opening lazily lets
    the caller still emit a valid empty .tap via :meth:`ensure_open` while
    avoiding writing a file before we know there is data.

    Protocol-specific per-conversion state lives in registered namespaces (see
    :func:`register_protocol_state` / :meth:`protocol_state`); the legacy
    attribute names a namespace claims are routed to it transparently.
    """

    def __init__(self, writer: TapWriter, tap_path: str, target: str,
                 keylog_path: str | None) -> None:
        self._protocol_states: dict = {}
        self._writer = writer
        self._tap_path = tap_path
        self._target = target
        self._keylog_path = keylog_path
        self.opened = False
        # Side-channel for a TLS-riding decryptor's parsed inner metadata that
        # DatalogEvent cannot carry, keyed by canonical_4tuple; consumed by
        # _attach_transport_metadata_layers.
        self.inner_meta: dict = {}
        # Per-frame provenance of the single-pass TLS plaintext, keyed by
        # canonical_4tuple then direction (see friTap.offline.tls_spans).
        self.tls_spans: dict = {}

    def protocol_state(self, name: str):
        """This conversion's *name* namespace, created on first access."""
        namespace = self._protocol_states.get(name)
        if namespace is None:
            try:
                factory = _PROTOCOL_STATE_FACTORIES[name]
            except KeyError:
                raise KeyError(f"no protocol state registered as {name!r}") from None
            namespace = self._protocol_states[name] = factory()
        return namespace

    def __getattr__(self, attr: str):
        # Only reached when normal lookup fails: route legacy protocol names.
        owner = None if attr.startswith("_") else _LEGACY_ATTR_OWNERS.get(attr)
        if owner is None:
            raise AttributeError(
                f"{type(self).__name__!r} object has no attribute {attr!r}")
        return getattr(self.protocol_state(owner), attr)

    def __setattr__(self, attr: str, value) -> None:
        owner = None if attr.startswith("_") else _LEGACY_ATTR_OWNERS.get(attr)
        if owner is None:
            object.__setattr__(self, attr, value)
        else:
            setattr(self.protocol_state(owner), attr, value)

    def ensure_open(self, capture_start: float = 0.0) -> None:
        """Open the writer if it is not already open (idempotent)."""
        if self.opened:
            return
        self._writer.open(self._tap_path, target=self._target,
                           capture_start=capture_start)
        if self._keylog_path:
            _copy_keylog_into_tap(self._writer, self._keylog_path)
        self.opened = True

    def note_capture_time(self, ts: float) -> None:
        """Open the writer at *ts* (if needed) and lower the header start to it.

        *ts* is a real pcap capture time (epoch seconds); non-positive values
        mean "unknown" and only ensure the writer is open.
        """
        self.ensure_open(ts if ts > 0 else 0.0)
        self._writer.update_capture_start(ts)


def protocol_session_id(proto: str, src_addr: str, src_port: int,
                        dst_addr: str, dst_port: int) -> str:
    """Per-connection session token ``<proto>:<canonical 4-tuple>``.

    No longer needed to keep a TLS-riding protocol's events (RC4, Signal, ...)
    apart from the outer TLS flow of the same connection: the collector's
    ``net:`` tier is itself protocol-scoped (``net:<proto>:<canonical 4-tuple>``
    for every non-TLS ``DatalogEvent.protocol``, see
    :func:`~friTap.connection_index.resolve_connection_key`), so the built-in
    decryptors emit no session token. Kept as a public helper for plugins that
    want an explicit per-connection token (it lands in the ``sid:`` tier).
    Perspective- and spelling-independent via
    :func:`~friTap.connection_index.canonical_4tuple`.
    """
    return f"{proto}:" + canonical_4tuple(src_addr, src_port, dst_addr, dst_port)


def event_ts_kwargs(ts: float) -> dict:
    """``{"timestamp": ts}`` for a real capture time, else ``{}`` (keep the default)."""
    return {"timestamp": ts} if ts and ts > 0 else {}


def open_at_capture_time(state, ts: float) -> None:
    """Open *state*'s writer and lower its header start to capture time *ts*.

    Falls back to a plain ``ensure_open`` for minimal writer-state stand-ins
    that do not implement ``note_capture_time``.
    """
    note = getattr(state, "note_capture_time", None)
    if note is not None:
        note(ts)
    else:
        state.ensure_open(ts if ts > 0 else 0.0)


def unique_keylog_paths(keylog: str, keylogs: Sequence[str] = ()) -> list:
    """*keylog* plus any extra *keylogs*, de-duplicated by real path (order kept)."""
    paths: list = []
    seen: set = set()
    for path in (keylog, *keylogs):
        if not path:
            continue
        real = canonical_keylog_path(path)
        if real not in seen:
            seen.add(real)
            paths.append(path)
    return paths

# ---------------------------------------------------------------------------
# Per-flow message scoping
# ---------------------------------------------------------------------------

def chunk_key(direction: str, data: bytes) -> str:
    """Identity of one flow chunk: its direction plus a short SHA-1 of its bytes.

    Each offline MTProto/E2E ``DatalogEvent`` carries exactly one decrypted
    record, which the collector stores verbatim as one ``FlowChunk`` (same
    ``"write"``/``"read"`` direction naming). Tagging the parsed messages of a
    record with this key lets :func:`scope_messages_to_flow` hand each flow only
    the messages whose record actually landed in it.
    """
    import hashlib

    return f"{direction}:{hashlib.sha1(bytes(data or b'')).hexdigest()[:16]}"


def _flow_chunk_keys(flow) -> set:
    """The :func:`chunk_key` of every chunk the collector put into *flow*."""
    return {
        chunk_key(getattr(c, "direction", ""), getattr(c, "data", b""))
        for c in (getattr(flow, "chunks", None) or [])
    }


def _strip_private_keys(item: dict) -> dict:
    """Copy of a parsed-message dict without the private ``_chunk_key`` tag."""
    return {k: v for k, v in item.items() if k != "_chunk_key"}


def scope_messages_to_flow(flow, messages) -> list:
    """Keep only the side-channel *messages* whose record landed in *flow*.

    Side-channel entries are accumulated per connection (cloud) or per chat
    (E2E), but the collector splits them into several exchange flows. A message
    is kept when its ``_chunk_key`` matches one of *flow*'s chunks. Messages from
    a path that never tagged keys (no dict has one) pass through unchanged.
    Returned dicts are copies with ``_chunk_key`` stripped, so it never reaches
    the .tap.
    """
    messages = list(messages or [])
    if not any("_chunk_key" in item for item in messages):
        return [_strip_private_keys(item) for item in messages]
    keys = _flow_chunk_keys(flow)
    return [
        _strip_private_keys(item) for item in messages
        if item.get("_chunk_key") in keys
    ]

# ---------------------------------------------------------------------------
# TLS single pass (decrypted application data via one `-T ek` run)
# ---------------------------------------------------------------------------

def tls_packet_to_events(
    pkt: dict,
    tracker: StreamDirectionTracker,
    result: ConvertResult | None = None,
) -> list[DatalogEvent]:
    """Translate one TLS `-T ek` packet dict into DatalogEvents.

    Mirrors :func:`~friTap.offline.pcap_to_tap._quic_packet_to_events` but for TLS-over-TCP: the decrypted
    application bytes arrive in ``data.data`` (the HTTP subdissectors are
    disabled in :func:`~friTap.offline.tshark.build_tls_command` so plaintext
    surfaces there). A single frame may carry several TLS records, so
    ``data.data`` can be a parallel list — we concatenate the records in order
    into one event, preserving per-direction byte order for the parsers. The
    stream is keyed by ``tcp.stream`` and direction comes from *tracker* (seeded
    with the TLS server ports), exactly as the follow path's direction did.
    """
    layers = pkt.get("layers") or {}

    timestamp = coerce_float(ek_first(ek_field(layers, "frame.time_epoch")))

    src_addr, dst_addr, ss_family = extract_addrs(layers)

    src_port = coerce_int(ek_first(ek_field(layers, "tcp.srcport")))
    dst_port = coerce_int(ek_first(ek_field(layers, "tcp.dstport")))
    stream_key = f"tcp:{ek_first(ek_field(layers, 'tcp.stream'))}"
    direction = tracker.direction_for(
        stream_key, src_addr, src_port, dst_addr, dst_port)

    # data.data may be a list (several TLS records in one frame); join in order.
    payloads = ek_as_list(ek_field(layers, "data.data"))
    data = b"".join(decode_hex(str(p)) for p in payloads)
    if not data:
        return []

    return [DatalogEvent(
        timestamp=timestamp,
        data=data,
        function="tshark_offline",
        direction=direction,
        src_addr=src_addr,
        src_port=src_port,
        dst_addr=dst_addr,
        dst_port=dst_port,
        ss_family=ss_family,
        ssl_session_id="",
        transport="tcp",
        stream_id=None,
    )]


def emit_tls_session_event(
    bus: EventBus,
    endpoints: tuple[str, int, str, int],
    meta: dict,
) -> None:
    """Emit a SESSION_STARTED carrying handshake metadata for one TLS stream.

    Emitted on the SAME bus and BEFORE the stream's DatalogEvents so the
    collector caches it (``_stamp_tls_metadata``) and backfills the flow's TLS
    layer when the data events create it. The ``connection_id`` is computed with
    ``protocol="tls"`` to match the key ``on_data`` derives for the offline
    DatalogEvents (which default to the "tls" protocol), i.e. the unscoped
    ``net:<4tuple>`` endpoint key.
    """
    c_addr, c_port, s_addr, s_port = endpoints
    if not c_addr and not s_addr:
        return  # no resolvable endpoints — nothing to key the metadata to
    conn_id = resolve_connection_key(
        c_addr, c_port, s_addr, s_port, protocol="tls")
    bus.emit(SessionEvent(
        event_type=SESSION_STARTED,
        connection_id=conn_id,
        server_name=meta.get("sni", ""),
        protocol_version=meta.get("version", ""),
        alpn=meta.get("alpn", ""),
        cipher_suite=meta.get("cipher", ""),
        src_addr=c_addr,
        src_port=c_port,
        dst_addr=s_addr,
        dst_port=s_port,
        protocol="tls",
    ))


@dataclass
class _AnnouncedStream:
    """A TLS stream whose first data event was emitted (its metadata was looked up).

    *emitted* is a snapshot of the metadata last sent as a SessionEvent
    (``None`` while none was sent), so a late handshake row re-announces only
    a real change.
    """

    tls_stream: int | None
    tcp_stream: int
    endpoints: tuple[str, int, str, int]
    emitted: dict | None = None


class TlsSinglePass:
    """Emit decrypted TLS application data from `-T ek` rows, one row at a time.

    The per-row core of the combined pass: :meth:`feed` folds the handshake
    rows into the metadata as they stream by and emits the app-data rows.

    Per stream the handshake-metadata :class:`SessionEvent` is emitted lazily,
    once, right before the stream's first DatalogEvent, so the collector caches
    it and stamps the flow's TLS layer when the data creates the flow. When a
    handshake row arrives AFTER that (metadata not known yet at the first data
    event, e.g. 0-RTT), the changed metadata is announced again; the collector
    fills only the still-empty fields.

    *packet_to_events* defaults to :func:`tls_packet_to_events`;
    *app_data_marker* is the field :meth:`feed` gates app data on.
    """

    def __init__(
        self,
        *,
        bus: EventBus,
        state: WriterState,
        result: ConvertResult,
        tracker: StreamDirectionTracker,
        app_data_marker: str = TLS_APP_DATA_COUNT_FIELD,
        packet_to_events: Callable[..., list[DatalogEvent]] | None = None,
    ) -> None:
        self._bus = bus
        self._state = state
        self._result = result
        self._tracker = tracker
        self._marker = app_data_marker
        self._packet_to_events = packet_to_events or tls_packet_to_events
        self._accumulator = TlsMetadataAccumulator()
        self._announced: dict[int, _AnnouncedStream] = {}
        self._announced_by_key: dict[int, list[_AnnouncedStream]] = {}
        self._tcp_streams: set[int] = set()

    @property
    def meta_by_stream(self) -> dict[int, dict]:
        """The folded handshake metadata per ``tls.stream`` (a copy)."""
        return self._accumulator.result()

    def feed(self, pkt: dict) -> None:
        """Consume one combined-pass row: handshake metadata first, then app data.

        The handshake goes first because one frame can carry both (e.g. a
        server's last handshake message and its first application data).
        Handshake rows never reach *packet_to_events*: it seeds the stream's
        direction, which a ServerHello must not do.
        """
        layers = pkt.get("layers") or {}
        if is_tls_handshake_row(layers):
            self._fold_handshake(layers)
        if is_tls_app_data_row(layers, self._marker):
            self.emit_app_data(pkt)

    def _fold_handshake(self, layers: dict) -> None:
        """Fold one handshake row; re-announce streams whose metadata changed."""
        try:
            key = self._accumulator.feed_ek(layers)
        except Exception:
            logger.debug("Skipping unparseable TLS handshake row", exc_info=True)
            return
        if key is None:
            return
        for announced in self._announced_by_key.get(key, ()):
            self._announce(announced)

    def emit_app_data(self, pkt: dict) -> None:
        """Translate one app-data row and emit its events (metadata event first)."""
        try:
            events = self._packet_to_events(pkt, self._tracker, self._result)
        except Exception:
            self._result.dropped_packet_count += 1
            logger.debug("Skipping unparseable TLS packet", exc_info=True)
            return
        if not events:
            return

        layers = pkt.get("layers") or {}
        tcp_stream = coerce_int(ek_first(ek_field(layers, "tcp.stream")), default=None)
        self._state.ensure_open()
        # Look the stream's metadata up ONCE, before its first data event. The
        # conn_id resolve_connection_key derives is perspective-independent for
        # the net: tier, so the raw packet endpoints key it identically to the
        # data events the collector sees.
        if tcp_stream is not None and tcp_stream not in self._announced:
            ev0 = events[0]
            self._first_sight(layers, tcp_stream,
                              (ev0.src_addr, ev0.src_port, ev0.dst_addr, ev0.dst_port))
        if tcp_stream is not None:
            self._tcp_streams.add(tcp_stream)
        for ev in events:
            self._result.decrypted_packet_count += 1
            record_tls_span(self._state.tls_spans, pkt, ev)
            self._bus.emit(ev)

    def _first_sight(self, layers: dict, tcp_stream: int, endpoints) -> None:
        """Record a newly seen stream and emit its metadata, if any is known."""
        tls_stream = coerce_int(ek_first(ek_field(layers, "tls.stream")), default=None)
        announced = _AnnouncedStream(tls_stream, tcp_stream, endpoints)
        self._announced[tcp_stream] = announced
        # Both keys _tls_meta_lookup may read, so a later handshake row on
        # either one re-checks this stream.
        for key in {tls_stream, tcp_stream} - {None}:
            self._announced_by_key.setdefault(key, []).append(announced)
        self._announce(announced)

    def _announce(self, announced: _AnnouncedStream) -> None:
        """Emit *announced*'s metadata when present and changed since the last emit."""
        meta = _tls_meta_lookup(self._accumulator.by_stream, announced.tls_stream,
                                announced.tcp_stream)
        if not meta or meta == announced.emitted:
            return
        announced.emitted = dict(meta)
        emit_tls_session_event(self._bus, announced.endpoints, meta)

    def finish(self) -> None:
        """Add the number of distinct TCP streams that carried data to ``stream_count``."""
        self._result.stream_count += len(self._tcp_streams)


def run_tls_combined_pass(
    tshark_bin: str,
    pcap_path: str,
    keylog_path: str | None,
    *,
    tls_ports: tuple[int, ...],
    extra_decode_as: tuple[str, ...],
    heuristic: bool,
    bus: EventBus,
    state: WriterState,
    result: ConvertResult,
    tracker: StreamDirectionTracker,
    packet_source: Callable[[list], Iterable[dict]] | None = None,
    packet_to_events: Callable[..., list[DatalogEvent]] | None = None,
    app_data_marker: str | None = None,
) -> dict[int, dict]:
    """Decrypt TLS with ONE tshark run: handshake metadata and app data together.

    The TLS-only form of the combined pass (:func:`~friTap.offline.tshark.
    build_combined_command` without the QUIC and SSH sections). Returns the
    final ``{tls_stream: metadata}``. *app_data_marker* defaults to the one
    for this tshark's version.
    """
    packet_source = packet_source or stream_packets
    marker = app_data_marker or tls_app_data_marker(tshark_version(tshark_bin))
    cmd = build_combined_command(
        pcap_path, keylog_path, tls_ports=tls_ports,
        extra_decode_as=extra_decode_as, heuristic=heuristic,
        include_quic=False, include_ssh=False, app_data_marker=marker)
    cmd[0] = tshark_bin

    tls = TlsSinglePass(bus=bus, state=state, result=result, tracker=tracker,
                        app_data_marker=marker, packet_to_events=packet_to_events)
    with _closing_packets(packet_source(cmd)) as packets:
        for pkt in packets:
            tls.feed(pkt)
    tls.finish()
    return tls.meta_by_stream


@contextlib.contextmanager
def _closing_packets(packets: Iterable[dict]):
    """Yield *packets*, then close them (when they can be) however the block exits.

    :func:`stream_packets` is a generator owning a tshark process; closing it
    terminates and reaps tshark at once when a consumer raises mid-iteration,
    instead of whenever the abandoned generator is garbage-collected. Plain
    iterables (test fakes) have no ``close`` and are yielded unchanged.
    """
    try:
        yield packets
    finally:
        close = getattr(packets, "close", None)
        if callable(close):
            close()


def _tls_meta_lookup(tls_meta_by_stream: dict, tls_stream, tcp_stream):
    """Metadata under *tls_stream* when present, else under *tcp_stream*.

    The handshake metadata is keyed by ``tls.stream``, which differs from
    ``tcp.stream`` whenever non-TLS TCP streams precede the TLS one;
    ``tcp.stream`` is the fallback for exports without ``tls.stream``.
    """
    if tls_stream is not None and tls_stream in tls_meta_by_stream:
        return tls_meta_by_stream[tls_stream]
    return tls_meta_by_stream.get(tcp_stream)