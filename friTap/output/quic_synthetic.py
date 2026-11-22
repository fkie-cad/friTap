"""Re-encapsulate captured QUIC plaintext into a synthetic QUIC connection.

friTap sees QUIC stream payloads after decryption, so there are no real
packets to put in a pcap. For each captured connection an in-memory aioquic
client/server pair carries the plaintext again; the datagrams they exchange
plus their NSS key log let Wireshark dissect the streams as HTTP/3.

aioquic is an optional dependency: everything imports it lazily and
``is_available()`` tells callers whether this module can do anything.
"""

from __future__ import annotations

import datetime
import io
import logging
import ssl
import threading
from dataclasses import dataclass, field
from typing import Any, Hashable, Optional, Sequence

from .bounded_lru import BoundedLRU

_logger = logging.getLogger("friTap.output.quic_synthetic")

CLIENT = "client"
SERVER = "server"
_DIRECTIONS = (CLIENT, SERVER)

CLIENT_ADDR = ("10.0.0.1", 50000)
SERVER_ADDR = ("10.0.0.2", 443)

DEFAULT_MAX_CONNECTIONS = 256
DEFAULT_MAX_BYTES_PER_CONNECTION = 64 * 1024 * 1024

# aioquic hardcodes 128 concurrent streams per type; browsers open far more
# over a connection's life. Peer-side implicit opening allocates one object
# per skipped id, so the limit also bounds memory for sparse ids.
MAX_STREAMS_PER_TYPE = 4096
# aioquic's own initial limit, in force when the limits cannot be raised.
AIOQUIC_DEFAULT_MAX_STREAMS = 128

# aioquic delays ACKs by max_ack_delay (25 ms); stepping past it makes the
# peers acknowledge immediately so no sent packet stays tracked for loss.
_ACK_FLUSH_STEP = 0.05
# Flushing per record doubles the exchanges and adds an ACK per record, so it
# is batched; a record whose data pacing or the congestion window held back
# flushes at once, so nothing waits for a later record.
_ACK_FLUSH_EVERY_RECORDS = 16
_MAX_PUMP_ROUNDS = 64

_H3_FRAME_DATA = 0x0
_H3_FRAME_HEADERS = 0x1


def is_available() -> bool:
    """Return True when aioquic and pylsqpack can be imported."""
    try:
        import aioquic.quic.connection  # noqa: F401
        import pylsqpack  # noqa: F401
    except ImportError:
        return False
    return True


@dataclass
class SyntheticOutput:
    """Datagrams that crossed the in-memory wire, plus new key log lines."""

    packets: list[tuple[str, bytes]] = field(default_factory=list)
    keylog_lines: list[str] = field(default_factory=list)

    def extend(self, other: "SyntheticOutput") -> None:
        self.packets.extend(other.packets)
        self.keylog_lines.extend(other.keylog_lines)


def encode_http3_frames(
    stream_id: int,
    headers: Optional[Sequence[Sequence[Any]]] = None,
    body: Optional[bytes] = None,
) -> bytes:
    """Build HTTP/3 HEADERS and/or DATA frames for one stream."""
    frames = b""
    if headers:
        frames += _http3_frame(_H3_FRAME_HEADERS, _qpack_header_block(stream_id, headers))
    if body:
        frames += _http3_frame(_H3_FRAME_DATA, bytes(body))
    return frames


def _http3_frame(frame_type: int, payload: bytes) -> bytes:
    from aioquic.buffer import encode_uint_var

    return encode_uint_var(frame_type) + encode_uint_var(len(payload)) + payload


def _qpack_header_block(stream_id: int, headers: Sequence[Sequence[Any]]) -> bytes:
    import pylsqpack

    # A fresh encoder has table capacity 0: static table and literals only,
    # so the block decodes without any encoder-stream state.
    _encoder_stream, block = pylsqpack.Encoder().encode(
        stream_id, [(_as_bytes(name), _as_bytes(value)) for name, value in headers]
    )
    return block


def _as_bytes(value: Any) -> bytes:
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    return str(value).encode("utf-8", "replace")


_cert_lock = threading.Lock()
_cert_cache: Optional[tuple[Any, Any]] = None


def _server_identity() -> tuple[Any, Any]:
    """Self-signed certificate shared by all synthetic servers in the process."""
    global _cert_cache
    with _cert_lock:
        if _cert_cache is None:
            _cert_cache = _generate_self_signed()
        return _cert_cache


def _generate_self_signed() -> tuple[Any, Any]:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "fritap-synthetic")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    return cert, key


class _KeylogBuffer(io.StringIO):
    """Text sink for aioquic's secrets log that hands out only new lines."""

    def __init__(self) -> None:
        super().__init__()
        self._consumed = 0

    def take_new_lines(self) -> list[str]:
        text = self.getvalue()
        end = text.rfind("\n") + 1
        fresh = text[self._consumed:end]
        self._consumed = end
        return [line for line in fresh.splitlines() if line]


def _configuration(is_client: bool, keylog: Optional[_KeylogBuffer], max_bytes: int):
    from aioquic.quic.configuration import QuicConfiguration

    config = QuicConfiguration(
        is_client=is_client,
        alpn_protocols=["h3"],
        secrets_log_file=keylog,
        max_data=max_bytes * 2,
        max_stream_data=max_bytes,
        # Capture timestamps can be minutes apart; never let a gap close it.
        idle_timeout=10 ** 9,
    )
    if is_client:
        config.verify_mode = ssl.CERT_NONE
        config.server_name = "fritap.synthetic"
    else:
        config.certificate, config.private_key = _server_identity()
    return config


def _raise_stream_limits(connection) -> int:
    """Raise the advertised stream limits; return the per-type limit in force."""
    # Must run before the handshake: the limits travel in transport params.
    limits = [getattr(connection, name, None)
              for name in ("_local_max_streams_bidi", "_local_max_streams_uni")]
    if not all(hasattr(limit, "value") and hasattr(limit, "sent") for limit in limits):
        # Private aioquic state changed: keep its default rather than guess.
        _logger.debug("synthetic QUIC: cannot raise aioquic stream limits; using %d",
                      AIOQUIC_DEFAULT_MAX_STREAMS)
        return AIOQUIC_DEFAULT_MAX_STREAMS
    for limit in limits:
        limit.value = limit.sent = MAX_STREAMS_PER_TYPE
    return MAX_STREAMS_PER_TYPE


def _can_open_peer_streams(sender, receiver) -> bool:
    """Whether the private aioquic hooks that open a stream silently exist."""
    return (callable(getattr(receiver, "_get_or_create_stream_for_send", None))
            and callable(getattr(sender, "_get_or_create_stream", None)))


def _known_streams(connection) -> dict:
    # Private aioquic state; an empty view only routes more ids to the open path.
    streams = getattr(connection, "_streams", None)
    return streams if isinstance(streams, dict) else {}


def _open_skipped_local_streams(connection, stream_id: int) -> None:
    """Create the unused local stream ids below *stream_id* before it is opened."""
    # aioquic counts every local id below its next id as opened, and one not in
    # _streams as finished; a lower id sent after a higher one would be refused.
    attr = "_local_next_stream_id_uni" if _is_unidirectional(stream_id) else "_local_next_stream_id_bidi"
    next_id = getattr(connection, attr, None)
    create = getattr(connection, "_get_or_create_stream_for_send", None)
    if not isinstance(next_id, int) or not callable(create):
        return
    for skipped in range(next_id, stream_id, 4):
        create(skipped)


def _has_unsent_stream_data(connection) -> bool:
    """Whether any stream still holds data aioquic has not put on the wire."""
    for stream in _known_streams(connection).values():
        pending = getattr(getattr(stream, "sender", None), "_pending", None)
        # Private aioquic state gone: assume unsent, flushing is merely slower.
        if pending is None or len(pending):
            return True
    return False


def _is_client_initiated(stream_id: int) -> bool:
    return stream_id & 0x1 == 0


def _is_unidirectional(stream_id: int) -> bool:
    return stream_id & 0x2 != 0


class _SyntheticConnection:
    """One aioquic client/server pair talking over an in-memory wire."""

    def __init__(self, max_bytes: int, now: float) -> None:
        from aioquic.quic.connection import QuicConnection

        self._max_bytes = max_bytes
        self._clock = now
        self.bytes_fed = 0
        self._keylog = _KeylogBuffer()
        self._unflushed_records = 0
        self._client = QuicConnection(configuration=_configuration(True, self._keylog, max_bytes))
        self._stream_limit = _raise_stream_limits(self._client)
        self._server = None

    def handshake(self, now: float) -> SyntheticOutput:
        self._client.connect(SERVER_ADDR, self._tick(now))
        return self._pump(flush_acks=True)

    def send(self, direction: str, stream_id: int, data: bytes, fin: bool, now: float) -> SyntheticOutput:
        self._tick(now)
        sender, receiver = self._endpoints(direction)
        if not self._can_send(sender, receiver, stream_id) or not self._write(sender, stream_id, data, fin):
            return SyntheticOutput(keylog_lines=self._keylog.take_new_lines())
        self.bytes_fed += len(data)
        self._unflushed_records += 1
        return self._pump(flush_acks=self._unflushed_records >= _ACK_FLUSH_EVERY_RECORDS)

    def close(self, now: float) -> SyntheticOutput:
        self._client.close(reason_phrase="capture ended")
        self._tick(now)
        return self._pump(flush_acks=True)

    def within_budget(self, extra: int) -> bool:
        return self.bytes_fed + extra <= self._max_bytes

    def _endpoints(self, direction: str):
        if direction == CLIENT:
            return self._client, self._server
        return self._server, self._client

    def _can_send(self, sender, receiver, stream_id: int) -> bool:
        if stream_id // 4 >= self._stream_limit:
            _logger.debug("synthetic QUIC: stream %d beyond limit, skipped", stream_id)
            return False
        is_client = sender.configuration.is_client
        if stream_id in _known_streams(sender):
            return True
        if _is_client_initiated(stream_id) == is_client:
            _open_skipped_local_streams(sender, stream_id)
            return True
        if _is_unidirectional(stream_id):
            _logger.debug("synthetic QUIC: cannot send on peer uni stream %d", stream_id)
            return False
        if not _can_open_peer_streams(sender, receiver):
            _logger.debug("synthetic QUIC: aioquic cannot open peer stream %d first; skipped", stream_id)
            return False
        self._open_peer_stream(sender, receiver, stream_id)
        return True

    @staticmethod
    def _write(sender, stream_id: int, data: bytes, fin: bool) -> bool:
        from aioquic.quic.exceptions import OutOfRangeError, StreamStateError, StreamTypeError

        try:
            sender.send_stream_data(stream_id, data, end_stream=fin)
        except (OutOfRangeError, StreamStateError, StreamTypeError) as exc:
            # e.g. data after FIN: one bad record must not cost the connection.
            _logger.debug("synthetic QUIC: stream %d record skipped: %s", stream_id, exc)
            return False
        return True

    @staticmethod
    def _open_peer_stream(sender, receiver, stream_id: int) -> None:
        # The response arrived before its request: open the stream on both
        # ends without emitting bytes, since an empty STREAM frame is never sent.
        from aioquic.quic.packet import QuicFrameType

        _open_skipped_local_streams(receiver, stream_id)
        receiver._get_or_create_stream_for_send(stream_id)
        sender._get_or_create_stream(QuicFrameType.STREAM_BASE, stream_id)

    def _tick(self, now: float) -> float:
        self._clock = max(self._clock, float(now))
        return self._clock

    def _pump(self, flush_acks: bool = False) -> SyntheticOutput:
        packets: list[tuple[str, bytes]] = []
        self._exchange(packets)
        if flush_acks or self._sending_stalled():
            self._flush_acks(packets)
        return SyntheticOutput(packets=packets, keylog_lines=self._keylog.take_new_lines())

    def _flush_acks(self, packets: list[tuple[str, bytes]]) -> None:
        # Each step releases the delayed ACKs, which may unblock more data
        # held back by the congestion window: repeat until the wire is quiet.
        self._unflushed_records = 0
        for _ in range(_MAX_PUMP_ROUNDS):
            self._clock += _ACK_FLUSH_STEP
            if not self._exchange(packets):
                return

    def _sending_stalled(self) -> bool:
        return any(connection is not None and _has_unsent_stream_data(connection)
                   for connection in (self._client, self._server))

    def _exchange(self, packets: list[tuple[str, bytes]]) -> int:
        total = 0
        for _ in range(_MAX_PUMP_ROUNDS):
            moved = self._transmit(CLIENT, packets) + self._transmit(SERVER, packets)
            if not moved:
                break
            total += moved
        return total

    def _transmit(self, direction: str, packets: list[tuple[str, bytes]]) -> int:
        sender, _receiver = self._endpoints(direction)
        if sender is None:
            return 0
        datagrams = [data for data, _addr in sender.datagrams_to_send(self._clock)]
        for data in datagrams:
            packets.append((direction, data))
            self._deliver(direction, data)
        self._discard_events()
        return len(datagrams)

    def _deliver(self, direction: str, data: bytes) -> None:
        if direction == CLIENT:
            if self._server is None:
                self._server = self._accept(data)
            self._server.receive_datagram(data, CLIENT_ADDR, self._clock)
        else:
            self._client.receive_datagram(data, SERVER_ADDR, self._clock)

    def _accept(self, first_datagram: bytes):
        from aioquic.buffer import Buffer
        from aioquic.quic.connection import QuicConnection
        from aioquic.quic.packet import pull_quic_header

        # The client's key log already holds every secret of the connection.
        config = _configuration(False, None, self._max_bytes)
        header = pull_quic_header(Buffer(data=first_datagram), host_cid_length=config.connection_id_length)
        server = QuicConnection(
            configuration=config, original_destination_connection_id=header.destination_cid
        )
        # Both peers advertise the same limit (both use the same aioquic).
        self._stream_limit = min(self._stream_limit, _raise_stream_limits(server))
        return server

    def _discard_events(self) -> None:
        # Events carry the received stream data; nobody reads them here.
        for connection in (self._client, self._server):
            while connection is not None and connection.next_event() is not None:
                pass


class SyntheticQuicWriter:
    """Maps captured QUIC connections onto synthetic aioquic connections.

    Never raises into callers: a failing connection is dropped and further
    records for it start a fresh synthetic connection.
    """

    def __init__(
        self,
        max_connections: int = DEFAULT_MAX_CONNECTIONS,
        max_bytes_per_connection: int = DEFAULT_MAX_BYTES_PER_CONNECTION,
    ) -> None:
        self._max_connections = max(1, int(max_connections))
        self._max_bytes = max(1, int(max_bytes_per_connection))
        self._connections: "BoundedLRU[Hashable, _SyntheticConnection]" = BoundedLRU(self._max_connections)
        # Keys only (values unused): bounded so a long capture cannot grow them.
        self._over_budget: "BoundedLRU[Hashable, None]" = BoundedLRU(self._max_connections * 4)
        self._failed_logged: "BoundedLRU[Hashable, None]" = BoundedLRU(self._max_connections * 4)
        # Resolved once: the import probe is too costly to repeat per record.
        self._available = is_available()
        self._lock = threading.Lock()

    @property
    def max_connections(self) -> int:
        """How many synthetic connections stay open before the oldest is evicted."""
        return self._max_connections

    def __len__(self) -> int:
        return len(self._connections)

    def __contains__(self, conn_key: Hashable) -> bool:
        return conn_key in self._connections

    def feed_stream(
        self,
        conn_key: Hashable,
        direction: str,
        stream_id: int,
        data: bytes,
        fin: bool = False,
        now: float = 0.0,
    ) -> SyntheticOutput:
        """Carry one captured stream chunk; return the resulting datagrams."""
        if direction not in _DIRECTIONS or not self._available:
            return SyntheticOutput()
        payload = data if isinstance(data, bytes) else bytes(data)
        with self._lock:
            return self._guarded(conn_key, self._feed, conn_key, direction, int(stream_id), payload, fin, now)

    def feed_headers_body(
        self,
        conn_key: Hashable,
        direction: str,
        stream_id: int,
        http3_headers: Optional[Sequence[Sequence[Any]]] = None,
        body: Optional[bytes] = None,
        fin: bool = False,
        now: float = 0.0,
    ) -> SyntheticOutput:
        """Re-frame decoded headers/body as HTTP/3 and carry them on the stream."""
        if not (http3_headers or body) or not self._available:
            return SyntheticOutput()
        try:
            data = encode_http3_frames(int(stream_id), http3_headers, body)
        except Exception as exc:
            _logger.debug("synthetic QUIC: cannot encode HTTP/3 frames: %s", exc)
            return SyntheticOutput()
        return self.feed_stream(conn_key, direction, stream_id, data, fin, now)

    def close(self, conn_key: Hashable, now: float = 0.0) -> SyntheticOutput:
        """Emit a CONNECTION_CLOSE for the connection and forget it."""
        with self._lock:
            self._over_budget.pop(conn_key)
            connection = self._connections.pop(conn_key, None)
            if connection is None:
                return SyntheticOutput()
            return self._guarded(conn_key, connection.close, now)

    def _feed(self, conn_key, direction, stream_id, data, fin, now) -> SyntheticOutput:
        if conn_key in self._over_budget:
            return SyntheticOutput()
        output = SyntheticOutput()
        connection = self._connections.get(conn_key)
        if connection is None:
            connection, output = self._open(conn_key, now)
        if not connection.within_budget(len(data)):
            self._mark_over_budget(conn_key)
            return output
        output.extend(connection.send(direction, stream_id, data, fin, now))
        return output

    def _open(self, conn_key, now) -> tuple[_SyntheticConnection, SyntheticOutput]:
        connection = _SyntheticConnection(self._max_bytes, now)
        for evicted, _connection in self._connections.put(conn_key, connection):
            _logger.debug("synthetic QUIC: evicted connection %r", evicted)
        return connection, connection.handshake(now)

    def _mark_over_budget(self, conn_key) -> None:
        _logger.warning(
            "synthetic QUIC: connection %r exceeded %d bytes; further data is not re-encapsulated",
            conn_key, self._max_bytes,
        )
        self._connections.pop(conn_key, None)
        self._over_budget.put(conn_key, None)

    def _guarded(self, conn_key, action, *args) -> SyntheticOutput:
        try:
            return action(*args)
        except Exception as exc:
            self._connections.pop(conn_key, None)
            self._log_failure_once(conn_key, exc)
            return SyntheticOutput()

    def _log_failure_once(self, conn_key, exc: Exception) -> None:
        if conn_key in self._failed_logged:
            _logger.debug("synthetic QUIC: connection %r failed again: %s", conn_key, exc)
            return
        self._failed_logged.put(conn_key, None)
        _logger.warning("synthetic QUIC: dropping connection %r after error: %s", conn_key, exc)
