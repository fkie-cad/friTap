"""HTTP/2 frame-exact flow attribution (Http2StreamFlowMixin).

A decrypted TLS record is not an HTTP/2 unit: records carry frames of several
multiplexed streams and frames span records. Each stream's flow must end up
with exactly its own frames (frame-aligned), so its body reconstructs and
decompresses intact, whatever the record boundaries are.
"""

from __future__ import annotations

import gzip
import random
import struct
from types import SimpleNamespace

import pytest

pytest.importorskip("hpack")

from hpack import Encoder  # noqa: E402

from friTap.events import DatalogEvent  # noqa: E402
from friTap.flow.collector import IDLE_THRESHOLD, FlowCollector  # noqa: E402
from friTap.flow.models import FlowEventType, FlowState  # noqa: E402
from friTap.parsers.http2 import _CONNECTION_PREFACE  # noqa: E402
from friTap.parsers.http2_dataframe import _walk_data_frames  # noqa: E402

_DATA, _HEADERS, _RST_STREAM, _SETTINGS, _WINDOW_UPDATE, _CONTINUATION = (
    0x0, 0x1, 0x3, 0x4, 0x8, 0x9)
_CANCEL = 0x8
_END_STREAM, _ACK, _END_HEADERS, _PADDED = 0x1, 0x1, 0x4, 0x8
_DATA_FRAME_LEN = 4096


# ---------------------------------------------------------------------------
# Wire builders
# ---------------------------------------------------------------------------

def _frame(ftype: int, flags: int, stream_id: int, payload: bytes = b"") -> bytes:
    return (struct.pack("!I", len(payload))[1:] + bytes([ftype, flags])
            + struct.pack("!I", stream_id) + payload)


def _settings(ack: bool = False) -> bytes:
    return _frame(_SETTINGS, _ACK if ack else 0, 0, b"" if ack else struct.pack("!HI", 0x3, 100))


def _window_update(stream_id: int = 0) -> bytes:
    return _frame(_WINDOW_UPDATE, 0, stream_id, struct.pack("!I", 65535))


def _padded(payload: bytes, pad: int) -> bytes:
    return bytes([pad]) + payload + b"\x00" * pad


def _data_frames(stream_id: int, body: bytes, pad: int = 0) -> list[bytes]:
    """*body* as DATA frames (optionally PADDED); END_STREAM on the last one."""
    pieces = [body[i:i + _DATA_FRAME_LEN] for i in range(0, len(body), _DATA_FRAME_LEN)]
    frames = []
    for index, piece in enumerate(pieces):
        flags = _END_STREAM if index == len(pieces) - 1 else 0
        payload = piece
        if pad:
            flags |= _PADDED
            payload = _padded(piece, pad)
        frames.append(_frame(_DATA, flags, stream_id, payload))
    return frames


def _request_headers(encoder: Encoder, stream_id: int, path: str,
                     method: str = "GET", end_stream: bool = True) -> bytes:
    block = encoder.encode([(":method", method), (":scheme", "https"),
                            (":authority", "example.com"), (":path", path)])
    flags = _END_HEADERS | (_END_STREAM if end_stream else 0)
    return _frame(_HEADERS, flags, stream_id, block)


def _response_headers(encoder: Encoder, stream_id: int, encoding: str) -> bytes:
    return _frame(_HEADERS, _END_HEADERS, stream_id, encoder.encode(
        [(":status", "200"), ("content-encoding", encoding)]))


def _split_response_headers(encoder: Encoder, stream_id: int, encoding: str) -> list[bytes]:
    """PADDED HEADERS without END_HEADERS, completed by a CONTINUATION."""
    block = encoder.encode([(":status", "200"), ("content-encoding", encoding),
                            ("x-filler", "f" * 300)])
    half = len(block) // 2
    return [_frame(_HEADERS, _PADDED, stream_id, _padded(block[:half], 7)),
            _frame(_CONTINUATION, _END_HEADERS, stream_id, block[half:])]


def _interleave(*frame_lists: list[bytes]) -> list[bytes]:
    """Round-robin the frames of several streams (multiplexed wire order)."""
    out, queues = [], [list(frames) for frames in frame_lists]
    while any(queues):
        for queue in queues:
            if queue:
                out.append(queue.pop(0))
    return out


def _body(seed: int, size: int) -> bytes:
    rng = random.Random(seed)
    words = [b"alpha", b"bravo", b"charlie", b"delta", b"echo", b"foxtrot"]
    return b" ".join(rng.choice(words) + str(rng.randrange(10**6)).encode()
                     for _ in range(size // 8))[:size]


def _brotli_or_gzip(data: bytes) -> tuple[str, bytes]:
    try:
        import brotli
    except ImportError:
        return "gzip", gzip.compress(data)
    return "br", brotli.compress(data)


def _connection():
    """A multiplexed connection: three GETs, interleaved compressed responses.

    Stream 5's response headers are PADDED and continued in a CONTINUATION,
    its DATA frames PADDED.
    """
    bodies = {1: _body(1, 60000), 3: _body(3, 45000), 5: _body(5, 20000)}
    encodings = {1: ("gzip", gzip.compress(bodies[1])),
                 3: _brotli_or_gzip(bodies[3]),
                 5: ("gzip", gzip.compress(bodies[5]))}
    client_enc, server_enc = Encoder(), Encoder()
    client = (_CONNECTION_PREFACE + _settings() + _window_update()
              + _request_headers(client_enc, 1, "/one")
              + _request_headers(client_enc, 3, "/three")
              + _request_headers(client_enc, 5, "/five"))
    frames = [_settings(), _settings(ack=True),
              _response_headers(server_enc, 1, encodings[1][0]),
              _response_headers(server_enc, 3, encodings[3][0]),
              *_split_response_headers(server_enc, 5, encodings[5][0])]
    frames += _interleave(_data_frames(1, encodings[1][1]),
                          _data_frames(3, encodings[3][1]),
                          _data_frames(5, encodings[5][1], pad=5))
    frames.insert(9, _window_update())  # a connection-level frame mid-body
    server = b"".join(frames)
    return SimpleNamespace(client=client, server=server, frames=frames,
                           bodies=bodies, paths={1: "/one", 3: "/three", 5: "/five"})


# ---------------------------------------------------------------------------
# Record splitting / feeding
# ---------------------------------------------------------------------------

def _frame_starts(frames: list[bytes]) -> list[int]:
    starts, offset = [], 0
    for frame in frames:
        starts.append(offset)
        offset += len(frame)
    return starts


def _records(data: bytes, cuts) -> list[bytes]:
    bounds = [0, *sorted({c for c in cuts if 0 < c < len(data)}), len(data)]
    return [data[a:b] for a, b in zip(bounds, bounds[1:])]


def _tricky_cuts(conn) -> list[int]:
    """Record boundaries mid-frame-header, mid-payload and at TLS record size."""
    starts = _frame_starts(conn.frames)
    mid_header = [starts[i] + 4 for i in (3, 6, 10)]
    mid_payload = [starts[i] + 1000 for i in (8, 12)]
    return mid_header + mid_payload + list(range(1369, len(conn.server), 1369))


def _event(data: bytes, direction: str, ts: float) -> DatalogEvent:
    return DatalogEvent(
        timestamp=ts, data=data, direction=direction,
        function="SSL_read" if direction == "read" else "SSL_write",
        src_addr="10.0.0.2", src_port=40000, dst_addr="93.184.216.34", dst_port=443,
        ssl_session_id="h2-session",
    )


def _feed(collector: FlowCollector, client_records, server_records) -> FlowCollector:
    ts = 1.0
    for record in client_records:
        collector.on_data(_event(record, "write", ts))
        ts += 0.001
    for record in server_records:
        collector.on_data(_event(record, "read", ts))
        ts += 0.001
    collector.flush()
    return collector


def _flows_by_path(collector: FlowCollector) -> dict:
    return {f.request.url: f for f in collector.get_flows()
            if f.request is not None and not f.request.is_control_frame}


def _assert_bodies_intact(collector: FlowCollector, conn) -> None:
    flows = _flows_by_path(collector)
    for sid, path in conn.paths.items():
        flow = flows[path]
        assert flow.response is not None and flow.response.stream_id == sid
        assert flow.get_decompressed_response_body() == conn.bodies[sid], path


def _assert_frame_aligned(collector: FlowCollector) -> None:
    for flow in collector.get_flows():
        for direction in ("read", "write"):
            data = flow.get_direction_bytes(direction)
            degraded = _walk_data_frames(data, lambda *a: None, skip_unknown_types=True)
            assert not data or not degraded, (flow.flow_id, direction)


def _direction_total(collector: FlowCollector, direction: str) -> int:
    return sum(len(f.get_direction_bytes(direction)) for f in collector.get_flows())


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_interleaved_streams_spanning_records_keep_full_bodies():
    conn = _connection()
    cuts = _tricky_cuts(conn)
    collector = _feed(FlowCollector(), [conn.client], _records(conn.server, cuts))
    _assert_bodies_intact(collector, conn)
    _assert_frame_aligned(collector)


def test_records_start_mid_header_and_mid_payload():
    """Guard the fixture: the split really exercises both hard cases."""
    conn = _connection()
    starts = set(_frame_starts(conn.frames))
    header_spans = {s + k for s in starts for k in range(1, 9)}
    record_starts = _frame_starts(_records(conn.server, _tricky_cuts(conn)))
    assert any(r in header_spans for r in record_starts)
    assert any(r not in starts and r not in header_spans for r in record_starts)


@pytest.mark.parametrize("seed", range(12))
def test_random_record_boundaries_keep_full_bodies(seed):
    conn = _connection()
    rng = random.Random(seed)
    cuts, pos = [], 0
    while pos < len(conn.server):
        pos += rng.randint(1, 3000)
        cuts.append(pos)
    # Clients write the preface + SETTINGS as one record (protocol detection
    # needs it); the request HEADERS after it are split anywhere.
    opening = len(_CONNECTION_PREFACE + _settings())
    client_cuts = [opening] + [rng.randint(opening, len(conn.client) - 1) for _ in range(3)]
    collector = _feed(FlowCollector(), _records(conn.client, client_cuts),
                      _records(conn.server, cuts))
    _assert_bodies_intact(collector, conn)
    _assert_frame_aligned(collector)


def test_every_byte_lands_in_exactly_one_flow():
    conn = _connection()
    collector = _feed(FlowCollector(), [conn.client], _records(conn.server, _tricky_cuts(conn)))
    assert _direction_total(collector, "read") == len(conn.server)
    assert _direction_total(collector, "write") == len(conn.client)


def test_each_flow_holds_only_its_own_stream_frames():
    conn = _connection()
    collector = _feed(FlowCollector(), [conn.client], _records(conn.server, _tricky_cuts(conn)))
    for path, flow in _flows_by_path(collector).items():
        sids = set()

        def collect(sid, _payload, _end, sids=sids):
            sids.add(sid)

        _walk_data_frames(flow.get_direction_bytes("read"), collect)
        assert sids == {flow.response.stream_id}, path


def test_server_settings_do_not_complete_first_request():
    """The server's SETTINGS used to become the first request's "response"."""
    conn = _connection()
    collector = FlowCollector()
    collector.on_data(_event(conn.client, "write", 1.0))
    collector.on_data(_event(_settings(), "read", 1.1))
    requests = _flows_by_path(collector)
    assert all(f.state == FlowState.ACTIVE and f.response is None
               for f in requests.values())
    control = [f for f in collector.get_flows()
               if f.response is not None and f.response.is_control_frame]
    assert len(control) == 1 and control[0].request is None


def test_headers_and_data_in_one_record_attached_once():
    encoder, server_enc = Encoder(), Encoder()
    client = _CONNECTION_PREFACE + _settings() + _request_headers(encoder, 1, "/x")
    body = b"hello world"
    record = (_response_headers(server_enc, 1, "identity")
              + _frame(_DATA, _END_STREAM, 1, body))
    collector = _feed(FlowCollector(), [client], [record])
    flow = _flows_by_path(collector)["/x"]
    assert flow.get_direction_bytes("read") == record
    assert flow.response_body == body


def test_request_body_spanning_records_reaches_request_flow():
    encoder = Encoder()
    payload = gzip.compress(_body(9, 30000))
    wire = (_CONNECTION_PREFACE + _settings()
            + _request_headers(encoder, 1, "/upload", "POST", end_stream=False)
            + b"".join(_data_frames(1, payload)))
    collector = _feed(FlowCollector(), _records(wire, range(700, len(wire), 700)), [])
    flow = _flows_by_path(collector)["/upload"]
    assert flow.request_body == payload


def test_hidden_control_frames_drop_connection_only_records():
    conn = _connection()
    control = [_settings(), _settings(ack=True)]
    rest = conn.server[len(b"".join(control)):]
    assert conn.server.startswith(b"".join(control))
    collector = FlowCollector(show_control_frames=False)
    _feed(collector, [conn.client], control + _records(rest, range(1369, len(rest), 1369)))
    _assert_bodies_intact(collector, conn)
    # The control-only records are dropped; the mid-body WINDOW_UPDATE rides
    # with stream frames unless its record completes no other frame.
    assert _direction_total(collector, "read") in (len(rest), len(rest) - len(_window_update()))


def test_truncated_last_frame_is_kept_at_flush():
    encoder, server_enc = Encoder(), Encoder()
    client = _CONNECTION_PREFACE + _settings() + _request_headers(encoder, 1, "/cut")
    complete = _response_headers(server_enc, 1, "identity") + _frame(_DATA, 0, 1, b"a" * 100)
    truncated = _frame(_DATA, _END_STREAM, 1, b"b" * 100)[:50]
    collector = _feed(FlowCollector(), [client], [complete, truncated])
    flow = _flows_by_path(collector)["/cut"]
    assert flow.get_direction_bytes("read") == complete + truncated
    assert flow.response_body == b"a" * 100


def test_unknown_stream_frames_stay_together():
    """DATA of a stream whose HEADERS predate the capture keeps one flow."""
    collector = FlowCollector()
    frames = [_frame(_DATA, 0, 7, b"x" * 3000), _frame(_DATA, 0, 7, b"y" * 3000)]
    wire = b"".join(frames)
    for index, record in enumerate(_records(wire, [1000, 4000])):
        collector.on_data(_event(record, "read", 1.0 + index))
    holders = [f for f in collector.get_flows() if f.get_direction_bytes("read")]
    assert len(holders) == 1 and holders[0].get_direction_bytes("read") == wire


# ---------------------------------------------------------------------------
# Late frames of completed streams / protocol labels
# ---------------------------------------------------------------------------

class _EmittedSnapshots:
    """What a writer (TapWriter, live sinks) persists: each flow at COMPLETED."""

    def __init__(self, collector: FlowCollector) -> None:
        self.flows: dict = {}
        collector.subscribe(self._on_event)

    def _on_event(self, flow, event_type) -> None:
        if event_type == FlowEventType.COMPLETED:
            self.flows[flow.flow_id] = SimpleNamespace(
                flow=flow, detected_protocol=flow.detected_protocol,
                read=flow.get_direction_bytes("read"),
                write=flow.get_direction_bytes("write"))

    def total(self, direction: str) -> int:
        return sum(len(getattr(snap, direction)) for snap in self.flows.values())

    def holders(self, frame: bytes, direction: str) -> list:
        return [snap for snap in self.flows.values() if frame in getattr(snap, direction)]


def _rst_stream(stream_id: int, error_code: int = _CANCEL) -> bytes:
    return _frame(_RST_STREAM, 0, stream_id, struct.pack("!I", error_code))


def _finished_exchange():
    """One GET whose response ends with END_STREAM, plus the client's late
    RST_STREAM (CANCEL) and WINDOW_UPDATE for the finished stream."""
    encoder, server_enc = Encoder(), Encoder()
    client = _CONNECTION_PREFACE + _settings() + _request_headers(encoder, 1, "/done")
    server = (_response_headers(server_enc, 1, "identity")
              + _frame(_DATA, _END_STREAM, 1, b"body"))
    return SimpleNamespace(client=client, server=server,
                           late=[_rst_stream(1), _window_update(1)])


def _feed_finished_exchange(collector: FlowCollector, conn) -> None:
    collector.on_data(_event(conn.client, "write", 1.0))
    collector.on_data(_event(conn.server, "read", 1.1))
    for offset, frame in enumerate(conn.late):
        collector.on_data(_event(frame, "write", 1.2 + offset / 10))


def test_late_rst_after_end_stream_lands_in_emitted_control_flow():
    conn = _finished_exchange()
    collector = FlowCollector()
    emitted = _EmittedSnapshots(collector)
    collector.on_data(_event(conn.client, "write", 1.0))
    collector.on_data(_event(conn.server, "read", 1.1))
    stream_flow = _flows_by_path(collector)["/done"]
    assert stream_flow.state == FlowState.COMPLETE
    assert stream_flow.flow_id in emitted.flows  # already handed to the writers

    for offset, frame in enumerate(conn.late):
        collector.on_data(_event(frame, "write", 1.2 + offset / 10))
    collector.flush()

    for frame in conn.late:
        holders = emitted.holders(frame, "write")
        assert len(holders) == 1, frame
        assert holders[0].flow.flow_id != stream_flow.flow_id
        assert holders[0].detected_protocol == "HTTP/2"
    assert stream_flow.get_direction_bytes("write") == emitted.flows[stream_flow.flow_id].write
    assert emitted.total("write") == len(conn.client) + len(b"".join(conn.late))
    assert emitted.total("read") == len(conn.server)


def test_late_frames_are_emitted_at_idle_finalize_before_flush():
    conn = _finished_exchange()
    collector = FlowCollector()
    emitted = _EmittedSnapshots(collector)
    _feed_finished_exchange(collector, conn)
    resumed = 1.5 + IDLE_THRESHOLD + 1
    collector.on_data(_event(_settings(), "write", resumed))  # idle gap -> finalize

    assert [len(emitted.holders(f, "write")) for f in conn.late] == [1, 1]


def test_late_frames_dropped_while_control_frames_hidden():
    conn = _finished_exchange()
    collector = FlowCollector(show_control_frames=False)
    emitted = _EmittedSnapshots(collector)
    _feed_finished_exchange(collector, conn)
    collector.flush()

    assert all(not emitted.holders(f, "write") for f in conn.late)
    assert emitted.total("write") == len(conn.client)


def test_every_h2_stream_and_control_flow_is_labelled():
    conn = _connection()
    collector = FlowCollector()
    emitted = _EmittedSnapshots(collector)
    # One record per server frame: SETTINGS and its ACK each answer a control
    # flow, so the connection carries several control and stream flows.
    _feed(collector, [conn.client], _records(conn.server, _frame_starts(conn.frames)))

    flows = collector.get_flows()
    controls = [f for f in flows if f.request is None or f.request.is_control_frame]
    assert len(controls) >= 2 and len(flows) > len(controls)
    assert {f.detected_protocol for f in flows} == {"HTTP/2"}
    assert {snap.detected_protocol for snap in emitted.flows.values()} == {"HTTP/2"}


def test_existing_detected_protocol_is_not_overwritten():
    conn = _finished_exchange()
    collector = FlowCollector()
    collector.on_data(_event(conn.client, "write", 1.0))
    flow = _flows_by_path(collector)["/done"]
    flow.detected_protocol = "gRPC"
    collector.on_data(_event(conn.server, "read", 1.1))

    assert flow.detected_protocol == "gRPC"


def _pinned_stream_exchange():
    """GET /req on stream 1; DATA of stream 7 (HEADERS before the capture)
    pinned to that flow, which completes with stream 1's END_STREAM; then two
    more DATA frames of stream 7 arrive late."""
    encoder, server_enc = Encoder(), Encoder()
    client = _CONNECTION_PREFACE + _settings() + _request_headers(encoder, 1, "/req")
    server = [_frame(_DATA, 0, 7, b"early"),
              _response_headers(server_enc, 1, "identity")
              + _frame(_DATA, _END_STREAM, 1, b"done")]
    late = [_frame(_DATA, 0, 7, b"late-1"), _frame(_DATA, 0, 7, b"late-2")]
    return SimpleNamespace(client=client, server=server, late=late)


def _feed_pinned(collector: FlowCollector, conn) -> None:
    collector.on_data(_event(conn.client, "write", 1.0))
    for offset, record in enumerate(conn.server + conn.late):
        collector.on_data(_event(record, "read", 1.1 + offset / 10))


def test_late_stream_data_opens_fresh_flow_that_later_frames_join():
    conn = _pinned_stream_exchange()
    collector = FlowCollector()
    emitted = _EmittedSnapshots(collector)
    _feed_pinned(collector, conn)
    late_rst = _rst_stream(1)  # control-type: the control flow, not the fresh one
    collector.on_data(_event(late_rst, "write", 2.0))
    collector.flush()

    request_flow = _flows_by_path(collector)["/req"]
    first, second = (emitted.holders(f, "read") for f in conn.late)
    assert len(first) == 1 and first == second
    fresh = first[0]
    assert fresh.flow.flow_id != request_flow.flow_id
    (control,) = emitted.holders(late_rst, "write")
    assert control.flow.flow_id != fresh.flow.flow_id
    assert fresh.read == b"".join(conn.late) and fresh.detected_protocol == "HTTP/2"
    assert emitted.total("read") == len(b"".join(conn.server + conn.late))
    assert emitted.total("write") == len(conn.client) + len(late_rst)


def test_late_stream_flow_is_emitted_at_idle_finalize_before_flush():
    conn = _pinned_stream_exchange()
    collector = FlowCollector()
    emitted = _EmittedSnapshots(collector)
    _feed_pinned(collector, conn)
    collector.on_data(_event(_settings(), "write", 2.0 + IDLE_THRESHOLD))

    assert [len(emitted.holders(f, "read")) for f in conn.late] == [1, 1]


def test_late_stream_data_kept_while_control_frames_hidden():
    conn = _pinned_stream_exchange()
    collector = FlowCollector(show_control_frames=False)
    emitted = _EmittedSnapshots(collector)
    _feed_pinned(collector, conn)
    collector.flush()

    assert emitted.total("read") == len(b"".join(conn.server + conn.late))


def test_truncated_leftover_after_completion_lands_in_emitted_flow():
    conn = _finished_exchange()
    truncated = _frame(_DATA, _END_STREAM, 1, b"t" * 100)[:50]
    collector = FlowCollector()
    emitted = _EmittedSnapshots(collector)
    collector.on_data(_event(conn.client, "write", 1.0))
    collector.on_data(_event(conn.server, "read", 1.1))
    collector.on_data(_event(truncated, "read", 1.2))
    collector.flush()

    holders = emitted.holders(truncated, "read")
    assert len(holders) == 1 and holders[0].detected_protocol == "HTTP/2"
    assert holders[0].flow.flow_id != _flows_by_path(collector)["/done"].flow_id
    assert emitted.total("read") == len(conn.server) + len(truncated)
