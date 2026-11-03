"""FlowCollector attribution fixes: orphan keying, HTTP/3 screening, protocol
labels on control flows and after parser recovery, and bounded state."""

import logging
import struct

import pytest

from friTap.events import DatalogEvent
from friTap.flow import collector as collector_mod
from friTap.flow.collector import FlowCollector
from friTap.flow.models import FlowEventType, FlowState
from friTap.parsers.base import MAX_PARSER_RESETS, BaseParser, ParseResult
from friTap.parsers.hexdump import HexdumpParser
from friTap.parsers.http3 import Http3Parser

DEVICE = ("10.0.0.1", 50914)
SERVER_A = ("157.240.27.37", 443)
SERVER_B = ("216.239.36.223", 443)


def _event(data: bytes, *, direction: str, server, client_random: str = "",
           ts: float = 1000.0, protocol: str = "tls", **kw) -> DatalogEvent:
    """A DatalogEvent between DEVICE and *server*, oriented by *direction*."""
    if direction == "read":
        src, dst = server, DEVICE
    else:
        src, dst = DEVICE, server
    ev = DatalogEvent(
        data=data, function="SSL_read" if direction == "read" else "SSL_write",
        direction=direction, src_addr=src[0], src_port=src[1],
        dst_addr=dst[0], dst_port=dst[1], client_random=client_random,
        timestamp=ts, **kw)
    ev.protocol = protocol
    return ev


HTTP1_REQUEST = b"GET / HTTP/1.1\r\nHost: example\r\n\r\n"
HTTP1_RESPONSE = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"


def _recording_collector():
    collector = FlowCollector()
    events: list = []
    collector.subscribe(lambda flow, event_type: events.append((event_type, flow)))
    return collector, events


# ---------------------------------------------------------------------------
# 1. Orphan requests are keyed by the server endpoint
# ---------------------------------------------------------------------------

class _MarkerParser(BaseParser):
    """``REQ`` bytes are a request, ``RSP`` bytes a response -- either direction.

    Lets a test produce a request from a READ (server-side capture shape),
    which is what registered orphans under the device's own address before.
    """

    PROTOCOL = "MARK/1"

    def __init__(self):
        self.trailing_data = None

    def feed(self, data, direction, stream_id=None):
        return [ParseResult(protocol=self.PROTOCOL,
                            is_request=data.startswith(b"REQ"),
                            is_complete=True)]

    def flush(self):
        return []

    def can_parse(self, data):
        return True

    def recognized_any(self):
        return True


@pytest.fixture
def marker_collector(monkeypatch):
    monkeypatch.setattr(FlowCollector, "_detect_parser",
                        lambda self, conn, data: _MarkerParser())
    return _recording_collector()[0]


class TestOrphanKeying:
    def test_orphan_key_is_remote_endpoint_for_both_directions(self):
        read = _event(b"x", direction="read", server=SERVER_A)
        write = _event(b"x", direction="write", server=SERVER_A)
        assert FlowCollector._orphan_key(read, "read") == "157.240.27.37:443"
        assert FlowCollector._orphan_key(write, "write") == "157.240.27.37:443"

    def test_response_from_other_server_on_shared_socket_does_not_match(
            self, marker_collector):
        """Server A's read must not attach to server B's leftover request,
        although both arrive on the device's single shared UDP socket."""
        collector = marker_collector
        # A request result produced by a READ from server B.
        collector.on_data(_event(b"REQ", direction="read",
                                 server=SERVER_B, client_random="bb" * 32))
        collector.on_data(_event(b"RSP", direction="read",
                                 server=SERVER_A, client_random="aa" * 32,
                                 ts=1000.1))
        flows = collector.get_flows()
        b_flow = next(f for f in flows if f.src_addr == SERVER_B[0])
        a_flow = next(f for f in flows if f.src_addr == SERVER_A[0])
        assert b_flow is not a_flow
        assert b_flow.request is not None and b_flow.response is None
        assert a_flow.response is not None and a_flow.request is None

    def test_response_from_same_server_still_matches_orphan(self, marker_collector):
        collector = marker_collector
        collector.on_data(_event(b"REQ", direction="read",
                                 server=SERVER_B, client_random="bb" * 32))
        # Same server, different connection key: the orphan index pairs them.
        collector.on_data(_event(b"RSP", direction="read",
                                 server=SERVER_B, client_random="cc" * 32,
                                 ts=1000.1))
        flows = collector.get_flows()
        assert len(flows) == 1
        assert flows[0].request is not None and flows[0].response is not None


# ---------------------------------------------------------------------------
# 1b. HTTP/3 detection is vetoed on unframeable (encrypted QUIC) bytes
# ---------------------------------------------------------------------------

# Looks like a 59-byte DATA frame, then a frame whose 8-byte varint length is
# far beyond any real HTTP/3 frame -- the shape of QUIC cipher-text.
CIPHER_LIKE = (b"\x00\x3b" + b"\x11" * 59
               + b"\x21" + b"\xc0\x00\x00\x00\x40\x00\x00\x00" + b"\x22" * 200)
PLAIN_H3_SETTINGS = b"\x04\x00"


class TestHttp3Screening:
    def test_cipher_like_bytes_are_vetoed_off_quic(self):
        assert Http3Parser().can_parse(CIPHER_LIKE)
        screened = FlowCollector._screen_h3_detection(
            Http3Parser(), CIPHER_LIKE, "tls")
        assert isinstance(screened, HexdumpParser)

    def test_plain_http3_detection_is_kept(self):
        detected = Http3Parser()
        assert FlowCollector._screen_h3_detection(
            detected, PLAIN_H3_SETTINGS, "tls") is detected

    def test_quic_transport_is_never_screened(self):
        detected = Http3Parser()
        assert FlowCollector._screen_h3_detection(
            detected, CIPHER_LIKE, "quic") is detected

    def test_encrypted_datagram_is_not_labelled_http3(self):
        collector, _ = _recording_collector()
        collector.on_data(_event(CIPHER_LIKE, direction="read", server=SERVER_B))
        collector.flush()
        (flow,) = collector.get_flows()
        assert flow.detected_protocol != "HTTP/3"
        assert flow.request is None


# ---------------------------------------------------------------------------
# 2. A control-only HTTP/2 connection keeps its protocol label
# ---------------------------------------------------------------------------

def _h2_goaway() -> bytes:
    payload = struct.pack(">II", 0, 0)
    return struct.pack(">I", len(payload))[1:] + bytes([0x7, 0]) + struct.pack(">I", 0) + payload


class TestControlFlowProtocolLabel:
    def test_goaway_only_connection_is_labelled_http2(self):
        collector, _ = _recording_collector()
        collector.on_data(_event(_h2_goaway(), direction="read", server=SERVER_A))
        collector.flush()
        (flow,) = collector.get_flows()
        assert flow.response is not None and flow.response.is_control_frame
        assert flow.detected_protocol == "HTTP/2"


# ---------------------------------------------------------------------------
# 3. Protocol label survives a recovered parser failure
# ---------------------------------------------------------------------------

class _FailOnceParser(BaseParser):
    """The first instance raises on feed; fresh instances parse fine."""

    PROTOCOL = "FAKE/1"
    instances = 0

    def __init__(self):
        type(self).instances += 1
        self._explode = type(self).instances == 1
        self._seen = False
        self.trailing_data = None

    def feed(self, data, direction, stream_id=None):
        if self._explode:
            raise RuntimeError("boom")
        self._seen = True
        return [ParseResult(protocol=self.PROTOCOL, is_request=direction == "write")]

    def flush(self):
        return []

    def can_parse(self, data):
        return True

    def recognized_any(self):
        return self._seen


class _AlwaysFailParser(_FailOnceParser):
    def __init__(self):
        super().__init__()
        self._explode = True


class TestProtocolLabelAfterRecovery:
    def _collector_with_parser(self, parser_cls):
        parser_cls.instances = 0
        collector, _ = _recording_collector()
        collector.on_data(_event(HTTP1_REQUEST, direction="write", server=SERVER_A))
        conn = next(iter(collector._connections.values()))
        flow = collector._flows[conn.active_flow_id]
        flow.detected_protocol = "HTTP/1.1"
        conn.parser = collector._wrap_parser(parser_cls(), conn)
        return collector, conn, flow

    def test_recovered_failure_keeps_label(self):
        collector, conn, flow = self._collector_with_parser(_FailOnceParser)
        collector.on_data(_event(b"more", direction="write", server=SERVER_A))
        assert conn.parser.reset_count == 1 and not conn.parser.disabled
        assert flow.detected_protocol == "HTTP/1.1"

    def test_disabling_failure_marks_unknown(self):
        collector, conn, flow = self._collector_with_parser(_AlwaysFailParser)
        for _ in range(MAX_PARSER_RESETS):
            collector.on_data(_event(b"more", direction="write", server=SERVER_A))
            assert flow.detected_protocol == "HTTP/1.1"
        collector.on_data(_event(b"more", direction="write", server=SERVER_A))
        assert conn.parser.disabled
        assert flow.detected_protocol == "unknown"


# ---------------------------------------------------------------------------
# 4. Bounded connection / orphan state
# ---------------------------------------------------------------------------

class TestBoundedState:
    def test_connection_id_flood_stays_bounded_and_emits_evicted_flows(self, caplog):
        collector, events = _recording_collector()
        # Event clock: the periodic sweep measures idleness on event time, so
        # only the cap (not the idle sweep) can retire these connections.
        collector.use_event_clock(True)
        total = 10_000
        with caplog.at_level(logging.WARNING, logger=collector_mod.logger.name):
            for i in range(total):
                collector.on_data(_event(
                    HTTP1_REQUEST, direction="write", server=SERVER_A,
                    client_random=f"{i:064x}", ts=1000.0 + i * 1e-4))
        stats = collector.memory_stats()
        assert stats["connection_count"] <= collector_mod.MAX_TRACKED_CONNECTIONS
        assert stats["orphan_request_count"] <= collector_mod.MAX_ORPHAN_REQUESTS
        assert collector._orphan_request_total == stats["orphan_request_count"]
        evicted = total - collector_mod.MAX_TRACKED_CONNECTIONS
        completed = [f for t, f in events if t == FlowEventType.COMPLETED]
        assert len(completed) == evicted
        assert all(f.state == FlowState.COMPLETE for f in completed)
        cap_warnings = [r for r in caplog.records if "evicting" in r.getMessage()]
        assert len(cap_warnings) == 2  # one per cap, not one per eviction

    def test_recently_used_connection_survives_eviction(self, monkeypatch):
        monkeypatch.setattr(collector_mod, "MAX_TRACKED_CONNECTIONS", 3)
        collector, _ = _recording_collector()
        for i in range(3):
            collector.on_data(_event(HTTP1_REQUEST, direction="write",
                                     server=SERVER_A, client_random=f"{i:064x}"))
        oldest = next(iter(collector._connections))
        # Touch the oldest, then add a new connection: the 2nd one goes.
        collector.on_data(_event(b"more", direction="write", server=SERVER_A,
                                 client_random=f"{0:064x}"))
        collector.on_data(_event(HTTP1_REQUEST, direction="write",
                                 server=SERVER_A, client_random=f"{9:064x}"))
        assert oldest in collector._connections
        assert len(collector._connections) == 3

    def test_orphan_cap_drops_oldest_index_entry_only(self, monkeypatch):
        monkeypatch.setattr(collector_mod, "MAX_ORPHAN_REQUESTS", 2)
        collector, _ = _recording_collector()
        for i, server in enumerate((SERVER_A, SERVER_B, ("1.2.3.4", 443))):
            collector.on_data(_event(HTTP1_REQUEST, direction="write",
                                     server=server, client_random=f"{i:064x}"))
        assert collector._orphan_request_total == 2
        assert "157.240.27.37:443" not in collector._orphan_requests
        assert len(collector.get_flows()) == 3  # the flow itself is kept

    def test_flush_and_clear_reset_orphan_total(self):
        collector, _ = _recording_collector()
        collector.on_data(_event(HTTP1_REQUEST, direction="write", server=SERVER_A))
        assert collector._orphan_request_total == 1
        collector.flush()
        assert collector._orphan_request_total == 0
        collector.on_data(_event(HTTP1_REQUEST, direction="write", server=SERVER_A,
                                 client_random="dd" * 32, ts=2000.0))
        collector.clear()
        assert collector._orphan_request_total == 0
        assert not collector._orphan_requests


@pytest.mark.parametrize("raw, expected", [
    (b"plain", "plain"),
    ("already-text", "already-text"),
    ("café".encode("utf-8"), "café"),
    (b"\xff\xfe", "\xff\xfe"),
])
def test_decode_header_text_public_helper(raw, expected):
    from friTap.parsers.http2 import Http2Parser, decode_header_text
    assert decode_header_text(raw) == expected
    assert Http2Parser._header_text(raw) == expected
