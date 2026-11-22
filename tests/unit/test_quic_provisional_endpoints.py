#!/usr/bin/env python3

"""QUIC records whose tuple the agent had to guess (Chrome 0-RTT: first write
before any peer is readable) are flagged synthetic, upgraded to the
connection's real tuple once a later record carries it, and kept out of the
``-p`` pcap as a separate fake UDP conversation."""

from __future__ import annotations

import pytest

from friTap.events import DatalogEvent, EventBus
from friTap.flow.collector import FlowCollector
from friTap.message_router import MessageRouter
from friTap.output.pcap_handler import PcapOutputHandler
from friTap.output.provisional_endpoint_hold import ProvisionalEndpointHold

CONN = "0x7a1b2c3d40"


@pytest.fixture(autouse=True)
def _legacy_udp_path(monkeypatch):
    # These tests pin the bare-UDP payloads; synthetic QUIC (aioquic) would re-encapsulate them.
    monkeypatch.setattr("friTap.output.quic_synthetic.is_available", lambda: False)


SYN_LOCAL = ("10.0.0.1", 0x0A000001, 50000)
SYN_PEER = ("240.1.2.3", 0xF0010203, 443)
REAL_LOCAL = ("192.168.1.20", 0xC0A80114, 41000)
REAL_PEER = ("142.250.74.46", 0x8EFA4A2E, 443)


def _quic_event(direction="write", synthetic=False, data=b"\x01\x02payload",
                timestamp=1000.0, session=CONN):
    local, peer = (SYN_LOCAL, SYN_PEER) if synthetic else (REAL_LOCAL, REAL_PEER)
    src, dst = (peer, local) if direction == "read" else (local, peer)
    return DatalogEvent(
        data=data, function="QuicSession_WriteStreamData" if direction == "write"
        else "QuicConnection_OnStreamFrame",
        direction=direction, src_addr=src[0], src_addr_raw=src[1], src_port=src[2],
        dst_addr=dst[0], dst_addr_raw=dst[1], dst_port=dst[2], ss_family="AF_INET",
        ssl_session_id=session, transport="udp", protocol="quic", stream_id=0,
        quic_payload="stream", endpoints_synthetic=synthetic, timestamp=timestamp,
    )


# --- router ------------------------------------------------------------------

class _Bus:
    def __init__(self):
        self.events = []

    def emit(self, event):
        self.events.append(event)


def _route(**fields):
    bus = _Bus()
    payload = {"contentType": "datalog", "function": "QuicSession_WriteStreamData",
               "direction": "write", "transport": "udp", "ss_family": "AF_INET",
               "src_addr": SYN_LOCAL[1], "src_port": SYN_LOCAL[2],
               "dst_addr": SYN_PEER[1], "dst_port": SYN_PEER[2], "ssl_session_id": CONN}
    payload.update(fields)
    MessageRouter(bus).route(payload, b"x")
    [event] = [e for e in bus.events if isinstance(e, DatalogEvent)]
    return event


def test_router_flags_agent_declared_synthetic_quic_tuple():
    event = _route(endpoints_synthetic=True)
    assert event.endpoints_synthetic is True
    assert (event.src_addr, event.dst_addr) == (SYN_LOCAL[0], SYN_PEER[0])


def test_router_leaves_unflagged_quic_record_real():
    assert _route().endpoints_synthetic is False


def test_router_accepts_only_a_literal_true_flag():
    assert _route(endpoints_synthetic="yes").endpoints_synthetic is False


# --- collector ---------------------------------------------------------------

def _collector():
    bus = EventBus()
    collector = FlowCollector(event_bus=bus)
    bus.subscribe(DatalogEvent, collector.on_data)
    return bus, collector


def _tuple(flow):
    return ((flow.src_addr, flow.src_port), (flow.dst_addr, flow.dst_port))


def test_provisional_flow_is_upgraded_by_the_first_real_record():
    bus, collector = _collector()
    bus.emit(_quic_event(synthetic=True))
    [first] = collector.get_flows()
    assert first.endpoints_synthetic is True
    bus.emit(_quic_event(direction="read", timestamp=1001.0))
    flows = collector.get_flows()
    assert all(f.connection_id == first.connection_id for f in flows)
    for flow in flows:
        assert flow.endpoints_synthetic is False
        assert _tuple(flow) == ((REAL_LOCAL[0], REAL_LOCAL[2]), (REAL_PEER[0], REAL_PEER[2]))


def test_synthetic_only_connection_stays_flagged():
    bus, collector = _collector()
    bus.emit(_quic_event(synthetic=True))
    bus.emit(_quic_event(synthetic=True, direction="read", timestamp=1001.0))
    flows = collector.get_flows()
    assert flows and all(f.endpoints_synthetic for f in flows)
    assert all(_tuple(f) == ((SYN_LOCAL[0], SYN_LOCAL[2]), (SYN_PEER[0], SYN_PEER[2]))
               for f in flows)


def test_real_record_of_another_connection_does_not_upgrade():
    bus, collector = _collector()
    bus.emit(_quic_event(synthetic=True))
    bus.emit(_quic_event(timestamp=1001.0, session="0xother"))
    synthetic = [f for f in collector.get_flows() if f.ssl_session_id == CONN]
    assert synthetic and all(f.endpoints_synthetic for f in synthetic)


# --- pcap hold ---------------------------------------------------------------

def _endpoints(event):
    return (event.src_addr_raw, event.src_port, event.dst_addr_raw, event.dst_port)


def test_hold_releases_provisional_records_rewritten_to_the_real_tuple():
    hold = ProvisionalEndpointHold()
    assert hold.admit(_quic_event(synthetic=True, data=b"req")) == []
    released = hold.admit(_quic_event(direction="read", data=b"resp"))
    assert [e.data for e in released] == [b"req", b"resp"]
    assert _endpoints(released[0]) == (REAL_LOCAL[1], REAL_LOCAL[2], REAL_PEER[1], REAL_PEER[2])
    assert released[0].endpoints_synthetic is False
    # Later guesses of the same connection are rewritten at once.
    [late] = hold.admit(_quic_event(synthetic=True, direction="read"))
    assert _endpoints(late) == (REAL_PEER[1], REAL_PEER[2], REAL_LOCAL[1], REAL_LOCAL[2])
    assert hold.drain() == []


def test_hold_drain_keeps_the_guess_when_no_real_tuple_appeared():
    hold = ProvisionalEndpointHold()
    event = _quic_event(synthetic=True)
    assert hold.admit(event) == []
    assert hold.drain() == [event]


def test_hold_passes_tcp_and_unflagged_records_through():
    hold = ProvisionalEndpointHold()
    tcp = _quic_event(synthetic=True)
    tcp.transport = "tcp"
    real = _quic_event()
    assert hold.admit(tcp) == [tcp]
    assert hold.admit(real) == [real]


def test_hold_is_bounded_per_connection():
    hold = ProvisionalEndpointHold(max_held_per_connection=2)
    assert hold.admit(_quic_event(synthetic=True)) == []
    assert hold.admit(_quic_event(synthetic=True)) == []
    assert len(hold.admit(_quic_event(synthetic=True))) == 3
    assert hold.drain() == []


class _RecordingPcap:
    def __init__(self):
        self.packets = []
        self.pcap_file = None

    def log_plaintext_payload(self, ss_family, function, src_addr, src_port,
                              dst_addr, dst_port, data, transport="tcp", timestamp=None):
        self.packets.append((src_addr, src_port, dst_addr, dst_port, data, transport))


def test_pcap_has_no_fake_udp_conversation_for_an_upgraded_connection():
    pcap = _RecordingPcap()
    handler = PcapOutputHandler(pcap)
    handler.on_data(_quic_event(synthetic=True, data=b"req"))
    assert pcap.packets == []
    handler.on_data(_quic_event(direction="read", data=b"resp"))
    handler.close()
    endpoints = {frozenset({(p[0], p[1]), (p[2], p[3])}) for p in pcap.packets}
    assert endpoints == {frozenset({REAL_LOCAL[1:], REAL_PEER[1:]})}
    assert [p[4] for p in pcap.packets] == [b"req", b"resp"]


def test_pcap_close_writes_a_never_upgraded_connection_with_its_guess():
    pcap = _RecordingPcap()
    handler = PcapOutputHandler(pcap)
    handler.on_data(_quic_event(synthetic=True, data=b"req"))
    handler.close()
    assert pcap.packets == [(SYN_LOCAL[1], SYN_LOCAL[2], SYN_PEER[1], SYN_PEER[2], b"req", "udp")]


# --- half-guessed tuple (real peer, guessed local) ---------------------------

def _half_guessed_event(direction="write", data=b"early", timestamp=1000.5):
    """Real peer read, local not yet readable: the agent flags the tuple synthetic."""
    event = _quic_event(direction=direction, synthetic=True, data=data, timestamp=timestamp)
    peer_side = "dst" if direction == "write" else "src"
    setattr(event, peer_side + "_addr", REAL_PEER[0])
    setattr(event, peer_side + "_addr_raw", REAL_PEER[1])
    setattr(event, peer_side + "_port", REAL_PEER[2])
    return event


def _synthetic_half_real_sequence():
    return [_quic_event(synthetic=True, data=b"guess"),
            _half_guessed_event(),
            _quic_event(direction="read", data=b"resp", timestamp=1001.0)]


def test_collector_ends_on_the_real_tuple_after_a_half_guessed_one():
    bus, collector = _collector()
    bus.emit(_quic_event(synthetic=True))
    bus.emit(_half_guessed_event(data=b"\x01\x02payload"))
    bus.emit(_quic_event(direction="read", timestamp=1001.0))
    flows = collector.get_flows()
    assert flows
    for flow in flows:
        assert flow.endpoints_synthetic is False
        assert _tuple(flow) == ((REAL_LOCAL[0], REAL_LOCAL[2]), (REAL_PEER[0], REAL_PEER[2]))


def test_pcap_ends_on_the_real_tuple_after_a_half_guessed_one():
    pcap = _RecordingPcap()
    handler = PcapOutputHandler(pcap)
    for event in _synthetic_half_real_sequence():
        handler.on_data(event)
    handler.close()
    endpoints = {frozenset({(p[0], p[1]), (p[2], p[3])}) for p in pcap.packets}
    assert endpoints == {frozenset({REAL_LOCAL[1:], REAL_PEER[1:]})}
    assert [p[4] for p in pcap.packets] == [b"guess", b"early", b"resp"]


# --- ordering and close-time drain -------------------------------------------

def _unusable_event(data=b"noaddr"):
    event = _quic_event(data=data, timestamp=1000.7)
    event.src_addr, event.src_addr_raw, event.src_port = "", 0, 0
    return event


def test_hold_queues_an_unusable_real_record_behind_the_held_ones():
    hold = ProvisionalEndpointHold()
    assert hold.admit(_quic_event(synthetic=True, data=b"req")) == []
    unusable = _unusable_event()
    assert hold.admit(unusable) == []
    released = hold.admit(_quic_event(direction="read", data=b"resp"))
    assert [e.data for e in released] == [b"req", b"noaddr", b"resp"]
    assert released[1] is unusable


def test_hold_passes_an_unusable_record_through_when_nothing_is_held():
    hold = ProvisionalEndpointHold()
    unusable = _unusable_event()
    assert hold.admit(unusable) == [unusable]


class _FailingOncePcap(_RecordingPcap):
    def __init__(self):
        super().__init__()
        self.failed = False

    def log_plaintext_payload(self, *args, **kwargs):
        if not self.failed:
            self.failed = True
            raise ValueError("write to closed file")
        super().log_plaintext_payload(*args, **kwargs)


def test_pcap_close_keeps_writing_held_records_after_one_fails():
    pcap = _FailingOncePcap()
    handler = PcapOutputHandler(pcap)
    handler.on_data(_quic_event(synthetic=True, data=b"a"))
    handler.on_data(_quic_event(synthetic=True, data=b"b", session="0xother"))
    handler.close()
    assert len(pcap.packets) == 1


def test_pcapng_close_keeps_writing_held_records_after_one_fails(tmp_path):
    from friTap.output.pcapng_handler import PcapngOutputHandler
    handler = PcapngOutputHandler(str(tmp_path / "out.pcapng"))
    handler._file = object()
    written = []

    def write_epb(record):
        if not written:
            written.append(None)
            raise OSError("disk full")
        written.append(record.data)

    handler._write_epb = write_epb
    handler.on_data(_quic_event(synthetic=True, data=b"a"))
    handler.on_data(_quic_event(synthetic=True, data=b"b", session="0xother"))
    handler._release_held_records()
    assert written == [None, b"b"]


# --- live Wireshark ----------------------------------------------------------

def test_live_wireshark_rewrites_guessed_records_to_the_real_tuple():
    from friTap.output.live_wireshark_handler import LiveWiresharkHandler
    pcap = _RecordingPcap()
    handler = LiveWiresharkHandler()
    handler.set_pcap(pcap)
    handler.on_data(_quic_event(synthetic=True, data=b"req"))
    assert pcap.packets == []
    handler.on_data(_quic_event(direction="read", data=b"resp"))
    handler.on_data(_quic_event(synthetic=True, data=b"held", session="0xother"))
    handler.close()
    assert [p[4] for p in pcap.packets] == [b"req", b"resp", b"held"]
    assert (pcap.packets[0][0], pcap.packets[0][1]) == REAL_LOCAL[1:]


# --- shared side helper ------------------------------------------------------

def test_record_sides_orients_by_direction_with_any_endpoint_getter():
    from friTap.synthetic_endpoints import record_sides
    write, read = _quic_event(), _quic_event(direction="read")
    assert record_sides(write) == record_sides(read) == (REAL_LOCAL[::2], REAL_PEER[::2])
    raw = lambda e, side: getattr(e, side + "_addr_raw")  # noqa: E731
    assert record_sides(read, raw) == (REAL_LOCAL[1], REAL_PEER[1])
