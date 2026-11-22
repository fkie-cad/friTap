#!/usr/bin/env python3

"""Captured QUIC records reach -p as a synthetic QUIC connection (fritap[quic-pcap])."""

from __future__ import annotations

import json
import logging
import shutil
import struct
import subprocess
import threading
import time

import pytest

from friTap.events import DatalogEvent, EventBus, SessionEvent
from friTap.output import quic_synthetic
from friTap.output.pcap_handler import QUIC_SYNTHETIC_KEYLOG_SUFFIX, PcapOutputHandler
from friTap.output.pcapng_blocks import BT_DSB, BT_EPB
from friTap.output.pcapng_handler import PcapngOutputHandler
from friTap.output.quic_pcap_bridge import (
    INSTALL_NOTICE,
    QuicPcapBridge,
    is_quic_stream_record,
)
from friTap.output.quic_synthetic import CLIENT, SERVER, SyntheticOutput, encode_http3_frames
from friTap.pcap import PCAP

needs_aioquic = pytest.mark.skipif(not quic_synthetic.is_available(), reason="aioquic not installed")

CONN = "0x5eed"
LOCAL = ("192.168.1.20", 0xC0A80114, 41000)
PEER = ("142.250.74.46", 0x8EFA4A2E, 443)
GUESS_LOCAL = ("10.0.0.1", 0x0A000001, 50000)
GUESS_PEER = ("240.1.2.3", 0xF0010203, 443)

REQUEST = [[":method", "GET"], [":scheme", "https"], [":authority", "example.org"], [":path", "/oracle"]]
RESPONSE = [[":status", "200"], ["content-type", "text/plain"]]


def _event(data=b"payload", direction="write", stream_id=0, payload="stream", transport="udp",
           headers=None, fin=False, timestamp=1000.0, session=CONN, local=LOCAL, peer=PEER,
           synthetic=False, offset=None):
    src, dst = (peer, local) if direction == "read" else (local, peer)
    return DatalogEvent(
        data=data, function="", direction=direction, src_addr=src[0], src_addr_raw=src[1],
        src_port=src[2], dst_addr=dst[0], dst_addr_raw=dst[1], dst_port=dst[2],
        ss_family="AF_INET", ssl_session_id=session, transport=transport, protocol="quic",
        stream_id=stream_id, quic_payload=payload, http3_headers=headers, fin=fin,
        timestamp=timestamp, endpoints_synthetic=synthetic, stream_offset=offset,
    )


class _FakeWriter:
    def __init__(self):
        self.calls = []

    def feed_stream(self, *args):
        self.calls.append(("stream",) + args)
        return SyntheticOutput(packets=[(CLIENT, b"c1"), (SERVER, b"s1")], keylog_lines=["K 1 2"])

    def feed_headers_body(self, *args):
        self.calls.append(("headers_body",) + args)
        return SyntheticOutput(packets=[(args[1], b"hb")])

    def close(self, *args):
        self.calls.append(("close",) + args)
        return SyntheticOutput(packets=[(CLIENT, b"bye")])


def _bridge(writer=None, notices=None):
    sink = notices if notices is not None else []
    return QuicPcapBridge(writer=writer or _FakeWriter(), available=lambda: True, notice=sink.append)


def _endpoints(record):
    return (record.src_addr_raw, record.src_port), (record.dst_addr_raw, record.dst_port)


# --- adapter mapping ---------------------------------------------------------

def test_stream_record_maps_to_feed_stream_with_fin_and_side():
    writer = _FakeWriter()
    out = _bridge(writer).translate(_event(data=b"abc", direction="read", stream_id=4, fin=True))
    assert writer.calls == [("stream", CONN, SERVER, 4, b"abc", True, 1000.0)]
    assert out.keylog_lines == ["K 1 2"]


def _fed_stream_bytes(writer):
    return [call[4] for call in writer.calls if call[0] == "stream"]


def test_stream_offset_drops_duplicates_and_trims_overlaps():
    writer = _FakeWriter()
    bridge = _bridge(writer)
    assert bridge.translate(_event(data=b"abcd", offset=0)).records
    duplicate = bridge.translate(_event(data=b"abcd", offset=0))
    bridge.translate(_event(data=b"cdef", offset=2))
    bridge.translate(_event(data=b"ef", offset=4, fin=True))
    assert (duplicate.records, duplicate.keylog_lines) == ([], [])
    assert _fed_stream_bytes(writer) == [b"abcd", b"ef", b""]
    assert writer.calls[-1][5] is True


def test_stream_offset_is_tracked_per_stream_and_side():
    writer = _FakeWriter()
    bridge = _bridge(writer)
    bridge.translate(_event(data=b"req", offset=0))
    bridge.translate(_event(data=b"resp", offset=0, direction="read"))
    bridge.translate(_event(data=b"next", offset=0, stream_id=4))
    assert _fed_stream_bytes(writer) == [b"req", b"resp", b"next"]


def test_stream_offset_gap_still_feeds_and_logs_once(fritap_log_records):
    records = fritap_log_records("friTap.output.quic_pcap")
    writer = _FakeWriter()
    bridge = _bridge(writer)
    for offset in (0, 10, 30):
        bridge.translate(_event(data=b"ab", offset=offset))
    assert _fed_stream_bytes(writer) == [b"ab", b"ab", b"ab"]
    assert sum("jumps from offset" in r.getMessage() for r in records) == 1


def test_records_without_offset_are_fed_unchanged():
    writer = _FakeWriter()
    bridge = _bridge(writer)
    bridge.translate(_event(data=b"same"))
    bridge.translate(_event(data=b"same"))
    assert _fed_stream_bytes(writer) == [b"same", b"same"]


def test_synthetic_packets_carry_the_real_tuple_both_ways():
    out = _bridge().translate(_event(direction="read"))
    client, server = out.records
    assert _endpoints(client) == ((LOCAL[1], LOCAL[2]), (PEER[1], PEER[2]))
    assert _endpoints(server) == ((PEER[1], PEER[2]), (LOCAL[1], LOCAL[2]))
    assert (client.data, client.direction, server.data, server.direction) == (b"c1", "write", b"s1", "read")
    assert {r.timestamp for r in out.records} == {1000.0}
    assert all(r.transport == "udp" and r.stream_id == -1 for r in out.records)


def test_body_and_header_records_map_to_feed_headers_body():
    writer = _FakeWriter()
    bridge = _bridge(writer)
    bridge.translate(_event(data=b"body", payload="body", stream_id=8))
    bridge.translate(_event(data=b"", payload="", headers=RESPONSE, direction="read", stream_id=8))
    assert writer.calls == [
        ("headers_body", CONN, CLIENT, 8, None, b"body", False, 1000.0),
        ("headers_body", CONN, SERVER, 8, RESPONSE, None, False, 1000.0),
    ]


@pytest.mark.parametrize("event", [
    _event(stream_id=-1),
    _event(stream_id=None),
    _event(payload=""),
    _event(transport="tcp"),
])
def test_non_stream_records_keep_the_legacy_path(event):
    writer = _FakeWriter()
    assert not is_quic_stream_record(event)
    assert _bridge(writer).translate(event) is None
    assert writer.calls == []


def test_empty_synthetic_output_falls_back_to_legacy():
    writer = _FakeWriter()
    writer.feed_stream = lambda *a: SyntheticOutput()
    assert _bridge(writer).translate(_event()) is None


def test_records_reuse_one_payload_free_template_per_side():
    bridge = _bridge()
    bridge.translate(_event(data=b"first"))
    templates = dict(bridge._connections.get(CONN).templates)
    out = bridge.translate(_event(data=b"second", timestamp=1001.0))
    assert bridge._connections.get(CONN).templates == templates
    assert all(t.data == b"" and t.http3_headers is None for t in templates.values())
    assert [r.timestamp for r in out.records] == [1001.0, 1001.0]


def test_route_writes_secrets_before_records_and_legacy_as_is():
    calls = []

    def write_record(record, timestamp=None):
        calls.append(("record", record.data, timestamp))

    def write_secrets(lines):
        calls.append(("secrets", lines))

    bridge = _bridge()
    bridge.route(_event(), write_record, write_secrets)
    legacy = _event(data=b"tcp", transport="tcp", payload="", stream_id=None)
    bridge.route(legacy, write_record, write_secrets)
    bridge.close_on_destroyed(SessionEvent(session_id=CONN, event_type="destroyed", timestamp=2000.0),
                              write_record, write_secrets)
    assert calls == [("secrets", ["K 1 2"]), ("record", b"c1", 1000.0), ("record", b"s1", 1000.0),
                     ("record", b"tcp", None), ("record", b"bye", 2000.0)]


def test_close_connection_uses_the_remembered_tuple_once():
    writer = _FakeWriter()
    bridge = _bridge(writer)
    bridge.translate(_event())
    out = bridge.close_connection(CONN, 2000.0)
    assert [(_endpoints(r), r.timestamp) for r in out.records] == [
        (((LOCAL[1], LOCAL[2]), (PEER[1], PEER[2])), 2000.0)]
    assert bridge.close_connection(CONN, 2001.0).records == []
    assert writer.calls[-1] == ("close", CONN, 2000.0)


# --- concurrency and eviction -------------------------------------------------

class _BlockingFirstFeedWriter(_FakeWriter):
    """Holds the first feed until released, so a second record can race it."""

    def __init__(self):
        super().__init__()
        self.entered, self.release = threading.Event(), threading.Event()

    def feed_stream(self, *args):
        if not self.entered.is_set():
            self.entered.set()
            self.release.wait(2.0)
        return super().feed_stream(*args)


def test_concurrent_same_stream_records_reach_the_writer_in_offset_order():
    writer = _BlockingFirstFeedWriter()
    bridge = _bridge(writer)
    first = threading.Thread(target=bridge.translate, args=(_event(b"hello", offset=0),))
    second = threading.Thread(target=bridge.translate, args=(_event(b"world", offset=5),))
    first.start()
    assert writer.entered.wait(2.0)
    second.start()
    time.sleep(0.1)  # give the second record every chance to overtake the first
    writer.release.set()
    first.join(2.0)
    second.join(2.0)
    assert [call[4] for call in writer.calls] == [b"hello", b"world"]


def test_bridge_tracks_no_more_connections_than_the_writer_keeps():
    writer = _FakeWriter()
    writer.max_connections = 2
    bridge = _bridge(writer)
    for n in range(3):
        bridge.translate(_event(session="0x%d" % n))
    assert bridge._connections.keys() == ["0x1", "0x2"]


def test_eviction_closes_the_writer_connection_before_new_records():
    writer = _FakeWriter()
    bridge = QuicPcapBridge(writer=writer, available=lambda: True, notice=[].append, max_tracked=1)
    other_local = ("192.168.1.21", 0xC0A80115, 42000)
    bridge.translate(_event(b"abc", offset=0))
    out = bridge.translate(_event(b"x", session="0xb", local=other_local, timestamp=1001.0, offset=0))
    assert ("close", CONN, 1001.0) in writer.calls
    # The evicted connection's close keeps its own tuple and comes first.
    assert out.records[0].data == b"bye"
    assert _endpoints(out.records[0]) == ((LOCAL[1], LOCAL[2]), (PEER[1], PEER[2]))
    assert out.records[0].timestamp == 1001.0
    assert [r.data for r in out.records[1:]] == [b"c1", b"s1"]


def test_route_writes_the_eviction_close_even_on_legacy_fallback():
    class _EmptyWriter(_FakeWriter):
        def feed_stream(self, *args):
            self.calls.append(("stream",) + args)
            return SyntheticOutput()

    writer = _EmptyWriter()
    bridge = QuicPcapBridge(writer=writer, available=lambda: True, notice=[].append, max_tracked=1)
    written = []
    bridge.route(_event(b"a"), lambda r, timestamp=None: written.append(r.data), lambda lines: None)
    bridge.route(_event(b"b", session="0xb"), lambda r, timestamp=None: written.append(r.data),
                 lambda lines: None)
    assert written == [b"a", b"bye", b"b"]


@needs_aioquic
def test_evicted_connection_is_closed_and_a_returning_one_starts_fresh():
    writer = quic_synthetic.SyntheticQuicWriter(max_connections=1)
    bridge = QuicPcapBridge(writer=writer, available=lambda: True, notice=[].append)
    first = bridge.translate(_event(b"hello", offset=0))
    assert first.records and CONN in writer
    out = bridge.translate(_event(b"x", session="0xb", timestamp=1001.0, offset=0))
    assert CONN not in writer and "0xb" in writer and len(writer) == 1
    assert out.records[0].timestamp == 1001.0  # the close of the evicted connection
    bridge.close_all(lambda r, timestamp=None: None, lambda lines: None, now=1002.0)
    # A returning connection gets a fresh synthetic connection, so its
    # retransmitted bytes are carried once there, not appended to a stale one.
    again = bridge.translate(_event(b"hello", offset=0, timestamp=1003.0))
    assert again.keylog_lines  # new handshake, new secrets
    assert bridge._connections[CONN].next_offsets == {(0, CLIENT): 5}


# --- handlers ----------------------------------------------------------------

def _read_pcapng_blocks(path):
    data = path.read_bytes()
    blocks, offset = [], 0
    while offset + 8 <= len(data):
        block_type, length = struct.unpack_from("<II", data, offset)
        blocks.append((block_type, data[offset + 8:offset + length - 4]))
        offset += length
    return blocks


def _pcapng_handler(tmp_path):
    bus = EventBus()
    handler = PcapngOutputHandler(str(tmp_path / "out.pcapng"))
    handler.setup(bus)
    return bus, handler


@needs_aioquic
def test_pcapng_dsb_precedes_the_first_synthetic_packet(tmp_path):
    bus, handler = _pcapng_handler(tmp_path)
    bus.emit(_event(data=encode_http3_frames(0, REQUEST), fin=True))
    handler.close()
    kinds = [block_type for block_type, _ in _read_pcapng_blocks(tmp_path / "out.pcapng")]
    assert BT_DSB in kinds and BT_EPB in kinds
    assert kinds.index(BT_DSB) < kinds.index(BT_EPB)
    dsb = next(body for block_type, body in _read_pcapng_blocks(tmp_path / "out.pcapng")
               if block_type == BT_DSB)
    assert b"CLIENT_HANDSHAKE_TRAFFIC_SECRET" in dsb


@needs_aioquic
def test_destroyed_lifecycle_closes_the_synthetic_connection(tmp_path):
    bus, handler = _pcapng_handler(tmp_path)
    bus.emit(_event(data=encode_http3_frames(0, REQUEST), fin=True))
    assert CONN in handler._quic_bridge._writer
    bus.emit(SessionEvent(session_id=CONN, event_type="destroyed", protocol="quic", timestamp=1001.0))
    assert CONN not in handler._quic_bridge._writer
    handler.close()


@needs_aioquic
def test_held_provisional_records_are_synthesised_on_the_real_tuple(tmp_path):
    bus, handler = _pcapng_handler(tmp_path)
    bus.emit(_event(data=encode_http3_frames(0, REQUEST), local=GUESS_LOCAL, peer=GUESS_PEER,
                    synthetic=True))
    assert CONN not in handler._quic_bridge._writer
    bus.emit(_event(data=encode_http3_frames(0, RESPONSE), direction="read", fin=True))
    tup = handler._quic_bridge._connections.get(CONN).tup
    assert (tup.local[1], tup.remote[1]) == (LOCAL[1], PEER[1])
    handler.close()


@pytest.fixture
def pcap_log(fritap_log_records):
    return fritap_log_records("friTap.output.pcap", logging.INFO)


def _classic(tmp_path, name="out.pcap"):
    pcap = PCAP(str(tmp_path / name), ["SSL_read"], ["SSL_write"], False, False, pcap_format="pcap")
    handler = PcapOutputHandler(pcap)
    bus = EventBus()
    handler.setup(bus)
    return pcap, handler, bus


@needs_aioquic
def test_classic_sidecar_manifest_and_hint_once(tmp_path, pcap_log):
    pcap, handler, bus = _classic(tmp_path)
    bus.emit(_event(data=encode_http3_frames(0, REQUEST), fin=True))
    bus.emit(_event(data=encode_http3_frames(0, RESPONSE, b"hi"), direction="read", fin=True))
    handler.close()
    pcap.finalize_plaintext_capture()
    sidecar = str(tmp_path / "out.pcap") + QUIC_SYNTHETIC_KEYLOG_SUFFIX
    with open(sidecar, encoding="utf-8") as fh:
        assert "CLIENT_TRAFFIC_SECRET_0" in fh.read()
    with open(str(tmp_path / "out.pcap") + ".fritap.json", encoding="utf-8") as fh:
        assert json.load(fh) == {"quic_synthetic_keylog": sidecar}
    hints = [m for m in (r.getMessage() for r in pcap_log) if m.startswith("HTTP/3 in")]
    assert hints == [f"HTTP/3 in {tmp_path / 'out.pcap'}: open with Wireshark, TLS keylog file {sidecar}"]


def test_classic_without_quic_writes_no_sidecar_or_manifest(tmp_path):
    pcap, handler, bus = _classic(tmp_path)
    bus.emit(_event(transport="tcp", payload="", stream_id=None))
    handler.close()
    pcap.finalize_plaintext_capture()
    assert not (tmp_path / ("out.pcap" + QUIC_SYNTHETIC_KEYLOG_SUFFIX)).exists()
    assert not (tmp_path / "out.pcap.fritap.json").exists()


def test_without_aioquic_notice_once_and_legacy_output_unchanged(tmp_path, monkeypatch, pcap_log):
    events = [_event(data=b"one"), _event(data=b"two", direction="read"), _event(data=b"dgram", stream_id=-1)]
    monkeypatch.setattr(quic_synthetic, "is_available", lambda: False)
    pcap, handler, bus = _classic(tmp_path, "new.pcap")
    for event in events:
        bus.emit(event)
    handler.close()
    assert [r.getMessage() for r in pcap_log].count(INSTALL_NOTICE) == 1
    assert not (tmp_path / ("new.pcap" + QUIC_SYNTHETIC_KEYLOG_SUFFIX)).exists()

    class _Bridgeless(PcapOutputHandler):
        def _write(self, event):
            self._write_record(event)

    legacy_pcap = PCAP(str(tmp_path / "old.pcap"), ["SSL_read"], ["SSL_write"], False, False,
                       pcap_format="pcap")
    legacy = _Bridgeless(legacy_pcap)
    for event in events:
        legacy.on_data(event)
    legacy.close()
    assert _pcap_payloads(tmp_path / "new.pcap") == _pcap_payloads(tmp_path / "old.pcap") \
        == [b"one", b"two", b"dgram"]


def _pcap_payloads(path):
    """UDP payloads of a classic raw-IPv4 pcap (timestamps ignored)."""
    data, offset, payloads = path.read_bytes(), 24, []
    while offset < len(data):
        incl = struct.unpack_from("=I", data, offset + 8)[0]
        packet = data[offset + 16:offset + 16 + incl]
        payloads.append(packet[28:])
        offset += 16 + incl
    return payloads


# --- end-to-end oracle -------------------------------------------------------

def _settings_stream(stream_type):
    return bytes([stream_type, 0x04, 0x00])


def _realistic_sequence():
    """Client control/QPACK uni streams, request HEADERS on 0, server response."""
    return [
        _event(data=_settings_stream(0x00), stream_id=2, timestamp=1000.0),
        _event(data=b"\x02", stream_id=6, timestamp=1000.001),
        _event(data=b"\x03", stream_id=10, timestamp=1000.002),
        _event(data=encode_http3_frames(0, REQUEST), stream_id=0, fin=True, timestamp=1000.003),
        _event(data=_settings_stream(0x00), direction="read", stream_id=3, timestamp=1000.050),
        _event(data=encode_http3_frames(0, RESPONSE), direction="read", stream_id=0, timestamp=1000.051),
        _event(data=b"oracle-body", payload="body", direction="read", stream_id=0, fin=True,
               timestamp=1000.052),
    ]


def _tshark(path, *extra):
    from friTap.offline.tshark import find_tshark

    cmd = [find_tshark(), "-r", str(path), "-o", "tls.ignore_ssl_mac_failed:FALSE", *extra,
           "-Y", "http3", "-T", "fields", "-E", "separator=|",
           "-e", "http3.headers.path", "-e", "http3.headers.status", "-e", "http3.data"]
    # A broken user Lua plugin may print to stderr; only stdout matters.
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=120)
    return result.stdout.decode("utf-8", "replace")


def _assert_http3(output):
    assert "/oracle" in output
    assert "200" in output
    assert b"oracle-body".hex() in output.replace(":", "")


@needs_aioquic
@pytest.mark.skipif(shutil.which("tshark") is None, reason="tshark not installed")
def test_tshark_reads_http3_from_pcapng_handler(tmp_path):
    bus, handler = _pcapng_handler(tmp_path)
    for event in _realistic_sequence():
        bus.emit(event)
    handler.close()
    _assert_http3(_tshark(tmp_path / "out.pcapng"))


@needs_aioquic
@pytest.mark.skipif(shutil.which("tshark") is None, reason="tshark not installed")
def test_tshark_reads_http3_from_classic_handler_with_sidecar(tmp_path):
    pcap, handler, bus = _classic(tmp_path)
    for event in _realistic_sequence():
        bus.emit(event)
    handler.close()
    sidecar = (tmp_path / ("out.pcap" + QUIC_SYNTHETIC_KEYLOG_SUFFIX)).resolve()
    _assert_http3(_tshark(tmp_path / "out.pcap", "-o", f"tls.keylog_file:{sidecar}"))
