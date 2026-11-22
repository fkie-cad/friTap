"""Tests for friTap.output.quic_synthetic (synthetic QUIC re-encapsulation)."""

import logging
import shutil
import subprocess

import pytest

pytest.importorskip("aioquic")
pylsqpack = pytest.importorskip("pylsqpack")

from friTap.output import quic_synthetic  # noqa: E402
from friTap.output.quic_synthetic import (  # noqa: E402
    CLIENT,
    SERVER,
    SyntheticQuicWriter,
    encode_http3_frames,
    is_available,
)

REQUEST_A = [[":method", "GET"], [":scheme", "https"], [":authority", "example.test"], [":path", "/alpha"]]
REQUEST_B = [[":method", "GET"], [":scheme", "https"], [":authority", "example.test"], [":path", "/beta"]]
RESPONSE = [[":status", "200"], ["content-type", "text/plain"]]


@pytest.fixture
def log_records(fritap_log_records):
    return fritap_log_records("friTap.output.quic_synthetic")


def _directions(output):
    return {direction for direction, _payload in output.packets}


def _decode_frames(data):
    from aioquic.buffer import Buffer

    buf = Buffer(data=data)
    frames = []
    while not buf.eof():
        frame_type = buf.pull_uint_var()
        frames.append((frame_type, buf.pull_bytes(buf.pull_uint_var())))
    return frames


def test_is_available():
    assert is_available() is True


def test_first_record_emits_handshake_in_both_directions():
    output = SyntheticQuicWriter().feed_stream("c", CLIENT, 0, b"hi", fin=True, now=1.0)

    assert _directions(output) == {CLIENT, SERVER}
    assert output.packets[0][0] == CLIENT
    labels = {line.split(" ", 1)[0] for line in output.keylog_lines}
    assert {"CLIENT_HANDSHAKE_TRAFFIC_SECRET", "SERVER_HANDSHAKE_TRAFFIC_SECRET",
            "CLIENT_TRAFFIC_SECRET_0", "SERVER_TRAFFIC_SECRET_0"} <= labels


def test_keylog_lines_are_reported_only_once():
    writer = SyntheticQuicWriter()
    writer.feed_stream("c", CLIENT, 0, b"a", now=1.0)

    later = writer.feed_stream("c", CLIENT, 0, b"b", now=2.0)

    assert later.keylog_lines == []
    assert later.packets


def test_stream_data_produces_datagrams_and_batched_acks():
    writer = SyntheticQuicWriter()
    writer.feed_stream("c", CLIENT, 0, b"request", now=1.0)

    output = writer.feed_stream("c", SERVER, 0, b"response", fin=True, now=1.0)
    later = [writer.feed_stream("c", CLIENT, 4 * n, b"x", fin=True, now=1.0) for n in range(1, 15)]

    assert output.packets[0][0] == SERVER
    # Same capture time: delayed ACKs wait for a batched flush, not one per record.
    assert _directions(output) == {SERVER}
    acked = [SERVER in _directions(out) for out in later]
    assert 0 < sum(acked) <= len(later) // 2


def _received_bytes(monkeypatch):
    """Count stream bytes each synthetic peer actually receives."""
    from aioquic.quic.events import StreamDataReceived

    received = {}

    def collect(self):
        for connection in (self._client, self._server):
            while connection is not None and (event := connection.next_event()) is not None:
                if isinstance(event, StreamDataReceived):
                    received[event.stream_id] = received.get(event.stream_id, 0) + len(event.data)

    monkeypatch.setattr(quic_synthetic._SyntheticConnection, "_discard_events", collect)
    return received


def test_large_records_are_delivered_within_their_own_record(monkeypatch):
    received = _received_bytes(monkeypatch)
    writer = SyntheticQuicWriter()
    for stream_id, size in ((0, 6000), (4, 20000), (8, 70000)):
        writer.feed_stream("c", CLIENT, stream_id, b"x" * size, now=1.0)
        assert received.get(stream_id) == size


@pytest.mark.parametrize("direction", [CLIENT, SERVER])
def test_lower_stream_id_after_a_higher_one_is_carried(monkeypatch, direction):
    received = _received_bytes(monkeypatch)
    writer = SyntheticQuicWriter()
    writer.feed_stream("c", CLIENT, 2, b"\x00\x04\x00", now=1.0)

    high = writer.feed_stream("c", direction, 8, b"eight", now=2.0)
    low = writer.feed_stream("c", direction, 4, b"four", now=3.0)

    assert high.packets and low.packets
    assert received.get(8) == 5 and received.get(4) == 4


def test_server_record_before_client_opened_the_stream():
    writer = SyntheticQuicWriter()
    writer.feed_stream("c", CLIENT, 0, b"x", now=1.0)

    output = writer.feed_stream("c", SERVER, 400, b"early response", now=2.0)
    follow_up = writer.feed_stream("c", CLIENT, 400, b"late request", fin=True, now=3.0)

    assert output.packets and output.packets[0][0] == SERVER
    assert follow_up.packets
    assert "c" in writer


def test_sparse_client_stream_ids_are_accepted():
    writer = SyntheticQuicWriter()
    for stream_id in (0, 400, 4000):
        output = writer.feed_stream("c", CLIENT, stream_id, b"x", fin=True, now=1.0)
        assert output.packets


def test_refused_peer_uni_stream_is_skipped(log_records):
    writer = SyntheticQuicWriter()
    writer.feed_stream("c", CLIENT, 0, b"x", now=1.0)

    output = writer.feed_stream("c", SERVER, 2, b"x", now=2.0)

    assert output.packets == []
    assert "c" in writer
    assert any("uni stream 2" in r.getMessage() for r in log_records)


def test_data_after_fin_skips_record_but_keeps_connection():
    writer = SyntheticQuicWriter()
    writer.feed_stream("c", CLIENT, 0, b"x", fin=True, now=1.0)

    output = writer.feed_stream("c", CLIENT, 0, b"more", now=2.0)

    assert output.packets == []
    assert writer.feed_stream("c", CLIENT, 4, b"y", now=3.0).packets


def test_invalid_direction_is_ignored():
    writer = SyntheticQuicWriter()
    assert writer.feed_stream("c", "sideways", 0, b"x").packets == []
    assert len(writer) == 0


def test_lru_evicts_oldest_connection():
    writer = SyntheticQuicWriter(max_connections=2)
    writer.feed_stream("a", CLIENT, 0, b"x", now=1.0)
    writer.feed_stream("b", CLIENT, 0, b"x", now=1.0)
    writer.feed_stream("a", CLIENT, 4, b"x", now=2.0)

    writer.feed_stream("c", CLIENT, 0, b"x", now=3.0)

    assert "a" in writer and "c" in writer
    assert "b" not in writer
    assert len(writer) == 2


def test_byte_cap_stops_reencapsulation(log_records):
    writer = SyntheticQuicWriter(max_bytes_per_connection=1000)
    assert writer.feed_stream("c", CLIENT, 0, b"x" * 600, now=1.0).packets

    output = writer.feed_stream("c", CLIENT, 0, b"x" * 600, now=2.0)

    assert output.packets == []
    assert writer.feed_stream("c", CLIENT, 4, b"y", now=3.0).packets == []
    assert any(r.levelno == logging.WARNING and "exceeded" in r.getMessage() for r in log_records)


def test_close_emits_connection_close_and_forgets():
    writer = SyntheticQuicWriter()
    writer.feed_stream("c", CLIENT, 0, b"x", now=1.0)

    output = writer.close("c", now=2.0)

    assert output.packets and output.packets[0][0] == CLIENT
    assert "c" not in writer
    assert writer.close("c").packets == []


def test_aioquic_failure_is_isolated_and_logged_once(monkeypatch, log_records):
    writer = SyntheticQuicWriter()
    writer.feed_stream("good", CLIENT, 0, b"x", now=1.0)
    writer.feed_stream("bad", CLIENT, 0, b"x", now=1.0)

    def explode(*_args, **_kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr(writer._connections["bad"], "send", explode)
    assert writer.feed_stream("bad", CLIENT, 4, b"x", now=2.0).packets == []
    monkeypatch.setattr(quic_synthetic._SyntheticConnection, "send", explode)
    writer.feed_stream("bad", CLIENT, 4, b"x", now=3.0)
    monkeypatch.undo()

    warnings = [r for r in log_records if r.levelno == logging.WARNING and "bad" in r.getMessage()]
    assert len(warnings) == 1
    assert writer.feed_stream("good", CLIENT, 4, b"y", now=4.0).packets


def test_encode_http3_frames_round_trips_through_qpack():
    data = encode_http3_frames(0, REQUEST_A, b"payload")

    frames = _decode_frames(data)

    assert [frame_type for frame_type, _ in frames] == [0x1, 0x0]
    _stream_updates, headers = pylsqpack.Decoder(4096, 16).feed_header(0, frames[0][1])
    assert [[n.decode(), v.decode()] for n, v in headers] == REQUEST_A
    assert frames[1][1] == b"payload"


def test_encode_http3_frames_accepts_bytes_headers_and_body_only():
    assert _decode_frames(encode_http3_frames(0, None, b"abc")) == [(0x0, b"abc")]
    data = encode_http3_frames(0, [[b":status", b"204"]])
    assert _decode_frames(data)[0][0] == 0x1


def test_feed_headers_body_without_content_does_nothing():
    writer = SyntheticQuicWriter()
    assert writer.feed_headers_body("c", CLIENT, 0).packets == []
    assert len(writer) == 0


def _write_pcapng(path, packets, keylog_lines):
    from friTap.output.pcapng_blocks import build_dsb, build_epb, build_idb, build_shb
    from friTap.sinks.tcp_state import build_ipv4_udp_packet

    client_ip, server_ip = 0x0A000001, 0x0A000002
    blocks = [build_shb(), build_idb(), build_dsb(("\n".join(keylog_lines) + "\n").encode())]
    for index, (direction, payload) in enumerate(packets):
        if direction == CLIENT:
            frame = build_ipv4_udp_packet(client_ip, 50000, server_ip, 443, payload)
        else:
            frame = build_ipv4_udp_packet(server_ip, 443, client_ip, 50000, payload)
        blocks.append(build_epb(frame, 1_700_000_000_000_000 + index * 1000))
    path.write_bytes(b"".join(blocks))


_IN_ORDER_EXCHANGE = (
    (CLIENT, 0, REQUEST_A, None),
    (CLIENT, 4, REQUEST_B, None),
    (SERVER, 4, RESPONSE, b"beta-body"),
    (SERVER, 0, RESPONSE, b"alpha-body"),
)
# Stream 4 is opened after stream 8 (aioquic once refused the lower id).
_DESCENDING_EXCHANGE = (
    (CLIENT, 8, REQUEST_A, None),
    (CLIENT, 4, REQUEST_B, None),
    (SERVER, 4, RESPONSE, b"beta-body"),
    (SERVER, 8, RESPONSE, b"alpha-body"),
)


def _synthetic_exchange(records=_IN_ORDER_EXCHANGE):
    writer = SyntheticQuicWriter()
    packets, keylog = [], []
    for direction, stream_id, headers, body in records:
        output = writer.feed_headers_body("conn", direction, stream_id, headers, body, fin=True, now=1.0)
        packets += output.packets
        keylog += output.keylog_lines
    packets += writer.close("conn", now=2.0).packets
    return packets, keylog


def _run_tshark(pcap_path, fields):
    from friTap.offline.tshark import find_tshark

    cmd = [find_tshark(), "-r", str(pcap_path), "-o", "tls.ignore_ssl_mac_failed:FALSE",
           "-Y", "http3", "-T", "fields", "-E", "separator=|"]
    for name in fields:
        cmd += ["-e", name]
    # A broken user Lua plugin may print to stderr; only stdout matters.
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=120)
    return result.stdout.decode("utf-8", "replace")


@pytest.mark.skipif(shutil.which("tshark") is None, reason="tshark not installed")
@pytest.mark.parametrize("records", [_IN_ORDER_EXCHANGE, _DESCENDING_EXCHANGE], ids=["in-order", "8-then-4"])
def test_tshark_dissects_synthetic_connection_as_http3(tmp_path, records):
    packets, keylog = _synthetic_exchange(records)
    pcap = tmp_path / "synthetic.pcapng"
    _write_pcapng(pcap, packets, keylog)

    paths = _run_tshark(pcap, ["http3.headers.path"])
    bodies = _run_tshark(pcap, ["http3.data"])

    assert "/alpha" in paths and "/beta" in paths
    assert b"alpha-body".hex() in bodies.replace(":", "")
    assert b"beta-body".hex() in bodies.replace(":", "")


def test_writer_is_inert_without_aioquic(monkeypatch):
    monkeypatch.setattr(quic_synthetic, "is_available", lambda: False)
    writer = SyntheticQuicWriter()

    assert writer.feed_stream("c", CLIENT, 0, b"x").packets == []
    assert writer.feed_headers_body("c", CLIENT, 0, REQUEST_A).packets == []
    assert len(writer) == 0
