"""Offline QUIC stream reassembly (pcap -> .tap).

Covers the per-frame layout alignment built from tshark's OFF/LEN/FIN flag
lists, FIN-only frame handling, and the per-direction stream reassembler that
trims retransmissions and reorders out-of-order STREAM frames.
"""

from __future__ import annotations

from friTap.offline import pcap_to_tap as p2t

# ek sample taken from a real capture: stream 2 has OFF+LEN, stream 10 only LEN,
# stream 0 neither (offset 0, implicit length to the end of the packet).
EK_SAMPLE = {
    "quic_stream_stream_id": ["2", "10", "0"],
    "quic_stream_off": ["True", "False", "False"],
    "quic_stream_len": ["True", "True", "False"],
    "quic_stream_fin": ["False", "False", "True"],
    "quic_stream_offset": ["41"],
    "quic_stream_length": ["12", "923"],
}


def _pkt(frames, *, src="10.0.0.1", sport=50000, dst="8.8.8.8", dport=443,
         ts="1700000000.0", udp_stream="2", payloads=None):
    """Build a `-T ek` QUIC packet from ``(stream_id, offset, data, fin)`` frames.

    *offset* None -> OFF bit clear. Every frame sets LEN (explicit length).
    *payloads* overrides the ``quic_stream_data`` list (for FIN-only frames).
    """
    layers = {
        "frame_time_epoch": [ts],
        "ip_src": [src], "ip_dst": [dst], "udp_stream": [udp_stream],
        "udp_srcport": [str(sport)], "udp_dstport": [str(dport)],
        "quic_stream_stream_id": [str(f[0]) for f in frames],
        "quic_stream_off": [str(f[1] is not None) for f in frames],
        "quic_stream_len": ["True" for _ in frames],
        "quic_stream_fin": [str(f[3]) for f in frames],
        "quic_stream_offset": [str(f[1]) for f in frames if f[1] is not None],
        "quic_stream_length": [str(len(f[2])) for f in frames],
    }
    if payloads is None:
        payloads = [f[2].hex() for f in frames if f[2]]
    layers["quic_stream_data"] = payloads
    return {"layers": layers}


def _feed(pkts):
    tracker = p2t._StreamDirectionTracker()
    reassembler = p2t._QuicStreamReassembler()
    events = []
    for pkt in pkts:
        events += p2t._quic_packet_to_events(pkt, tracker, None, reassembler)
    return events, reassembler


# --- layout / alignment -----------------------------------------------------

def test_frame_layout_aligns_sparse_offset_and_length_lists():
    layout = p2t._quic_frame_layout(EK_SAMPLE, 3)
    assert layout == [(41, 12, False), (0, 923, False), (0, None, True)]


def test_frame_layout_absent_flags_returns_none():
    assert p2t._quic_frame_layout({"quic_stream_stream_id": ["0"]}, 1) is None


def test_frame_layout_inconsistent_counts_returns_none():
    bad = dict(EK_SAMPLE, quic_stream_offset=[])  # OFF set but no offset value
    assert p2t._quic_frame_layout(bad, 3) is None
    assert p2t._quic_frame_layout(EK_SAMPLE, 2) is None


def test_align_payloads_drops_fin_only_frame():
    layout = [(0, 3, False), (7, 0, True), (0, 2, False)]
    aligned = p2t._align_payloads(["0", "4", "8"], ["aa", "bb"], layout)
    assert [(sid, pl) for sid, pl, _ in aligned] == [("0", "aa"), ("8", "bb")]


def test_align_payloads_unrecoverable_mismatch_returns_none():
    assert p2t._align_payloads(["0", "4"], ["aa"], None) is None
    layout = [(0, 3, False), (0, 2, False)]
    assert p2t._align_payloads(["0", "4"], ["aa"], layout) is None


# --- reassembler ------------------------------------------------------------

def test_reassembler_trims_retransmission_and_overlap():
    r = p2t._QuicStreamReassembler()
    assert r.push("k", 0, b"hello") == b"hello"
    assert r.push("k", 0, b"hello") == b""          # full retransmit
    assert r.push("k", 3, b"lo world") == b" world"  # overlapping retransmit
    assert r.duplicate_bytes == 5 + 2


def test_reassembler_reorders_out_of_order_frames():
    r = p2t._QuicStreamReassembler()
    assert r.push("k", 6, b"world") == b""
    assert r.push("k", 0, b"hello ") == b"hello world"
    assert r.drain("k") == b""


def test_reassembler_keys_are_independent():
    r = p2t._QuicStreamReassembler()
    assert r.push("a", 0, b"x") == b"x"
    assert r.push("b", 0, b"y") == b"y"


def test_reassembler_gap_cap_skips_gap():
    r = p2t._QuicStreamReassembler(gap_cap=8)
    assert r.push("k", 10, b"abcd") == b""
    assert r.push("k", 14, b"efghij") == b"abcdefghij"  # 10 > cap -> skip gap
    assert r.gap_count == 1
    assert r.push("k", 0, b"late") == b""  # the skipped gap is gone for good


def test_reassembler_drain_all_flushes_held_bytes_past_gaps():
    r = p2t._QuicStreamReassembler()
    r.push("k", 0, b"ab", context={"stream_id": 0})
    r.push("k", 5, b"fg")
    r.push("k", 9, b"j")
    assert r.drain_all() == [("k", {"stream_id": 0}, b"fgj")]
    assert r.gap_count == 2


# --- packet -> events -------------------------------------------------------

def test_retransmitted_frame_emitted_once():
    events, _ = _feed([
        _pkt([(0, None, b"GET", False)]),
        _pkt([(0, None, b"GET", False)]),  # retransmission
        _pkt([(0, 3, b" /", False)]),
    ])
    assert [e.data for e in events] == [b"GET", b" /"]


def test_out_of_order_frames_emitted_in_order():
    events, _ = _feed([
        _pkt([(0, 3, b"DEF", False)]),
        _pkt([(0, None, b"ABC", False)]),
    ])
    assert [e.data for e in events] == [b"ABCDEF"]


def test_directions_reassemble_independently():
    events, _ = _feed([
        _pkt([(0, None, b"req", False)]),
        _pkt([(0, None, b"resp", False)], src="8.8.8.8", sport=443,
             dst="10.0.0.1", dport=50000),
    ])
    assert [(e.direction, e.data) for e in events] == [
        ("write", b"req"), ("read", b"resp")]


def test_fin_only_frame_no_longer_drops_packet():
    result = p2t.ConvertResult(tap_path="x.tap")
    pkt = _pkt([(0, None, b"AB", False), (4, 9, b"", True), (8, None, b"C", False)])
    events = p2t._quic_packet_to_events(pkt, p2t._StreamDirectionTracker(), result)
    assert [(e.stream_id, e.data) for e in events] == [(0, b"AB"), (8, b"C")]
    assert result.dropped_packet_count == 0


def test_legacy_packet_without_flags_passes_through_unchanged():
    tracker = p2t._StreamDirectionTracker()
    reassembler = p2t._QuicStreamReassembler()
    pkt = {"layers": {
        "frame_time_epoch": ["1.0"], "ip_src": ["10.0.0.1"], "ip_dst": ["8.8.8.8"],
        "udp_stream": ["2"], "udp_srcport": ["50000"], "udp_dstport": ["443"],
        "quic_stream_stream_id": ["0", "0"], "quic_stream_data": ["41", "41"],
    }}
    events = p2t._quic_packet_to_events(pkt, tracker, None, reassembler)
    assert [e.data for e in events] == [b"A", b"A"]  # no layout -> no dedupe


def test_legacy_mismatch_still_skipped_and_counted():
    result = p2t.ConvertResult(tap_path="x.tap")
    pkt = {"layers": {
        "udp_stream": ["2"], "quic_stream_stream_id": ["0", "4"],
        "quic_stream_data": ["41"],
    }}
    assert p2t._quic_packet_to_events(pkt, p2t._StreamDirectionTracker(), result) == []
    assert result.dropped_packet_count == 1


# --- _emit_quic_streams end-to-end ------------------------------------------

class _FakeBus:
    def __init__(self):
        self.events = []

    def emit(self, ev):
        self.events.append(ev)


class _FakeState:
    def ensure_open(self, ts):
        pass


def test_emit_quic_streams_drains_leftovers_with_last_timestamp(monkeypatch):
    pkts = [
        _pkt([(0, None, b"AB", False)], ts="1.0"),
        _pkt([(0, 5, b"FG", False)], ts="2.0"),  # gap 2..5 never fills
        _pkt([(4, None, b"Z", False)], ts="3.0"),
    ]
    monkeypatch.setattr(p2t, "build_quic_command", lambda *a, **k: ["tshark"])
    monkeypatch.setattr(p2t, "stream_packets", lambda cmd: iter(pkts))
    bus, result = _FakeBus(), p2t.ConvertResult(tap_path="x.tap")
    p2t._emit_quic_streams(
        "tshark", "in.pcap", None, quic_ports=(), extra_decode_as=(),
        heuristic=False, bus=bus, state=_FakeState(), result=result,
        tracker=p2t._StreamDirectionTracker())
    assert [(e.stream_id, e.data, e.timestamp) for e in bus.events] == [
        (0, b"AB", 1.0), (4, b"Z", 3.0), (0, b"FG", 3.0)]
    assert result.stream_count == 2
    assert result.decrypted_packet_count == 3
