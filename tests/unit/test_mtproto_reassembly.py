"""Hermetic tests for the hand-rolled TCP reassembler."""

from __future__ import annotations

from friTap.offline.mtproto.reassembly import TcpStreamReassembler


def test_in_order_contiguous():
    r = TcpStreamReassembler()
    r.feed(1000, b"AAAA")
    r.feed(1004, b"BBBB")
    r.feed(1008, b"CCCC")
    assert r.contiguous_bytes() == b"AAAABBBBCCCC"
    assert r.degraded is False


def test_out_of_order_reassembled():
    r = TcpStreamReassembler()
    r.feed(2000, b"AAAA")
    r.feed(2008, b"CCCC")  # arrives before the middle
    r.feed(2004, b"BBBB")
    assert r.contiguous_bytes() == b"AAAABBBBCCCC"
    assert r.degraded is False


def test_retransmit_deduped():
    r = TcpStreamReassembler()
    r.feed(500, b"HELLO")
    r.feed(500, b"HELLO")  # exact retransmit
    r.feed(505, b"WORLD")
    assert r.contiguous_bytes() == b"HELLOWORLD"
    assert r.degraded is False


def test_overlapping_retransmit_trimmed():
    r = TcpStreamReassembler()
    r.feed(100, b"ABCD")
    r.feed(102, b"CDEF")  # overlaps then extends
    assert r.contiguous_bytes() == b"ABCDEF"
    assert r.degraded is False


def test_syn_anchors_data_at_seq_plus_one():
    r = TcpStreamReassembler()
    r.feed(999, b"", syn=True)  # SYN consumes seq 999; data starts at 1000
    r.feed(1000, b"DATA")
    assert r.contiguous_bytes() == b"DATA"
    assert r.degraded is False


def test_start_gap_is_degraded():
    r = TcpStreamReassembler()
    r.feed(1000, b"", syn=True)  # anchor at 1001
    r.feed(1050, b"LATEBYTES")  # first data segment past the anchor -> start gap
    assert r.degraded is True


def test_mid_stream_gap_is_degraded():
    r = TcpStreamReassembler()
    r.feed(0, b"AAAA")
    r.feed(8, b"CCCC")  # gap at [4,8)
    assert r.contiguous_bytes() == b"AAAA"
    assert r.degraded is True


def test_no_anchor_no_data_is_degraded():
    r = TcpStreamReassembler()
    assert r.contiguous_bytes() == b""
    assert r.degraded is True


def test_wraparound_seq_is_contiguous():
    """A stream whose 32-bit seq wraps past 2^32 mid-capture still reassembles.

    Regression for the raw-seq comparison that treated the wrap as a giant gap
    and dropped everything after it. With wrap-safe serial arithmetic the
    post-wrap bytes follow the pre-wrap bytes contiguously.
    """
    r = TcpStreamReassembler()
    r.feed(0xFFFFFFF0, b"A" * 16)   # spans 0xFFFFFFF0 .. 0x100000000 (wraps to 0)
    r.feed(0x00000000, b"BBBB")     # the next 4 bytes, just past the wrap
    assert r.contiguous_bytes() == b"A" * 16 + b"BBBB"
    assert r.degraded is False


# --------------------------------------------------------------------------- #
# Per-byte capture timestamps (timestamp_at)
# --------------------------------------------------------------------------- #


def test_timestamp_at_single_segment():
    r = TcpStreamReassembler()
    r.feed(1000, b"ABCD", ts=10.5)
    assert r.timestamp_at(0) == 10.5
    assert r.timestamp_at(3) == 10.5


def test_timestamp_at_multi_segment_maps_each_byte_to_its_segment():
    r = TcpStreamReassembler()
    r.feed(1000, b"AAAA", ts=1.0)
    r.feed(1008, b"CCCC", ts=3.0)  # out of order
    r.feed(1004, b"BBBB", ts=2.0)
    assert [r.timestamp_at(i) for i in (0, 3, 4, 7, 8, 11)] == [1.0, 1.0, 2.0, 2.0, 3.0, 3.0]


def test_timestamp_at_retransmit_keeps_earliest_time():
    r = TcpStreamReassembler()
    r.feed(500, b"HELLO", ts=5.0)
    r.feed(500, b"HELLO", ts=9.0)  # retransmit later — must not move the time
    r.feed(505, b"WORLD", ts=6.0)
    assert r.timestamp_at(0) == 5.0
    assert r.timestamp_at(5) == 6.0


def test_timestamp_at_retransmit_arriving_first_in_file_order_still_min():
    r = TcpStreamReassembler()
    r.feed(500, b"HELLO", ts=9.0)
    r.feed(500, b"HELLO", ts=5.0)
    assert r.timestamp_at(2) == 5.0


def test_timestamp_at_overlap_uses_contributing_segment():
    r = TcpStreamReassembler()
    r.feed(100, b"ABCD", ts=1.0)
    r.feed(102, b"CDEF", ts=2.0)  # only "EF" is new
    assert r.timestamp_at(3) == 1.0
    assert r.timestamp_at(4) == 2.0


def test_timestamp_at_across_seq_wraparound():
    r = TcpStreamReassembler()
    r.feed(0xFFFFFFFC, b"AAAA", ts=1.0)
    r.feed(0x00000000, b"BBBB", ts=2.0)
    assert r.contiguous_bytes() == b"AAAABBBB"
    assert r.timestamp_at(3) == 1.0
    assert r.timestamp_at(4) == 2.0


def test_timestamp_at_unknown_is_zero():
    r = TcpStreamReassembler()
    assert r.timestamp_at(0) == 0.0  # no data at all
    r.feed(1000, b"AAAA")  # no ts supplied
    r.feed(1010, b"CCCC", ts=4.0)  # beyond a gap
    assert r.timestamp_at(0) == 0.0
    assert r.timestamp_at(4) == 0.0  # past the contiguous run
    assert r.timestamp_at(-1) == 0.0


def test_timestamp_at_refreshes_after_new_feed():
    r = TcpStreamReassembler()
    r.feed(1000, b"AAAA", ts=1.0)
    assert r.timestamp_at(4) == 0.0
    r.feed(1004, b"BBBB", ts=2.0)
    assert r.timestamp_at(4) == 2.0
