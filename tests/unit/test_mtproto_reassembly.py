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
