"""Protocol-neutral TCP reassembly (friTap.offline.net.tcp_reassembly)."""

import pytest

from friTap.offline.net.tcp_reassembly import (
    ConvBuilder,
    TcpStreamPair,
    TcpStreamReassembler,
    normalized_key,
    reassemble_pcap,
)

_CLIENT = ("10.0.0.5", 50000)
_SERVER = ("10.0.0.9", 443)


def test_contiguous_run_stops_at_gap():
    r = TcpStreamReassembler()
    r.feed(100, b"", syn=True)
    r.feed(101, b"abc")
    r.feed(107, b"xyz")  # gap at 104..106
    assert r.contiguous_bytes() == b"abc"
    assert r.degraded
    r.feed(104, b"def")
    assert r.contiguous_bytes() == b"abcdefxyz"
    assert not r.degraded


def test_retransmit_keeps_longest_copy():
    r = TcpStreamReassembler()
    r.feed(1, b"", syn=True)
    r.feed(2, b"ab")
    r.feed(2, b"abcd")
    r.feed(2, b"a")
    assert r.contiguous_bytes() == b"abcd"


def test_sequence_wrap_is_contiguous():
    r = TcpStreamReassembler()
    start = 0xFFFFFFFE
    r.feed(start, b"1234")
    r.feed((start + 4) & 0xFFFFFFFF, b"5678")
    assert r.contiguous_bytes() == b"12345678"
    assert not r.degraded


def test_normalized_key_is_direction_independent():
    a = normalized_key(*_CLIENT, *_SERVER)
    b = normalized_key(*_SERVER, *_CLIENT)
    assert a == b


def test_conv_builder_defaults_to_neutral_pair_without_degraded():
    b = ConvBuilder("AF_INET", (443,))
    b.add(*_SERVER, *_CLIENT, 1000, b"server-first", False, False, ts=1.0)
    b.add(*_CLIENT, *_SERVER, 2000, b"client", False, False, ts=2.0)
    pair = b.finalize()
    assert type(pair) is TcpStreamPair
    assert not hasattr(pair, "degraded")
    assert pair.client_addr == _CLIENT
    assert pair.client.contiguous_bytes() == b"client"


def test_conv_builder_honours_pair_cls():
    class Tagged(TcpStreamPair):
        pass

    b = ConvBuilder("AF_INET", (443,), Tagged)
    b.add(*_CLIENT, *_SERVER, 1, b"x", False, False)
    assert type(b.finalize()) is Tagged


def test_reassemble_pcap_keeps_443_payload_with_scapy_tls_loaded(tmp_path):
    pytest.importorskip("scapy.all")
    pytest.importorskip("scapy.layers.tls.record")  # binds TCP/443 -> TLS
    from scapy.all import IP, TCP, wrpcap

    payload = b"\x17\x03\x03\x00\x05hello" + bytes(range(50))
    pkts = [
        IP(src=_CLIENT[0], dst=_SERVER[0]) / TCP(
            sport=_CLIENT[1], dport=_SERVER[1], seq=1000, flags="S"),
        IP(src=_CLIENT[0], dst=_SERVER[0]) / TCP(
            sport=_CLIENT[1], dport=_SERVER[1], seq=1001, flags="PA") / payload,
    ]
    path = tmp_path / "tls_looking.pcap"
    wrpcap(str(path), pkts)
    pairs = reassemble_pcap(str(path))
    (pair,) = pairs.values()
    assert type(pair) is TcpStreamPair
    assert pair.client_addr == _CLIENT
    assert pair.client.contiguous_bytes() == payload


def test_mtproto_shim_still_builds_degraded_aware_pairs():
    from friTap.offline.mtproto import reassembly as mt
    from friTap.offline.mtproto.transport import _INIT_LEN

    assert mt.INIT_BLOCK_LEN == _INIT_LEN == 64
    assert mt.TcpStreamReassembler is TcpStreamReassembler
    b = mt._ConvBuilder("AF_INET", (443,))
    b.add(*_CLIENT, *_SERVER, 1, b"short", True, False)
    pair = b.finalize()
    assert isinstance(pair, mt.StreamPair)
    assert pair.degraded  # fewer than 64 client bytes


def test_cached_views_invalidate_on_feed():
    """Reads memoize the ordered/contiguous/after-gap views; feed() must reset them."""
    r = TcpStreamReassembler()
    r.feed(100, b"", syn=True)
    r.feed(104, b"def")  # start gap: bytes 101..103 missing
    assert r.has_start_gap and r.degraded
    assert r.contiguous_bytes() == b""
    assert r.bytes_after_start_gap() == b"def"
    r.feed(107, b"gh")  # extends the post-gap run
    assert r.bytes_after_start_gap() == b"defgh"
    r.feed(101, b"abc")  # fills the start gap
    assert not r.has_start_gap and not r.degraded
    assert r.contiguous_bytes() == b"abcdefgh"
    assert r.bytes_after_start_gap() == b"abcdefgh"
