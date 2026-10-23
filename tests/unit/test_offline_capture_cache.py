"""One scapy parse per conversion: ParsedCapture, the capture cache scope, and
the orchestrator wiring (friTap.offline.net.tcp_reassembly / capture_cache)."""

from __future__ import annotations

import hashlib
import os

import pytest

pytest.importorskip("scapy.all")

from scapy.all import ARP, IP, TCP, UDP, Dot1Q, Ether, IPv6, wrpcap  # noqa: E402

from friTap.offline.net import capture_cache, tcp_reassembly  # noqa: E402
from friTap.offline.net.tcp_reassembly import (  # noqa: E402
    ConvBuilder,
    TcpStreamPair,
    normalized_key,
    parse_pcap,
    reassemble_pcap,
)
from tests.unit import _fake_tshark as ft  # noqa: E402

_CLIENT = ("10.0.0.5", 50000)
_SERVER = ("10.0.0.9", 443)
_ETH = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")


# --------------------------------------------------------------------------- #
# ConvBuilder.finalize is pure and repeatable
# --------------------------------------------------------------------------- #

def test_finalize_twice_with_different_ports_reorients_and_shares_reassemblers():
    b = ConvBuilder("AF_INET", (443,))
    # Server-first mid-stream conversation between 50000 and 443.
    b.add(*_SERVER, *_CLIENT, 1000, b"server-first", False, False, ts=1.0)
    b.add(*_CLIENT, *_SERVER, 2000, b"client", False, False, ts=2.0)

    by_443 = b.finalize(server_ports=(443,))
    by_50000 = b.finalize(server_ports=(50000,))
    default = b.finalize()  # falls back to the constructor's ports

    assert by_443.client_addr == _CLIENT and by_443.server_addr == _SERVER
    assert by_50000.client_addr == _SERVER and by_50000.server_addr == _CLIENT
    assert default.client_addr == _CLIENT
    # Fresh pairs, same reassembler objects.
    assert by_443 is not default
    assert by_443.client is by_50000.server is default.client
    assert by_443.server is by_50000.client is default.server
    assert by_443.client.contiguous_bytes() == b"client"


def test_finalize_pair_cls_override_and_fallback():
    class Tagged(TcpStreamPair):
        pass

    b = ConvBuilder("AF_INET", (443,), Tagged)
    b.add(*_CLIENT, *_SERVER, 1, b"x", False, False)
    assert type(b.finalize()) is Tagged
    assert type(b.finalize(pair_cls=TcpStreamPair)) is TcpStreamPair
    assert type(b.finalize()) is Tagged  # the override did not stick


# --------------------------------------------------------------------------- #
# parse_pcap().pairs(...) == the legacy single-function reassembly
# --------------------------------------------------------------------------- #

def _legacy_reassemble(path, server_ports, pair_cls=TcpStreamPair):
    """The pre-split reassemble_pcap: one ConvBuilder per key, ports fixed upfront."""
    from scapy.layers.inet import IP as _IP
    from scapy.layers.inet import TCP as _TCP
    from scapy.layers.inet6 import IPv6 as _IPv6
    from scapy.packet import Raw
    from scapy.utils import PcapReader

    pending = {}
    with PcapReader(path) as reader:
        for pkt in reader:
            if _IP in pkt:
                ip, family = pkt[_IP], "AF_INET"
            elif _IPv6 in pkt:
                ip, family = pkt[_IPv6], "AF_INET6"
            else:
                continue
            if _TCP not in pkt:
                continue
            tcp = pkt[_TCP]
            sport, dport = int(tcp.sport), int(tcp.dport)
            flags = int(tcp.flags)
            key = normalized_key(ip.src, sport, ip.dst, dport)
            builder = pending.setdefault(key, ConvBuilder(family, server_ports, pair_cls))
            builder.add(ip.src, sport, ip.dst, dport, int(tcp.seq),
                        tcp_reassembly.tcp_payload(ip, tcp, Raw),
                        bool(flags & 0x02), bool(flags & 0x01), ts=float(pkt.time))
    return {key: b.finalize() for key, b in pending.items()}


def _summary(pairs):
    def side(r):
        data = r.contiguous_bytes()
        return (data, r.degraded, r.has_start_gap, r.bytes_after_start_gap(),
                [r.timestamp_at(i) for i in range(0, len(data), 3)])
    return {
        key: (type(p).__name__, p.client_addr, p.server_addr, p.ss_family,
              side(p.client), side(p.server), getattr(p, "degraded", None))
        for key, p in pairs.items()
    }


def _tcp(src, dst, sport, dport, seq, flags="PA", payload=b"", v6=False, vlan=False):
    ip = IPv6(src=src, dst=dst) if v6 else IP(src=src, dst=dst)
    frame = _ETH / Dot1Q(vlan=7) / ip if vlan else _ETH / ip
    pkt = frame / TCP(sport=sport, dport=dport, seq=seq, flags=flags)
    return pkt / payload if payload else pkt


@pytest.fixture
def mixed_pcap(tmp_path):
    a, b, c = "10.1.0.1", "10.1.0.2", "10.1.0.3"
    v6a, v6b = "2001:db8::1", "2001:db8::2"
    pkts = [
        _ETH / ARP(psrc=a, pdst=b),
        # IPv4 443 with handshake, client first.
        _tcp(a, b, 40001, 443, 100, "S"),
        _tcp(a, b, 40001, 443, 101, payload=b"hello-443"),
        _tcp(b, a, 443, 40001, 900, payload=b"reply-443"),
        _ETH / IP(src=a, dst=b) / UDP(sport=5353, dport=5353) / b"noise",
        # Server-first mid-stream on 443 (no SYN).
        _tcp(c, a, 443, 40002, 5000, payload=b"server-speaks-first"),
        _tcp(a, c, 40002, 443, 7000, payload=b"client-later"),
        # Port 80 and 5222 flows, server first, so the port set decides roles.
        _tcp(b, c, 80, 40003, 10, payload=b"http-server"),
        _tcp(c, b, 40003, 80, 20, payload=b"http-client"),
        _tcp(a, c, 5222, 40004, 30, payload=b"xmpp-server"),
        _tcp(c, a, 40004, 5222, 40, payload=b"xmpp-client"),
        # IPv6 with a gap and a retransmit.
        _tcp(v6a, v6b, 40005, 443, 1, payload=b"v6-one", v6=True),
        _tcp(v6a, v6b, 40005, 443, 1, payload=b"v6-one", v6=True),
        _tcp(v6a, v6b, 40005, 443, 20, payload=b"after-gap", v6=True),
        _tcp(v6b, v6a, 443, 40005, 50, payload=b"v6-reply", v6=True),
        # VLAN-tagged IPv4.
        _tcp(a, b, 40006, 443, 300, payload=b"vlan-client", vlan=True),
        _tcp(b, a, 443, 40006, 400, payload=b"vlan-server", vlan=True),
    ]
    for i, pkt in enumerate(pkts):
        pkt.time = 1_700_000_000 + i * 0.25
    path = tmp_path / "mixed.pcap"
    wrpcap(str(path), pkts)
    return str(path)


@pytest.mark.parametrize("ports", [(443,), (443, 80), (443, 80, 5222)])
def test_parse_pcap_pairs_match_legacy(mixed_pcap, ports):
    parsed = parse_pcap(mixed_pcap)
    assert len(parsed) == 6
    assert _summary(parsed.pairs(ports)) == _summary(_legacy_reassemble(mixed_pcap, ports))
    assert _summary(reassemble_pcap(mixed_pcap, server_ports=ports)) == _summary(
        _legacy_reassemble(mixed_pcap, ports))


def test_parse_pcap_pairs_match_legacy_for_mtproto_stream_pair(mixed_pcap):
    from friTap.offline.mtproto import reassembly as mt

    ports = (443, 80, 5222)
    parsed = parse_pcap(mixed_pcap)
    got = parsed.pairs(ports, mt.StreamPair)
    assert all(type(p) is mt.StreamPair for p in got.values())
    assert _summary(got) == _summary(_legacy_reassemble(mixed_pcap, ports, mt.StreamPair))
    assert _summary(mt.reassemble_pcap(mixed_pcap)) == _summary(got)


def test_pairs_are_fresh_but_share_reassemblers(mixed_pcap):
    parsed = parse_pcap(mixed_pcap)
    first, second = parsed.pairs((443,)), parsed.pairs((443, 80))
    assert first is not second
    for key in first:
        assert first[key] is not second[key]
        assert {id(first[key].client), id(first[key].server)} == {
            id(second[key].client), id(second[key].server)}


def test_explicit_parsed_capture_is_used(mixed_pcap, monkeypatch):
    parsed = parse_pcap(mixed_pcap)
    monkeypatch.setattr(tcp_reassembly, "parse_pcap",
                        lambda path: pytest.fail("must not re-parse"))
    pairs = reassemble_pcap("/nonexistent.pcap", server_ports=(443,), parsed=parsed)
    assert len(pairs) == 6


# --------------------------------------------------------------------------- #
# capture_cache_scope semantics
# --------------------------------------------------------------------------- #

@pytest.fixture
def parse_counter(monkeypatch):
    calls = []
    original = tcp_reassembly.parse_pcap

    def counting(path):
        calls.append(path)
        return original(path)

    monkeypatch.setattr(tcp_reassembly, "parse_pcap", counting)
    return calls


def test_scope_parses_once_for_any_port_set(mixed_pcap, parse_counter):
    with capture_cache.capture_cache_scope(mixed_pcap) as cache:
        a = reassemble_pcap(mixed_pcap, server_ports=(443,))
        b = reassemble_pcap(mixed_pcap, server_ports=(443, 80, 5222))
    assert len(parse_counter) == 1 and cache.parse_count == 1
    assert _summary(a) == _summary(_legacy_reassemble(mixed_pcap, (443,)))
    assert _summary(b) == _summary(_legacy_reassemble(mixed_pcap, (443, 80, 5222)))
    # Outside the scope every call parses again.
    reassemble_pcap(mixed_pcap)
    assert len(parse_counter) == 2
    assert capture_cache.active_parsed_capture(mixed_pcap) is None


def test_scope_bypasses_other_paths(mixed_pcap, tmp_path, parse_counter):
    other = tmp_path / "other.pcap"
    other.write_bytes(open(mixed_pcap, "rb").read())
    with capture_cache.capture_cache_scope(mixed_pcap) as cache:
        reassemble_pcap(str(other))
        reassemble_pcap(str(other))
        assert cache.parse_count == 0
    assert len(parse_counter) == 2


def test_scope_bypasses_a_modified_capture(mixed_pcap, parse_counter):
    with capture_cache.capture_cache_scope(mixed_pcap) as cache:
        reassemble_pcap(mixed_pcap)
        st = os.stat(mixed_pcap)
        os.utime(mixed_pcap, ns=(st.st_atime_ns, st.st_mtime_ns + 1_000_000_000))
        reassemble_pcap(mixed_pcap)
        assert cache.parse_count == 1
    assert len(parse_counter) == 2


def test_symlinked_path_shares_the_parse(mixed_pcap, tmp_path, parse_counter):
    link = tmp_path / "link.pcap"
    link.symlink_to(mixed_pcap)
    with capture_cache.capture_cache_scope(mixed_pcap):
        reassemble_pcap(str(link))
        reassemble_pcap(mixed_pcap)
    assert len(parse_counter) == 1


@pytest.mark.parametrize("env_value, cached", [("0", False), ("0.000001", False),
                                               ("1", True), ("bogus", True)])
def test_size_threshold_from_env(mixed_pcap, parse_counter, monkeypatch, env_value, cached):
    monkeypatch.setenv(capture_cache.MAX_MB_ENV, env_value)
    with capture_cache.capture_cache_scope(mixed_pcap) as cache:
        reassemble_pcap(mixed_pcap)
        reassemble_pcap(mixed_pcap)
    assert len(parse_counter) == (1 if cached else 2)
    if env_value == "0":
        assert cache is None


def test_nested_scopes_restore_the_outer_one(mixed_pcap, tmp_path, parse_counter):
    other = tmp_path / "other.pcap"
    other.write_bytes(open(mixed_pcap, "rb").read())
    with capture_cache.capture_cache_scope(mixed_pcap) as outer:
        reassemble_pcap(mixed_pcap)
        with capture_cache.capture_cache_scope(str(other)) as inner:
            reassemble_pcap(str(other))
            reassemble_pcap(str(other))
            assert capture_cache._ACTIVE_CACHE.get() is inner
        assert capture_cache._ACTIVE_CACHE.get() is outer
        reassemble_pcap(mixed_pcap)
    assert capture_cache._ACTIVE_CACHE.get() is None
    assert (outer.parse_count, inner.parse_count) == (1, 1)
    assert len(parse_counter) == 2


def test_scope_is_reset_when_the_body_raises(mixed_pcap):
    with pytest.raises(RuntimeError):
        with capture_cache.capture_cache_scope(mixed_pcap):
            raise RuntimeError("boom")
    assert capture_cache._ACTIVE_CACHE.get() is None


def test_parse_errors_are_not_memoized(mixed_pcap, monkeypatch):
    original = tcp_reassembly.parse_pcap
    attempts = []

    def flaky(path):
        attempts.append(path)
        if len(attempts) == 1:
            raise OSError("transient")
        return original(path)

    monkeypatch.setattr(tcp_reassembly, "parse_pcap", flaky)
    with capture_cache.capture_cache_scope(mixed_pcap) as cache:
        with pytest.raises(OSError):
            reassemble_pcap(mixed_pcap)
        assert len(reassemble_pcap(mixed_pcap)) == 6
        reassemble_pcap(mixed_pcap)
    assert len(attempts) == 2 and cache.parse_count == 1


# --------------------------------------------------------------------------- #
# The orchestrator parses once per conversion
# --------------------------------------------------------------------------- #

def _write_orchestrator_inputs(tmp_path):
    pcap = tmp_path / "x.pcap"
    wrpcap(str(pcap), [
        IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=40000, dport=443, seq=1,
                                                 flags="PA") / (b"\xef" + bytes(100)),
        IP(src="10.0.0.2", dst="10.0.0.1") / TCP(sport=443, dport=40000, seq=9,
                                                 flags="PA") / bytes(50),
    ])
    key = bytes(range(256))
    key_id = hashlib.sha1(key).digest()[-8:]
    mt = tmp_path / "mt.log"
    mt.write_text(f"MTPROTO_AUTH_KEY 2 {key_id.hex()} {key.hex()} perm\n")
    rc4 = tmp_path / "rc4.log"
    rc4.write_text("RC4_KEY 6672697461702d7263342d64656d6f2d6b6579 19 trial-key(mem) in 4116\n")
    return str(pcap), {"mtproto": str(mt), "rc4": str(rc4)}


@pytest.mark.parametrize("cache_mb, expected_parses", [(None, 1), ("0", 2)])
def test_conversion_parses_the_capture_once(tmp_path, parse_counter, monkeypatch,
                                            cache_mb, expected_parses):
    """MTProto and standalone RC4 both reassemble raw TCP; with the cache they
    share one parse (and with it disabled each parses, proving both ran)."""
    pytest.importorskip("cryptography")
    from friTap.offline.pcap_to_tap import convert_pcap_to_tap

    ft.stub_tshark_discovery(monkeypatch)
    if cache_mb is not None:
        monkeypatch.setenv(capture_cache.MAX_MB_ENV, cache_mb)
    pcap, keylogs = _write_orchestrator_inputs(tmp_path)
    result = convert_pcap_to_tap(pcap, tap_path=str(tmp_path / "x.tap"),
                                 run_scan=False, protocol_keylogs=keylogs)
    per_protocol = result.to_dict().get("per_protocol") or {}
    assert per_protocol["mtproto"]["streams"] == 1
    assert per_protocol["rc4"]["streams"] == 1
    assert len(parse_counter) == expected_parses
    assert capture_cache._ACTIVE_CACHE.get() is None  # released after conversion


# --------------------------------------------------------------------------- #
# Non-finite size limits and consumer-count gating
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("env_value", ["inf", "-inf", "1e400", "nan", "NaN"])
def test_non_finite_size_limit_falls_back_to_default(monkeypatch, env_value):
    monkeypatch.setenv(capture_cache.MAX_MB_ENV, env_value)
    assert capture_cache.max_cache_bytes() == capture_cache.DEFAULT_MAX_MB * 1024 * 1024


def test_non_finite_size_limit_does_not_escape_the_scope(mixed_pcap, parse_counter,
                                                        monkeypatch):
    monkeypatch.setenv(capture_cache.MAX_MB_ENV, "inf")
    with capture_cache.capture_cache_scope(mixed_pcap) as cache:
        reassemble_pcap(mixed_pcap)
        reassemble_pcap(mixed_pcap)
    assert cache is not None and len(parse_counter) == 1


@pytest.mark.parametrize("expected, cached", [(None, True), (0, False), (1, False),
                                              (2, True), (3, True)])
def test_scope_caches_only_with_two_or_more_consumers(mixed_pcap, parse_counter,
                                                      expected, cached):
    with capture_cache.capture_cache_scope(mixed_pcap,
                                           expected_consumers=expected) as cache:
        reassemble_pcap(mixed_pcap)
        reassemble_pcap(mixed_pcap)
    assert (cache is not None) is cached
    assert len(parse_counter) == (1 if cached else 2)


def test_possible_raw_tcp_consumers_counts_sidecar_and_plan(tmp_path):
    from friTap.offline.pcap_to_tap import _possible_raw_tcp_consumers

    sidecar = tmp_path / "s.tls_midstream.secrets.jsonl"
    assert _possible_raw_tcp_consumers(None, []) == 0
    assert _possible_raw_tcp_consumers(str(sidecar), ["a"]) == 1  # absent sidecar
    sidecar.write_text("{}\n")
    assert _possible_raw_tcp_consumers(str(sidecar), ["a"]) == 2
    assert _possible_raw_tcp_consumers(None, ["a", "b"]) == 2


def test_single_consumer_conversion_holds_no_cache(tmp_path, parse_counter, monkeypatch):
    """A lone raw-TCP consumer gets no cache scope, so its parse is not retained."""
    pytest.importorskip("cryptography")
    from friTap.offline.pcap_to_tap import convert_pcap_to_tap

    created = []
    original_init = capture_cache.CaptureCache.__init__

    def spy_init(self, *args, **kwargs):
        created.append(self)
        original_init(self, *args, **kwargs)

    monkeypatch.setattr(capture_cache.CaptureCache, "__init__", spy_init)
    ft.stub_tshark_discovery(monkeypatch)
    pcap, keylogs = _write_orchestrator_inputs(tmp_path)
    result = convert_pcap_to_tap(pcap, tap_path=str(tmp_path / "x.tap"),
                                 run_scan=False,
                                 protocol_keylogs={"mtproto": keylogs["mtproto"]})
    per_protocol = result.to_dict().get("per_protocol") or {}
    assert per_protocol["mtproto"]["streams"] == 1
    assert created == [] and len(parse_counter) == 1
