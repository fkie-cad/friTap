"""Regression tests: IPv6 plaintext packets must be written to the pcap.

The content-only normalization in ``PCAP.log_plaintext_payload`` used to coerce
every non-int address to ``0``, which turned IPv6 hex-string addresses into
``0`` and made ``bytes.fromhex(0)`` raise for every IPv6 packet (TCP and UDP),
so QUIC/IPv6 plaintext captures ended up empty.
"""

import io
import logging
import types

from friTap.constants import SSL_READ, SSL_WRITE
from friTap.pcap import PCAP, _ipv6_bytes

_SRC6 = "20010db8000000000000000000000001"
_DST6 = "20010db8000000000000000000000002"


def _make_stub():
    """Minimal stub bound to the pcap writer methods (see test_pcap_server_port)."""
    stub = types.SimpleNamespace()
    stub.logger = logging.getLogger("test_pcap_ipv6")
    stub.SSL_READ = SSL_READ
    stub.SSL_WRITE = SSL_WRITE
    stub.pcap_file = io.BytesIO()
    stub.ssl_sessions = {}
    stub._observed_server_ports = {"tcp": set(), "udp": set()}
    stub._record_server_port = PCAP._record_server_port.__get__(stub)
    stub._log_plaintext_payload_udp = PCAP._log_plaintext_payload_udp.__get__(stub)
    stub.log_plaintext_payload = PCAP.log_plaintext_payload.__get__(stub)
    return stub


class TestIpv6Bytes:
    def test_hex_string_is_packed(self):
        assert _ipv6_bytes(_SRC6) == bytes.fromhex(_SRC6)

    def test_missing_or_invalid_address_maps_to_placeholder(self):
        for addr in ("", None, 0, "zz", "abcd"):
            assert _ipv6_bytes(addr) == bytes(16)


class TestIpv6PlaintextWrite:
    def test_udp_ipv6_packet_written(self):
        stub = _make_stub()
        read_fn = next(iter(SSL_READ))
        stub.log_plaintext_payload("AF_INET6", read_fn, _SRC6, 443, _DST6, 51234,
                                   b"quic-plaintext", transport="udp")
        written = stub.pcap_file.getvalue()
        assert bytes.fromhex(_SRC6) in written
        assert bytes.fromhex(_DST6) in written
        assert written.endswith(b"quic-plaintext")

    def test_tcp_ipv6_packet_written(self):
        stub = _make_stub()
        write_fn = next(iter(SSL_WRITE))
        stub.log_plaintext_payload("AF_INET6", write_fn, _SRC6, 51234, _DST6, 443,
                                   b"GET / HTTP/1.1\r\n")
        written = stub.pcap_file.getvalue()
        assert bytes.fromhex(_SRC6) in written
        assert written.endswith(b"GET / HTTP/1.1\r\n")

    def test_content_only_ipv6_packet_uses_placeholder(self):
        stub = _make_stub()
        read_fn = next(iter(SSL_READ))
        stub.log_plaintext_payload("AF_INET6", read_fn, "", "", "", "",
                                   b"e2e-content", transport="udp")
        assert stub.pcap_file.getvalue().endswith(b"e2e-content")
