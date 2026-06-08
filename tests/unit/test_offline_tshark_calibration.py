#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Real-tshark calibration harness for the offline metadata extractors.

These tests are GATED: the WHOLE module skips when tshark cannot be located OR
scapy cannot be imported. When both are present (as in CI/dev environments with
Wireshark + scapy installed) they craft minimal real pcaps with scapy and run
the offline extractors through the REAL tshark binary, verifying that the field
names and codepoint renderings the pure parsers depend on are still accurate.

A calibration mismatch here is a REAL finding (e.g. tshark renamed a field or
changed a rendering), not a flaky test — do not weaken the assertions to make
it pass.
"""

from __future__ import annotations

import warnings

import pytest

# Gate 1: locate tshark (None when unavailable).
try:
    from friTap.offline.tshark import find_tshark
    try:
        _TSHARK = find_tshark()
    except Exception:
        _TSHARK = None
except Exception:  # pragma: no cover - import-time failure
    _TSHARK = None

# Gate 2: scapy must be importable.
scapy = pytest.importorskip("scapy")

pytestmark = pytest.mark.skipif(_TSHARK is None, reason="tshark not installed")

# scapy's TLS/SSH crafting is noisy; silence the warnings module-wide.
warnings.filterwarnings("ignore")

from friTap.offline.tshark import (  # noqa: E402  (after the gates)
    extract_quic_metadata,
    extract_ssh_connections,
    extract_tls_metadata,
)


def test_tls_metadata_calibration(tmp_path):
    """A crafted TLS 1.3 handshake yields SNI/cipher/version/ALPN via tshark."""
    from scapy.all import IP, TCP, wrpcap, raw
    from scapy.layers.tls.record import TLS
    from scapy.layers.tls.handshake import TLSClientHello, TLSServerHello
    from scapy.layers.tls.extensions import (
        TLS_Ext_ServerName, ServerName, TLS_Ext_ALPN,
        ProtocolName, TLS_Ext_SupportedVersion_SH,
    )

    pcap_path = tmp_path / "tls_calib.pcap"
    C = ("10.0.0.1", 50000)
    S = ("93.184.216.34", 443)
    ch = TLS(msg=[TLSClientHello(
        ciphers=[0x1301, 0xc02f],
        ext=[
            TLS_Ext_ServerName(servernames=[ServerName(servername=b"example.com")]),
            TLS_Ext_ALPN(protocols=[ProtocolName(protocol=b"h2")]),
        ])])
    sh = TLS(msg=[TLSServerHello(
        cipher=0x1301,
        ext=[
            TLS_Ext_SupportedVersion_SH(version=0x0304),
            TLS_Ext_ALPN(protocols=[ProtocolName(protocol=b"h2")]),
        ])])
    p1 = IP(src=C[0], dst=S[0]) / TCP(sport=C[1], dport=S[1], flags="PA",
                                      seq=1, ack=1) / raw(ch)
    p2 = IP(src=S[0], dst=C[0]) / TCP(sport=S[1], dport=C[1], flags="PA",
                                      seq=1, ack=len(raw(ch)) + 1) / raw(sh)
    wrpcap(str(pcap_path), [p1, p2])

    meta = extract_tls_metadata(_TSHARK, str(pcap_path), None)
    assert meta == {0: {
        "sni": "example.com",
        "cipher": "TLS_AES_128_GCM_SHA256",
        "version": "TLS 1.3",
        "alpn": "h2",
    }}


def test_ssh_metadata_calibration(tmp_path):
    """A crafted SSH banner + KEXINIT exchange yields connection metadata."""
    import struct
    from scapy.all import IP, TCP, wrpcap, Raw

    def namelist(s):
        b = s.encode()
        return struct.pack(">I", len(b)) + b

    def kexinit(kex, enc, mac):
        payload = (bytes([20]) + b"\x00" * 16
                   + namelist(kex) + namelist("ssh-ed25519")
                   + namelist(enc) + namelist(enc)
                   + namelist(mac) + namelist(mac)
                   + namelist("none") * 2 + namelist("") * 2
                   + b"\x00" + b"\x00\x00\x00\x00")
        pad = 8 - ((len(payload) + 5) % 8)
        pad = pad if pad >= 4 else pad + 8
        pkt = bytes([pad]) + payload + b"\x00" * pad
        return struct.pack(">I", len(pkt)) + pkt

    pcap_path = tmp_path / "ssh_calib.pcap"
    C = ("10.0.0.1", 51000)
    S = ("2.2.2.2", 22)
    cb = b"SSH-2.0-OpenSSH_9.6\r\n"
    sb = b"SSH-2.0-OpenSSH_8.9\r\n"
    ck = kexinit("curve25519-sha256", "aes256-gcm@openssh.com", "hmac-sha2-256")
    sk = kexinit("curve25519-sha256", "chacha20-poly1305@openssh.com",
                 "hmac-sha2-512")
    pkts = [
        IP(src=C[0], dst=S[0]) / TCP(sport=C[1], dport=S[1], flags="PA",
                                     seq=1, ack=1) / Raw(cb),
        IP(src=S[0], dst=C[0]) / TCP(sport=S[1], dport=C[1], flags="PA",
                                     seq=1, ack=len(cb) + 1) / Raw(sb),
        IP(src=C[0], dst=S[0]) / TCP(sport=C[1], dport=S[1], flags="PA",
                                     seq=len(cb) + 1, ack=len(sb) + 1) / Raw(ck),
        IP(src=S[0], dst=C[0]) / TCP(sport=S[1], dport=C[1], flags="PA",
                                     seq=len(sb) + 1,
                                     ack=len(cb) + len(ck) + 1) / Raw(sk),
    ]
    wrpcap(str(pcap_path), pkts)

    conns = extract_ssh_connections(_TSHARK, str(pcap_path))
    assert len(conns) == 1
    c = conns[0]
    assert c["client_version"] == "SSH-2.0-OpenSSH_9.6"
    assert c["server_version"] == "SSH-2.0-OpenSSH_8.9"
    assert c["kex"] == "curve25519-sha256"
    assert c["cipher"] == "aes256-gcm@openssh.com"
    assert c["mac"] == "hmac-sha2-256"


def test_quic_version_calibration(tmp_path):
    """A crafted QUIC v1 Initial long header yields version "1" via tshark.

    ALPN/cipher are empty here — a bare Initial carries no decryptable TLS
    handshake, so only the plaintext quic.version is recoverable.
    """
    import struct
    from scapy.all import IP, UDP, wrpcap, Raw

    pcap_path = tmp_path / "quic_calib.pcap"
    hdr = (bytes([0xC3]) + struct.pack(">I", 0x00000001)
           + bytes([8]) + b"\xde\xad\xbe\xef\xca\xfe\x00\x01"
           + bytes([0]) + bytes([0])
           + b"\x44\x10" + b"\x00\x00\x00\x00" + b"\x00" * 40)
    pkt = IP(src="10.0.0.1", dst="2.2.2.2") / UDP(sport=50000, dport=443) / Raw(hdr)
    wrpcap(str(pcap_path), [pkt])

    meta = extract_quic_metadata(_TSHARK, str(pcap_path), None)
    assert meta, "tshark produced no QUIC metadata for the crafted Initial"
    assert meta[0]["version"] == "1"
