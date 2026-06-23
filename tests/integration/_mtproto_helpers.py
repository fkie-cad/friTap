"""Shared scaffolding for the hermetic MTProto / Telegram offline e2e tests.

Both ``test_offline_mtproto_e2e`` and ``test_offline_telegram_e2e`` build a
synthetic obfuscated MTProto stream over a fake TCP flow and run it through the
real ``convert_pcap_to_tap`` path with the tshark seams monkeypatched. The
stream-construction primitives are identical between the two, so they live here.
"""

from __future__ import annotations

import os

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from scapy.layers.inet import IP, TCP
from scapy.packet import Raw

import friTap.offline.pcap_to_tap as p2t
from friTap.offline.mtproto.transport import derive_obfuscation_keys

CLIENT = ("10.0.0.5", 50000)
SERVER = ("149.154.167.51", 443)


def _ctr(key, iv):
    return Cipher(algorithms.AES(key), modes.CTR(iv)).encryptor()


def _intermediate(payload: bytes) -> bytes:
    return len(payload).to_bytes(4, "little") + payload


def _build_init(tag: bytes) -> bytes:
    enc_init = bytearray(os.urandom(64))
    key_out, iv_out, _, _ = derive_obfuscation_keys(bytes(enc_init))
    dec = bytearray(_ctr(key_out, iv_out).update(bytes(enc_init)))
    dec[56:60] = tag
    return _ctr(key_out, iv_out).update(bytes(dec))


def _obfuscate(init: bytes, client_payload: bytes, server_payload: bytes):
    key_out, iv_out, key_in, iv_in = derive_obfuscation_keys(init)
    out = _ctr(key_out, iv_out)
    out.update(init)  # advance over the 64 init bytes (they are on the wire as-is)
    client_wire = init + out.update(client_payload)
    server_wire = _ctr(key_in, iv_in).update(server_payload)
    return client_wire, server_wire


def _seg(src, dst, seq, payload, syn=False):
    return (
        IP(src=src[0], dst=dst[0])
        / TCP(sport=src[1], dport=dst[1], seq=seq, flags=("S" if syn else "PA"))
        / Raw(load=payload)
    )


def _patch_tshark(monkeypatch):
    monkeypatch.setattr(p2t, "find_tshark", lambda *a, **k: "/usr/bin/tshark")
    monkeypatch.setattr(p2t, "tshark_version", lambda path: (4, 6, 0))
    monkeypatch.setattr(p2t, "warn_if_outdated", lambda *a, **k: None)
    monkeypatch.setattr(p2t, "capture_has_dsb", lambda *a, **k: False)
    # SSH metadata pass shells out to tshark; no-op it for the hermetic run.
    monkeypatch.setattr(p2t, "_emit_ssh_connections", lambda *a, **k: None)
