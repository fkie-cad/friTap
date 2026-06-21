"""Golden end-to-end test: synthetic Telegram pcap + keylog -> decrypted .tap.

Hermetic — no device, no real Telegram traffic, no tshark (the tshark seams are
monkeypatched; MTProto decryption is friTap's own and works on the synthetic
pcap directly). Proves the full Phase-B path: convert_pcap_to_tap(mtproto_keylog=…)
decrypts the obfuscated MTProto stream into an MtprotoLayer flow in the .tap.
"""

from __future__ import annotations

import os

import pytest

pytest.importorskip("cryptography")

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from scapy.layers.inet import IP, TCP
from scapy.packet import Raw
from scapy.utils import wrpcap

import friTap.offline.pcap_to_tap as p2t
from friTap.flow.layers import MtprotoLayer
from friTap.flow.tap_reader import TapReader
from friTap.offline.mtproto import crypto
from friTap.offline.mtproto.transport import derive_obfuscation_keys
from friTap.protocols import mtproto_keylog_spec as spec

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


def test_offline_mtproto_golden(tmp_path, monkeypatch):
    _patch_tshark(monkeypatch)

    auth_key = os.urandom(crypto.AUTH_KEY_LEN)
    msg_c2s = b"TG client->server hello"
    msg_s2c = b"TG server->client reply"

    rec_c2s = crypto.build_encrypted_record(auth_key, msg_c2s, "write")
    rec_s2c = crypto.build_encrypted_record(auth_key, msg_s2c, "read")

    init = _build_init(b"\xee\xee\xee\xee")  # intermediate transport tag
    client_wire, server_wire = _obfuscate(init, _intermediate(rec_c2s), _intermediate(rec_s2c))

    # Build the pcap: SYN, client data (split + out-of-order + a retransmit), server reply.
    base_c, base_s = 1000, 5000
    half = len(client_wire) // 2
    pkts = [
        _seg(CLIENT, SERVER, base_c, b"", syn=True),
        # out-of-order: second half first, then first half, then retransmit first half
        _seg(CLIENT, SERVER, base_c + 1 + half, client_wire[half:]),
        _seg(CLIENT, SERVER, base_c + 1, client_wire[:half]),
        _seg(CLIENT, SERVER, base_c + 1, client_wire[:half]),  # retransmit (dup)
        _seg(SERVER, CLIENT, base_s, server_wire),
    ]
    pcap_path = str(tmp_path / "tg.pcapng")
    wrpcap(pcap_path, pkts)

    # Write the MTProto keylog.
    keylog_path = str(tmp_path / "tg.keys")
    line = spec.format_line(
        dc_id=2,
        auth_key_id=crypto.compute_auth_key_id(auth_key).hex(),
        auth_key=auth_key.hex(),
        key_type="temp",
    )
    assert line is not None
    with open(keylog_path, "w") as fh:
        fh.write(spec.HEADER_COMMENT + "\n" + line + "\n")

    tap_path = str(tmp_path / "tg.tap")
    result = p2t.convert_pcap_to_tap(pcap_path, mtproto_keylog=keylog_path, tap_path=tap_path)

    # Both directions decrypted.
    assert result.mtproto_messages == 2
    assert result.mtproto_records_undecryptable == 0
    assert result.decrypted_packet_count == 2
    assert result.flow_count >= 1

    # The .tap round-trips an MTProto flow carrying the decrypted message bytes.
    reader = TapReader(tap_path)
    reader.open()
    flows = reader.read_all_flows()
    mtproto_flows = [f for f in flows if f.transport == "mtproto"]
    assert mtproto_flows, "expected at least one mtproto flow"
    flow = mtproto_flows[0]
    assert isinstance(flow.mtproto, MtprotoLayer)
    blob = flow.get_direction_bytes("write") + flow.get_direction_bytes("read")
    assert msg_c2s in blob
    assert msg_s2c in blob


def test_offline_mtproto_wrong_key_undecryptable(tmp_path, monkeypatch):
    _patch_tshark(monkeypatch)

    auth_key = os.urandom(crypto.AUTH_KEY_LEN)
    rec = crypto.build_encrypted_record(auth_key, b"secret", "write")
    init = _build_init(b"\xee\xee\xee\xee")
    client_wire, _ = _obfuscate(init, _intermediate(rec), b"")

    pkts = [
        _seg(CLIENT, SERVER, 1000, b"", syn=True),
        _seg(CLIENT, SERVER, 1001, client_wire),
    ]
    pcap_path = str(tmp_path / "tg.pcapng")
    wrpcap(pcap_path, pkts)

    # Keylog with a DIFFERENT auth_key -> auth_key_id won't match -> undecryptable.
    wrong = os.urandom(crypto.AUTH_KEY_LEN)
    keylog_path = str(tmp_path / "tg.keys")
    with open(keylog_path, "w") as fh:
        fh.write(spec.format_line(
            dc_id=2,
            auth_key_id=crypto.compute_auth_key_id(wrong).hex(),
            auth_key=wrong.hex(),
        ) + "\n")

    result = p2t.convert_pcap_to_tap(
        pcap_path, mtproto_keylog=keylog_path, tap_path=str(tmp_path / "tg.tap"))
    assert result.mtproto_messages == 0
    assert result.mtproto_records_undecryptable >= 1
