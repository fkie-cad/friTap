"""End-to-end hermetic test for the offline MTProto orchestrator.

We synthesize a full obfuscated INTERMEDIATE conversation in memory: build the
64-byte init block with chosen CTR keys, CTR-encrypt a framed concatenation of
records produced by ``crypto.build_encrypted_record``, write a scapy pcap split
across segments (incl. out-of-order + retransmit), then assert the orchestrator
recovers every message.
"""

from __future__ import annotations

import os

import pytest

pytest.importorskip("cryptography")  # CTR + AES-IGE backend

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from scapy.layers.inet import IP, TCP
from scapy.packet import Raw
from scapy.utils import wrpcap

from friTap.offline.mtproto import crypto
from friTap.offline.mtproto.decrypt import iter_decrypted_messages
from friTap.offline.mtproto.records import MtprotoStats
from friTap.offline.mtproto.transport import derive_obfuscation_keys
from friTap.protocols.mtproto_keylog_spec import MtprotoAuthKey

CLIENT = ("10.0.0.5", 50000)
SERVER = ("149.154.167.51", 443)


def _ctr(key, iv):
    return Cipher(algorithms.AES(key), modes.CTR(iv)).encryptor()


def _intermediate_frame(payload: bytes) -> bytes:
    return len(payload).to_bytes(4, "little") + payload


def _build_init(tag: bytes) -> bytes:
    """Return an on-wire 64-byte init that decrypts to ``tag`` at [56:60]."""
    enc_init = bytearray(os.urandom(64))
    key_out, iv_out, _, _ = derive_obfuscation_keys(bytes(enc_init))
    dec = bytearray(_ctr(key_out, iv_out).update(bytes(enc_init)))
    dec[56:60] = tag
    enc_fixed = _ctr(key_out, iv_out).update(bytes(dec))
    return bytes(enc_fixed)


def _obfuscate_stream(init: bytes, client_payload: bytes, server_payload: bytes):
    """Return on-wire (client_bytes, server_bytes) under the init-derived keys."""
    key_out, iv_out, key_in, iv_in = derive_obfuscation_keys(init)
    # Client wire = encrypted(init || client_payload); init's own bytes are wire.
    out_ks = _ctr(key_out, iv_out)
    out_ks.update(init)  # advances counter over the 64 init bytes
    client_wire = init + out_ks.update(client_payload)
    server_wire = _ctr(key_in, iv_in).update(server_payload)
    return client_wire, server_wire


def _segment(src, dst, seq, payload, syn=False):
    flags = "S" if syn else "PA"
    return (
        IP(src=src[0], dst=dst[0])
        / TCP(sport=src[1], dport=dst[1], seq=seq, flags=flags)
        / (Raw(load=payload) if payload else Raw(load=b""))
    )


def _write_pcap(path, client_wire, server_wire, *, n_client_segs=3):
    """Split client_wire across segments incl. out-of-order + a retransmit."""
    pkts = []
    base_c = 1000
    # split client into chunks
    chunks = []
    step = max(1, len(client_wire) // n_client_segs)
    off = 0
    while off < len(client_wire):
        chunks.append(client_wire[off : off + step])
        off += step
    # Build in-order segments first.
    segs = []
    seq = base_c
    for ch in chunks:
        segs.append((seq, ch))
        seq += len(ch)
    # Emit: first, then swap order of segs[1] and segs[2] (out-of-order), and
    # duplicate segs[0] (retransmit).
    emit_order = list(segs)
    if len(emit_order) >= 3:
        emit_order[1], emit_order[2] = emit_order[2], emit_order[1]
    for s_seq, ch in emit_order:
        pkts.append(_segment(CLIENT, SERVER, s_seq, ch))
    # retransmit the first client segment
    pkts.append(_segment(CLIENT, SERVER, segs[0][0], segs[0][1]))
    # server direction, single segment
    pkts.append(_segment(SERVER, CLIENT, 5000, server_wire))
    wrpcap(str(path), pkts)


def _make_keymap(auth_key: bytes, dc_id: int = 2) -> dict:
    aid = crypto.compute_auth_key_id(auth_key)
    return {aid: MtprotoAuthKey(dc_id=dc_id, auth_key_id=aid, auth_key=auth_key)}


# --------------------------------------------------------------------------- #
# Happy path
# --------------------------------------------------------------------------- #


def test_decrypts_n_intermediate_records(tmp_path):
    auth_key = os.urandom(crypto.AUTH_KEY_LEN)
    keymap = _make_keymap(auth_key)

    client_msgs = [b"client-msg-%02d-payload" % i for i in range(3)]
    server_msgs = [b"server-reply-%02d" % i for i in range(2)]

    init = _build_init(b"\xee\xee\xee\xee")  # intermediate
    client_payload = b"".join(
        _intermediate_frame(crypto.build_encrypted_record(auth_key, m, "write"))
        for m in client_msgs
    )
    server_payload = b"".join(
        _intermediate_frame(crypto.build_encrypted_record(auth_key, m, "read"))
        for m in server_msgs
    )
    client_wire, server_wire = _obfuscate_stream(init, client_payload, server_payload)

    pcap = tmp_path / "mtproto.pcap"
    _write_pcap(pcap, client_wire, server_wire)

    stats = MtprotoStats()
    out = list(iter_decrypted_messages(str(pcap), keymap, stats=stats))

    writes = [m for m in out if m.direction == "write"]
    reads = [m for m in out if m.direction == "read"]
    assert [m.message for m in writes] == client_msgs
    assert [m.message for m in reads] == server_msgs
    assert stats.messages == len(client_msgs) + len(server_msgs)
    assert stats.records_undecryptable == 0
    assert stats.streams_degraded == 0
    # Metadata sanity on one write record.
    w0 = writes[0]
    assert w0.transport == "intermediate"
    assert w0.obfuscated is True
    assert w0.src_addr == CLIENT[0] and w0.dst_addr == SERVER[0]
    assert w0.dc_id == 2
    assert w0.auth_key_id_hex == crypto.compute_auth_key_id(auth_key).hex()


# --------------------------------------------------------------------------- #
# Negatives
# --------------------------------------------------------------------------- #


def test_wrong_key_marks_undecryptable(tmp_path):
    real_key = os.urandom(crypto.AUTH_KEY_LEN)
    wrong_key = os.urandom(crypto.AUTH_KEY_LEN)
    # keymap maps the REAL auth_key_id to a WRONG auth_key -> msg_key verify fails.
    aid = crypto.compute_auth_key_id(real_key)
    keymap = {aid: MtprotoAuthKey(dc_id=2, auth_key_id=aid, auth_key=wrong_key)}

    init = _build_init(b"\xee\xee\xee\xee")
    rec = crypto.build_encrypted_record(real_key, b"secret", "write")
    client_payload = _intermediate_frame(rec)
    client_wire, server_wire = _obfuscate_stream(init, client_payload, b"")

    pcap = tmp_path / "wrongkey.pcap"
    _write_pcap(pcap, client_wire, server_wire, n_client_segs=2)

    stats = MtprotoStats()
    out = list(iter_decrypted_messages(str(pcap), keymap, stats=stats))
    assert out == []
    assert stats.records_undecryptable >= 1
    assert stats.messages == 0


def test_truncated_first_bytes_is_degraded(tmp_path):
    auth_key = os.urandom(crypto.AUTH_KEY_LEN)
    keymap = _make_keymap(auth_key)

    init = _build_init(b"\xee\xee\xee\xee")
    rec = crypto.build_encrypted_record(auth_key, b"hi", "write")
    client_wire, server_wire = _obfuscate_stream(init, _intermediate_frame(rec), b"")

    # Drop the leading client bytes so the init block is incomplete -> degraded.
    pkts = [
        _segment(CLIENT, SERVER, 1000, b"", syn=True),  # anchor at 1001
        _segment(CLIENT, SERVER, 1040, client_wire[39:]),  # start gap
        _segment(SERVER, CLIENT, 5000, server_wire),
    ]
    pcap = tmp_path / "truncated.pcap"
    wrpcap(str(pcap), pkts)

    stats = MtprotoStats()
    out = list(iter_decrypted_messages(str(pcap), keymap, stats=stats))
    assert out == []
    assert stats.streams_degraded >= 1


def test_non_mtproto_stream_not_yielded(tmp_path):
    auth_key = os.urandom(crypto.AUTH_KEY_LEN)
    keymap = _make_keymap(auth_key)

    # A TLS-ish random stream with full first 64 client bytes but no MTProto tag.
    client_wire = b"\x16\x03\x01" + os.urandom(200)
    server_wire = b"\x16\x03\x03" + os.urandom(120)
    pcap = tmp_path / "tls.pcap"
    _write_pcap(pcap, client_wire, server_wire, n_client_segs=2)

    stats = MtprotoStats()
    out = list(iter_decrypted_messages(str(pcap), keymap, stats=stats))
    assert out == []
    assert stats.messages == 0
    # Counted as a stream but not degraded (it had its first 64 bytes), just skipped.
    assert stats.streams >= 1
