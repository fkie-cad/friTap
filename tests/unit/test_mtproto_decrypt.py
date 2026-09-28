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


def test_truncated_first_bytes_is_short_not_mid_connection(tmp_path):
    auth_key = os.urandom(crypto.AUTH_KEY_LEN)
    keymap = _make_keymap(auth_key)

    init = _build_init(b"\xee\xee\xee\xee")
    rec = crypto.build_encrypted_record(auth_key, b"hi", "write")
    client_wire, server_wire = _obfuscate_stream(init, _intermediate_frame(rec), b"")

    # Drop the leading client bytes so the init block is incomplete. A SYN is seen
    # but a start gap swallowed the opening bytes -> SHORT/lossy stream, counted
    # under streams_short (NOT streams_degraded / "mid-connection").
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
    assert stats.streams_short >= 1
    assert stats.streams_degraded == 0


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


# --------------------------------------------------------------------------- #
# Why a record did not open: the three buckets behind records_undecryptable
# --------------------------------------------------------------------------- #


def test_the_total_is_derived_from_the_buckets_and_cannot_be_bumped_alone():
    """There is no way to say "one failed" without saying why.

    The total is a read-only property over the three buckets, so a caller that
    does not name a reason cannot contribute to it -- and the buckets can never
    drift away from the total they add up to.
    """
    stats = MtprotoStats()
    assert stats.records_undecryptable == 0
    assert not hasattr(MtprotoStats, "add_undecryptable")
    with pytest.raises(AttributeError):
        stats.records_undecryptable = 2  # type: ignore[misc]


def test_the_three_kinds_each_bump_the_total_and_their_own_bucket():
    stats = MtprotoStats()
    stats.add_malformed_record()
    stats.add_unknown_key("a1b2c3d4e5f60718")
    stats.add_unknown_key("a1b2c3d4e5f60718")
    stats.add_unknown_key("0011223344556677")
    stats.add_crypto_failure()
    assert stats.records_undecryptable == 5
    assert stats.records_malformed == 1
    assert stats.records_unknown_key == 3
    assert stats.records_crypto_failed == 1
    # Counted per id, not merely collected: the count is what says whether a
    # missing key hides one stray record or a whole session.
    assert stats.unknown_key_ids == {"a1b2c3d4e5f60718": 2, "0011223344556677": 1}


def test_two_stats_objects_do_not_share_one_dict():
    """A mutable dataclass default is the classic way to get this wrong."""
    first, second = MtprotoStats(), MtprotoStats()
    first.add_unknown_key("a1b2c3d4e5f60718")
    assert second.unknown_key_ids == {}


def test_records_under_a_key_we_do_not_hold_report_their_auth_key_id(tmp_path):
    """The recoverable failure, end to end.

    The capture is real MTProto under a real key; we simply do not have that
    key. The id travels in the clear in each record's first 8 bytes, so the
    decryptor can hand it back and the user can go hunt exactly that key.
    """
    unseen_key = os.urandom(crypto.AUTH_KEY_LEN)
    # A keymap holding some OTHER key: not empty, just not the right one.
    keymap = _make_keymap(os.urandom(crypto.AUTH_KEY_LEN))

    init = _build_init(b"\xee\xee\xee\xee")
    client_payload = b"".join(
        _intermediate_frame(crypto.build_encrypted_record(unseen_key, m, "write"))
        for m in (b"one", b"two", b"three")
    )
    server_payload = _intermediate_frame(
        crypto.build_encrypted_record(unseen_key, b"reply", "read")
    )
    client_wire, server_wire = _obfuscate_stream(init, client_payload, server_payload)

    pcap = tmp_path / "unknownkey.pcap"
    _write_pcap(pcap, client_wire, server_wire, n_client_segs=2)

    stats = MtprotoStats()
    assert list(iter_decrypted_messages(str(pcap), keymap, stats=stats)) == []
    unseen_id = crypto.compute_auth_key_id(unseen_key).hex()
    assert stats.unknown_key_ids == {unseen_id: 4}
    assert stats.records_unknown_key == 4
    assert stats.records_undecryptable == 4
    assert stats.records_crypto_failed == 0


def test_a_msg_key_failure_is_not_reported_as_a_missing_key(tmp_path):
    """The un-recoverable failure. Same keymap as
    ``test_wrong_key_marks_undecryptable``: the id IS known, the key behind it
    is wrong. Feeding that id into a key hunt would only find the key already in
    hand, so it must stay out of ``unknown_key_ids``.
    """
    real_key = os.urandom(crypto.AUTH_KEY_LEN)
    aid = crypto.compute_auth_key_id(real_key)
    keymap = {aid: MtprotoAuthKey(dc_id=2, auth_key_id=aid,
                                  auth_key=os.urandom(crypto.AUTH_KEY_LEN))}

    init = _build_init(b"\xee\xee\xee\xee")
    client_payload = _intermediate_frame(
        crypto.build_encrypted_record(real_key, b"secret", "write")
    )
    client_wire, server_wire = _obfuscate_stream(init, client_payload, b"")

    pcap = tmp_path / "badmsgkey.pcap"
    _write_pcap(pcap, client_wire, server_wire, n_client_segs=2)

    stats = MtprotoStats()
    assert list(iter_decrypted_messages(str(pcap), keymap, stats=stats)) == []
    assert stats.records_crypto_failed >= 1
    assert stats.records_unknown_key == 0
    assert stats.unknown_key_ids == {}


# --------------------------------------------------------------------------- #
# Capture timestamps
# --------------------------------------------------------------------------- #


def _timed_segment(src, dst, seq, payload, ts):
    pkt = _segment(src, dst, seq, payload)
    pkt.time = ts
    return pkt


def test_messages_carry_capture_time_of_their_last_byte(tmp_path):
    """Each record is stamped with the time of the segment holding its LAST byte.

    Client record 0 is split across two segments (t=100, t=101): its stamp must be
    101. The 64-byte init block sits in front of the client payload, so this also
    proves the INIT_BLOCK_LEN offset is accounted for. Yield order is unchanged.
    """
    auth_key = os.urandom(crypto.AUTH_KEY_LEN)
    keymap = _make_keymap(auth_key)
    init = _build_init(b"\xee\xee\xee\xee")
    c_frames = [_intermediate_frame(crypto.build_encrypted_record(auth_key, m, "write"))
                for m in (b"first-write-msg", b"second-write-msg")]
    s_frame = _intermediate_frame(crypto.build_encrypted_record(auth_key, b"reply", "read"))
    client_wire, server_wire = _obfuscate_stream(init, b"".join(c_frames), s_frame)

    split = 64 + len(c_frames[0]) - 3  # last 3 bytes of record 0 arrive later
    end0 = 64 + len(c_frames[0])
    pkts = [
        _timed_segment(CLIENT, SERVER, 1000, client_wire[:split], 100.0),
        _timed_segment(CLIENT, SERVER, 1000 + split, client_wire[split:end0], 101.0),
        _timed_segment(SERVER, CLIENT, 5000, server_wire, 102.0),
        _timed_segment(CLIENT, SERVER, 1000 + end0, client_wire[end0:], 103.0),
    ]
    pcap = tmp_path / "timed.pcap"
    wrpcap(str(pcap), pkts)

    out = list(iter_decrypted_messages(str(pcap), keymap))
    assert [(m.direction, m.timestamp) for m in out] == [
        ("write", 101.0), ("write", 103.0), ("read", 102.0),
    ]


def test_message_timestamp_falls_back_to_msg_id_seconds():
    from friTap.offline.mtproto.decrypt import _message_timestamp, _msg_id_seconds

    msg_id = (1790358568 << 32) | 0x1234
    assert _msg_id_seconds(msg_id) == 1790358568.0
    assert _msg_id_seconds(0) == 0.0
    assert _msg_id_seconds(5 << 32) == 0.0  # implausible epoch
    assert _message_timestamp(None, 10, msg_id) == 1790358568.0
    assert _message_timestamp(lambda off: 0.0, 10, msg_id) == 1790358568.0
    assert _message_timestamp(lambda off: 42.5, 10, msg_id) == 42.5


def test_ts_lookup_is_queried_at_frame_last_byte():
    from friTap.offline.mtproto.decrypt import _message_timestamp

    seen = []
    _message_timestamp(lambda off: seen.append(off) or 1.0, 57, 0)
    assert seen == [56]
