"""Regression tests for three MTProto obfuscated-transport framing/alignment bugs.

* M2 — an abridged frame carrying the client's quick-ack REQUEST flag (0x80) under
  an auth_key_id NOT in the keymap was mistaken for a 4-byte server quick-ack
  TOKEN: frame sync was lost, later records dropped, and the unknown id never
  reached ``unknown_key_ids``. Token-vs-flagged-frame is now decided by direction.
* M8 — INTERMEDIATE framing read the 4-byte length without masking quick-ack bit
  31 (a ~2 GB length that ended the direction), and a server 4-byte token with
  bit 31 set was not skipped either.
* M1 — mid-stream alignment only tried capture lags that are whole 16-byte
  blocks, and never a pcap running PAST the live snapshot (negative lag).
"""

from __future__ import annotations

import random
from types import SimpleNamespace

import pytest

pytest.importorskip("cryptography")  # CTR + IGE backend

from friTap.offline.mtproto import crypto, transport
from friTap.offline.mtproto.decrypt import _decrypt_direction, _process_recovered_stream
from friTap.offline.mtproto.records import MtprotoStats
from friTap.offline.mtproto.transport import (
    ABRIDGED,
    CLIENT_TO_SERVER,
    INTERMEDIATE,
    SERVER_TO_CLIENT,
    counter_add,
    deobfuscate_at,
    iter_frames_with_offsets,
    recover_obf_alignment,
)
from friTap.protocols.mtproto_keylog_spec import MtprotoAuthKey, MtprotoObfKey
from tests.unit._mtproto_helpers import aes_ctr
from tests.unit._mtproto_helpers import intermediate_frame as _intermediate_frame

_BIT31 = 0x80000000


# --------------------------------------------------------------------------- #
# Builders
# --------------------------------------------------------------------------- #

def _abridged_frame(payload: bytes, quick_ack: bool = False) -> bytes:
    words = len(payload) // 4
    flag = 0x80 if quick_ack else 0
    if words < 0x7F:
        return bytes([words | flag]) + payload
    return bytes([0x7F | flag]) + words.to_bytes(3, "little") + payload


def _intermediate_flagged(payload: bytes) -> bytes:
    return (len(payload) | _BIT31).to_bytes(4, "little") + payload


def _authkey(auth_key: bytes) -> MtprotoAuthKey:
    return MtprotoAuthKey(
        dc_id=2, auth_key_id=crypto.compute_auth_key_id(auth_key), auth_key=auth_key,
    )


def _records(auth_key, messages, direction):
    return [crypto.build_encrypted_record(auth_key, m, direction) for m in messages]


def _payloads(spans):
    return [p for _s, _e, p in spans]


def _obf_run(rng, plaintext: bytes, lag_bytes: int):
    """Obfuscate *plaintext*; place the live snapshot *lag_bytes* past its end.

    A negative *lag_bytes* means the capture ran past the snapshot. Returns
    ``(key, ciphertext_run, live_counter, num)`` in the memscan keylog model: the
    16-byte counter of the current block plus the byte-phase within it.
    """
    key = rng.randbytes(32)
    start_counter = rng.randbytes(16)
    ct = aes_ctr(key, start_counter).update(plaintext)
    live_pos = len(plaintext) + lag_bytes
    assert live_pos >= 0
    return key, ct, counter_add(start_counter, live_pos // 16), live_pos % 16


def _pair(client_data, server_data):
    side = lambda data: SimpleNamespace(  # noqa: E731 - tiny offline stub
        contiguous_bytes=lambda: bytes(data), timestamp_at=lambda _o: 0.0,
        saw_syn=False, has_start_gap=False, degraded=False,
    )
    return SimpleNamespace(
        client=side(client_data), server=side(server_data),
        client_addr=("192.168.0.66", 59040), server_addr=("149.154.167.41", 443),
        ss_family="AF_INET",
    )


@pytest.fixture
def keys():
    rng = random.Random(3)
    known, unknown = rng.randbytes(256), rng.randbytes(256)
    keymap = {crypto.compute_auth_key_id(known): _authkey(known)}
    return known, unknown, keymap


# --------------------------------------------------------------------------- #
# M2 — abridged quick-ack flag vs token, decided by direction
# --------------------------------------------------------------------------- #

def _abridged_with_flagged_unknown(known, unknown):
    recs = [crypto.build_encrypted_record(k, m, "write")
            for k, m in [(known, b"a"), (unknown, b"b"), (known, b"c"),
                         (known, b"d"), (known, b"e")]]
    buf = b"".join(_abridged_frame(r, quick_ack=(i == 1)) for i, r in enumerate(recs))
    return recs, buf


@pytest.mark.parametrize("direction", [CLIENT_TO_SERVER, None])
def test_flagged_frame_with_unknown_key_keeps_frame_sync(keys, direction):
    known, unknown, keymap = keys
    recs, buf = _abridged_with_flagged_unknown(known, unknown)
    assert _payloads(iter_frames_with_offsets(ABRIDGED, buf, keymap, direction)) == recs


def test_flagged_unknown_key_is_reported_by_the_decryptor(keys):
    known, unknown, keymap = keys
    _recs, buf = _abridged_with_flagged_unknown(known, unknown)
    stats = MtprotoStats()
    got = list(_decrypt_direction(ABRIDGED, buf, "write", _pair(b"", b""), keymap, stats))
    assert [m.message for m in got] == [b"a", b"c", b"d", b"e"]
    assert stats.unknown_key_ids == {crypto.compute_auth_key_id(unknown).hex(): 1}


def test_client_direction_never_reads_a_token(keys):
    """Client->server: even a flagged frame that looks token-sized is a data frame."""
    known, _unknown, keymap = keys
    short = bytes([0x02 | 0x80]) + b"\x11" * 8  # flagged 8-byte (non-record) frame
    rec = _records(known, [b"x"], "write")[0]
    spans = list(iter_frames_with_offsets(
        ABRIDGED, short + _abridged_frame(rec), keymap, CLIENT_TO_SERVER,
    ))
    assert _payloads(spans) == [b"\x11" * 8, rec]


@pytest.mark.parametrize("keymap_given", [True, False])
def test_server_token_between_records_is_skipped(keys, keymap_given):
    known, _unknown, keymap = keys
    recs = _records(known, [b"r1", b"r2"], "read")
    token = bytes([0x05 | 0x80]) + b"\x10\x20\x30"
    buf = _abridged_frame(recs[0]) + token + _abridged_frame(recs[1])
    spans = list(iter_frames_with_offsets(
        ABRIDGED, buf, keymap if keymap_given else None, SERVER_TO_CLIENT,
    ))
    assert _payloads(spans) == [recs[0], b"", recs[1]]


def test_server_flagged_frame_still_named_by_known_key_is_data(keys):
    known, _unknown, keymap = keys
    rec = _records(known, [b"srv"], "read")[0]
    spans = list(iter_frames_with_offsets(
        ABRIDGED, _abridged_frame(rec, quick_ack=True), keymap, SERVER_TO_CLIENT,
    ))
    assert _payloads(spans) == [rec]


# --------------------------------------------------------------------------- #
# M8 — intermediate quick-ack bit 31
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("direction", [CLIENT_TO_SERVER, None])
def test_intermediate_client_quick_ack_bit_is_masked(keys, direction):
    known, unknown, keymap = keys
    recs = _records(known, [b"a"], "write") + _records(unknown, [b"b"], "write") \
        + _records(known, [b"c"], "write")
    buf = b"".join(_intermediate_flagged(r) for r in recs)
    assert _payloads(iter_frames_with_offsets(INTERMEDIATE, buf, keymap, direction)) == recs


def test_intermediate_server_token_is_skipped(keys):
    known, _unknown, keymap = keys
    recs = _records(known, [b"r1", b"r2"], "read")
    token = (0x1234 | _BIT31).to_bytes(4, "little")
    buf = _intermediate_frame(recs[0]) + token + _intermediate_frame(recs[1])
    spans = list(iter_frames_with_offsets(INTERMEDIATE, buf, keymap, SERVER_TO_CLIENT))
    assert _payloads(spans) == [recs[0], b"", recs[1]]


def test_count_anchor_frames_steps_over_a_server_token(keys):
    known, _unknown, keymap = keys
    recs = _records(known, [b"r1", b"r2"], "read")
    token = (0x1234 | _BIT31).to_bytes(4, "little")
    buf = _intermediate_frame(recs[0]) + token + _intermediate_frame(recs[1])
    assert transport._count_anchor_frames(
        buf, 0, INTERMEDIATE, keymap, 2, SERVER_TO_CLIENT,
    )
    # The anchor frame itself must be a real record, never a token.
    assert not transport._count_anchor_frames(
        token + buf, 0, INTERMEDIATE, keymap, 1, SERVER_TO_CLIENT,
    )


def test_intermediate_flagged_client_stream_aligns(keys):
    known, _unknown, keymap = keys
    rng = random.Random(8)
    plain = b"".join(_intermediate_flagged(r) for r in _records(known, [b"a", b"b", b"c"], "write"))
    key, run, live, num = _obf_run(rng, plain, lag_bytes=48)
    align = recover_obf_alignment(key, live, num, run, keymap, max_blocks=16)
    assert align is not None and align.transport_type == INTERMEDIATE


# --------------------------------------------------------------------------- #
# M1 — byte-granular (and negative) capture lag
# --------------------------------------------------------------------------- #

_BYTE_LAGS = [0, 5, 16, 37, 44, 300, 16 * 64 - 1, -21, -300]


def _intermediate_stream(auth_key, direction="write"):
    return b"".join(
        _intermediate_frame(r)
        for r in _records(auth_key, [b"alpha", b"bravo", b"charlie", b"delta"], direction)
    )


@pytest.mark.parametrize("lag", _BYTE_LAGS)
def test_alignment_found_at_any_byte_lag(keys, lag):
    known, _unknown, keymap = keys
    rng = random.Random(1000 + lag)
    plain = _intermediate_stream(known)
    key, run, live, num = _obf_run(rng, plain, lag)
    align = recover_obf_alignment(key, live, num, run, keymap, max_blocks=64)
    assert align is not None
    # The resolved counter/phase really de-obfuscates the run from its first byte.
    got = deobfuscate_at(key, align.counter_block, b"\x00" * align.phase + run)
    assert got[align.phase:] == plain
    assert align.frame_offset == 0


@pytest.mark.parametrize("lag", [37, -21])
def test_byte_lag_recovers_messages_end_to_end(keys, lag):
    known, _unknown, keymap = keys
    rng = random.Random(77)
    key, run, live, num = _obf_run(rng, _intermediate_stream(known), lag)
    obf = MtprotoObfKey(
        key_out=key, iv_out=live, num_out=num,
        key_in=rng.randbytes(32), iv_in=rng.randbytes(16), num_in=0, endpoint="-",
    )
    got = _process_recovered_stream(_pair(run, b""), [obf], keymap, MtprotoStats(),
                                    obf_max_blocks=64)
    assert got is not None
    assert [m.message for m in got] == [b"alpha", b"bravo", b"charlie", b"delta"]


@pytest.mark.parametrize("lag", [16 * 64 + 16, -(16 * 64 + 16)])
def test_lag_beyond_the_search_depth_is_not_found(keys, lag):
    known, _unknown, keymap = keys
    rng = random.Random(5)
    plain = _intermediate_stream(known) * 8  # long enough for the negative lag
    key, run, live, num = _obf_run(rng, plain, lag)
    assert recover_obf_alignment(key, live, num, run, keymap, max_blocks=64) is None


def test_mid_run_chop_with_byte_lag_finds_a_later_frame(keys):
    """A head-chopped tail (starts mid-record) still anchors at the next frame."""
    known, _unknown, keymap = keys
    rng = random.Random(6)
    plain = _intermediate_stream(known)
    key, ct, live, num = _obf_run(rng, plain, 29)
    chop = 11
    align = recover_obf_alignment(key, live, num, ct[chop:], keymap, max_blocks=64)
    assert align is not None
    _start, first_frame, _payload = next(iter_frames_with_offsets(INTERMEDIATE, plain))
    assert align.frame_offset == first_frame - chop
