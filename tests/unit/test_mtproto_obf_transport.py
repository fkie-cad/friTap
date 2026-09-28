"""Hermetic tests for the mid-stream obfuscation-recovery transport helpers.

Covers ``ObfuscationCipher.from_recovered``, the seekable ``counter_add`` /
``deobfuscate_at`` primitives, and ``recover_obf_alignment`` against a synthetic
advanced-counter stream.
"""

from __future__ import annotations

import os

import pytest

pytest.importorskip("cryptography")  # CTR backend

from friTap.offline.mtproto import crypto
from friTap.offline.mtproto.transport import (
    INTERMEDIATE,
    ObfuscationCipher,
    counter_add,
    deobfuscate_at,
    derive_obfuscation_keys,
    recover_obf_alignment,
)
from tests.unit._mtproto_helpers import aes_ctr as _ctr
from tests.unit._mtproto_helpers import intermediate_frame as _intermediate_frame

# --------------------------------------------------------------------------- #
# counter_add
# --------------------------------------------------------------------------- #

def test_counter_add_zero_is_identity():
    ctr = os.urandom(16)
    assert counter_add(ctr, 0) == ctr


def test_counter_add_increments_and_carries():
    assert counter_add(b"\x00" * 15 + b"\x01", 1) == b"\x00" * 15 + b"\x02"
    # Carry across a byte boundary.
    assert counter_add(b"\x00" * 15 + b"\xff", 1) == b"\x00" * 14 + b"\x01\x00"
    # Negative walks backwards.
    assert counter_add(b"\x00" * 14 + b"\x01\x00", -1) == b"\x00" * 15 + b"\xff"


def test_counter_add_wraps_mod_2_128():
    assert counter_add(b"\xff" * 16, 1) == b"\x00" * 16
    assert counter_add(b"\x00" * 16, -1) == b"\xff" * 16


def test_counter_add_rejects_bad_width():
    with pytest.raises(ValueError):
        counter_add(b"\x00" * 8, 1)


# --------------------------------------------------------------------------- #
# deobfuscate_at seek correctness
# --------------------------------------------------------------------------- #

def test_deobfuscate_at_seeks_to_a_block_boundary():
    key = os.urandom(32)
    iv = os.urandom(16)
    data = os.urandom(160)  # 10 blocks
    full = _ctr(key, iv).update(data)
    # Seek to block 4 and de-obfuscate the tail in isolation.
    seek_blocks = 4
    tail_ct = full[seek_blocks * 16:]
    recovered = deobfuscate_at(key, counter_add(iv, seek_blocks), tail_ct)
    assert recovered == data[seek_blocks * 16:]


def test_deobfuscate_at_handles_sub_block_phase_via_padding():
    key = os.urandom(32)
    iv = os.urandom(16)
    data = os.urandom(200)
    full = _ctr(key, iv).update(data)
    # Start 35 bytes in: block 2 (35 // 16), phase 3 (35 % 16).
    offset = 35
    block, phase = offset // 16, offset % 16
    base = counter_add(iv, block)
    tail_ct = full[offset:]
    recovered = deobfuscate_at(key, base, b"\x00" * phase + tail_ct)[phase:]
    assert recovered == data[offset:]


# --------------------------------------------------------------------------- #
# from_recovered == init-derivation for the same key/iv
# --------------------------------------------------------------------------- #

def test_from_recovered_matches_init_derivation():
    init = os.urandom(64)
    key_out, iv_out, key_in, iv_in = derive_obfuscation_keys(init)

    from_init = ObfuscationCipher(init)
    from_rec = ObfuscationCipher.from_recovered(key_out, iv_out, key_in, iv_in)

    client_data = os.urandom(128)
    server_data = os.urandom(96)
    assert from_init.decrypt_out(client_data) == from_rec.decrypt_out(client_data)
    assert from_init.decrypt_in(server_data) == from_rec.decrypt_in(server_data)


# --------------------------------------------------------------------------- #
# recover_obf_alignment on a synthetic advanced-counter stream
# --------------------------------------------------------------------------- #

def _build_obf_stream(auth_key, key, start_counter, chop):
    """Build (run_bytes, live_counter, num) for a synthetic obfuscated tail.

    Four intermediate frames (each an in-keymap record), CTR-obfuscated from
    ``start_counter``; the counter is then advanced to its live value and the
    first ``chop`` bytes are dropped to simulate a capture that began mid-stream.
    """
    frames = b"".join(
        _intermediate_frame(crypto.build_encrypted_record(auth_key, msg, "write"))
        for msg in (b"one", b"two", b"three", b"four")
    )
    ct = _ctr(key, start_counter).update(frames)
    total = len(frames)
    live_counter = counter_add(start_counter, total // 16)
    num = total % 16
    return ct[chop:], live_counter, num


def test_recover_obf_alignment_finds_the_offset():
    auth_key = os.urandom(crypto.AUTH_KEY_LEN)
    aid = crypto.compute_auth_key_id(auth_key)
    keymap = {aid: object()}

    key = os.urandom(32)
    start_counter = os.urandom(16)
    chop = 30  # lands inside the first frame -> forces a non-zero frame_offset
    run_bytes, live_counter, num = _build_obf_stream(auth_key, key, start_counter, chop)

    align = recover_obf_alignment(key, live_counter, num, run_bytes, keymap)
    assert align is not None
    assert align.transport_type == INTERMEDIATE

    # De-obfuscate the whole run from the resolved alignment and confirm the framed
    # payload begins at frame_offset with a decryptable record.
    plain = deobfuscate_at(key, align.counter_block, b"\x00" * align.phase + run_bytes)
    plain = plain[align.phase:]
    payload = plain[align.frame_offset:]
    length = int.from_bytes(payload[:4], "little")
    record = payload[4:4 + length]
    dec = crypto.decrypt_record(auth_key, record, "write")
    assert dec.envelope.message in (b"one", b"two", b"three", b"four")


def test_recover_obf_alignment_returns_none_on_wrong_key():
    auth_key = os.urandom(crypto.AUTH_KEY_LEN)
    aid = crypto.compute_auth_key_id(auth_key)
    keymap = {aid: object()}

    key = os.urandom(32)
    start_counter = os.urandom(16)
    run_bytes, live_counter, num = _build_obf_stream(auth_key, key, start_counter, 30)

    wrong_key = os.urandom(32)
    assert recover_obf_alignment(wrong_key, live_counter, num, run_bytes, keymap) is None


def test_recover_obf_alignment_none_without_oracle():
    # An empty keymap gives the known-plaintext anchor nothing to test against.
    key = os.urandom(32)
    assert recover_obf_alignment(key, os.urandom(16), 0, os.urandom(200), {}) is None
