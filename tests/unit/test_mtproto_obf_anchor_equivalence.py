"""The optimised obf-alignment search must match the brute-force reference exactly.

``recover_obf_alignment`` prefilters anchor candidates by locating known
auth_key_ids and derives every candidate plaintext from one sliced keystream.
These tests pin that it returns the very same alignment (or ``None``) as the
straightforward per-offset / per-cipher search it replaced.
"""

from __future__ import annotations

import random

import pytest

pytest.importorskip("cryptography")  # CTR backend

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from friTap.offline.mtproto import crypto, transport
from friTap.offline.mtproto.transport import (
    ABRIDGED,
    INTERMEDIATE,
    ObfAlignment,
    counter_add,
    deobfuscate_at,
    recover_obf_alignment,
)
from tests.unit._mtproto_helpers import intermediate_frame as _intermediate_frame

# --------------------------------------------------------------------------- #
# Reference: the original brute-force search
# --------------------------------------------------------------------------- #

def _reference_find_anchor(buf, transport_type, auth_keymap, need):
    limit = min(len(buf), transport._ANCHOR_MAX_START)
    for start in range(0, limit):
        if transport._count_anchor_frames(buf, start, transport_type, auth_keymap, need):
            return start
    return None


def _reference_recover(key, live_counter, num, run_bytes, auth_keymap,
                       *, transport_hint=None, max_blocks=transport.DEFAULT_OBF_MAX_BLOCKS):
    run_len = len(run_bytes)
    if run_len < transport._MIN_RECORD_LEN or not auth_keymap:
        return None
    if transport_hint in (ABRIDGED, INTERMEDIATE):
        transports = (transport_hint,)
    else:
        transports = (ABRIDGED, INTERMEDIATE)
    phase = (num - run_len) % 16
    blocks_behind_exact = -((num - run_len) // 16)
    window = run_bytes[:transport._ANCHOR_TEST_WINDOW]
    pad = b"\x00" * phase
    for k in range(0, max_blocks + 1):
        base = counter_add(live_counter, -(blocks_behind_exact + k))
        plain = deobfuscate_at(key, base, pad + window)[phase:]
        for transport_type in transports:
            start = _reference_find_anchor(plain, transport_type, auth_keymap,
                                           transport._ANCHOR_FRAMES)
            if start is not None:
                return ObfAlignment(base, phase, start, transport_type)
    return None


# --------------------------------------------------------------------------- #
# Synthetic stream builders
# --------------------------------------------------------------------------- #

def _abridged_frame(payload: bytes, quick_ack: bool = False) -> bytes:
    words = len(payload) // 4
    if words < 0x7F:
        head = bytes([words | (0x80 if quick_ack else 0)])
    else:
        head = bytes([0x7F | (0x80 if quick_ack else 0)]) + words.to_bytes(3, "little")
    return head + payload


def _obf_tail(rng, framer, messages, auth_key, *, chop, lag_blocks):
    key = rng.randbytes(32)
    start_counter = rng.randbytes(16)
    frames = b"".join(
        framer(crypto.build_encrypted_record(auth_key, m, "write")) for m in messages
    )
    ct = Cipher(algorithms.AES(key), modes.CTR(start_counter)).encryptor().update(frames)
    live_counter = counter_add(start_counter, len(frames) // 16 + lag_blocks)
    return key, ct[chop:], live_counter, len(frames) % 16


def _keymap(rng, auth_key, decoys=3):
    ids = [crypto.compute_auth_key_id(auth_key)] + [rng.randbytes(8) for _ in range(decoys)]
    return {kid: object() for kid in ids}


def _assert_same(key, live, num, run, keymap, **kw):
    got = recover_obf_alignment(key, live, num, run, keymap, **kw)
    assert got == _reference_recover(key, live, num, run, keymap, **kw)
    return got


# --------------------------------------------------------------------------- #
# Tests
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("seed", range(6))
@pytest.mark.parametrize(
    "framer",
    [_intermediate_frame, _abridged_frame, lambda p: _abridged_frame(p, quick_ack=True)],
    ids=["intermediate", "abridged", "abridged-quickack"],
)
def test_matching_key_alignment_identical(seed, framer):
    rng = random.Random(seed)
    auth_key = rng.randbytes(crypto.AUTH_KEY_LEN)
    keymap = _keymap(rng, auth_key)
    # Mix short (1-byte abridged header) and long (4-byte header) records, and
    # plant the auth_key_id inside a message body as a decoy occurrence.
    decoy = crypto.compute_auth_key_id(auth_key) * 3
    messages = [b"one", decoy, rng.randbytes(700), b"four", b"five"]
    key, run, live, num = _obf_tail(
        rng, framer, messages, auth_key,
        chop=rng.randrange(0, 60), lag_blocks=rng.randrange(0, 40),
    )
    assert _assert_same(key, live, num, run, keymap, max_blocks=64) is not None


@pytest.mark.parametrize("hint", [None, ABRIDGED, INTERMEDIATE])
def test_transport_hint_alignment_identical(hint):
    rng = random.Random(99)
    auth_key = rng.randbytes(crypto.AUTH_KEY_LEN)
    keymap = _keymap(rng, auth_key)
    key, run, live, num = _obf_tail(
        rng, _intermediate_frame, [b"a", b"b", b"c", b"d"], auth_key, chop=17, lag_blocks=3,
    )
    got = _assert_same(key, live, num, run, keymap, transport_hint=hint, max_blocks=16)
    assert (got is None) == (hint == ABRIDGED)


@pytest.mark.parametrize("seed", range(3))
def test_wrong_key_both_return_none(seed):
    rng = random.Random(1000 + seed)
    auth_key = rng.randbytes(crypto.AUTH_KEY_LEN)
    keymap = _keymap(rng, auth_key)
    _key, run, live, num = _obf_tail(
        rng, _intermediate_frame, [b"a", b"b", b"c"], auth_key, chop=5, lag_blocks=0,
    )
    wrong = rng.randbytes(32)
    assert recover_obf_alignment(wrong, live, num, run, keymap, max_blocks=24) is None
    _assert_same(wrong, live, num, run, keymap, max_blocks=24)


def test_negative_max_blocks_returns_none():
    rng = random.Random(7)
    auth_key = rng.randbytes(crypto.AUTH_KEY_LEN)
    key, run, live, num = _obf_tail(
        rng, _intermediate_frame, [b"a", b"b"], auth_key, chop=0, lag_blocks=0,
    )
    _assert_same(key, live, num, run, _keymap(rng, auth_key), max_blocks=-1)


@pytest.mark.parametrize("transport_type", [ABRIDGED, INTERMEDIATE])
def test_find_frame_anchor_matches_bruteforce_on_planted_buffers(transport_type):
    """Random buffers densely seeded with known ids and plausible length headers."""
    rng = random.Random(4242)
    ids = [rng.randbytes(8) for _ in range(3)]
    keymap = {kid: object() for kid in ids}
    for _ in range(400):
        buf = bytearray(rng.randbytes(rng.randrange(0, 1400)))
        for _ in range(rng.randrange(0, 12)):
            pos = rng.randrange(0, max(1, len(buf)))
            header = rng.choice([
                bytes([rng.randrange(10, 0x7F) | rng.choice([0, 0x80])]),
                b"\x7f" + rng.randrange(10, 300).to_bytes(3, "little"),
                rng.randrange(40, 400).to_bytes(4, "little"),
            ])
            buf[pos:pos] = header + rng.choice(ids)
        data = bytes(buf)
        assert transport._find_frame_anchor(data, transport_type, keymap, 2) == (
            _reference_find_anchor(data, transport_type, keymap, 2)
        )
        assert transport._find_frame_anchor(data, transport_type, keymap, 1) == (
            _reference_find_anchor(data, transport_type, keymap, 1)
        )
