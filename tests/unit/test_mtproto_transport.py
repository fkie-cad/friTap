"""Hermetic tests for MTProto obfuscated-transport keying and framing."""

from __future__ import annotations

import os

import pytest

pytest.importorskip("cryptography")  # CTR backend

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from friTap.offline.mtproto.transport import (
    ABRIDGED,
    INTERMEDIATE,
    PADDED_INTERMEDIATE,
    ObfuscationCipher,
    derive_obfuscation_keys,
    detect_transport,
    iter_frames,
)


def _ctr(key, iv):
    return Cipher(algorithms.AES(key), modes.CTR(iv)).encryptor()


def _make_init(tag: bytes) -> tuple[bytes, bytes]:
    """Build a (plaintext_init, encrypted_init) pair carrying ``tag`` at [56:60].

    The on-wire init is the CTR-*encryption* of the plaintext init under keys
    derived from the on-wire init itself, so we iterate: pick random bytes for
    [0:56], place the tag, encrypt, and the result is what the client sends.
    Because the keys live in the encrypted bytes [8:56], we just choose the
    *encrypted* init randomly and derive the plaintext by decrypting it.
    """
    enc_init = bytearray(os.urandom(64))
    key_out, iv_out, _, _ = derive_obfuscation_keys(bytes(enc_init))
    dec = _ctr(key_out, iv_out).update(bytes(enc_init))
    dec = bytearray(dec)
    dec[56:60] = tag
    # Re-encrypt so on-wire bytes decrypt to our chosen tag.
    enc_fixed = _ctr(key_out, iv_out).update(bytes(dec))
    return bytes(dec), bytes(enc_fixed)


# --------------------------------------------------------------------------- #
# Key derivation
# --------------------------------------------------------------------------- #


def test_key_derivation_offsets():
    init = os.urandom(64)
    key_out, iv_out, key_in, iv_in = derive_obfuscation_keys(init)
    assert key_out == init[8:40]
    assert iv_out == init[40:56]
    rev = init[8:56][::-1]
    assert key_in == rev[0:32]
    assert iv_in == rev[32:48]
    assert len(key_out) == 32 and len(iv_out) == 16
    assert len(key_in) == 32 and len(iv_in) == 16


# --------------------------------------------------------------------------- #
# CTR keystream continuity
# --------------------------------------------------------------------------- #


def test_ctr_continuity_split_equals_whole():
    init = os.urandom(64)
    stream = os.urandom(200)

    whole = ObfuscationCipher(init).decrypt_out(stream)

    split_cipher = ObfuscationCipher(init)
    part1 = split_cipher.decrypt_out(stream[:37])
    part2 = split_cipher.decrypt_out(stream[37:128])
    part3 = split_cipher.decrypt_out(stream[128:])
    assert part1 + part2 + part3 == whole


def test_in_and_out_use_different_keystreams():
    init = os.urandom(64)
    data = os.urandom(80)
    c = ObfuscationCipher(init)
    assert c.decrypt_out(data) != c.decrypt_in(data)


# --------------------------------------------------------------------------- #
# Transport detection
# --------------------------------------------------------------------------- #


def test_detect_abridged():
    dec, enc = _make_init(b"\xef\xef\xef\xef")
    out = ObfuscationCipher(enc).decrypt_out(enc)
    assert detect_transport(out) == ABRIDGED


def test_detect_intermediate():
    dec, enc = _make_init(b"\xee\xee\xee\xee")
    out = ObfuscationCipher(enc).decrypt_out(enc)
    assert detect_transport(out) == INTERMEDIATE


def test_detect_padded_intermediate():
    dec, enc = _make_init(b"\xdd\xdd\xdd\xdd")
    out = ObfuscationCipher(enc).decrypt_out(enc)
    assert detect_transport(out) == PADDED_INTERMEDIATE


def test_detect_false_positive_returns_none():
    # Random init: the [56:60] tag will (overwhelmingly) not match any known tag.
    for _ in range(20):
        init = os.urandom(64)
        out = ObfuscationCipher(init).decrypt_out(init)
        assert detect_transport(out) is None


# --------------------------------------------------------------------------- #
# Framing
# --------------------------------------------------------------------------- #


def _abridged_frame(payload: bytes) -> bytes:
    assert len(payload) % 4 == 0
    n = len(payload) // 4
    if n < 0x7F:
        return bytes([n]) + payload
    return b"\x7f" + n.to_bytes(3, "little") + payload


def _intermediate_frame(payload: bytes) -> bytes:
    return len(payload).to_bytes(4, "little") + payload


def test_abridged_multi_frame():
    p1, p2, p3 = os.urandom(8), os.urandom(40), os.urandom(0)
    buf = _abridged_frame(p1) + _abridged_frame(p2) + _abridged_frame(p3)
    assert list(iter_frames(ABRIDGED, buf)) == [p1, p2, p3]


def test_abridged_long_length():
    payload = os.urandom(0x7F * 4)  # forces the 3-byte length path
    buf = _abridged_frame(payload)
    assert list(iter_frames(ABRIDGED, buf)) == [payload]


def test_abridged_masks_quick_ack_bit():
    payload = os.urandom(8)  # n == 2
    frame = bytes([0x02 | 0x80]) + payload  # quick-ack high bit set
    assert list(iter_frames(ABRIDGED, frame)) == [payload]


def test_abridged_quick_ack_token_skipped_with_keymap():
    """A server quick-ack TOKEN (4 bytes, high bit set, not a real record) between
    two data frames must be skipped so the following record still frames — the bug
    that dropped every received message after the first quick-ack."""
    from friTap.offline.mtproto.transport import iter_frames_with_offsets

    aid = b"\xaa" * 8
    keymap = {aid: object()}
    rec = aid + os.urandom(40)               # a real 48-byte record (>= _MIN_RECORD_LEN)
    data = _abridged_frame(rec)
    # 4-byte quick-ack token: high bit set, masked length (2 -> 8 bytes) is NOT a real
    # record, so the oracle classifies it as a token and consumes exactly 4 bytes.
    token = bytes([0x02 | 0x80]) + b"\x11\x22\x33"
    spans = list(iter_frames_with_offsets(ABRIDGED, data + token + data, keymap))
    payloads = [p for _s, _e, p in spans]
    assert payloads.count(rec) == 2          # both records recovered across the token
    assert b"" in payloads                   # the token yielded an empty (control) frame


def test_abridged_quick_ack_request_flag_kept_as_data_frame_with_keymap():
    """A data frame that merely REQUESTS an ack (high bit on its length byte) is a
    real record and must be read as a normal frame, not mistaken for a 4-byte token."""
    from friTap.offline.mtproto.transport import iter_frames_with_offsets

    aid = b"\xbb" * 8
    keymap = {aid: object()}
    rec = aid + os.urandom(40)               # 48-byte record, n == 12
    flagged = bytes([(len(rec) // 4) | 0x80]) + rec  # ack-request flag on the length
    spans = list(iter_frames_with_offsets(ABRIDGED, flagged, keymap))
    assert [p for _s, _e, p in spans] == [rec]


def test_abridged_partial_trailing_dropped():
    good = _abridged_frame(os.urandom(12))
    # A length byte promising 5*4 bytes but only 4 present -> dropped cleanly.
    partial = bytes([5]) + os.urandom(4)
    assert list(iter_frames(ABRIDGED, good + partial)) == [good[1:]]


def test_intermediate_multi_frame():
    p1, p2 = os.urandom(16), os.urandom(64)
    buf = _intermediate_frame(p1) + _intermediate_frame(p2)
    assert list(iter_frames(INTERMEDIATE, buf)) == [p1, p2]


def test_intermediate_partial_trailing_dropped():
    good = _intermediate_frame(os.urandom(20))
    partial = (100).to_bytes(4, "little") + os.urandom(10)  # short body
    assert list(iter_frames(INTERMEDIATE, good + partial)) == [good[4:]]


def test_intermediate_partial_length_header_dropped():
    good = _intermediate_frame(os.urandom(8))
    assert list(iter_frames(INTERMEDIATE, good + b"\x01\x02")) == [good[4:]]


def test_padded_intermediate_not_implemented():
    with pytest.raises(NotImplementedError):
        list(iter_frames(PADDED_INTERMEDIATE, b"\x00" * 16))


# --------------------------------------------------------------------------- #
# iter_frames_with_offsets
# --------------------------------------------------------------------------- #


def _abridged(payload: bytes) -> bytes:
    n = len(payload) // 4
    if n < 0x7F:
        return bytes([n]) + payload
    return b"\x7f" + n.to_bytes(3, "little") + payload


def _intermediate(payload: bytes) -> bytes:
    return len(payload).to_bytes(4, "little") + payload


@pytest.mark.parametrize(
    "transport, framer",
    [("abridged", _abridged), ("intermediate", _intermediate)],
)
def test_iter_frames_with_offsets_matches_iter_frames(transport, framer):
    from friTap.offline.mtproto.transport import iter_frames_with_offsets

    payloads = [b"A" * 8, b"B" * 4 * 0x80, b"C" * 12]  # includes a long abridged
    buf = b"".join(framer(p) for p in payloads) + framer(b"D" * 16)[:7]  # partial tail
    spans = list(iter_frames_with_offsets(transport, buf))
    assert [p for _s, _e, p in spans] == list(iter_frames(transport, buf)) == payloads
    pos = 0
    for (start, end, payload), raw in zip(spans, payloads):
        framed = framer(raw)
        assert (start, end) == (pos, pos + len(framed))
        assert buf[end - len(payload):end] == payload
        pos = end


def test_iter_frames_with_offsets_rejects_unsupported():
    from friTap.offline.mtproto.transport import iter_frames_with_offsets

    with pytest.raises(NotImplementedError):
        list(iter_frames_with_offsets(PADDED_INTERMEDIATE, b"\x00" * 8))
