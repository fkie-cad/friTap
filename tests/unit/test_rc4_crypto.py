"""Correctness tests for the RC4 offline crypto core + candidate extraction.

Ports the pure (no live process, no pcap) layers of
``research/memory_scan_lsass/tests/test_rc4_trial_decrypt.py`` and the RFC 8448
key-schedule vector from ``test_tls13_trial_decrypt.py``:

  * RC4 KAT + symmetric KSA/PRGA roundtrip (always run; RC4 is pure Python).
  * candidate extraction (isolated ASCII, UTF-16LE, windowed-embedded, giant-skip).
  * TLS 1.3 HKDF-Expand-Label key/iv derivation vs the published RFC 8448 vector
    (skipped when ``cryptography`` is absent, like the research suite).
"""
from __future__ import annotations

import pytest

from friTap.offline.rc4 import crypto
from friTap.offline.rc4 import decrypt as rc4d

KEY = b"fritap-rc4-demo-key"
PLAINTEXT = b"GET / rc4-over-tls13 nested-cipher fixture"


# --------------------------------------------------------------------------- #
# RC4 core
# --------------------------------------------------------------------------- #

def test_rc4_known_answer():
    # The shared KAT pinned across agent/rc4_decrypt.js, the research tool, and
    # tls13_rc4_target.ps1. Also asserted at import of crypto.py.
    assert crypto.rc4(b"Key", b"Plaintext").hex() == "bbf316e8d940af0ad3"


def test_rc4_symmetric_roundtrip():
    ct = crypto.rc4(KEY, PLAINTEXT)
    assert ct != PLAINTEXT
    assert crypto.rc4(KEY, ct) == PLAINTEXT


def test_ksa_prga_symmetric_via_sbox():
    sbox = crypto.rc4_ksa(KEY)
    ct = crypto.rc4_prga(sbox, PLAINTEXT)
    # PRGA runs over a COPY of the S-box, so the same box decrypts.
    assert crypto.rc4_prga(sbox, ct) == PLAINTEXT


def test_rc4_empty_key_rejected():
    with pytest.raises(ValueError):
        crypto.rc4_ksa(b"")


# --------------------------------------------------------------------------- #
# Candidate extraction
# --------------------------------------------------------------------------- #

def test_extract_finds_isolated_ascii_key():
    blob = b"\x00\x01" + KEY + b"\x00\xff"
    assert KEY in set(rc4d.extract_candidates(blob))


def test_extract_finds_utf16_key():
    utf16 = b"".join(bytes([c, 0]) for c in KEY)   # UTF-16LE
    blob = b"\x00" + utf16 + b"\x00"
    assert KEY in set(rc4d.extract_candidates(blob))


def test_extract_windows_key_inside_longer_blob():
    filler = b"x" * 40
    blob = filler + KEY + filler                       # one printable run > 64
    assert KEY in set(rc4d.extract_candidates(blob, max_window_run=256))


def test_extract_skips_giant_run():
    giant = b"A" * 5000                                 # > max_window_run -> skipped
    assert b"A" * 6 not in set(rc4d.extract_candidates(giant, max_window_run=256))


def test_materialize_dedups():
    stream = [("a", b"one"), ("b", b"one"), ("c", b"two"), ("d", b"")]
    out = rc4d.materialize_candidates(stream)
    assert [k for _, k in out] == [b"one", b"two"]


# --------------------------------------------------------------------------- #
# TLS 1.3 key schedule — RFC 8448 sec 3, TLS_AES_128_GCM_SHA256
# --------------------------------------------------------------------------- #

CHTS = "b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21"
CHTS_KEY = "dbfaa693d1762c5b666af5d950258d01"
CHTS_IV = "5bd3c71b836e0b76bb73265f"
SHTS = "b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38"
SHTS_KEY = "3fce516009c21727d0f2e4e86ee403bc"
SHTS_IV = "5d313eb2671276ee13000b30"


def test_rfc8448_client_key_iv():
    pytest.importorskip("cryptography")
    key, iv = crypto.derive_key_iv(bytes.fromhex(CHTS), "TLS_AES_128_GCM_SHA256")
    assert key.hex() == CHTS_KEY
    assert iv.hex() == CHTS_IV


def test_rfc8448_server_key_iv():
    pytest.importorskip("cryptography")
    key, iv = crypto.derive_key_iv(bytes.fromhex(SHTS), "TLS_AES_128_GCM_SHA256")
    assert key.hex() == SHTS_KEY
    assert iv.hex() == SHTS_IV


def test_aead_roundtrip_and_wrong_secret():
    pytest.importorskip("cryptography")
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    secret = "11" * 32
    suite = "TLS_AES_256_GCM_SHA384"
    key, iv = crypto.derive_key_iv(bytes.fromhex(secret), suite)
    plaintext = b"hello tls13\x17"          # content + inner type 0x17
    aad = bytes.fromhex("1703030020")
    ct = AESGCM(key).encrypt(crypto.record_nonce(iv, 0), plaintext, aad)
    got = crypto.try_decrypt(bytes.fromhex(secret), suite, 0, aad, ct)
    assert got == plaintext
    assert crypto.inner_content_type(got) == 0x17
    # wrong secret -> tag fails -> None
    assert crypto.try_decrypt(bytes.fromhex("22" * 48), suite, 0, aad, ct) is None
    # right secret, wrong seq -> None
    assert crypto.try_decrypt(bytes.fromhex(secret), suite, 5, aad, ct) is None


def test_parse_records_and_hello_parsers():
    stream = bytes.fromhex("16030300" + "03" + "aabbcc" + "17030300" + "02" + "dead")
    recs = crypto.parse_records(stream)
    assert [(c, f.hex()) for c, _, f in recs] == [(0x16, "aabbcc"), (0x17, "dead")]
    ch = bytes([0x01, 0, 0, 40, 0x03, 0x03]) + bytes(range(32)) + b"\x00\x00"
    assert crypto.client_random_from_clienthello(ch) == bytes(range(32)).hex()
    sh = bytes([0x02, 0, 0, 40, 0x03, 0x03]) + bytes(32) + b"\x00" + b"\x13\x02"
    assert crypto.cipher_suite_from_serverhello(sh) == 0x1302


def test_trial_decrypt_rejects_low_printable_output_with_token():
    # S2 regression: output that is almost entirely non-printable but happens to
    # contain a token byte ("{") must NOT be accepted just because a token exists.
    key = b"secretkey"
    plaintext = b"\x00" * 100 + b"{" + b"\x00" * 100
    ct = crypto.rc4(key, plaintext)
    r = rc4d.trial_decrypt(ct, [("k", key)])
    assert r is not None and r["key"] == key
    assert r["accepted"] is False


def test_trial_decrypt_accepts_real_plaintext():
    key = b"secretkey"
    plaintext = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"
    ct = crypto.rc4(key, plaintext)
    r = rc4d.trial_decrypt(ct, [("k", key)])
    assert r is not None and r["accepted"] is True
