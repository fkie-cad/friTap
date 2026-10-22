#!/usr/bin/env python3

"""Regression tests for the mid-stream TLS binding PERFORMANCE fixes.

The mid-stream stage dominated offline decode time (~37s on a real capture):
`recover_seq` brute-forces the unknown starting record sequence over up to
`DEFAULT_MAX_SEQ` (100k) candidates against the first record, and every wrong
`(secret, suite, stream)` combination exhausted the full range. Two bugs made
each trial 10x too expensive and multiplied the number of wrong trials:

  * A. `try_decrypt` re-derived the AEAD key+iv (HKDF) AND rebuilt the AEAD
       object on EVERY seq candidate, though both are invariant per (secret,
       suite). Fixed by the memoized `_prepared_cipher`.
  * C. binding walked streams-outer / bundles-inner, so a placed key kept being
       retried and unrelated streams kept being scanned after every key was
       placed. Fixed by the key-centric loop in `run_midstream_tls_stage`.

These tests pin the fixes without asserting wall-clock time (which is flaky).
"""

from __future__ import annotations

import pytest

from friTap.offline.rc4 import crypto as rc4crypto
from friTap.offline.tls import tls13
from friTap.offline.tls_midstream import crypto as mscrypto
from friTap.offline.tls_midstream import pipeline as P

# --- A: key/iv derived once, not once per seq candidate -------------------- #

@pytest.mark.skipif(not rc4crypto.backend_available(),
                    reason="AES backend (cryptography) not installed")
def test_key_derivation_hoisted_out_of_seq_loop(monkeypatch):
    """A wrong secret makes `recover_seq` try every seq in range, but the AEAD
    key/iv must be derived at most ONCE (memoized), not once per trial."""
    rc4crypto._prepared_cipher.cache_clear()
    calls = {"n": 0}
    original = rc4crypto.derive_key_iv

    def counting_derive(secret, suite):
        calls["n"] += 1
        return original(secret, suite)

    # _prepared_cipher now lives in friTap.offline.tls.tls13 and resolves
    # derive_key_iv through that module's globals, so patch it there.
    monkeypatch.setattr(tls13, "derive_key_iv", counting_derive)

    # One application_data record (content_type 0x17, fragment >= 17 bytes).
    records = [(0x17, b"\x17\x03\x03\x00\x20", b"\x00" * 32)]
    N = 4000
    # Wrong secret -> no seq authenticates -> the whole 0..N range is tried.
    assert mscrypto.recover_seq("00" * 32, "TLS_AES_128_GCM_SHA256",
                                records, max_seq=N) is None
    assert calls["n"] <= 1, (
        f"derive_key_iv ran {calls['n']} times across {N} seq trials — "
        "the per-seq key derivation regressed"
    )


# --- B: fast record_nonce is byte-identical to the reference --------------- #

def test_record_nonce_matches_reference():
    iv = bytes(range(12))
    for seq in (0, 1, 255, 256, 65535, 100000, 2 ** 40):
        reference = bytes(a ^ b for a, b in zip(iv, seq.to_bytes(len(iv), "big")))
        assert rc4crypto.record_nonce(iv, seq) == reference


# --- C: key-centric binding stops once every bundle is placed -------------- #

class _FakeStream:
    def __init__(self, name):
        self.name = name
        self.client_addr = ("10.0.0.1", 1000)
        self.server_addr = ("93.0.0.1", 443)


class _FakeState:
    tls_spans: dict = {}

    def ensure_open(self):
        pass


class _FakeResult:
    def __init__(self):
        self.stream_count = 0


class _FakeBus:
    def emit(self, event):
        pass


def test_key_centric_binding_skips_streams_after_all_bundles_placed(monkeypatch):
    """Each bundle is placed against exactly one stream; a matched bundle is never
    retried, a claimed stream never re-tested, and streams past the last placement
    are never touched."""
    streams = [_FakeStream(n) for n in ("s0", "s1", "s2", "s3")]
    bundles = [{"id": "b0"}, {"id": "b1"}]
    tested = []

    def fake_bind(bundle, stream, max_seq=P.DEFAULT_MAX_SEQ, max_records=1,
                  first_record=0):
        tested.append((bundle["id"], stream.name))
        if bundle["id"] == "b0" and stream.name == "s0":
            return object()          # b0 lives on s0
        if bundle["id"] == "b1" and stream.name == "s2":
            return object()          # b1 lives on s2
        return None

    monkeypatch.setattr(P, "load_secret_bundles", lambda path: bundles)
    monkeypatch.setattr(P, "midstream_tls_streams",
                        lambda path, server_ports=(443,): list(streams))
    monkeypatch.setattr(P, "_bind_bundle_to_stream", fake_bind)
    monkeypatch.setattr(P, "_emit_binding", lambda *a, **k: True)
    monkeypatch.setattr(P, "canonical_4tuple", lambda *a: "key")

    result = _FakeResult()
    keys = P.run_midstream_tls_stage(
        "x.pcap", "side.json",
        bus=_FakeBus(), state=_FakeState(), result=result,
    )

    assert result.stream_count == 2 and len(keys) == 1  # canonical key stubbed to one value
    assert ("b0", "s0") in tested and ("b1", "s2") in tested
    # A claimed stream is not re-tested by a later bundle...
    assert ("b1", "s0") not in tested
    # ...and no stream is touched after the last bundle is placed.
    assert all(name != "s3" for _, name in tested), f"s3 was tested: {tested}"
