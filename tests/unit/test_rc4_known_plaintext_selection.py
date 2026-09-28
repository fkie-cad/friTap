"""known_plaintext must SELECT the RC4 key, not merely veto the score winner.

Regression tests for two review findings:

* R1 ``trial_decrypt``: the candidate used to be picked by printable score and
  known_plaintext was only checked on that winner, so a wrong key whose prefix
  merely looked more printable shadowed the proven key.
* R2 ``decrypt_framed``: known_plaintext was required inside EVERY frame, so
  frames without the marker (and a marker spanning two frames) were all dropped.
"""
from __future__ import annotations

from friTap.offline.rc4 import crypto
from friTap.offline.rc4 import decrypt as rc4d

KEY = b"fritap-rc4-demo-key"
MARKER = b"GET /"
# A binary (control-byte) prefix scores near zero for the CORRECT key, while a
# wrong key's ~random output scores higher, so score ranking alone picks wrong.
BINARY_PLAINTEXT = bytes(range(1, 9)) * 12 + MARKER + b" index.html"


def _frame(payload: bytes) -> bytes:
    return len(payload).to_bytes(4, "big") + payload


def _wrong_keys(count: int = 40):
    return [(f"w{i}", f"wrong-key-{i:03d}".encode()) for i in range(count)]


def test_known_plaintext_picks_the_proving_key_over_a_higher_scoring_one():
    ct = crypto.rc4(KEY, BINARY_PLAINTEXT)
    cands = rc4d.materialize_candidates(_wrong_keys() + [("right", KEY)])
    # Precondition: score ranking alone does NOT choose the right key.
    assert rc4d.trial_decrypt(ct, cands)["key"] != KEY
    r = rc4d.trial_decrypt(ct, cands, known_plaintext=MARKER)
    assert r["key"] == KEY and r["accepted"] is True
    assert r["plaintext"] == BINARY_PLAINTEXT


def test_known_plaintext_falls_back_to_score_when_no_key_proves_it():
    ct = crypto.rc4(KEY, BINARY_PLAINTEXT)
    r = rc4d.trial_decrypt(ct, _wrong_keys(5), known_plaintext=MARKER)
    assert r is not None and r["accepted"] is False


def test_framed_known_plaintext_accepts_marker_free_frames_by_score():
    frames = [b"GET / hello over framed rc4", b"second message, no marker at all"]
    blob = b"".join(_frame(crypto.rc4(KEY, f)) for f in frames)
    cands = _wrong_keys(5) + [("right", KEY)]
    out = rc4d.decrypt_framed(blob, cands, known_plaintext=MARKER)
    assert [r["plaintext"] for r in out] == frames
    assert all(r["key"] == KEY for r in out)


def test_framed_known_plaintext_spanning_a_frame_boundary():
    frames = [b"the request line is GE", b"T / and it continues here"]
    blob = b"".join(_frame(crypto.rc4(KEY, f)) for f in frames)
    out = rc4d.decrypt_framed(blob, [("right", KEY)], known_plaintext=MARKER)
    assert [r["plaintext"] for r in out] == frames


def test_framed_marker_frame_accepted_even_when_it_scores_low():
    frames = [bytes(range(1, 9)) * 8 + MARKER, b"a normal printable second frame"]
    blob = b"".join(_frame(crypto.rc4(KEY, f)) for f in frames)
    out = rc4d.decrypt_framed(blob, [("right", KEY)], known_plaintext=MARKER)
    assert [r["plaintext"] for r in out] == frames


def test_framed_known_plaintext_rejects_low_scoring_marker_free_frames():
    frames = [b"GET / first", bytes(range(1, 9)) * 8]
    blob = b"".join(_frame(crypto.rc4(KEY, f)) for f in frames)
    out = rc4d.decrypt_framed(blob, [("right", KEY)], known_plaintext=MARKER)
    assert [r["plaintext"] for r in out] == [frames[0]]


def test_framed_known_plaintext_no_proving_key_yields_nothing():
    frames = [b"GET / hello", b"more printable text"]
    blob = b"".join(_frame(crypto.rc4(KEY, f)) for f in frames)
    assert rc4d.decrypt_framed(blob, _wrong_keys(5), known_plaintext=MARKER) == []


def test_framed_without_known_plaintext_unchanged():
    frames = [b"plain printable message one", b"plain printable message two"]
    blob = b"".join(_frame(crypto.rc4(KEY, f)) for f in frames)
    out = rc4d.decrypt_framed(blob, _wrong_keys(3) + [("right", KEY)])
    assert [r["plaintext"] for r in out] == frames
