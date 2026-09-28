"""Mid-stream MTProto recovery E2E via ``_process_stream`` (Workstream F).

Drives the offline decryptor with a hand-built init-less ``StreamPair`` (no SYN,
to a Telegram DC) and a synthetic obfuscated tail, exercising the three outcomes:
a matching obfuscation key recovers the stream, a missing key leaves it degraded,
and a non-matching key is counted as an attempted-but-unrecovered degrade.
"""

from __future__ import annotations

import os

import pytest

pytest.importorskip("cryptography")

from friTap.offline.mtproto import crypto
from friTap.offline.mtproto.decrypt import _process_stream
from friTap.offline.mtproto.reassembly import StreamPair
from friTap.offline.mtproto.records import MtprotoStats
from friTap.offline.mtproto.transport import counter_add
from friTap.protocols.mtproto_keylog_spec import MtprotoAuthKey, MtprotoObfKey
from tests.unit._mtproto_helpers import aes_ctr as _ctr
from tests.unit._mtproto_helpers import intermediate_frame as _intermediate_frame

_TELEGRAM_DC = "149.154.167.51"  # inside 149.154.160.0/20 — provides MTProto evidence
_CLIENT = ("10.0.0.5", 50000)


def _synthetic_stream():
    """Return (auth_key, keymap, key, run_bytes, live_counter, num)."""
    auth_key = os.urandom(crypto.AUTH_KEY_LEN)
    aid = crypto.compute_auth_key_id(auth_key)
    keymap = {aid: MtprotoAuthKey(dc_id=2, auth_key_id=aid, auth_key=auth_key)}

    frames = b"".join(
        _intermediate_frame(crypto.build_encrypted_record(auth_key, msg, "write"))
        for msg in (b"one", b"two", b"three", b"four")
    )
    key = os.urandom(32)
    start_counter = os.urandom(16)
    ct = _ctr(key, start_counter).update(frames)
    total = len(frames)
    live_counter = counter_add(start_counter, total // 16)
    num = total % 16
    chop = 30
    return auth_key, keymap, key, ct[chop:], live_counter, num


def _mid_stream_pair(run_bytes: bytes) -> StreamPair:
    pair = StreamPair(_CLIENT, (_TELEGRAM_DC, 443), "AF_INET")
    pair.client.feed(1000, run_bytes)  # NO syn -> anchor untrusted, init-less
    return pair


def test_matching_obf_key_recovers_the_stream():
    auth_key, keymap, key, run_bytes, live_counter, num = _synthetic_stream()
    obf = MtprotoObfKey(
        key_out=key, iv_out=live_counter,
        key_in=os.urandom(32), iv_in=os.urandom(16),
        num_out=num, num_in=0, endpoint="-",
    )
    stats = MtprotoStats()
    msgs = list(_process_stream(_mid_stream_pair(run_bytes), keymap, stats, [obf]))

    decoded = {m.message for m in msgs}
    # Recovery aligned at the first whole frame after the chop, so the later
    # records decrypt (the partial first frame before the boundary is dropped).
    assert b"two" in decoded
    assert stats.streams_recovered_via_obf == 1
    assert stats.streams_degraded == 0
    assert stats.streams_degraded_unrecovered == 0
    assert stats.obf_trials == 1


def test_no_obf_key_leaves_the_stream_degraded():
    _auth_key, keymap, _key, run_bytes, _lc, _n = _synthetic_stream()
    stats = MtprotoStats()
    msgs = list(_process_stream(_mid_stream_pair(run_bytes), keymap, stats))
    assert msgs == []
    assert stats.streams_degraded == 1                # E's path, no recovery tried
    assert stats.streams_recovered_via_obf == 0
    assert stats.streams_degraded_unrecovered == 0


def test_non_matching_obf_key_counts_as_unrecovered():
    _auth_key, keymap, _key, run_bytes, live_counter, num = _synthetic_stream()
    wrong = MtprotoObfKey(
        key_out=os.urandom(32), iv_out=live_counter,
        key_in=os.urandom(32), iv_in=os.urandom(16),
        num_out=num, num_in=0, endpoint="-",
    )
    stats = MtprotoStats()
    msgs = list(_process_stream(_mid_stream_pair(run_bytes), keymap, stats, [wrong]))
    assert msgs == []
    assert stats.streams_recovered_via_obf == 0
    assert stats.streams_degraded_unrecovered == 1
    assert stats.obf_trials == 1
    assert stats.obf_alignment_failed == 1
