"""Mid-stream MTProto obf recovery: per-direction key choice + short-client streams.

* direction wiring — each alignment search is told which direction it runs on
  ("write" for the client run, "read" for the server run), so the quick-ack
  disambiguation in :func:`recover_obf_alignment` applies to the right side.
* M4 — a stream whose client run never reaches the 64-byte init block (idle
  client, download-heavy flow) is still recovered from its server run alone.
* M6 — each direction may be recovered by a DIFFERENT snapshot of the same
  connection: an older snapshot that only reaches the client tail no longer
  blocks a newer one from recovering the server tail. Trials are counted once
  per key actually tried, and the extra search stays bounded.

Synthetic data only; see ``test_mtproto_obf_recovery_directions`` for builders.
"""

from __future__ import annotations

import random

import pytest

pytest.importorskip("cryptography")  # CTR + IGE backend

from friTap.offline.mtproto import crypto
from friTap.offline.mtproto import decrypt
from friTap.offline.mtproto.decrypt import _process_recovered_stream, _process_stream
from friTap.offline.mtproto.records import MtprotoStats
from friTap.offline.mtproto.transport import (
    CLIENT_TO_SERVER,
    DEFAULT_OBF_ENDPOINT_MATCH_BLOCKS,
    SERVER_TO_CLIENT,
    counter_add,
)
from friTap.protocols.mtproto_keylog_spec import MtprotoObfKey
from tests.unit.test_mtproto_obf_recovery_directions import (
    _TELEGRAM_DC,
    _authkey,
    _obf_tail_dir,
    _pair,
)

_MATCHING_ENDPOINT = f"{_TELEGRAM_DC[0]}:{_TELEGRAM_DC[1]}"
_CLIENT_MSGS = [b"c1", b"c2", b"c3"]
_SERVER_MSGS = [b"s1", b"s2", b"s3"]
_BASE = 64  # a small base depth keeps every real search cheap


def _keymap(rng):
    auth_key = rng.randbytes(crypto.AUTH_KEY_LEN)
    return auth_key, {crypto.compute_auth_key_id(auth_key): _authkey(auth_key)}


def _random_key(rng, *, endpoint="-", key_out=None, key_in=None):
    return MtprotoObfKey(
        key_out=key_out or rng.randbytes(32), iv_out=rng.randbytes(16), num_out=0,
        key_in=key_in or rng.randbytes(32), iv_in=rng.randbytes(16), num_in=0,
        endpoint=endpoint,
    )


def _server_only_key(rng, key_in, iv_in, num_in, *, endpoint="-"):
    return MtprotoObfKey(
        key_out=rng.randbytes(32), iv_out=rng.randbytes(16), num_out=0,
        key_in=key_in, iv_in=iv_in, num_in=num_in, endpoint=endpoint,
    )


def _spy(monkeypatch, *, skip_wide=True):
    """Record ``(direction, max_blocks)`` per search; wide searches return None."""
    seen: list = []
    real = decrypt.recover_obf_alignment

    def _record(key, live, num, run, akm, *, transport_hint=None, max_blocks=None,
                direction=None):
        seen.append((direction, max_blocks))
        if skip_wide and max_blocks == DEFAULT_OBF_ENDPOINT_MATCH_BLOCKS:
            return None
        return real(key, live, num, run, akm, transport_hint=transport_hint,
                    max_blocks=max_blocks, direction=direction)

    monkeypatch.setattr(decrypt, "recover_obf_alignment", _record)
    return seen


def _two_snapshots(rng, auth_key):
    """(S1, S2, pair): S1 reaches the client tail only, S2 reaches both tails."""
    key_out, run_out, iv_out, num_out = _obf_tail_dir(
        rng, _CLIENT_MSGS, auth_key, "write", chop=0, lag_blocks=1,
    )
    key_in, run_in, iv_in, num_in = _obf_tail_dir(
        rng, _SERVER_MSGS, auth_key, "read", chop=0, lag_blocks=1,
    )
    s2 = MtprotoObfKey(
        key_out=key_out, iv_out=iv_out, num_out=num_out,
        key_in=key_in, iv_in=iv_in, num_in=num_in, endpoint="-",
    )
    # Older snapshot: same key material, but its server counter sits far beyond
    # the base window, so only its client half aligns.
    s1 = MtprotoObfKey(
        key_out=key_out, iv_out=counter_add(iv_out, -1), num_out=num_out,
        key_in=key_in, iv_in=counter_add(iv_in, -200), num_in=num_in, endpoint="-",
    )
    return s1, s2, _pair(run_out, run_in)


# --------------------------------------------------------------------------- #
# direction wiring
# --------------------------------------------------------------------------- #

def test_each_search_is_told_its_direction(monkeypatch):
    rng = random.Random(1)
    _auth_key, keymap = _keymap(rng)
    seen = _spy(monkeypatch)
    pair = _pair(rng.randbytes(200), rng.randbytes(200))

    assert _process_recovered_stream(
        pair, [_random_key(rng)], keymap, MtprotoStats(), obf_max_blocks=_BASE,
    ) is None
    assert seen == [(CLIENT_TO_SERVER, _BASE), (SERVER_TO_CLIENT, _BASE)]
    assert (CLIENT_TO_SERVER, SERVER_TO_CLIENT) == ("write", "read")


# --------------------------------------------------------------------------- #
# M4: a short client run no longer hides a recoverable server run
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("client_len", [0, 20, 63])
def test_short_client_stream_recovers_from_server_run(client_len):
    rng = random.Random(40 + client_len)
    auth_key, keymap = _keymap(rng)
    key_in, run_in, iv_in, num_in = _obf_tail_dir(
        rng, _SERVER_MSGS, auth_key, "read", chop=0, lag_blocks=2,
    )
    pair = _pair(rng.randbytes(client_len), run_in)
    stats = MtprotoStats()

    got = list(_process_stream(
        pair, keymap, stats, [_server_only_key(rng, key_in, iv_in, num_in)],
        obf_max_blocks=_BASE,
    ))

    assert [m.message for m in got] == _SERVER_MSGS
    assert all(m.direction == "read" for m in got)
    assert stats.streams_recovered_via_obf == 1
    assert stats.streams_short == 0


def test_short_client_stream_that_does_not_recover_keeps_short_counting():
    rng = random.Random(50)
    _auth_key, keymap = _keymap(rng)
    pair = _pair(rng.randbytes(20), rng.randbytes(300))  # DC endpoint: MTProto evidence
    stats = MtprotoStats()

    assert list(_process_stream(
        pair, keymap, stats, [_random_key(rng)], obf_max_blocks=_BASE,
    )) == []
    assert stats.streams_short == 1
    assert stats.streams_recovered_via_obf == 0
    assert stats.streams_degraded_unrecovered == 0


def test_short_non_mtproto_stream_that_does_not_recover_stays_non_mtproto():
    rng = random.Random(51)
    _auth_key, keymap = _keymap(rng)
    pair = _pair(rng.randbytes(20), rng.randbytes(300),
                 server_addr=("10.0.0.1", 443))
    stats = MtprotoStats()

    assert list(_process_stream(
        pair, keymap, stats, [_random_key(rng)], obf_max_blocks=_BASE,
    )) == []
    assert stats.streams_degraded_non_mtproto == 1
    assert stats.streams_short == 0


def test_short_stream_without_a_recoverable_server_run_is_never_searched(monkeypatch):
    rng = random.Random(52)
    _auth_key, keymap = _keymap(rng)
    seen = _spy(monkeypatch)
    pair = _pair(rng.randbytes(20), rng.randbytes(39))
    stats = MtprotoStats()

    assert list(_process_stream(
        pair, keymap, stats, [_random_key(rng)], obf_max_blocks=_BASE,
    )) == []
    assert seen == []
    assert stats.obf_trials == 0
    assert stats.streams_short == 1


# --------------------------------------------------------------------------- #
# M6: each direction may be recovered by a different snapshot
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("newer_first", [False, True])
def test_both_directions_recover_whatever_the_snapshot_order(newer_first):
    rng = random.Random(60)
    auth_key, keymap = _keymap(rng)
    s1, s2, pair = _two_snapshots(rng, auth_key)
    order = [s2, s1] if newer_first else [s1, s2]
    stats = MtprotoStats()

    got = _process_recovered_stream(pair, order, keymap, stats, obf_max_blocks=_BASE)

    assert sorted(m.message for m in got if m.direction == "write") == _CLIENT_MSGS
    assert sorted(m.message for m in got if m.direction == "read") == _SERVER_MSGS
    assert stats.obf_alignment_failed == 0
    # Older-first: both snapshots were needed. Newer-first: S1 is never tried.
    assert stats.obf_trials == (1 if newer_first else 2)


def test_aligned_direction_is_never_searched_again(monkeypatch):
    rng = random.Random(61)
    auth_key, keymap = _keymap(rng)
    s1, s2, pair = _two_snapshots(rng, auth_key)
    seen = _spy(monkeypatch)

    _process_recovered_stream(pair, [s1, s2], keymap, MtprotoStats(),
                              obf_max_blocks=_BASE)

    # S1: client (hit) + server (miss); then only S2's server half is searched.
    assert seen == [(CLIENT_TO_SERVER, _BASE), (SERVER_TO_CLIENT, _BASE),
                    (SERVER_TO_CLIENT, _BASE)]


def test_deferred_key_trial_is_counted_when_a_later_key_wins():
    rng = random.Random(62)
    auth_key, keymap = _keymap(rng)
    key_in, run_in, iv_in, num_in = _obf_tail_dir(
        rng, _SERVER_MSGS, auth_key, "read", chop=0, lag_blocks=2,
    )
    wrong_matched = _random_key(rng, endpoint=_MATCHING_ENDPOINT)
    good = _server_only_key(rng, key_in, iv_in, num_in)
    stats = MtprotoStats()

    got = _process_recovered_stream(
        _pair(b"", run_in), [wrong_matched, good], keymap, stats, obf_max_blocks=_BASE,
    )

    assert [m.message for m in got] == _SERVER_MSGS
    assert stats.obf_trials == 2
    assert stats.obf_alignment_failed == 1


def test_missing_direction_widens_only_same_material_matched_keys(monkeypatch):
    """The fill-in wide search stays on snapshots of the SAME connection."""
    rng = random.Random(63)
    auth_key, keymap = _keymap(rng)
    key_in, run_in, iv_in, num_in = _obf_tail_dir(
        rng, _SERVER_MSGS, auth_key, "read", chop=0, lag_blocks=2,
    )
    primary = _server_only_key(rng, key_in, iv_in, num_in, endpoint=_MATCHING_ENDPOINT)
    sibling = MtprotoObfKey(  # same client material, another counter
        key_out=primary.key_out, iv_out=rng.randbytes(16), num_out=0,
        key_in=key_in, iv_in=iv_in, num_in=num_in, endpoint=_MATCHING_ENDPOINT,
    )
    unrelated = [_random_key(rng, endpoint=_MATCHING_ENDPOINT) for _ in range(3)]
    seen = _spy(monkeypatch)
    stats = MtprotoStats()

    got = _process_recovered_stream(
        _pair(rng.randbytes(300), run_in), [primary, *unrelated, sibling],
        keymap, stats, obf_max_blocks=_BASE,
    )

    assert [m.message for m in got] == _SERVER_MSGS
    wide_client = [s for s in seen if s == (CLIENT_TO_SERVER,
                                            DEFAULT_OBF_ENDPOINT_MATCH_BLOCKS)]
    assert len(wide_client) == 2  # primary + sibling, never the unrelated keys
    assert (SERVER_TO_CLIENT, DEFAULT_OBF_ENDPOINT_MATCH_BLOCKS) not in seen
    # Every key was tried once for the missing client direction at base depth.
    assert seen.count((CLIENT_TO_SERVER, _BASE)) == 5
    assert stats.obf_trials == 5
    assert stats.obf_alignment_failed == 4
