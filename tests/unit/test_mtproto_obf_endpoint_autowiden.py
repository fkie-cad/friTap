"""Endpoint-matched auto-widen + the generic ``--resync-search-depth`` override.

These cover the "make the mid-stream search automatic when we're confident, behind
ONE general knob" work built on top of the per-direction recovery:

* Part A — an obf key whose endpoint hint ties it to THIS flow auto-widens the CTR
  back-search on a base-depth miss, so it recovers a mid-stream flow at the DEFAULT
  depth with no flag; the SAME key with a blank (``-``) endpoint does NOT, proving
  the expensive deep search is gated on the endpoint match (never fired for every
  un-attributed key).
* Part B — the generic ``resync_search_depth`` reaches the recovery search: the CLI
  merge emits it (replacing the old MTProto-specific kwarg) and the ``pcap_to_tap``
  boundary forwards it.

Synthetic data only (no real keys): the fixtures/helpers are reused from
``test_mtproto_obf_recovery_directions``.
"""

from __future__ import annotations

import random
from types import SimpleNamespace

import pytest

pytest.importorskip("cryptography")  # CTR + IGE backend

from friTap.offline.mtproto import crypto
from friTap.offline.mtproto import decrypt
from friTap.offline.mtproto.decrypt import _process_recovered_stream
from friTap.offline.mtproto.records import MtprotoStats
from friTap.offline.mtproto.transport import (
    DEFAULT_OBF_ENDPOINT_MATCH_BLOCKS,
    DEFAULT_OBF_MAX_BLOCKS,
)
from friTap.protocols.mtproto_keylog_spec import MtprotoObfKey

# Reuse the prior worker's synthetic builders so the two suites stay in lock-step.
from tests.unit.test_mtproto_obf_recovery_directions import (
    _TELEGRAM_DC,
    _authkey,
    _obf_tail_dir,
    _pair,
)

# The published Telegram DC endpoint, as an obf-key hint string ("ip:port").
_MATCHING_ENDPOINT = f"{_TELEGRAM_DC[0]}:{_TELEGRAM_DC[1]}"


def _server_only_key(rng, run_in, iv_in, num_in, *, endpoint):
    """An obf key whose IN half recovers the server direction; OUT half is noise."""
    return MtprotoObfKey(
        key_out=rng.randbytes(32), iv_out=rng.randbytes(16), num_out=0,
        key_in=run_in, iv_in=iv_in, num_in=num_in,
        endpoint=endpoint,
    )


# --------------------------------------------------------------------------- #
# Part A: endpoint-matched keys auto-widen the search; blank-endpoint keys do not
# --------------------------------------------------------------------------- #

def test_endpoint_matched_key_auto_recovers_at_default_depth():
    """A key tagged with the flow's endpoint recovers a far tail with NO depth flag."""
    rng = random.Random(101)
    auth_key = rng.randbytes(crypto.AUTH_KEY_LEN)
    keymap = {crypto.compute_auth_key_id(auth_key): _authkey(auth_key)}
    server_messages = [b"srv-a", b"srv-b", b"srv-c"]

    # Plant the server run BEYOND the default window, so recovery at the default
    # depth is only possible if the endpoint match escalates the search.
    lag = DEFAULT_OBF_MAX_BLOCKS + 8
    key_in, run_in, iv_in, num_in = _obf_tail_dir(
        rng, server_messages, auth_key, "read", chop=0, lag_blocks=lag,
    )
    pair = _pair(b"", run_in)  # server_addr is the Telegram DC -> endpoint matches

    # Endpoint '-' (no match): at the DEFAULT depth the tail is out of reach.
    unmatched = _server_only_key(rng, key_in, iv_in, num_in, endpoint="-")
    assert _process_recovered_stream(pair, [unmatched], keymap, MtprotoStats()) is None

    # Endpoint == the flow's server: the same key auto-widens and recovers, still
    # at the DEFAULT depth (no obf_max_blocks / --resync-search-depth given).
    matched = _server_only_key(
        rng, key_in, iv_in, num_in, endpoint=_MATCHING_ENDPOINT,
    )
    stats = MtprotoStats()
    got = _process_recovered_stream(pair, [matched], keymap, stats)
    assert got is not None
    assert [m.message for m in got] == server_messages
    assert all(m.direction == "read" for m in got)
    assert stats.obf_trials == 1
    assert stats.obf_alignment_failed == 0


# --------------------------------------------------------------------------- #
# Part A guard: the deep search fires ONLY for endpoint-matched keys
# --------------------------------------------------------------------------- #

def _spy_recover(seen):
    """A recover_obf_alignment stand-in that records each call's max_blocks."""

    def _spy(key, live, num, run, akm, *, transport_hint=None, max_blocks=None,
             direction=None):
        seen.append(max_blocks)
        return None

    return _spy


def test_unmatched_key_is_never_searched_at_the_wide_ceiling(monkeypatch):
    """A blank-endpoint key stays capped at obf_max_blocks — no expensive escalation."""
    rng = random.Random(202)
    auth_key = rng.randbytes(crypto.AUTH_KEY_LEN)
    keymap = {crypto.compute_auth_key_id(auth_key): _authkey(auth_key)}
    pair = _pair(rng.randbytes(200), rng.randbytes(200))

    seen: list = []
    monkeypatch.setattr(decrypt, "recover_obf_alignment", _spy_recover(seen))

    unmatched = MtprotoObfKey(
        key_out=rng.randbytes(32), iv_out=rng.randbytes(16), num_out=0,
        key_in=rng.randbytes(32), iv_in=rng.randbytes(16), num_in=0,
        endpoint="-",
    )
    assert _process_recovered_stream(pair, [unmatched], keymap, MtprotoStats()) is None

    # Both directions were searched, but only ever at the caller's base depth: the
    # ~500x deeper ceiling was NEVER handed to a non-matched key.
    assert seen == [DEFAULT_OBF_MAX_BLOCKS, DEFAULT_OBF_MAX_BLOCKS]
    assert DEFAULT_OBF_ENDPOINT_MATCH_BLOCKS not in seen


def test_matched_key_escalates_to_the_wide_ceiling_on_a_base_miss(monkeypatch):
    """An endpoint-matched key retries at the wide ceiling when the base depth fails."""
    rng = random.Random(303)
    auth_key = rng.randbytes(crypto.AUTH_KEY_LEN)
    keymap = {crypto.compute_auth_key_id(auth_key): _authkey(auth_key)}
    pair = _pair(rng.randbytes(200), rng.randbytes(200))

    seen: list = []
    monkeypatch.setattr(decrypt, "recover_obf_alignment", _spy_recover(seen))

    matched = MtprotoObfKey(
        key_out=rng.randbytes(32), iv_out=rng.randbytes(16), num_out=0,
        key_in=rng.randbytes(32), iv_in=rng.randbytes(16), num_in=0,
        endpoint=_MATCHING_ENDPOINT,
    )
    assert _process_recovered_stream(pair, [matched], keymap, MtprotoStats()) is None

    # Each direction was tried at the base depth first, then escalated once to the
    # confident-case ceiling.
    assert seen.count(DEFAULT_OBF_MAX_BLOCKS) == 2
    assert seen.count(DEFAULT_OBF_ENDPOINT_MATCH_BLOCKS) == 2


def test_matched_key_does_not_escalate_when_base_depth_already_succeeds(monkeypatch):
    """No wasted deep search: a base-depth hit means the wide ceiling is never tried."""
    rng = random.Random(404)
    auth_key = rng.randbytes(crypto.AUTH_KEY_LEN)
    keymap = {crypto.compute_auth_key_id(auth_key): _authkey(auth_key)}
    # >= 2 messages: recovery needs two consecutive anchor frames to lock alignment.
    server_messages = [b"srv-1", b"srv-2", b"srv-3"]

    key_in, run_in, iv_in, num_in = _obf_tail_dir(
        rng, server_messages, auth_key, "read", chop=0, lag_blocks=3,
    )
    pair = _pair(b"", run_in)

    seen: list = []
    real_recover = decrypt.recover_obf_alignment

    def _record(key, live, num, run, akm, *, transport_hint=None, max_blocks=None,
                direction=None):
        seen.append(max_blocks)
        return real_recover(
            key, live, num, run, akm,
            transport_hint=transport_hint, max_blocks=max_blocks,
            direction=direction,
        )

    monkeypatch.setattr(decrypt, "recover_obf_alignment", _record)

    matched = _server_only_key(
        rng, key_in, iv_in, num_in, endpoint=_MATCHING_ENDPOINT,
    )
    got = _process_recovered_stream(pair, [matched], keymap, MtprotoStats())
    assert got is not None
    # The single server-direction search succeeded at the base depth, so no escalation.
    assert seen == [DEFAULT_OBF_MAX_BLOCKS]


def test_wrong_same_endpoint_keys_never_escalate_when_a_base_hit_exists(monkeypatch):
    """PERF regression (two-pass base-first): when several same-endpoint keys are
    present and ONE aligns at the base depth, the WRONG matched keys must NOT each
    trigger the wide (~2M) ceiling. The old inline per-key escalation searched every
    wrong same-endpoint key to the deep ceiling first — a 10+ min hang on a real
    concurrent memscan keylog full of same-DC snapshots.
    """
    rng = random.Random(505)
    auth_key = rng.randbytes(crypto.AUTH_KEY_LEN)
    keymap = {crypto.compute_auth_key_id(auth_key): _authkey(auth_key)}
    server_messages = [b"srv-1", b"srv-2", b"srv-3"]
    key_in, run_in, iv_in, num_in = _obf_tail_dir(
        rng, server_messages, auth_key, "read", chop=0, lag_blocks=3,
    )
    pair = _pair(b"", run_in)

    seen: list = []
    real_recover = decrypt.recover_obf_alignment

    def _record(key, live, num, run, akm, *, transport_hint=None, max_blocks=None,
                direction=None):
        seen.append(max_blocks)
        return real_recover(
            key, live, num, run, akm,
            transport_hint=transport_hint, max_blocks=max_blocks,
            direction=direction,
        )

    monkeypatch.setattr(decrypt, "recover_obf_alignment", _record)

    good = _server_only_key(rng, key_in, iv_in, num_in, endpoint=_MATCHING_ENDPOINT)
    wrong = [
        MtprotoObfKey(
            key_out=rng.randbytes(32), iv_out=rng.randbytes(16), num_out=0,
            key_in=rng.randbytes(32), iv_in=rng.randbytes(16), num_in=0,
            endpoint=_MATCHING_ENDPOINT,
        )
        for _ in range(3)
    ]
    # Good key LAST: the wrong same-endpoint keys are tried first. The base pass finds
    # the good key, so NO key is ever searched at the wide ceiling.
    got = _process_recovered_stream(pair, wrong + [good], keymap, MtprotoStats())
    assert got is not None
    assert DEFAULT_OBF_ENDPOINT_MATCH_BLOCKS not in seen
    assert all(mb == DEFAULT_OBF_MAX_BLOCKS for mb in seen)


# --------------------------------------------------------------------------- #
# Part B: the generic --resync-search-depth reaches the recovery search
# --------------------------------------------------------------------------- #

def test_merge_manifest_emits_resync_search_depth():
    """The renamed CLI arg lands in the convert kwargs as the generic knob."""
    from friTap.offline import cli

    args = SimpleNamespace(
        tls_ports=[], quic_ports=[], keylog=None, decode_as=[],
        tls_heuristic=False, resync_search_depth=300000,
    )
    merged = cli.merge_manifest(args, {})

    assert merged["resync_search_depth"] == 300000
    # The old MTProto-specific kwarg is gone from the convert boundary.
    assert "obf_max_blocks" not in merged


def test_merge_manifest_defaults_resync_search_depth(monkeypatch):
    """Missing arg falls back to the default depth, so behaviour is unchanged."""
    from friTap.offline import cli

    args = SimpleNamespace(
        tls_ports=[], quic_ports=[], keylog=None, decode_as=[],
        tls_heuristic=False,
    )
    merged = cli.merge_manifest(args, {})
    assert merged["resync_search_depth"] == DEFAULT_OBF_MAX_BLOCKS


def test_pcap_to_tap_forwards_resync_search_depth(monkeypatch):
    """The wrapper hands the generic depth to convert_pcap_to_tap unchanged."""
    from friTap.offline import pcap_to_tap as p2t

    captured: dict = {}

    def _fake_convert(pcap_path, **kwargs):
        captured.update(kwargs)
        return SimpleNamespace(tap_path="x.tap")

    monkeypatch.setattr(p2t, "convert_pcap_to_tap", _fake_convert)
    p2t.pcap_to_tap("x.pcap", resync_search_depth=777, use_manifest=False)

    assert captured["resync_search_depth"] == 777
