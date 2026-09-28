"""Mid-stream MTProto obf-recovery: configurable back-search + per-direction align.

These cover three production fixes on the offline recovery path:

* FIX 1 — the CTR back-search window (``obf_max_blocks``) is threaded from the
  caller, so a run placed further behind the live counter than the default
  window can still be recovered by raising the bound.
* FIX 2 — each direction aligns INDEPENDENTLY: a flow whose client tail never
  aligns is still recovered from the server direction alone.
* FIX 3 — a mid-stream flow whose obf recovery was attempted-and-failed is
  counted ONLY as ``degraded_unrecovered`` (never also ``degraded``), while a
  mid-stream flow with no obf keys is counted as ``degraded``.

Synthetic data only: a known AES-256 obf key + CTR counter, a short
abridged/intermediate MTProto stream carrying a known auth_key_id, and a
"captured" run planted a chosen number of blocks behind the live counter.
"""

from __future__ import annotations

import random
from types import SimpleNamespace

import pytest

pytest.importorskip("cryptography")  # CTR + IGE backend

from friTap.offline.mtproto import crypto
from friTap.offline.mtproto import decrypt
from friTap.offline.mtproto.decrypt import (
    _process_recovered_stream,
    _process_stream,
    iter_decrypted_messages,
)
from friTap.offline.mtproto.records import MtprotoStats
from friTap.offline.mtproto.transport import DEFAULT_OBF_MAX_BLOCKS, counter_add
from friTap.protocols.mtproto_keylog_spec import MtprotoAuthKey, MtprotoObfKey
from tests.unit._mtproto_helpers import aes_ctr
from tests.unit._mtproto_helpers import intermediate_frame as _intermediate_frame

# A published Telegram DC endpoint, so an init-less stream carries MTProto evidence.
_TELEGRAM_DC = ("149.154.167.41", 443)


# --------------------------------------------------------------------------- #
# Synthetic stream builders
# --------------------------------------------------------------------------- #

def _authkey(auth_key: bytes, dc_id: int = 2) -> MtprotoAuthKey:
    return MtprotoAuthKey(
        dc_id=dc_id,
        auth_key_id=crypto.compute_auth_key_id(auth_key),
        auth_key=auth_key,
    )


def _obf_tail_dir(rng, messages, auth_key, direction, *, chop, lag_blocks):
    """Build one direction's obfuscated tail + its live CTR state.

    Frames are AES-IGE records for *direction* ("write"/"read"), obfuscated with a
    fresh AES-256-CTR key. The live counter is placed ``lag_blocks`` whole blocks
    past the end of the captured (optionally head-chopped) tail — i.e. the run sits
    ``lag_blocks`` blocks behind where the search anchors from.

    Returns ``(key, run_bytes, live_counter, num)`` — the fields an
    :class:`MtprotoObfKey` half is seeded from.
    """
    key = rng.randbytes(32)
    start_counter = rng.randbytes(16)
    frames = b"".join(
        _intermediate_frame(crypto.build_encrypted_record(auth_key, m, direction))
        for m in messages
    )
    ct = aes_ctr(key, start_counter).update(frames)
    live_counter = counter_add(start_counter, len(frames) // 16 + lag_blocks)
    return key, ct[chop:], live_counter, len(frames) % 16


class _Side:
    """Minimal stand-in for a reassembled TCP direction."""

    def __init__(self, data, *, saw_syn=False, has_start_gap=False, degraded=False):
        self._data = bytes(data)
        self.saw_syn = saw_syn
        self.has_start_gap = has_start_gap
        self.degraded = degraded

    def contiguous_bytes(self) -> bytes:
        return self._data

    def timestamp_at(self, offset: int) -> float:  # noqa: ARG002 - offline stub
        return 0.0


def _pair(client_data, server_data, *, client_addr=("192.168.0.66", 59040),
          server_addr=_TELEGRAM_DC, **client_kw):
    return SimpleNamespace(
        client=_Side(client_data, **client_kw),
        server=_Side(server_data),
        client_addr=client_addr,
        server_addr=server_addr,
        ss_family="AF_INET",
    )


# --------------------------------------------------------------------------- #
# FIX 1: the back-search window is configurable
# --------------------------------------------------------------------------- #

def test_alignment_fails_at_default_window_but_succeeds_when_widened():
    rng = random.Random(11)
    auth_key = rng.randbytes(crypto.AUTH_KEY_LEN)
    keymap = {crypto.compute_auth_key_id(auth_key): _authkey(auth_key)}
    messages = [b"alpha", b"bravo", b"charlie"]

    # Plant the captured client run a few blocks BEYOND the default window, so the
    # search must be widened past DEFAULT_OBF_MAX_BLOCKS to reach it.
    lag = DEFAULT_OBF_MAX_BLOCKS + 8
    key_out, run_out, iv_out, num_out = _obf_tail_dir(
        rng, messages, auth_key, "write", chop=0, lag_blocks=lag,
    )
    obf = MtprotoObfKey(
        key_out=key_out, iv_out=iv_out, num_out=num_out,
        key_in=rng.randbytes(32), iv_in=rng.randbytes(16), num_in=0,
        endpoint="-",
    )
    pair = _pair(run_out, b"")

    # Default window (== DEFAULT_OBF_MAX_BLOCKS): the run is out of reach.
    assert _process_recovered_stream(pair, [obf], keymap, MtprotoStats()) is None

    # Widened window: the same key now aligns and every client record decrypts.
    stats = MtprotoStats()
    got = _process_recovered_stream(
        pair, [obf], keymap, stats, obf_max_blocks=lag + 4,
    )
    assert got is not None
    assert [m.message for m in got] == messages
    assert all(m.direction == "write" for m in got)


# --------------------------------------------------------------------------- #
# FIX 2: each direction is recovered independently
# --------------------------------------------------------------------------- #

def test_server_direction_alone_is_recovered_when_client_never_aligns():
    rng = random.Random(22)
    auth_key = rng.randbytes(crypto.AUTH_KEY_LEN)
    keymap = {crypto.compute_auth_key_id(auth_key): _authkey(auth_key)}
    server_messages = [b"srv-1", b"srv-2", b"srv-3"]

    key_in, run_in, iv_in, num_in = _obf_tail_dir(
        rng, server_messages, auth_key, "read", chop=0, lag_blocks=3,
    )
    # The client run is long enough to be attempted but is random noise under a
    # random key, so it can never align — only the server direction can recover.
    client_noise = rng.randbytes(300)
    obf = MtprotoObfKey(
        key_out=rng.randbytes(32), iv_out=rng.randbytes(16), num_out=0,
        key_in=key_in, iv_in=iv_in, num_in=num_in,
        endpoint="-",
    )
    pair = _pair(client_noise, run_in)

    stats = MtprotoStats()
    got = _process_recovered_stream(pair, [obf], keymap, stats, obf_max_blocks=64)

    assert got is not None
    assert [m.message for m in got] == server_messages
    assert all(m.direction == "read" for m in got)
    # One (stream, key) trial, and it counts as aligned because a direction resolved.
    assert stats.obf_trials == 1
    assert stats.obf_alignment_failed == 0


# --------------------------------------------------------------------------- #
# FIX 3: a failed mid-stream flow is counted exactly once
# --------------------------------------------------------------------------- #

def _assert_midstream_transport_undetected(pair) -> None:
    """Guard the synthetic fixture: the random init must not look like a transport."""
    from friTap.offline.mtproto.reassembly import INIT_BLOCK_LEN
    from friTap.offline.mtproto.transport import ObfuscationCipher, detect_transport

    init = pair.client.contiguous_bytes()[:INIT_BLOCK_LEN]
    decrypted = ObfuscationCipher(init).decrypt_out(init)
    assert detect_transport(decrypted) is None


def test_failed_recovery_counts_degraded_unrecovered_once_not_degraded():
    rng = random.Random(33)
    auth_key = rng.randbytes(crypto.AUTH_KEY_LEN)
    keymap = {crypto.compute_auth_key_id(auth_key): _authkey(auth_key)}
    # A genuine mid-stream flow (>= 64 random client bytes -> transport undetected)
    # WITH obf keys supplied, but a random key that cannot align.
    obf = MtprotoObfKey(
        key_out=rng.randbytes(32), iv_out=rng.randbytes(16), num_out=0,
        key_in=rng.randbytes(32), iv_in=rng.randbytes(16), num_in=0,
        endpoint="-",
    )
    pair = _pair(rng.randbytes(200), rng.randbytes(200))
    _assert_midstream_transport_undetected(pair)

    stats = MtprotoStats()
    msgs = list(_process_stream(pair, keymap, stats, [obf]))

    assert msgs == []
    # Mutually exclusive: unrecovered exactly once, and NOT also degraded.
    assert stats.streams_degraded_unrecovered == 1
    assert stats.streams_degraded == 0


def test_midstream_flow_without_obf_keys_counts_degraded_only():
    rng = random.Random(34)
    pair = _pair(rng.randbytes(200), rng.randbytes(100))  # server_addr is a DC
    _assert_midstream_transport_undetected(pair)

    stats = MtprotoStats()
    msgs = list(_process_stream(pair, {}, stats, None))

    assert msgs == []
    # No obf keys -> the only recovery path is a re-capture, so it is degraded,
    # and never touches the unrecovered bucket.
    assert stats.streams_degraded == 1
    assert stats.streams_degraded_unrecovered == 0


# --------------------------------------------------------------------------- #
# The CLI knob reaches the recovery search
# --------------------------------------------------------------------------- #

def test_iter_decrypted_messages_forwards_obf_max_blocks(monkeypatch):
    rng = random.Random(35)
    auth_key = rng.randbytes(crypto.AUTH_KEY_LEN)
    keymap = {crypto.compute_auth_key_id(auth_key): _authkey(auth_key)}
    pair = _pair(rng.randbytes(200), rng.randbytes(200))

    seen: list = []

    def _spy(key, live, num, run, akm, *, transport_hint=None, max_blocks=None,
             direction=None):
        seen.append(max_blocks)
        return None

    monkeypatch.setattr(
        decrypt, "reassemble_pcap", lambda path, server_ports=(): {"only": pair})
    monkeypatch.setattr(decrypt, "recover_obf_alignment", _spy)

    obf = MtprotoObfKey(
        key_out=rng.randbytes(32), iv_out=rng.randbytes(16), num_out=0,
        key_in=rng.randbytes(32), iv_in=rng.randbytes(16), num_in=0,
        endpoint="-",
    )
    list(iter_decrypted_messages(
        "unused.pcap", keymap, obf_keys=[obf], obf_max_blocks=12345,
    ))

    # Both directions were attempted with the threaded bound (client + server).
    assert seen and all(mb == 12345 for mb in seen)
