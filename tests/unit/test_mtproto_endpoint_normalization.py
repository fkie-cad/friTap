"""M5: MTProto obf-key endpoint hints must match IPv6 and v4-mapped peers.

The agent writes IPv6 peers bracketed with all eight groups uncompressed
(``[2001:67c:4e8:f004:0:0:0:a]:443``, see agent/ms_agent/engines/mtproto/
endpoint.ts) while scapy reports stream addresses compressed and unbracketed, so
IPv6 peers never matched. Both sides now go through ``normalize_endpoint``.
"""

from __future__ import annotations

import random
from types import SimpleNamespace

import pytest

from friTap.offline.mtproto import decrypt
from friTap.offline.mtproto.keylog import normalize_endpoint, stream_endpoint
from friTap.protocols.mtproto_keylog_spec import MtprotoObfKey

_V6_AGENT = "[2001:67c:4e8:f004:0:0:0:a]:443"
_V6_SCAPY = ("2001:67c:4e8:f004::a", 443)


@pytest.mark.parametrize("text, expected", [
    ("149.154.167.41:443", "149.154.167.41:443"),
    (_V6_AGENT, "[2001:67c:4e8:f004::a]:443"),
    ("[2001:67C:4E8:F004::A]:443", "[2001:67c:4e8:f004::a]:443"),
    ("[0:0:0:0:0:ffff:9505:a729]:443", "149.5.167.41:443"),
    ("[::ffff:149.154.167.41]:443", "149.154.167.41:443"),
    ("-", None),
    ("", None),
    (None, None),
    ("149.154.167.41", None),
    ("[2001:db8::1]:", None),
])
def test_normalize_endpoint(text, expected):
    assert normalize_endpoint(text) == expected


@pytest.mark.parametrize("addr, expected", [
    (("149.154.167.41", 443), "149.154.167.41:443"),
    (_V6_SCAPY, "[2001:67c:4e8:f004::a]:443"),
    (("::ffff:149.154.167.41", 443), "149.154.167.41:443"),
])
def test_stream_endpoint(addr, expected):
    assert stream_endpoint(addr) == expected


def _key(endpoint: str) -> MtprotoObfKey:
    rng = random.Random(endpoint)
    return MtprotoObfKey(key_out=rng.randbytes(32), iv_out=rng.randbytes(16),
                         key_in=rng.randbytes(32), iv_in=rng.randbytes(16),
                         endpoint=endpoint)


def _pair(server_addr):
    return SimpleNamespace(client_addr=("192.168.0.66", 59040), server_addr=server_addr)


@pytest.mark.parametrize("server_addr, hint", [
    (_V6_SCAPY, _V6_AGENT),
    (("::ffff:149.154.167.41", 443), "149.154.167.41:443"),
    (("149.154.167.41", 443), "[0:0:0:0:0:ffff:959a:a729]:443"),
    (("149.154.167.41", 443), "149.154.167.41:443"),
])
def test_agent_endpoint_hint_is_ordered_first(server_addr, hint):
    other, matching = _key("-"), _key(hint)
    ordered = decrypt._ordered_obf_keys([other, matching], _pair(server_addr))
    assert ordered == [matching, other]


def test_unknown_endpoint_never_matches():
    assert not decrypt._key_endpoint_in(_key("-"), decrypt._pair_endpoints(_pair(_V6_SCAPY)))


def test_ipv6_endpoint_hint_auto_widens_recovery():
    """End-to-end: the agent's IPv6 hint unlocks the endpoint-matched deep search."""
    pytest.importorskip("cryptography")
    from friTap.offline.mtproto import crypto
    from friTap.offline.mtproto.records import MtprotoStats
    from friTap.offline.mtproto.transport import DEFAULT_OBF_MAX_BLOCKS
    from tests.unit.test_mtproto_obf_recovery_directions import (
        _authkey, _obf_tail_dir, _pair as _stream_pair,
    )

    rng = random.Random(101)
    auth_key = rng.randbytes(crypto.AUTH_KEY_LEN)
    keymap = {crypto.compute_auth_key_id(auth_key): _authkey(auth_key)}
    messages = [b"srv-a", b"srv-b", b"srv-c"]
    key_in, run_in, iv_in, num_in = _obf_tail_dir(
        rng, messages, auth_key, "read", chop=0, lag_blocks=DEFAULT_OBF_MAX_BLOCKS + 8,
    )
    pair = _stream_pair(b"", run_in, server_addr=_V6_SCAPY)
    key = MtprotoObfKey(key_out=rng.randbytes(32), iv_out=rng.randbytes(16),
                        key_in=key_in, iv_in=iv_in, num_in=num_in, endpoint=_V6_AGENT)
    got = decrypt._process_recovered_stream(pair, [key], keymap, MtprotoStats())
    assert got is not None and [m.message for m in got] == messages
