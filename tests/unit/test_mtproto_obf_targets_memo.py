"""The key-independent anchor-target table is memoized per recovery window.

``recover_obf_alignment`` is called once per candidate obfuscation key against
the SAME direction window, and the keystream-target table depends only on
(window bytes, transports, auth_key_ids). These tests pin that the memoized
table equals the uncached one, is read-only, and is built once per window.
"""

import os
import types

import pytest

from friTap.offline.mtproto import transport
from friTap.offline.mtproto.transport import (
    ABRIDGED,
    INTERMEDIATE,
    recover_obf_alignment,
)

_BOTH = (ABRIDGED, INTERMEDIATE)


@pytest.fixture(autouse=True)
def _fresh_memo():
    transport._anchor_targets.cache_clear()
    transport._anchor_target_words.cache_clear()
    yield
    transport._anchor_targets.cache_clear()
    transport._anchor_target_words.cache_clear()


def _keymap(n=3):
    return {os.urandom(8): object() for _ in range(n)}


def _uncached(window, transports, keymap):
    positions = transport._anchor_id_positions(window, transports)
    return transport._keystream_targets(window, positions, keymap)


def test_memoized_targets_equal_uncached():
    window, keymap = os.urandom(2048), _keymap()
    keymap["not-an-id"] = object()  # malformed keys are ignored by both paths
    for transports in (_BOTH, (ABRIDGED,), (INTERMEDIATE,)):
        memo = transport._anchor_targets(
            window, transports, transport._known_key_ids(keymap)
        )
        expected = _uncached(window, transports, keymap)
        assert {p: list(js) for p, js in memo.items()} == expected


def test_memoized_targets_are_read_only():
    memo = transport._anchor_targets(
        os.urandom(256), _BOTH, transport._known_key_ids(_keymap())
    )
    assert isinstance(memo, types.MappingProxyType)
    with pytest.raises(TypeError):
        memo[b"x" * 8] = (0,)
    assert all(isinstance(js, tuple) for js in memo.values())


def test_key_change_is_a_cache_miss():
    window = os.urandom(512)
    first = transport._anchor_targets(window, _BOTH, transport._known_key_ids(_keymap()))
    other = transport._anchor_targets(window, _BOTH, transport._known_key_ids(_keymap()))
    assert first != other
    assert transport._anchor_targets.cache_info().misses == 2


def test_table_built_once_across_candidate_keys(monkeypatch):
    calls = []
    real = transport._keystream_targets

    def _counting(*args):
        calls.append(1)
        return real(*args)

    monkeypatch.setattr(transport, "_keystream_targets", _counting)
    run, keymap = os.urandom(600), _keymap()
    for _ in range(5):  # five wrong candidate keys over the same window
        assert recover_obf_alignment(
            os.urandom(32), os.urandom(16), 0, run, keymap, max_blocks=4
        ) is None
    assert len(calls) == 1


def test_word_index_hits_equal_unindexed_hits():
    window, keymap = os.urandom(1024), _keymap()
    key_ids = transport._known_key_ids(keymap)
    targets = transport._anchor_targets(window, _BOTH, key_ids)
    index = transport._anchor_target_words(window, _BOTH, key_ids)
    # Plant two target patterns at odd offsets so the hit set is non-empty.
    planted = list(targets)[:2]
    keystream = bytearray(os.urandom(4099))
    keystream[13:21], keystream[2050:2058] = planted
    keystream = bytes(keystream)
    indexed = transport._keystream_hits(keystream, targets, index)
    assert indexed == transport._keystream_hits(keystream, targets)
    assert set(planted) <= indexed


def test_word_index_is_read_only_and_built_once_across_candidate_keys(monkeypatch):
    calls = []
    real = transport._target_word_index

    def _counting(targets):
        calls.append(1)
        return real(targets)

    monkeypatch.setattr(transport, "_target_word_index", _counting)
    run, keymap = os.urandom(600), _keymap()
    for _ in range(5):  # five wrong candidate keys over the same window
        assert recover_obf_alignment(
            os.urandom(32), os.urandom(16), 0, run, keymap, max_blocks=4
        ) is None
    assert len(calls) == 1
    words, word_set = transport._anchor_target_words.__wrapped__(
        run, _BOTH, transport._known_key_ids(keymap)
    )
    assert isinstance(words, types.MappingProxyType)
    assert isinstance(word_set, frozenset)
