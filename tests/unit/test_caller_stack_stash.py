"""Unit tests for the bounded, TTL-expiring caller-stack stash."""

from friTap.flow.caller_stack_stash import (
    MAX_STASHED,
    STASH_TTL_SECONDS,
    CallerStackStash,
    StashedCallerStack,
)


def _entry(at: float, tag: str = "") -> StashedCallerStack:
    return StashedCallerStack(sdk=None, caller_stack={"tag": tag}, stashed_at=at)


def test_new_stash_is_empty():
    stash = CallerStackStash()
    assert stash.is_empty() and len(stash) == 0


def test_take_is_fifo_per_key_and_forgets_empty_keys():
    stash = CallerStackStash()
    stash.put(("cr", "a"), _entry(1.0, "first"), 1.0)
    stash.put(("cr", "a"), _entry(2.0, "second"), 2.0)
    assert stash.take([("cr", "a")], 3.0).caller_stack["tag"] == "first"
    assert stash.take([("cr", "a")], 3.0).caller_stack["tag"] == "second"
    assert ("cr", "a") not in stash and stash.is_empty()


def test_take_tries_keys_in_order():
    stash = CallerStackStash()
    stash.put(("sid", "s"), _entry(1.0, "sid"), 1.0)
    stash.put(("cr", "c"), _entry(1.0, "cr"), 1.0)
    taken = stash.take([("cr", "missing"), ("cr", "c"), ("sid", "s")], 2.0)
    assert taken.caller_stack["tag"] == "cr"
    assert len(stash) == 1


def test_take_misses_return_none():
    assert CallerStackStash().take([("cr", "x")], 0.0) is None


def test_entries_expire_after_ttl():
    stash = CallerStackStash()
    stash.put(("cr", "old"), _entry(0.0), 0.0)
    stash.put(("cr", "new"), _entry(50.0), 50.0)
    stash.expire(STASH_TTL_SECONDS + 1)
    assert ("cr", "old") not in stash and ("cr", "new") in stash
    assert len(stash) == 1


def test_cap_drops_oldest_live_entry_skipping_taken_ones():
    stash = CallerStackStash()
    stash.put(("cr", "taken"), _entry(0.0), 0.0)
    stash.take([("cr", "taken")], 0.0)
    for index in range(MAX_STASHED + 1):
        stash.put(("cr", str(index)), _entry(0.0), 0.0)
    assert len(stash) == MAX_STASHED
    assert ("cr", "0") not in stash and ("cr", str(MAX_STASHED)) in stash


def test_clear_empties_everything():
    stash = CallerStackStash()
    stash.put(("cr", "a"), _entry(0.0), 0.0)
    stash.clear()
    assert stash.is_empty() and ("cr", "a") not in stash


# --- one entry indexed under several keys (cr + tuple/sid) ---

_TUPLE = ("10.0.0.2", 1, "10.0.0.3", 2)


def test_multi_key_entry_is_taken_once_via_either_key():
    stash = CallerStackStash()
    stash.put_under([("cr", "c"), _TUPLE], _entry(1.0, "both"), 1.0)
    assert len(stash) == 1
    assert stash.take([_TUPLE], 2.0).caller_stack["tag"] == "both"
    assert stash.take([("cr", "c")], 2.0) is None
    assert stash.is_empty() and ("cr", "c") not in stash and _TUPLE not in stash


def test_multi_key_entry_taken_by_cr_does_not_resurrect_via_tuple():
    stash = CallerStackStash()
    stash.put_under([("cr", "c"), _TUPLE], _entry(1.0, "both"), 1.0)
    stash.put(_TUPLE, _entry(1.5, "tuple-only"), 1.5)
    assert stash.take([("cr", "c")], 2.0).caller_stack["tag"] == "both"
    assert stash.take([_TUPLE], 2.0).caller_stack["tag"] == "tuple-only"
    assert stash.is_empty()


def test_multi_key_entry_expires_from_every_key():
    stash = CallerStackStash()
    stash.put_under([("cr", "c"), _TUPLE], _entry(0.0), 0.0)
    stash.expire(STASH_TTL_SECONDS + 1)
    assert stash.is_empty() and ("cr", "c") not in stash and _TUPLE not in stash


def test_multi_key_entries_count_once_against_the_cap():
    stash = CallerStackStash()
    for index in range(MAX_STASHED + 1):
        stash.put_under([("cr", str(index)), ("sid", str(index))], _entry(0.0), 0.0)
    assert len(stash) == MAX_STASHED
    assert ("cr", "0") not in stash and ("sid", "0") not in stash
    assert ("sid", str(MAX_STASHED)) in stash
