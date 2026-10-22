"""normalize_addr is memoized for strings without changing its outputs."""

from __future__ import annotations

import pytest

from friTap import connection_index
from friTap.connection_index import canonical_4tuple, normalize_addr

CASES = [
    ("", ""),
    ("10.0.0.1", "10.0.0.1"),
    (" 10.0.0.1 ", "10.0.0.1"),
    ("[2001:db8:0:0::1]", "2001:db8::1"),
    ("2001:DB8::0001", "2001:db8::1"),
    ("fe80::1%eth0", "fe80::1"),
    ("example.org", "example.org"),
    ("not an ip", "not an ip"),
]


@pytest.mark.parametrize("addr, expected", CASES)
def test_cached_result_matches_uncached(addr, expected):
    assert connection_index._normalize_addr_uncached(addr) == expected
    assert normalize_addr(addr) == expected
    assert normalize_addr(addr) == expected  # second call served from the cache


def test_repeated_calls_hit_the_cache():
    connection_index._normalize_addr_cached.cache_clear()
    for _ in range(5):
        canonical_4tuple("2001:db8::1", 443, "10.0.0.1", 5555)
    info = connection_index._normalize_addr_cached.cache_info()
    assert info.misses == 2 and info.hits == 8


def test_non_string_inputs_bypass_the_cache():
    assert normalize_addr(None) is None
    unhashable = []  # falsy, so returned as-is; must not raise TypeError
    assert normalize_addr(unhashable) is unhashable
