"""Protocol-neutral endpoint helpers (friTap.offline.net.endpoints)."""

import pytest

from friTap.offline.net.endpoints import (
    join_by_direction,
    normalize_endpoint,
    ss_family,
    stream_endpoint,
)


@pytest.mark.parametrize("addr, expected", [
    ("10.0.0.1", "AF_INET"),
    ("2001:db8::1", "AF_INET6"),
    ("::ffff:1.2.3.4", "AF_INET6"),
])
def test_ss_family(addr, expected):
    assert ss_family(addr) == expected


def test_join_by_direction_concatenates_in_order():
    joined = join_by_direction([("read", b"r1"), ("write", b"w1"), ("read", b"r2")])
    assert list(joined) == ["write", "read"]
    assert joined == {"write": bytearray(b"w1"), "read": bytearray(b"r1r2")}


def test_join_by_direction_seeds_empty_and_keeps_extra_directions():
    joined = join_by_direction([("other", b"x")])
    assert joined == {"write": bytearray(), "read": bytearray(), "other": bytearray(b"x")}


@pytest.mark.parametrize("text, expected", [
    ("149.154.167.51:443", "149.154.167.51:443"),
    ("[2001:67c:4e8:f004:0:0:0:a]:443", "[2001:67c:4e8:f004::a]:443"),
    ("[::ffff:1.2.3.4]:80", "1.2.3.4:80"),
    ("-", None),
    (None, None),
])
def test_normalize_endpoint(text, expected):
    assert normalize_endpoint(text) == expected


def test_stream_endpoint_brackets_ipv6():
    assert stream_endpoint(("2001:67c:4e8:f004::a", 443)) == "[2001:67c:4e8:f004::a]:443"
    assert stream_endpoint(("1.2.3.4", 5222)) == "1.2.3.4:5222"


def test_old_mtproto_keylog_path_reexports_same_objects():
    from friTap.offline.mtproto import keylog

    assert keylog.normalize_endpoint is normalize_endpoint
    assert keylog.stream_endpoint is stream_endpoint


@pytest.mark.parametrize(
    "text, expected",
    [
        ("[2001:DB8:0:0:0:0:0:1]:443", "[2001:db8::1]:443"),
        ("2001:db8::1:443", "[2001:db8::1]:443"),
        ("[fe80::1%eth0]:443", "[fe80::1]:443"),
        ("[::ffff:1.2.3.4]:443", "1.2.3.4:443"),
        ("::FFFF:1.2.3.4:80", "1.2.3.4:80"),
        ("1.2.3.4:080", "1.2.3.4:80"),
        ("host%zone:443", "host%zone:443"),
        ("1.2.3.4 :443", "1.2.3.4 :443"),
        ("[not-an-ip]:443", "not-an-ip:443"),
        ("1.2.3.4", None),
        ("1.2.3.4:", None),
        (":443", None),
        ("-", None),
        (None, None),
    ],
)
def test_normalize_endpoint_characterization(text, expected):
    """Pins tricky inputs; these differ from connection_index.normalize_addr
    (v4-mapped collapse, zone kept on non-IP hosts, no inner whitespace strip)."""
    assert normalize_endpoint(text) == expected
