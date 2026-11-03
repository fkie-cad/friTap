#!/usr/bin/env python3

"""``SshKeylogFormatter`` hex-validates the cookie and shared-secret fields.

The agent runs inside a possibly hostile process: a non-hex cookie or shared
secret drops the whole ``SHARED_SECRET`` record with a once-per-reason
warning, while valid records stay byte-identical to the historical output.
"""

import logging

import pytest

from friTap.events import KeylogEvent
from friTap.output import keylog_format
from friTap.protocols.ssh_handler import SshKeylogFormatter

COOKIE = "aa" * 16
PEER = "cc" * 16
SECRET = "bb" * 32


@pytest.fixture(autouse=True)
def _reset_warn_once():
    keylog_format._dropped_reasons.clear()
    yield
    keylog_format._dropped_reasons.clear()


def _format(cookie="", peer_cookie="", shared_secret=SECRET):
    event = KeylogEvent(protocol="ssh", payload={
        "cookie": cookie, "peer_cookie": peer_cookie, "shared_secret": shared_secret,
    })
    return SshKeylogFormatter().format(event)


@pytest.mark.parametrize("cookie, peer, expected", [
    (COOKIE, PEER, [f"{COOKIE} SHARED_SECRET {SECRET}", f"{PEER} SHARED_SECRET {SECRET}"]),
    (COOKIE, COOKIE, [f"{COOKIE} SHARED_SECRET {SECRET}"]),
    ("", PEER, [f"{PEER} SHARED_SECRET {SECRET}"]),
    (COOKIE, "", [f"{COOKIE} SHARED_SECRET {SECRET}"]),
    ("", "", []),
    ("AA" * 16, "", [f"{'AA' * 16} SHARED_SECRET {SECRET}"]),  # upper-case hex kept
])
def test_valid_records_unchanged(cookie, peer, expected):
    assert _format(cookie, peer) == expected


def test_valid_upper_case_secret_unchanged():
    secret = "BB" * 32
    assert _format(COOKIE, shared_secret=secret) == [f"{COOKIE} SHARED_SECRET {secret}"]


@pytest.mark.parametrize("cookie, peer, secret", [
    (COOKIE, PEER, "zz" * 32),                     # non-hex secret
    (COOKIE, PEER, "abc"),                         # odd-length secret
    (COOKIE, PEER, SECRET + "\nCLIENT_RANDOM aa bb"),  # CR/LF injection
    (COOKIE, PEER, "bb" * 2049),                   # over-long secret
    ("not hex", PEER, SECRET),                     # bad local cookie
    (COOKIE, "cc\r\nFORGED", SECRET),              # bad peer cookie
    ("", "xyz", SECRET),                           # bad cookie, only one present
])
def test_invalid_hex_record_dropped(cookie, peer, secret):
    assert _format(cookie, peer, secret) == []


def test_non_str_fields_dropped():
    assert _format(cookie=1234, shared_secret=SECRET) == []
    assert _format(cookie=COOKIE, shared_secret=0xBB) == []


def test_drop_is_logged_once(caplog):
    with caplog.at_level(logging.WARNING, logger=keylog_format.__name__):
        _format(COOKIE, shared_secret="zz")
        _format("bad cookie", shared_secret=SECRET)
    drops = [r for r in caplog.records if "ssh SHARED_SECRET" in r.getMessage()]
    assert len(drops) == 1


def test_missing_secret_still_falls_back_to_key_data():
    event = KeylogEvent(
        protocol="ssh",
        key_data="SSH_ENC_KEY_C2S " + "ab" * 16,
        payload={"cookie": COOKIE, "shared_secret": ""},
    )
    assert SshKeylogFormatter().format(event) == ["SSH_ENC_KEY_C2S " + "ab" * 16]
