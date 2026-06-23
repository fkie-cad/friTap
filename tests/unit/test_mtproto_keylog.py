"""Tests for the MTProto keylog format, formatter, registry, and router demux.

All hermetic — no device, no crypto backend needed (these test the text format
and event plumbing, not decryption).
"""

from __future__ import annotations

import hashlib

import pytest

from friTap.events import EventBus, KeylogEvent
from friTap.message_router import MessageRouter
from friTap.protocols import mtproto_keylog_spec as spec
from friTap.protocols.mtproto_handler import MTProtoHandler, MtprotoKeylogFormatter
from friTap.protocols.registry import create_default_registry

_AID = "a1b2c3d4e5f60718"
_AK = "ab" * 256  # 512 hex chars


# --------------------------------------------------------------------------- #
# spec: format_line / parse_line round-trip
# --------------------------------------------------------------------------- #


def test_format_parse_roundtrip():
    line = spec.format_line(dc_id=2, auth_key_id=_AID, auth_key=_AK, key_type="temp")
    assert line == f"{spec.LABEL} 2 {_AID} {_AK} temp"
    parsed = spec.parse_line(line)
    assert parsed is not None
    assert parsed.dc_id == 2
    assert parsed.auth_key_id == bytes.fromhex(_AID)
    assert parsed.auth_key == bytes.fromhex(_AK)
    assert parsed.key_type == "temp"


def test_format_line_rejects_bad_lengths():
    assert spec.format_line(dc_id=1, auth_key_id="ab", auth_key=_AK) is None
    assert spec.format_line(dc_id=1, auth_key_id=_AID, auth_key="cd") is None
    assert spec.format_line(dc_id=1, auth_key_id=_AID, auth_key="zz" * 256) is None


def test_format_line_derives_empty_id_from_key():
    """An EMPTY auth_key_id with a valid key is rescued: the id is derived as
    sha1(auth_key)[-8:] rather than the (usable) key being silently dropped."""
    expected_id = hashlib.sha1(bytes.fromhex(_AK)).digest()[-8:].hex()
    line = spec.format_line(dc_id=2, auth_key_id="", auth_key=_AK, key_type="temp")
    assert line == f"{spec.LABEL} 2 {expected_id} {_AK} temp"
    parsed = spec.parse_line(line)
    assert parsed is not None and parsed.auth_key_id == bytes.fromhex(expected_id)


def test_format_line_defaults_key_type_and_dc():
    line = spec.format_line(dc_id="bogus", auth_key_id=_AID, auth_key=_AK, key_type="weird")
    assert line == f"{spec.LABEL} 0 {_AID} {_AK} perm"


def test_parse_line_skips_noise():
    assert spec.parse_line("") is None
    assert spec.parse_line("   ") is None
    assert spec.parse_line("# a comment") is None
    assert spec.parse_line(spec.HEADER_COMMENT) is None
    assert spec.parse_line("CLIENT_RANDOM abc def") is None  # foreign label
    assert spec.parse_line(f"{spec.E2E_LABEL} {_AID} {_AK}") is None  # reserved, not yet


# --------------------------------------------------------------------------- #
# formatter
# --------------------------------------------------------------------------- #


def test_formatter_emits_canonical_line():
    fmt = MtprotoKeylogFormatter()
    assert fmt.protocol == "mtproto"
    assert fmt.header_comment() == spec.HEADER_COMMENT
    ev = KeylogEvent(
        protocol="mtproto",
        payload={"auth_key_id": _AID, "auth_key": _AK, "dc_id": 4, "key_type": "temp"},
    )
    assert fmt.format(ev) == [f"{spec.LABEL} 4 {_AID} {_AK} temp"]
    assert fmt.dedup_key(ev) == f"{_AID}|temp"


def test_formatter_drops_malformed_payload():
    fmt = MtprotoKeylogFormatter()
    ev = KeylogEvent(protocol="mtproto", payload={"auth_key_id": "short", "auth_key": _AK})
    assert fmt.format(ev) == []


# --------------------------------------------------------------------------- #
# registry
# --------------------------------------------------------------------------- #


def test_registry_registers_mtproto():
    reg = create_default_registry(["mtproto"])
    handler = reg.get("mtproto")
    assert isinstance(handler, MTProtoHandler)
    assert handler.keylog_formatter().protocol == "mtproto"
    assert handler.name == "mtproto"


def test_registry_default_includes_mtproto():
    reg = create_default_registry()  # all known
    assert reg.get("mtproto") is not None


def test_registry_rejects_unknown():
    with pytest.raises(ValueError):
        create_default_registry(["nope"])


# --------------------------------------------------------------------------- #
# router demux
# --------------------------------------------------------------------------- #


def test_router_emits_mtproto_keylog_event():
    bus = EventBus()
    seen = []
    bus.subscribe(KeylogEvent, seen.append)
    router = MessageRouter(bus)
    router.route(
        {
            "contentType": "mtproto_key",
            "auth_key_id": _AID,
            "auth_key": _AK,
            "dc_id": 2,
            "key_type": "temp",
        },
        b"",
    )
    assert len(seen) == 1
    ev = seen[0]
    assert ev.protocol == "mtproto"
    assert ev.payload["auth_key_id"] == _AID
    assert ev.payload["key_type"] == "temp"
    # and the formatter turns it into the canonical line
    assert MtprotoKeylogFormatter().format(ev) == [f"{spec.LABEL} 2 {_AID} {_AK} temp"]
