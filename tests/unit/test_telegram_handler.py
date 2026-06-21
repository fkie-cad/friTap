"""Tests for the combined Telegram handler, formatter, registry, and router demux.

All hermetic — no device, no crypto backend needed (these test the text format
and event plumbing, not decryption). The ``telegram`` protocol writes BOTH
``MTPROTO_AUTH_KEY`` (cloud) and ``MTPROTO_E2E_KEY`` (Secret-Chat) lines into one
combined keylog, and routes MTProto cloud keys to ``protocol="telegram"`` when
``--protocol telegram`` is the active selection.
"""

from __future__ import annotations

from friTap.events import EventBus, KeylogEvent
from friTap.message_router import MessageRouter
from friTap.protocols import mtproto_keylog_spec as spec
from friTap.protocols.registry import create_default_registry
from friTap.protocols.telegram_handler import TelegramHandler, TelegramKeylogFormatter

_AID = "a1b2c3d4e5f60718"
_AK = "ab" * 256  # 512 hex chars
_FP = "0011223344556677"
_SK = "cd" * 256  # 512 hex chars


# --------------------------------------------------------------------------- #
# formatter: shape-driven cloud vs E2E line rendering
# --------------------------------------------------------------------------- #


def test_formatter_renders_e2e_line_for_e2e_payload():
    ev = KeylogEvent(
        protocol="telegram",
        payload={"key_fingerprint": _FP, "shared_key": _SK, "chat_id": 42},
    )
    assert TelegramKeylogFormatter().format(ev) == [
        f"{spec.E2E_LABEL} {_FP} {_SK} 42"
    ]


def test_formatter_renders_cloud_line_for_cloud_payload():
    ev = KeylogEvent(
        protocol="telegram",
        payload={"auth_key_id": _AID, "auth_key": _AK, "dc_id": 2, "key_type": "temp"},
    )
    assert TelegramKeylogFormatter().format(ev) == [
        f"{spec.LABEL} 2 {_AID} {_AK} temp"
    ]


def test_formatter_dedup_keys_distinguish_cloud_and_e2e():
    fmt = TelegramKeylogFormatter()
    e2e = KeylogEvent(protocol="telegram", payload={"key_fingerprint": _FP, "shared_key": _SK})
    cloud = KeylogEvent(protocol="telegram", payload={"auth_key_id": _AID, "auth_key": _AK})
    assert fmt.dedup_key(e2e) != fmt.dedup_key(cloud)
    assert _FP in fmt.dedup_key(e2e)
    assert _AID in fmt.dedup_key(cloud)


# --------------------------------------------------------------------------- #
# registry
# --------------------------------------------------------------------------- #


def test_registry_registers_telegram_handler():
    registry = create_default_registry(["telegram"])
    handler = registry.get("telegram")
    assert handler is not None
    assert isinstance(handler, TelegramHandler)
    assert handler.name == "telegram"
    assert handler.display_name == "Telegram"


# --------------------------------------------------------------------------- #
# router demux
# --------------------------------------------------------------------------- #


def test_router_routes_mtproto_key_to_telegram_when_active():
    bus = EventBus()
    seen = []
    bus.subscribe(KeylogEvent, seen.append)
    router = MessageRouter(bus, active_protocol="telegram")
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
    assert ev.protocol == "telegram"
    # The combined formatter renders the cloud line for this payload shape.
    assert TelegramKeylogFormatter().format(ev) == [f"{spec.LABEL} 2 {_AID} {_AK} temp"]


def test_router_keeps_mtproto_protocol_when_telegram_not_active():
    bus = EventBus()
    seen = []
    bus.subscribe(KeylogEvent, seen.append)
    router = MessageRouter(bus)  # default active_protocol -> historical behaviour
    router.route(
        {"contentType": "mtproto_key", "auth_key_id": _AID, "auth_key": _AK, "dc_id": 2},
        b"",
    )
    assert len(seen) == 1
    assert seen[0].protocol == "mtproto"


def test_router_emits_telegram_e2e_key_event():
    bus = EventBus()
    seen = []
    bus.subscribe(KeylogEvent, seen.append)
    router = MessageRouter(bus, active_protocol="telegram")
    router.route(
        {
            "contentType": "telegram_e2e_key",
            "shared_key": _SK,
            "key_fingerprint": _FP,
            "chat_id": 42,
        },
        b"",
    )
    assert len(seen) == 1
    ev = seen[0]
    assert ev.protocol == "telegram"
    assert ev.payload["key_fingerprint"] == _FP
    # and the formatter turns it into the canonical E2E line
    assert TelegramKeylogFormatter().format(ev) == [f"{spec.E2E_LABEL} {_FP} {_SK} 42"]
