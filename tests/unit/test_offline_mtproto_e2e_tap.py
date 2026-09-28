#!/usr/bin/env python3

"""Confirm the shipped ``--mtproto-keylog`` offline path surfaces E2E flows.

Item 6 of the MTProto memory-scan follow-ups. ``--mtproto-keylog`` used to decrypt
Telegram *cloud* transport only, silently dropping Secret-Chat (E2E) traffic even
though the ``.mtproto.keylog`` sidecar written by ``-ms mtproto`` carries BOTH
``MTPROTO_AUTH_KEY`` and ``MTPROTO_E2E_KEY`` lines. It now decrypts both. These
tests pin that behaviour: driving ``_emit_mtproto_streams`` (the
``--mtproto-keylog`` entry point) over a capture whose keylog holds an E2E key
emits a ``DatalogEvent(protocol="telegram_e2e")`` into the .tap event stream,
counted under the ``mtproto`` protocol bucket. The ``--telegram-keylog`` path is
also pinned as unchanged (counts under the ``telegram`` bucket).

The MTProto crypto backend is NOT exercised: the keylog loaders and decrypt
iterators the emitter imports lazily are monkeypatched with faithful fakes, so the
test is hermetic and needs no pcap fixture or optional dependency.
"""

from __future__ import annotations

import pytest

from friTap.events import DatalogEvent, EventBus
from friTap.offline import pcap_to_tap as p2t
from friTap.offline.mtproto.e2e.records import SecretChatMessage
from friTap.offline.mtproto.records import DecryptedMessage


class _FakeState:
    """Minimal stand-in for ``_WriterState`` — no TapWriter, no file I/O.

    The emitter only touches ``mtproto_meta``, ``telegram_e2e_meta`` and
    ``ensure_open``; everything else on the real state is irrelevant here.
    """

    def __init__(self) -> None:
        self.mtproto_meta: dict = {}
        self.telegram_e2e_meta: dict = {}
        self.opened = False

    def ensure_open(self, capture_start: float = 0.0) -> None:
        self.opened = True


def _cloud_msg() -> DecryptedMessage:
    return DecryptedMessage(
        src_addr="10.0.0.1", src_port=12345,
        dst_addr="149.154.167.51", dst_port=443,
        ss_family="AF_INET", direction="write",
        message=b"\x00" * 16, dc_id=2, transport="abridged",
        obfuscated=True, auth_key_id_hex="1122334455667788",
    )


def _e2e_msg() -> SecretChatMessage:
    return SecretChatMessage(
        src_addr="10.0.0.1", src_port=12345,
        dst_addr="149.154.167.51", dst_port=443,
        ss_family="AF_INET", direction="write",
        message=b"\x01" * 16, chat_id=4242,
        key_fingerprint_hex="aabbccddeeff0011",
    )


@pytest.fixture
def patched_backend(monkeypatch):
    """Patch the keylog loaders + decrypt iterators the emitter imports lazily.

    Returns the single cloud and E2E messages the fakes yield, so the tests can
    assert on their identifying fields.
    """
    cloud = _cloud_msg()
    e2e = _e2e_msg()

    # Non-empty keymaps so the emitter proceeds past its "no usable keys" guard;
    # the values are opaque to the fake iterators below.
    monkeypatch.setattr(
        "friTap.offline.mtproto.keylog.load_mtproto_keylog",
        lambda path: {b"\x11\x22\x33\x44\x55\x66\x77\x88": object()},
    )
    monkeypatch.setattr(
        "friTap.offline.mtproto.e2e.keylog.load_secret_chat_keylog",
        lambda path: {b"\xaa\xbb\xcc\xdd\xee\xff\x00\x11": object()},
    )
    # The obfuscation-key loader (Workstream F) rides the same code path; the fake
    # cloud iterator below ignores the keys, so an empty list keeps behaviour flat.
    monkeypatch.setattr(
        "friTap.offline.mtproto.keylog.load_mtproto_obf_keylog",
        lambda path: [],
    )

    def _fake_iter_cloud(pcap_path, keymap, stats=None, obf_keys=None, obf_max_blocks=None):
        if stats is not None:
            stats.add_message()
        yield cloud

    def _fake_iter_e2e(transport_messages, keymap, stats=None):
        # Exhaust the input like the real generator, then emit one E2E message.
        list(transport_messages)
        if stats is not None:
            stats.add_message()
        yield e2e

    monkeypatch.setattr(
        "friTap.offline.mtproto.decrypt.iter_decrypted_messages", _fake_iter_cloud,
    )
    monkeypatch.setattr(
        "friTap.offline.mtproto.e2e.decrypt.iter_secret_chat_messages", _fake_iter_e2e,
    )
    return cloud, e2e


def _run(emitter, keylog):
    """Drive one emitter and return (emitted DatalogEvents, ConvertResult)."""
    bus = EventBus()
    events: list[DatalogEvent] = []
    bus.subscribe(DatalogEvent, events.append)
    state = _FakeState()
    result = p2t.ConvertResult(tap_path="out.tap")
    emitter("cap.pcap", keylog, bus=bus, state=state, result=result)
    return events, result, state


def test_mtproto_keylog_surfaces_e2e_flows(patched_backend):
    _cloud, e2e = patched_backend
    events, _result, _state = _run(p2t._emit_mtproto_streams, "x.mtproto.keylog")

    protocols = [ev.protocol for ev in events]
    assert "telegram_e2e" in protocols, (
        "--mtproto-keylog must surface Secret-Chat E2E flows into the .tap"
    )
    assert "mtproto" in protocols, "cloud transport flow must still be emitted"

    # The E2E flow carries the per-chat session id the collector keys on so it
    # lands on its OWN telegram_e2e flow rather than the cloud flow.
    e2e_ev = next(ev for ev in events if ev.protocol == "telegram_e2e")
    assert e2e_ev.ssl_session_id == f"telegram_e2e:{e2e.key_fingerprint_hex}"
    # (The parsed-message side-channel state.telegram_e2e_meta is populated only
    # for valid TL payloads; it is exercised by the content/parser tests, not
    # this routing test, which uses opaque synthetic bytes.)


def test_mtproto_keylog_counts_cloud_and_e2e_under_mtproto_bucket(patched_backend):
    _events, result, _state = _run(p2t._emit_mtproto_streams, "x.mtproto.keylog")

    # Both messages are counted, and under the mtproto bucket (NOT telegram).
    assert "mtproto" in result.per_protocol
    assert "telegram" not in result.per_protocol
    assert result.per_protocol["mtproto"]["messages"] == 2  # 1 cloud + 1 E2E
    assert result.decrypted_packet_count == 2


def test_telegram_keylog_still_counts_under_telegram_bucket(patched_backend):
    _cloud, e2e = patched_backend
    events, result, _state = _run(p2t._emit_telegram_streams, "x.telegram.keylog")

    # --telegram-keylog is unchanged: same cloud + E2E output, telegram bucket.
    protocols = [ev.protocol for ev in events]
    assert "telegram_e2e" in protocols
    assert "mtproto" in protocols
    assert "telegram" in result.per_protocol
    assert "mtproto" not in result.per_protocol
    assert result.per_protocol["telegram"]["messages"] == 2


def test_e2e_only_keylog_flags_no_transport_auth_key(monkeypatch):
    """A keylog with an E2E (secret-chat) key but NO transport auth key.

    Every transport record misses the (empty) keymap, so the transport envelope
    never decrypts and the E2E blobs inside are never reached. The emitter must
    record ``e2e_only=True`` on the protocol bucket and surface the unknown
    auth_key_id(s) it saw in the clear, so the TUI/CLI can explain the true cause.
    """
    monkeypatch.setattr(
        "friTap.offline.mtproto.keylog.load_mtproto_keylog", lambda path: {})
    monkeypatch.setattr(
        "friTap.offline.mtproto.keylog.load_mtproto_obf_keylog", lambda path: [])
    monkeypatch.setattr(
        "friTap.offline.mtproto.e2e.keylog.load_secret_chat_keylog",
        lambda path: {b"\xaa\xbb\xcc\xdd\xee\xff\x00\x11": object()},
    )

    def _fake_iter_cloud(pcap_path, keymap, stats=None, obf_keys=None, obf_max_blocks=None):
        # Empty keymap: the record's auth_key_id is unknown, so nothing decrypts.
        if stats is not None:
            stats.add_unknown_key("1122334455667788")
        return iter(())

    monkeypatch.setattr(
        "friTap.offline.mtproto.decrypt.iter_decrypted_messages", _fake_iter_cloud)
    # iter_secret_chat_messages is never reached (no transport messages decrypt),
    # but patch it defensively so a real backend is never imported.
    monkeypatch.setattr(
        "friTap.offline.mtproto.e2e.decrypt.iter_secret_chat_messages",
        lambda transport_messages, keymap, stats=None: iter(()),
    )

    events, result, _state = _run(p2t._emit_mtproto_streams, "e2e_only.mtproto.keylog")
    assert events == []
    bucket = result.per_protocol["mtproto"]
    assert bucket["e2e_only"] is True
    assert bucket["unknown_key_ids"] == {"1122334455667788": 1}
    assert bucket["messages"] == 0


def test_full_keylog_does_not_flag_e2e_only(patched_backend):
    """When a transport auth key IS present, e2e_only stays False."""
    _events, result, _state = _run(p2t._emit_mtproto_streams, "x.mtproto.keylog")
    assert result.per_protocol["mtproto"]["e2e_only"] is False


def test_empty_keylog_emits_nothing(monkeypatch):
    # No usable keys of either kind -> the emitter skips cleanly, no events.
    monkeypatch.setattr(
        "friTap.offline.mtproto.keylog.load_mtproto_keylog", lambda path: {})
    monkeypatch.setattr(
        "friTap.offline.mtproto.keylog.load_mtproto_obf_keylog", lambda path: [])
    monkeypatch.setattr(
        "friTap.offline.mtproto.e2e.keylog.load_secret_chat_keylog", lambda path: {})
    events, result, _state = _run(p2t._emit_mtproto_streams, "empty.mtproto.keylog")
    assert events == []
    assert result.per_protocol == {}
