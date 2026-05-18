#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Integration test for SSH plaintext capture and the unified ``-k`` keylog.

This test exercises the full agent → router → handler pipeline at the Python
level WITHOUT spawning real sshd / ssh processes. The full end-to-end path
(spawn sshd via `ground_truth/example_ssh/start_sshd.sh`, attach Frida,
verify plaintext PCAPNG contains an expected substring) is the manual
verification recipe documented in `docs/protocols/ssh.md` and the plan file
— it requires sshd installed, a free port, and Frida CLI access, none of
which are reliable in CI.

What this test asserts:
  * MessageRouter routes ``ssh_keylog`` payloads to ``KeylogEvent`` with a
    structured ``payload`` dict carrying the cookies + shared secret.
  * ``KeylogOutputHandler`` bound to ``SshKeylogFormatter`` formats those as
    Wireshark-compatible ``<cookie> SHARED_SECRET <hex>`` lines.
  * The same ``shared_secret`` paired with different cookies produces one
    line per cookie, deduped across replays.
  * MessageRouter routes ``ssh_key`` payloads to ``KeylogEvent`` with the
    formatted ``<label> <hex>`` line used by the regular keys.log.
  * MessageRouter routes ``ssh_newkeys`` payloads as informational console
    events without crashing.
  * MessageRouter routes ``datalog`` payloads with ``protocol: "ssh"`` and
    ``function: "ssh_packet_send2"`` / ``"ssh_packet_read_poll2"`` through
    the same DatalogEvent pipeline TLS uses, with the correct direction.
"""

from __future__ import annotations

import os
import tempfile

import pytest

from friTap.events import (
    DatalogEvent,
    EventBus,
    KeylogEvent,
    ConsoleEvent,
)
from friTap.message_router import MessageRouter
from friTap.output.keylog_handler import KeylogOutputHandler
from friTap.protocols.ssh_handler import SshKeylogFormatter


@pytest.fixture
def bus_with_router():
    bus = EventBus()
    return bus, MessageRouter(bus)


class TestSshKeylogRouting:
    def test_ssh_keylog_emits_event(self, bus_with_router):
        bus, router = bus_with_router
        captured = []
        bus.subscribe(KeylogEvent, captured.append)

        router.route(
            {
                "contentType": "ssh_keylog",
                "cookie": "aa" * 16,
                "peer_cookie": "cc" * 16,
                "shared_secret": "bb" * 32,
                "direction": "client",
                "session_tag": "0x7fff1234",
                "protocol": "ssh",
            },
            b"",
        )

        assert len(captured) == 1
        evt = captured[0]
        assert evt.protocol == "ssh"
        assert evt.payload is not None
        assert evt.payload["cookie"] == "aa" * 16
        assert evt.payload["peer_cookie"] == "cc" * 16
        assert evt.payload["shared_secret"] == "bb" * 32
        assert evt.payload["direction"] == "client"
        assert evt.payload["session_tag"] == "0x7fff1234"


class TestSshKeylogHandler:
    def test_writes_both_cookies(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".log") as tmp:
            path = tmp.name
        try:
            bus = EventBus()
            handler = KeylogOutputHandler(path, formatter=SshKeylogFormatter())
            handler.setup(bus)
            bus.emit(
                KeylogEvent(
                    protocol="ssh",
                    payload={
                        "cookie": "aa" * 16,
                        "peer_cookie": "cc" * 16,
                        "shared_secret": "bb" * 32,
                    },
                )
            )
            handler.close()

            with open(path) as f:
                lines = [
                    line.strip()
                    for line in f.read().splitlines()
                    if line and not line.startswith("#")
                ]
            assert lines == [
                f"{'aa' * 16} SHARED_SECRET {'bb' * 32}",
                f"{'cc' * 16} SHARED_SECRET {'bb' * 32}",
            ]
        finally:
            os.unlink(path)

    def test_dedupes_repeated_event(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".log") as tmp:
            path = tmp.name
        try:
            bus = EventBus()
            handler = KeylogOutputHandler(path, formatter=SshKeylogFormatter())
            handler.setup(bus)
            payload = {"cookie": "aa" * 16, "shared_secret": "bb" * 32}
            bus.emit(KeylogEvent(protocol="ssh", payload=dict(payload)))
            bus.emit(KeylogEvent(protocol="ssh", payload=dict(payload)))
            bus.emit(KeylogEvent(protocol="ssh", payload=dict(payload)))
            handler.close()

            with open(path) as f:
                lines = [
                    line.strip()
                    for line in f.read().splitlines()
                    if line and not line.startswith("#")
                ]
            assert lines == [f"{'aa' * 16} SHARED_SECRET {'bb' * 32}"]
        finally:
            os.unlink(path)

    def test_skips_when_shared_secret_missing(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".log") as tmp:
            path = tmp.name
        # Lazy open means an event that produces zero lines must NOT create
        # the file. Remove the tempfile so we can assert non-creation.
        os.unlink(path)
        try:
            bus = EventBus()
            handler = KeylogOutputHandler(path, formatter=SshKeylogFormatter())
            handler.setup(bus)
            bus.emit(KeylogEvent(
                protocol="ssh",
                payload={"cookie": "aa" * 16, "shared_secret": ""},
            ))
            handler.close()

            assert not os.path.exists(path), \
                "lazy open: file should not be created when event produces no lines"
        finally:
            if os.path.exists(path):
                os.unlink(path)


class TestSshKeyAndNewKeysRouting:
    def test_ssh_key_becomes_keylog_event(self, bus_with_router):
        bus, router = bus_with_router
        captured = []
        bus.subscribe(KeylogEvent, captured.append)

        router.route(
            {
                "contentType": "ssh_key",
                "direction": "C2S",
                "key_type": "SSH_ENC_KEY_C2S",
                "cipher": "chacha20-poly1305@openssh.com",
                "key_data": "deadbeef" * 8,
                "protocol": "ssh",
            },
            b"",
        )

        assert len(captured) == 1
        assert captured[0].protocol == "ssh"
        assert captured[0].key_data == f"SSH_ENC_KEY_C2S {'deadbeef' * 8}"

    def test_ssh_key_with_missing_fields_is_dropped(self, bus_with_router):
        bus, router = bus_with_router
        captured = []
        bus.subscribe(KeylogEvent, captured.append)
        router.route({"contentType": "ssh_key"}, b"")
        router.route({"contentType": "ssh_key", "key_type": "SSH_IV_S2C"}, b"")
        router.route({"contentType": "ssh_key", "key_data": "abcd"}, b"")
        assert captured == []

    def test_ssh_newkeys_emits_console(self, bus_with_router):
        bus, router = bus_with_router
        captured = []
        bus.subscribe(ConsoleEvent, captured.append)
        router.route(
            {
                "contentType": "ssh_newkeys",
                "direction": "C2S",
                "message": "SSH new keys activated: C2S",
                "protocol": "ssh",
            },
            b"",
        )
        assert len(captured) == 1
        assert "C2S" in captured[0].message


class TestSshDatalogReusesPipeline:
    def test_ssh_datalog_read_direction(self, bus_with_router):
        bus, router = bus_with_router
        captured = []
        bus.subscribe(DatalogEvent, captured.append)

        router.route(
            {
                "contentType": "datalog",
                "function": "ssh_packet_read_poll2",
                "src_addr": 0x7F000001,
                "dst_addr": 0x7F000001,
                "src_port": 22,
                "dst_port": 54321,
                "ss_family": "AF_INET",
                "protocol": "ssh",
            },
            b"ssh-recv-payload",
        )

        assert len(captured) == 1
        evt = captured[0]
        assert evt.direction == "read"
        assert evt.data == b"ssh-recv-payload"
        assert evt.protocol == "ssh"

    def test_ssh_datalog_write_direction(self, bus_with_router):
        bus, router = bus_with_router
        captured = []
        bus.subscribe(DatalogEvent, captured.append)

        router.route(
            {
                "contentType": "datalog",
                "function": "ssh_packet_send2",
                "src_addr": 0x7F000001,
                "dst_addr": 0x7F000001,
                "src_port": 54321,
                "dst_port": 22,
                "ss_family": "AF_INET",
                "protocol": "ssh",
            },
            b"ssh-send-payload",
        )

        assert len(captured) == 1
        evt = captured[0]
        assert evt.direction == "write"
        assert evt.data == b"ssh-send-payload"
        assert evt.protocol == "ssh"


class TestSshKeylogConfigPlumbing:
    def test_from_legacy_params_threads_keylog(self):
        """``-k`` alone is enough now — no separate ssh-keylog option."""
        from friTap.config import FriTapConfig

        config = FriTapConfig.from_legacy_params(
            app="ssh", keylog="/tmp/x.log", protocol="ssh"
        )
        assert config.output.keylog == "/tmp/x.log"
        assert config.protocol == "ssh"
