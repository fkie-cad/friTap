#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Tests for per-protocol :class:`KeylogFormatter` implementations."""

from friTap.events import KeylogEvent
from friTap.protocols.tls_handler import TlsKeylogFormatter
from friTap.protocols.ssh_handler import SshKeylogFormatter


class TestTlsKeylogFormatter:
    def test_protocol_identifier(self):
        assert TlsKeylogFormatter().protocol == "tls"

    def test_passthrough(self):
        fmt = TlsKeylogFormatter()
        line = "CLIENT_RANDOM " + "aa" * 32 + " " + "bb" * 48
        assert fmt.format(KeylogEvent(protocol="tls", key_data=line)) == [line]

    def test_empty_event_produces_no_lines(self):
        assert TlsKeylogFormatter().format(KeylogEvent(protocol="tls")) == []

    def test_no_header_comment(self):
        # TLS keylog files are typically header-less; Wireshark accepts both
        # but the NSS-format convention is no header.
        assert TlsKeylogFormatter().header_comment() is None

    def test_dedup_key_is_line_content(self):
        fmt = TlsKeylogFormatter()
        evt = KeylogEvent(protocol="tls", key_data="CLIENT_RANDOM aaa bbb")
        assert fmt.dedup_key(evt) == "CLIENT_RANDOM aaa bbb"


class TestSshKeylogFormatter:
    def test_protocol_identifier(self):
        assert SshKeylogFormatter().protocol == "ssh"

    def test_header_comment_mentions_wireshark(self):
        header = SshKeylogFormatter().header_comment()
        assert header is not None
        assert "Wireshark" in header

    def test_structured_payload_emits_both_cookies(self):
        fmt = SshKeylogFormatter()
        evt = KeylogEvent(
            protocol="ssh",
            payload={
                "cookie": "aa" * 16,
                "peer_cookie": "cc" * 16,
                "shared_secret": "bb" * 32,
            },
        )
        assert fmt.format(evt) == [
            f"{'aa' * 16} SHARED_SECRET {'bb' * 32}",
            f"{'cc' * 16} SHARED_SECRET {'bb' * 32}",
        ]

    def test_duplicate_cookies_emit_one_line(self):
        fmt = SshKeylogFormatter()
        evt = KeylogEvent(
            protocol="ssh",
            payload={
                "cookie": "aa" * 16,
                "peer_cookie": "aa" * 16,
                "shared_secret": "bb" * 32,
            },
        )
        assert fmt.format(evt) == [f"{'aa' * 16} SHARED_SECRET {'bb' * 32}"]

    def test_only_peer_cookie_present(self):
        fmt = SshKeylogFormatter()
        evt = KeylogEvent(
            protocol="ssh",
            payload={
                "cookie": "",
                "peer_cookie": "cc" * 16,
                "shared_secret": "bb" * 32,
            },
        )
        assert fmt.format(evt) == [f"{'cc' * 16} SHARED_SECRET {'bb' * 32}"]

    def test_missing_shared_secret_falls_through_to_key_data(self):
        fmt = SshKeylogFormatter()
        # Structured payload missing secret → no SHARED_SECRET lines, falls
        # back to ``key_data`` if any (here empty → 0 lines).
        evt = KeylogEvent(
            protocol="ssh",
            payload={"cookie": "aa" * 16, "shared_secret": ""},
        )
        assert fmt.format(evt) == []

    def test_pre_formatted_key_data(self):
        """Per-direction derived-key lines stay verbatim."""
        fmt = SshKeylogFormatter()
        evt = KeylogEvent(protocol="ssh", key_data="SSH_ENC_KEY_C2S " + "de" * 16)
        assert fmt.format(evt) == ["SSH_ENC_KEY_C2S " + "de" * 16]

    def test_dedup_key_uses_cookie_plus_secret_for_shared_secret(self):
        fmt = SshKeylogFormatter()
        evt = KeylogEvent(
            protocol="ssh",
            payload={"cookie": "aa" * 16, "shared_secret": "bb" * 32},
        )
        assert fmt.dedup_key(evt) == f"{'aa' * 16}|{'bb' * 32}"

    def test_dedup_key_falls_back_to_peer_cookie_when_primary_empty(self):
        """If only ``peer_cookie`` is present (early-side hook saw the peer
        KEX_INIT first), the dedup key must distinguish that event from one
        with a different peer — falling back to ``peer_cookie`` prevents
        distinct shared-secret entries with the same blank ``cookie`` from
        colliding into a single ``"|<secret>"`` dedup bucket.
        """
        fmt = SshKeylogFormatter()
        evt_a = KeylogEvent(
            protocol="ssh",
            payload={
                "cookie": "",
                "peer_cookie": "cc" * 16,
                "shared_secret": "bb" * 32,
            },
        )
        evt_b = KeylogEvent(
            protocol="ssh",
            payload={
                "cookie": "",
                "peer_cookie": "dd" * 16,
                "shared_secret": "bb" * 32,
            },
        )
        assert fmt.dedup_key(evt_a) == f"{'cc' * 16}|{'bb' * 32}"
        assert fmt.dedup_key(evt_b) == f"{'dd' * 16}|{'bb' * 32}"
        assert fmt.dedup_key(evt_a) != fmt.dedup_key(evt_b)

    def test_dedup_key_for_derived_key_line(self):
        fmt = SshKeylogFormatter()
        evt = KeylogEvent(protocol="ssh", key_data="SSH_ENC_KEY_C2S abcd")
        assert fmt.dedup_key(evt) == "SSH_ENC_KEY_C2S abcd"

    def test_empty_event_produces_no_lines(self):
        assert SshKeylogFormatter().format(KeylogEvent(protocol="ssh")) == []
