#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""SSH protocol handler."""

from __future__ import annotations

from typing import TYPE_CHECKING, List, Optional

from .base import ProtocolHandler, BackendSupport
from ..backends.base import BackendName
from ..output.keylog_format import KeylogFormatter

if TYPE_CHECKING:
    from ..events import KeylogEvent

SSH_LIBRARY_PATTERNS = [
    "libssh", "sshd", "openssh",
]


class SshKeylogFormatter(KeylogFormatter):
    """Formatter for the unified SSH ``-k`` file.

    Handles two flavours of :class:`KeylogEvent`:

    1. **Structured payload** (``event.payload['shared_secret']`` set) — the
       RFC 4253 §7.2 shared secret K from a ``kex_derive_keys`` hook. Emits
       one ``<cookie> SHARED_SECRET <hex>`` line per available cookie (local
       and peer, when they differ). This is the Wireshark-native SSH
       dissector format (Wireshark 4.0+, Edit → Preferences → Protocols →
       SSH → Key log filename).
    2. **Pre-formatted line** (``event.key_data`` set) — informational
       per-direction derived keys (``SSH_ENC_KEY_C2S <hex>``,
       ``SSH_IV_S2C <hex>``, …). Wireshark ignores these unknown labels,
       but they're useful for manual cryptographic inspection.

    Both flavours coexist in the same ``-k`` file so users get one
    Wireshark-loadable artifact plus the historical derived-key view.
    """

    @property
    def protocol(self) -> str:
        return "ssh"

    def header_comment(self) -> Optional[str]:
        return (
            "# friTap SSH keylog — load via Wireshark "
            "Edit -> Preferences -> Protocols -> SSH"
        )

    def format(self, event: "KeylogEvent") -> List[str]:
        payload = event.payload or {}
        shared_secret = payload.get("shared_secret")
        if not shared_secret:
            # Fall back to the base passthrough (per-direction derived keys
            # like ``SSH_ENC_KEY_C2S …`` arrive pre-formatted in key_data).
            return super().format(event)
        out: List[str] = []
        cookie = payload.get("cookie") or ""
        peer = payload.get("peer_cookie") or ""
        if cookie:
            out.append(f"{cookie} SHARED_SECRET {shared_secret}")
        if peer and peer != cookie:
            out.append(f"{peer} SHARED_SECRET {shared_secret}")
        return out

    def dedup_key(self, event: "KeylogEvent") -> str:
        payload = event.payload or {}
        shared_secret = payload.get("shared_secret")
        if shared_secret:
            cookie = payload.get("cookie") or payload.get("peer_cookie") or ""
            return f"{cookie}|{shared_secret}"
        return event.key_data


class SSHHandler(ProtocolHandler):
    """Handler for SSH key material."""

    library_patterns = SSH_LIBRARY_PATTERNS

    @property
    def name(self) -> str:
        return "ssh"

    @property
    def display_name(self) -> str:
        return "SSH"

    def get_keylog_format(self) -> str:
        return "SSH Key Log Format"

    def get_wireshark_protocol_preference(self) -> str:
        return "ssh.keylog_file"  # Wireshark 4.0+

    def get_display_filter_template(self) -> str:
        return "ip.addr == {src} && ip.addr == {dst} && tcp.port == {port} && ssh"

    def keylog_formatter(self) -> Optional[KeylogFormatter]:
        return SshKeylogFormatter()

    @property
    def supported_backends(self) -> dict[str, str]:
        return {
            BackendName.FRIDA: BackendSupport.FULL,
            BackendName.GDB: BackendSupport.FULL,
            BackendName.LLDB: BackendSupport.FULL,
        }
