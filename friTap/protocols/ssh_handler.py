#!/usr/bin/env python3

"""SSH protocol handler."""

from __future__ import annotations

from typing import TYPE_CHECKING, List, Optional

from ..backends.base import BackendName
from ..output.keylog_format import (
    KeylogFormatter,
    is_hex_field,
    sanitize_keylog_fields,
    warn_dropped_keylog_line,
)
from .base import BackendSupport, ProtocolHandler

if TYPE_CHECKING:
    from ..events import KeylogEvent

SSH_LIBRARY_PATTERNS = [
    "libssh", "sshd", "openssh",
]

_SHARED_SECRET_LABEL = "SHARED_SECRET"
_SHARED_SECRET_DROP_REASON = "ssh SHARED_SECRET"


def _distinct_cookies(payload: dict) -> List[str]:
    """The local cookie, then the peer cookie when present and different."""
    cookie = payload.get("cookie") or ""
    peer = payload.get("peer_cookie") or ""
    cookies = [cookie] if cookie else []
    if peer and peer != cookie:
        cookies.append(peer)
    return cookies


class SshKeylogFormatter(KeylogFormatter):
    """Formatter for the unified SSH ``-k`` file.

    Two :class:`KeylogEvent` flavours share one file:

    1. Structured payload (``payload['shared_secret']``): the RFC 4253 7.2
       shared secret K from ``kex_derive_keys``. Emits one
       ``<cookie> SHARED_SECRET <hex>`` line per distinct cookie (Wireshark 4.0+
       SSH key log format).
    2. Pre-formatted ``event.key_data``: per-direction derived keys
       (``SSH_ENC_KEY_C2S <hex>``, ``SSH_IV_S2C <hex>``). Wireshark ignores
       these labels; they are for manual inspection.

    The agent runs in a possibly hostile process, so cookies and the shared
    secret must be even-length hex; otherwise the record is dropped with a
    once-per-reason warning.
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
            # Derived keys arrive pre-formatted in key_data.
            return super().format(event)
        secret_fields = sanitize_keylog_fields(_SHARED_SECRET_LABEL, shared_secret)
        cookies = _distinct_cookies(payload)
        if secret_fields is None or not all(is_hex_field(c) for c in cookies):
            warn_dropped_keylog_line(
                _SHARED_SECRET_DROP_REASON, "cookie and shared secret must be hex")
            return []
        return [f"{cookie} {secret_fields}" for cookie in cookies]

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
