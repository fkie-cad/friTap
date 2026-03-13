#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""SSH protocol handler."""

from __future__ import annotations

from .base import ProtocolHandler, BackendSupport
from ..backends.base import BackendName

SSH_LIBRARY_PATTERNS = [
    "libssh", "sshd", "openssh",
]


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

    @property
    def supported_backends(self) -> dict[str, str]:
        return {
            BackendName.FRIDA: BackendSupport.FULL,
            BackendName.GDB: BackendSupport.FULL,
            BackendName.LLDB: BackendSupport.FULL,
        }
