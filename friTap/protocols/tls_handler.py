#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""TLS/SSL protocol handler."""

from __future__ import annotations

from .base import ProtocolHandler

TLS_LIBRARY_PATTERNS = [
    "libssl", "libcrypto", "libgnutls", "libwolfssl", "libmbedtls",
    "libnss", "boringssl", "schannel", "secur32", "conscrypt",
    "cronet", "flutter", "monotls",
]


class TLSHandler(ProtocolHandler):
    """Handler for TLS/SSL protocol key material and data."""

    library_patterns = TLS_LIBRARY_PATTERNS

    @property
    def name(self) -> str:
        return "tls"

    @property
    def display_name(self) -> str:
        return "TLS/SSL"

    def get_keylog_format(self) -> str:
        return "NSS Key Log Format"

    def get_wireshark_protocol_preference(self) -> str:
        return "tls.keylog_file"

    def get_display_filter_template(self) -> str:
        return "ip.addr == {src} && ip.addr == {dst} && tcp.port == {port}"
