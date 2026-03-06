#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Example: WireGuard key extraction plugin.

Demonstrates advanced CustomProtocolPlugin features:
  - Multiple library patterns
  - Platform targeting
  - Base64 encoding
  - Struct offset access
  - on_leave key extraction
  - Custom format template for Wireshark

Usage:
    Copy to your platform's plugin directory and run friTap.
    Find the path with: python -c "from friTap.plugins.loader import PLUGIN_DIR; print(PLUGIN_DIR)"
"""

from friTap.plugins import CustomProtocolPlugin


class Plugin(CustomProtocolPlugin):
    name = "wireguard"
    version = "1.0.0"
    display_name = "WireGuard VPN"
    library_patterns = [r".*wireguard.*", r".*libwg.*"]
    platforms = ["linux", "android", "macos"]
    format_template = "{label}={secret_base64}"
    wireshark_preference = "wg.keylog_file"

    def setup_hooks(self):
        # Static private key from handshake initiation struct
        self.hook_key_on_enter(
            symbol="noise_handshake_consume_initiation",
            arg=1, byte_offset=0x20, size=32,
            label="LOCAL_STATIC_PRIVATE_KEY",
            encoding="base64",
        )
        # Ephemeral private key
        self.hook_key_on_enter(
            symbol="noise_handshake_create_initiation",
            arg=0, byte_offset=0x60, size=32,
            label="LOCAL_EPHEMERAL_PRIVATE_KEY",
            encoding="base64",
        )
        # Key from return value after handshake completes
        self.hook_key_on_leave(
            symbol="wg_noise_handshake_done",
            byte_offset=64, size=32,
            label="WG_SENDING_KEY",
        )
