#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Example: SRTP data capture plugin.

Demonstrates data capture with CustomProtocolPlugin for intercepting
SRTP (Secure Real-time Transport Protocol) via libsrtp.

Usage:
    Copy to your platform's plugin directory and run friTap.
    Find the path with: python -c "from friTap.plugins.loader import PLUGIN_DIR; print(PLUGIN_DIR)"
"""

from friTap.plugins import CustomProtocolPlugin


class Plugin(CustomProtocolPlugin):
    name = "srtp"
    version = "1.0.0"
    display_name = "SRTP (libsrtp)"
    library_patterns = [r".*libsrtp.*"]

    def setup_hooks(self):
        # Extract SRTP master key during policy setup
        self.hook_key_on_enter(
            symbol="srtp_crypto_policy_set_aes_cm_128_hmac_sha1_80",
            arg=0, size=30,
            label="SRTP_MASTER_KEY",
        )
        # Capture plaintext before SRTP protection
        self.hook_write(symbol="srtp_protect", data_arg=1, length_arg=2)
        # Capture plaintext after SRTP unprotection
        self.hook_read(symbol="srtp_unprotect", data_arg=1, length_arg=2)
