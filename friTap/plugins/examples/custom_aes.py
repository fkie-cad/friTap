#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Example: Minimal AES key capture plugin.

Demonstrates basic CustomProtocolPlugin usage for extracting AES keys
and capturing encrypted/decrypted data from a custom crypto library.

Usage:
    Copy to your platform's plugin directory and run friTap.
    Find the path with: python -c "from friTap.plugins.loader import PLUGIN_DIR; print(PLUGIN_DIR)"
"""

from friTap.plugins import CustomProtocolPlugin


class Plugin(CustomProtocolPlugin):
    name = "my_crypto"
    version = "1.0.0"
    display_name = "My App Crypto"
    library_patterns = [r".*libmycrypto.*"]

    def setup_hooks(self):
        # Extract AES key from first argument of key setup function
        self.hook_key_on_enter(
            symbol="my_aes_key_init",
            arg=0, size=32,
            label="AES_KEY",
        )
        # Capture plaintext before encryption
        self.hook_write(symbol="my_encrypt", data_arg=1, length_arg=2)
        # Capture plaintext after decryption
        self.hook_read(symbol="my_decrypt", data_arg=1, length_arg=2)
