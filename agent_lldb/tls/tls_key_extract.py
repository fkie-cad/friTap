#!/usr/bin/env python3
"""
LLDB script for TLS key extraction.

STATUS: Template stub — not yet implemented.
Planned approach: Hook HKDF-Expand-Label (TLS 1.3) and PRF (TLS 1.2)
per library using byte patterns from TLSKeyHunter research.

Usage (future):
    lldb -p <pid> -o "command script import tls_key_extract.py"
"""

try:
    import lldb
except ImportError:
    print("ERROR: This script must be run inside LLDB.")
    raise


# Target functions for TLS key extraction (per library)
TLS_KEY_FUNCTIONS = {
    "openssl": [
        "tls13_hkdf_expand",
        "tls1_PRF",
    ],
    "gnutls": [
        "_gnutls_PRF",
        "_gnutls13_expand_secret",
    ],
}


def __lldb_init_module(debugger, internal_dict):
    raise NotImplementedError(
        "LLDB-based TLS key extraction is not yet implemented. "
        "Use the Frida backend for TLS interception."
    )
