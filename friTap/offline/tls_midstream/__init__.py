"""Offline mid-stream TLS 1.3 record decryption.

A standalone, isolated crypto core (no pipeline wiring) that decrypts an
already-established TLS 1.3 flow captured mid-stream — no ClientHello/handshake
in the pcap — from a raw traffic secret, recovering the unknown starting record
sequence number (and, if unknown, the cipher suite) via the AEAD tag as a
zero-false-accept oracle.
"""

from __future__ import annotations

from .crypto import (
    DEFAULT_MAX_SEQ,
    decrypt_stream_from,
    pick_suite,
    recover_seq,
)
from .transport import MidstreamTlsStream, midstream_tls_streams

__all__ = [
    "DEFAULT_MAX_SEQ",
    "recover_seq",
    "decrypt_stream_from",
    "pick_suite",
    "MidstreamTlsStream",
    "midstream_tls_streams",
]
