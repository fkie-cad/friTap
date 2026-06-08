"""Offline pcap-to-tap reconstruction pipeline.

This package drives an external ``tshark`` to decrypt an encrypted full-capture
pcap/pcapng using a TLS keylog (or a DSB-embedded pcapng) and feeds the
decrypted application bytes through the existing FlowCollector + parsers +
TapWriter to reconstruct a friTap ``.tap`` file — entirely offline.
"""

from __future__ import annotations

from .pcap_to_tap import (
    ConvertResult,
    NoDecryptionKeysError,
    convert_pcap_to_tap,
)
from .tshark import capture_has_dsb

__all__ = [
    "ConvertResult",
    "NoDecryptionKeysError",
    "capture_has_dsb",
    "convert_pcap_to_tap",
]
