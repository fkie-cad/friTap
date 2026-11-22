"""Offline pcap-to-tap reconstruction pipeline.

This package drives an external ``tshark`` to decrypt an encrypted full-capture
pcap/pcapng using a TLS keylog (or a DSB-embedded pcapng) and feeds the
decrypted application bytes through the existing FlowCollector + parsers +
TapWriter to reconstruct a friTap ``.tap`` file offline.
"""

from __future__ import annotations

from .pcap_to_tap import (
    ConvertResult,
    NoDecryptionKeysError,
    convert_pcap_to_tap,
)
from .tshark import TSHARK_INSTALL_MESSAGE, TsharkNotFoundError, capture_has_dsb

# The ``pcap_to_tap`` wrapper function is not bound here: it would shadow the
# same-named submodule. It is re-exported as ``friTap.pcap_to_tap``.

__all__ = [
    "ConvertResult",
    "NoDecryptionKeysError",
    "TSHARK_INSTALL_MESSAGE",
    "TsharkNotFoundError",
    "capture_has_dsb",
    "convert_pcap_to_tap",
]
