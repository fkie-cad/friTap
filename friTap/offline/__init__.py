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

# NOTE: the manifest-aware ``pcap_to_tap`` wrapper lives in the submodule
# ``friTap.offline.pcap_to_tap`` (next to ``convert_pcap_to_tap``) and is NOT
# bound here, because doing so would shadow the same-named submodule attribute
# (``friTap.offline.pcap_to_tap`` must keep resolving to the module). The
# wrapper is re-exported from the package root as ``friTap.pcap_to_tap``.

__all__ = [
    "ConvertResult",
    "NoDecryptionKeysError",
    "capture_has_dsb",
    "convert_pcap_to_tap",
]
