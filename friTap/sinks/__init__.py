"""Sink implementations for friTap pipeline output."""

from .base import Sink
from .pcap import PcapSink
from .pcapng import PcapngSink
from .live_pcapng import LivePcapngSink
from .live_wireshark import LiveWiresharkSink

__all__ = [
    "Sink",
    "PcapSink",
    "PcapngSink",
    "LivePcapngSink",
    "LiveWiresharkSink",
]
