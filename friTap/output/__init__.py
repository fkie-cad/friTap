#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Output handler abstraction for friTap."""

from .base import OutputHandler
from .pcap_handler import PcapOutputHandler
from .keylog_handler import KeylogOutputHandler
from .json_handler import JsonOutputHandler
from .jsonl_handler import JsonlOutputHandler
from .console_handler import ConsoleOutputHandler
from .live_wireshark_handler import LiveWiresharkHandler
from .pcapng_handler import PcapngOutputHandler
from .live_pcapng_handler import LivePcapngHandler
from .factory import OutputHandlerFactory

__all__ = [
    "OutputHandler",
    "PcapOutputHandler",
    "KeylogOutputHandler",
    "JsonOutputHandler",
    "JsonlOutputHandler",
    "ConsoleOutputHandler",
    "LiveWiresharkHandler",
    "PcapngOutputHandler",
    "LivePcapngHandler",
    "OutputHandlerFactory",
]
