"""Canonical event types for the friTap pipeline output.

These frozen dataclasses represent the processed, immutable events that
sinks receive after pipeline processing. They are separate from the raw
agent messages emitted by Frida scripts.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import NamedTuple


class Direction(Enum):
    """Data flow direction."""

    READ = "read"
    WRITE = "write"


class AddressFamily(Enum):
    """Socket address family."""

    AF_INET = "AF_INET"
    AF_INET6 = "AF_INET6"


class Endpoint(NamedTuple):
    """Network endpoint (address and port)."""

    addr: str
    port: int


@dataclass(frozen=True)
class KeylogCanonical:
    """Processed key material event.

    Carries TLS/SSH/IPSec key-log lines ready for writing to a
    SSLKEYLOGFILE-compatible sink.
    """

    key_data: str
    protocol: str = "tls"
    timestamp: float = field(default_factory=time.time)


@dataclass(frozen=True)
class DataCanonical:
    """Processed decrypted data event.

    Represents a single chunk of decrypted payload captured from the
    target process, tagged with connection metadata for PCAP generation
    and downstream analysis.
    """

    data: bytes
    direction: Direction
    src: Endpoint
    dst: Endpoint
    ss_family: AddressFamily = AddressFamily.AF_INET
    ssl_session_id: str = ""
    protocol: str = "tls"
    timestamp: float = field(default_factory=time.time)
    connection_id: str = ""
    # Raw address values for PCAP writing
    src_addr_raw: int | str = 0
    dst_addr_raw: int | str = 0


@dataclass(frozen=True)
class MetaCanonical:
    """Processed metadata event.

    Covers auxiliary information such as library detection notifications,
    console output, session lifecycle, and error reports.
    """

    event_type: str  # "library_detected", "console", "session", "error"
    message: str = ""
    level: str = "info"
    library: str = ""
    protocol: str = "tls"
    timestamp: float = field(default_factory=time.time)
