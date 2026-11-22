"""Canonical event types for the friTap pipeline output.

Frozen events that sinks receive after pipeline processing, separate from
the raw agent messages.
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
    """Key-log lines (TLS/SSH/IPSec) ready for a SSLKEYLOGFILE-compatible sink."""

    key_data: str
    protocol: str = "tls"
    timestamp: float = field(default_factory=time.time)
    client_random: str = ""


@dataclass(frozen=True)
class DataCanonical:
    """One chunk of decrypted payload with connection metadata for PCAP generation."""

    data: bytes
    direction: Direction
    src: Endpoint
    dst: Endpoint
    ss_family: AddressFamily = AddressFamily.AF_INET
    ssl_session_id: str = ""
    protocol: str = "tls"
    timestamp: float = field(default_factory=time.time)
    # Arrival time when ``timestamp`` is back-dated (held record); packet writers use it.
    received_at: float | None = None
    connection_id: str = ""
    client_random: str = ""
    # Raw address values for PCAP writing
    src_addr_raw: int | str = 0
    dst_addr_raw: int | str = 0
    # QUIC-specific fields (None/empty for non-QUIC traffic)
    stream_id: int | None = None
    quic_scid: str = ""
    quic_dcid: str = ""


@dataclass(frozen=True)
class MetaCanonical:
    """Auxiliary event: library detection, console output, session lifecycle, errors."""

    event_type: str  # "library_detected", "console", "session", "error"
    message: str = ""
    level: str = "info"
    library: str = ""
    protocol: str = "tls"
    timestamp: float = field(default_factory=time.time)
