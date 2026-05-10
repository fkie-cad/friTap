#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""TCP session state tracker and IP/TCP packet construction for PCAPNG output.

Builds synthetic IPv4/IPv6 + TCP headers around decrypted TLS payload data
so that Wireshark/tshark can parse the resulting PCAPNG packets correctly.
The header format matches the legacy PCAP writer in ``friTap/pcap.py``.
"""

from __future__ import annotations

import random
import struct
import threading
from collections import OrderedDict
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..schemas.canonical import AddressFamily, DataCanonical


SessionKey = tuple[object, int, object, int]


@dataclass
class _SessionState:
    client_seq: int
    server_seq: int


class TcpSessionTracker:
    """Thread-safe tracker for fake TCP sequence/acknowledgment numbers.

    Each unique connection gets a random initial sequence number pair.
    Sequence numbers advance monotonically with each packet's data length.
    State is held in an LRU with ``MAX_SESSIONS`` entries — evicted sessions
    reappear with fresh ISNs, which Wireshark sees as a new TCP connection.
    """

    MAX_SESSIONS = 8192

    def __init__(self, max_sessions: int | None = None) -> None:
        self._lock = threading.Lock()
        self._sessions: OrderedDict[SessionKey, _SessionState] = OrderedDict()
        self._max = max_sessions if max_sessions is not None else self.MAX_SESSIONS

    def get_seq_ack(
        self, session_key: SessionKey, is_read: bool, data_len: int
    ) -> tuple[int, int]:
        """Return (seq, ack) for this packet and advance counters."""
        with self._lock:
            state = self._sessions.get(session_key)
            if state is None:
                if len(self._sessions) >= self._max:
                    self._sessions.popitem(last=False)
                state = _SessionState(
                    client_seq=random.randint(0, 0xFFFFFFFF),
                    server_seq=random.randint(0, 0xFFFFFFFF),
                )
                self._sessions[session_key] = state
            else:
                self._sessions.move_to_end(session_key)

            if is_read:
                seq, ack = state.server_seq, state.client_seq
                state.server_seq = (state.server_seq + data_len) & 0xFFFFFFFF
            else:
                seq, ack = state.client_seq, state.server_seq
                state.client_seq = (state.client_seq + data_len) & 0xFFFFFFFF

            return seq, ack

    def clear(self) -> None:
        with self._lock:
            self._sessions.clear()


def make_session_key(
    src_addr: int | str,
    src_port: int,
    dst_addr: int | str,
    dst_port: int,
    is_read: bool,
) -> SessionKey:
    """Return a direction-independent tuple key (server-side first)."""
    if is_read:
        return (src_addr, src_port, dst_addr, dst_port)
    return (dst_addr, dst_port, src_addr, src_port)


def build_ipv4_tcp_packet(
    src_addr: int,
    src_port: int,
    dst_addr: int,
    dst_port: int,
    seq: int,
    ack: int,
    payload: bytes,
) -> bytes:
    """Return 20-byte IPv4 + 20-byte TCP header + payload.

    Checksums are zero (valid for synthetic pcap data).
    TCP flags are PSH+ACK (0x5018) matching friTap/pcap.py.
    """
    total_len = 40 + len(payload)
    header = struct.pack(
        ">BBHHHBBHIIHHIIHHHH",
        0x45, 0, total_len,         # Version/IHL, ToS, Total Length
        0, 0x4000, 0xFF, 6, 0,      # ID, Flags/FragOff, TTL, Protocol, IP checksum
        src_addr, dst_addr,
        src_port, dst_port,
        seq, ack,
        0x5018, 0xFFFF, 0, 0,       # DataOff+Flags, Window, TCP checksum, Urgent
    )
    return header + payload


def build_ipv6_tcp_packet(
    src_addr_hex: str,
    src_port: int,
    dst_addr_hex: str,
    dst_port: int,
    seq: int,
    ack: int,
    payload: bytes,
) -> bytes:
    """Return 40-byte IPv6 + 20-byte TCP header + payload.

    Addresses are 32-character hex strings.
    """
    tcp_payload_len = 20 + len(payload)
    header = struct.pack(
        ">IHBB16s16sHHIIHHHH",
        0x60000000,                    # Version/Traffic Class/Flow Label
        tcp_payload_len, 6, 0xFF,      # Payload Length, Next Header, Hop Limit
        bytes.fromhex(src_addr_hex),
        bytes.fromhex(dst_addr_hex),
        src_port, dst_port,
        seq, ack,
        0x5018, 0xFFFF, 0, 0,
    )
    return header + payload


def _as_ipv6_hex(addr: int | str) -> str:
    return addr if isinstance(addr, str) else format(addr, '032x')


def _as_ipv4_int(addr: int | str) -> int:
    return addr if isinstance(addr, int) else 0


def build_framed_packet_from_fields(
    ss_family: "AddressFamily | str",
    src_addr: int | str,
    src_port: int,
    dst_addr: int | str,
    dst_port: int,
    is_read: bool,
    data: bytes,
    tracker: TcpSessionTracker,
) -> bytes:
    """Build a framed IP+TCP packet from raw connection fields.

    This is the low-level entry point shared by both the modern
    ``DataCanonical``-based sink and the legacy ``DatalogEvent``-based
    handler. Dispatches to IPv4 or IPv6 based on ``ss_family``.

    Accepts both :class:`~friTap.schemas.canonical.AddressFamily` enum
    values and raw strings for backward compatibility with legacy events.
    """
    from ..schemas.canonical import AddressFamily

    family_str = ss_family.value if isinstance(ss_family, AddressFamily) else ss_family
    key = make_session_key(src_addr, src_port, dst_addr, dst_port, is_read)
    seq, ack = tracker.get_seq_ack(key, is_read, len(data))

    if family_str == AddressFamily.AF_INET6.value:
        return build_ipv6_tcp_packet(
            _as_ipv6_hex(src_addr), src_port,
            _as_ipv6_hex(dst_addr), dst_port,
            seq, ack, data,
        )
    return build_ipv4_tcp_packet(
        _as_ipv4_int(src_addr), src_port,
        _as_ipv4_int(dst_addr), dst_port,
        seq, ack, data,
    )


def build_framed_packet(event: "DataCanonical", tracker: TcpSessionTracker) -> bytes:
    """Build a framed IP+TCP packet from a ``DataCanonical`` event."""
    from ..schemas.canonical import Direction

    return build_framed_packet_from_fields(
        ss_family=event.ss_family,
        src_addr=event.src_addr_raw,
        src_port=event.src.port,
        dst_addr=event.dst_addr_raw,
        dst_port=event.dst.port,
        is_read=(event.direction == Direction.READ),
        data=event.data,
        tracker=tracker,
    )
