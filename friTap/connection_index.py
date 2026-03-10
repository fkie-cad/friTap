#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Connection tracking index for friTap sessions.

Consolidates the scattered sets from the legacy SSL_Logger (keydump_Set,
traced_Socket_Set, traced_scapy_socket_Set) into a single
session-scoped tracker.
"""

from __future__ import annotations
import threading
from dataclasses import dataclass
from typing import Dict, Set, Tuple


@dataclass
class ConnectionInfo:
    """Metadata for a tracked connection."""
    src_addr: str = ""
    src_port: int = 0
    dst_addr: str = ""
    dst_port: int = 0
    ss_family: str = "AF_INET"
    ssl_session_id: str = ""
    protocol: str = "tls"
    bytes_read: int = 0
    bytes_written: int = 0


class ConnectionIndex:
    """Session-scoped connection and key deduplication tracker.

    Thread-safe. Created per-session, destroyed when session ends.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._seen_keys: Set[str] = set()
        self._traced_sockets: Set[Tuple[str, int, str, int]] = set()
        self._connections: Dict[str, ConnectionInfo] = {}

    def is_new_key(self, key_data: str) -> bool:
        """Check if key material is new (not seen before). Thread-safe."""
        with self._lock:
            if key_data in self._seen_keys:
                return False
            self._seen_keys.add(key_data)
            return True

    def is_new_socket(self, src_addr: str, src_port: int,
                       dst_addr: str, dst_port: int) -> bool:
        """Check if a socket tuple is new. Thread-safe."""
        key = (src_addr, src_port, dst_addr, dst_port)
        with self._lock:
            if key in self._traced_sockets:
                return False
            self._traced_sockets.add(key)
            return True

    def get_or_create_connection(
        self,
        src_addr: str,
        src_port: int,
        dst_addr: str,
        dst_port: int,
        **kwargs,
    ) -> Tuple[str, ConnectionInfo]:
        """Get existing or create new connection entry.

        Returns (connection_id, connection_info).
        """
        key = f"{src_addr}:{src_port}-{dst_addr}:{dst_port}"
        with self._lock:
            if key not in self._connections:
                self._connections[key] = ConnectionInfo(
                    src_addr=src_addr,
                    src_port=src_port,
                    dst_addr=dst_addr,
                    dst_port=dst_port,
                    **kwargs,
                )
            return key, self._connections[key]

    @property
    def key_count(self) -> int:
        """Number of unique keys seen."""
        with self._lock:
            return len(self._seen_keys)

    @property
    def connection_count(self) -> int:
        """Number of tracked connections."""
        with self._lock:
            return len(self._connections)

    @property
    def socket_count(self) -> int:
        """Number of traced sockets."""
        with self._lock:
            return len(self._traced_sockets)

    def clear(self) -> None:
        """Clear all tracking state."""
        with self._lock:
            self._seen_keys.clear()
            self._traced_sockets.clear()
            self._connections.clear()
