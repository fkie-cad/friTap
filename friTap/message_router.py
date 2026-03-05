#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Message routing for friTap.

Routes Frida message payloads to the EventBus as typed events.
"""

from __future__ import annotations
import socket
import struct
import logging

from .events import EventBus, KeylogEvent, DatalogEvent, LibraryDetectedEvent, ConsoleEvent

# Names of all supported read functions:
SSL_READ = frozenset({"SSL_read", "wolfSSL_read", "readApplicationData", "NSS_read", "Full_read"})
# Names of all supported write functions:
SSL_WRITE = frozenset({"SSL_write", "wolfSSL_write", "writeApplicationData", "NSS_write", "Full_write"})


class MessageRouter:
    """Routes Frida message payloads to typed EventBus events."""

    def __init__(self, event_bus: "EventBus") -> None:
        self._event_bus = event_bus
        self._logger = logging.getLogger("friTap.router")

    def route(self, payload: dict, data: bytes) -> None:
        """Parse a Frida message payload and emit the corresponding event."""
        content_type = payload.get("contentType")

        if content_type == "keylog" and payload.get("keylog"):
            self._emit_keylog(payload)
        elif content_type == "datalog" and data:
            self._emit_datalog(payload, data)
        elif content_type == "library_detected":
            self._emit_library_detected(payload)
        elif content_type == "console":
            self._emit_console(payload, level="info")
        elif content_type == "console_dev":
            self._emit_console_dev(payload)

    def _emit_keylog(self, payload: dict) -> None:
        self._event_bus.emit(KeylogEvent(
            key_data=payload["keylog"],
            protocol=payload.get("protocol", "tls"),
        ))

    def _emit_datalog(self, payload: dict, data: bytes) -> None:
        src_addr = payload.get("src_addr", "")
        dst_addr = payload.get("dst_addr", "")
        ss_family = payload.get("ss_family", "AF_INET")

        if ss_family == "AF_INET" and isinstance(src_addr, int):
            src_addr_str = socket.inet_ntop(socket.AF_INET, struct.pack(">I", src_addr))
            dst_addr_str = socket.inet_ntop(socket.AF_INET, struct.pack(">I", dst_addr))
        elif ss_family == "AF_INET6" and isinstance(src_addr, str):
            src_addr_str = socket.inet_ntop(socket.AF_INET6, struct.pack(">16s", bytes.fromhex(src_addr)))
            dst_addr_str = socket.inet_ntop(socket.AF_INET6, struct.pack(">16s", bytes.fromhex(dst_addr)))
        else:
            src_addr_str = str(src_addr)
            dst_addr_str = str(dst_addr)

        function = payload.get("function", "")
        self._event_bus.emit(DatalogEvent(
            data=data,
            function=function,
            direction="read" if function in SSL_READ else "write",
            src_addr=src_addr_str,
            src_port=payload.get("src_port", 0),
            dst_addr=dst_addr_str,
            dst_port=payload.get("dst_port", 0),
            src_addr_raw=src_addr,
            dst_addr_raw=dst_addr,
            ss_family=ss_family,
            ssl_session_id=str(payload.get("ssl_session_id", "")),
            protocol=payload.get("protocol", "tls"),
        ))

    def _emit_library_detected(self, payload: dict) -> None:
        self._event_bus.emit(LibraryDetectedEvent(
            library=payload.get("library", ""),
            path=payload.get("path", ""),
            protocol=payload.get("protocol", "tls"),
        ))

    def _emit_console(self, payload: dict, level: str = "info") -> None:
        self._event_bus.emit(ConsoleEvent(
            message=payload.get("console", ""),
            level=level,
        ))

    def _emit_console_dev(self, payload: dict) -> None:
        self._event_bus.emit(ConsoleEvent(
            message=payload.get("console_dev", ""),
            level="debug",
        ))
