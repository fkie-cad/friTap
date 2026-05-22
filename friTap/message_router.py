#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Message routing for friTap.

Extracted from SSL_Logger to reduce file length.
Routes agent message payloads to the EventBus as typed events.
"""

from __future__ import annotations
import logging

from .events import EventBus, KeylogEvent, DatalogEvent, LibraryDetectedEvent, ConsoleEvent, SessionEvent, OhttpEvent
from .constants import SSL_READ, ContentType
from .ssl_logger import get_addr_string


class _CanonicalProxy:
    """Minimal proxy satisfying DataCanonical canonical accessors (src, dst, protocol)."""
    __slots__ = ("src", "dst", "protocol")

    def __init__(self, src, dst, protocol: str) -> None:
        self.src = src
        self.dst = dst
        self.protocol = protocol


class MessageRouter:
    """Routes agent message payloads to typed EventBus events.

    Supports optional display filtering via set_filter(). When a filter is
    active, datalog events that don't match the filter are silently dropped.
    Keylog, lifecycle, and meta events always pass through.
    """

    def __init__(self, event_bus: "EventBus") -> None:
        self._event_bus = event_bus
        self._logger = logging.getLogger("friTap.router")
        self._data_filter = None  # Optional FilterEngine for network-level filtering

    def set_filter(self, filter_engine) -> None:
        """Set a display filter engine. Only network-level fields are checked."""
        self._data_filter = filter_engine

    def route(self, payload: dict, data: bytes) -> None:
        """Parse an agent message payload and emit the corresponding event."""
        content_type = payload.get("contentType")

        if content_type == "keylog" and payload.get("keylog"):
            self._emit_keylog(payload)
        elif content_type == "datalog" and (data or payload.get("http3_headers")):
            self._emit_datalog(payload, data)
        elif content_type == "library_detected":
            self._emit_library_detected(payload)
        elif content_type == "connection_lifecycle":
            self._emit_lifecycle(payload)
        elif content_type == "ohttp_plaintext":
            self._emit_ohttp(payload, data)
        elif content_type == ContentType.SSH_KEY:
            self._emit_ssh_key(payload)
        elif content_type == ContentType.SSH_KEYLOG:
            self._emit_ssh_keylog(payload)
        elif content_type == ContentType.SSH_NEWKEYS:
            self._emit_ssh_newkeys(payload)
        elif content_type == "console":
            self._emit_console(payload, level="info")
        elif content_type == "console_dev":
            self._emit_console_dev(payload)

    def _emit_keylog(self, payload: dict) -> None:
        self._event_bus.emit(KeylogEvent(
            key_data=payload["keylog"],
            protocol=payload.get("protocol", "tls"),
        ))

    @staticmethod
    def _resolve_addresses(payload: dict) -> tuple:
        """Extract and normalize source/destination addresses from a payload."""
        src_addr = payload.get("src_addr", "")
        dst_addr = payload.get("dst_addr", "")
        ss_family = payload.get("ss_family", "AF_INET")
        return (
            get_addr_string(src_addr, ss_family),
            payload.get("src_port", 0),
            get_addr_string(dst_addr, ss_family),
            payload.get("dst_port", 0),
            ss_family,
            src_addr,  # raw
            dst_addr,  # raw
        )

    def _emit_datalog(self, payload: dict, data: bytes) -> None:
        src_addr_str, src_port, dst_addr_str, dst_port, ss_family, src_addr, dst_addr = self._resolve_addresses(payload)

        if self._data_filter is not None:
            if not self._check_data_filter(
                src_addr_str, src_port, dst_addr_str, dst_port,
                payload.get("protocol", "tls"),
            ):
                return

        function = payload.get("function", "")
        self._event_bus.emit(DatalogEvent(
            data=data,
            function=function,
            direction="read" if function in SSL_READ else "write",
            src_addr=src_addr_str,
            src_port=src_port,
            dst_addr=dst_addr_str,
            dst_port=dst_port,
            src_addr_raw=src_addr,
            dst_addr_raw=dst_addr,
            ss_family=ss_family,
            ssl_session_id=str(payload.get("ssl_session_id", "")),
            client_random=str(payload.get("client_random", "")),
            transport=payload.get("transport", "tcp"),
            http3_headers=payload.get("http3_headers"),
            stream_id=payload.get("stream_id"),
            quic_scid=str(payload.get("quic_scid", "")),
            quic_dcid=str(payload.get("quic_dcid", "")),
            quic_stream_type=str(payload.get("quic_stream_type", "")),
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

    def _emit_ssh_key(self, payload: dict) -> None:
        """Format an SSH per-direction key/IV record as one line and emit a KeylogEvent.

        Lines use the labels OpenSSH writes via friTap's cipher_init hook
        (`SSH_ENC_KEY_C2S`, `SSH_ENC_KEY_S2C`, `SSH_IV_C2S`, `SSH_IV_S2C`).
        These are NOT the Wireshark SSH dissector's wire format — they land in
        the regular keys.log for users who want raw derived key material.
        Wireshark consumption uses the side-car file produced from
        :meth:`_emit_ssh_keylog`.
        """
        key_type = payload.get("key_type", "")
        key_data = payload.get("key_data", "")
        if not key_type or not key_data:
            return
        line = f"{key_type} {key_data}"
        self._event_bus.emit(KeylogEvent(
            key_data=line,
            protocol=payload.get("protocol", "ssh"),
        ))

    def _emit_ssh_keylog(self, payload: dict) -> None:
        """Emit a SHARED_SECRET KeylogEvent for the Wireshark SSH dissector.

        Routed to the unified :class:`KeylogOutputHandler` bound to the SSH
        :class:`SshKeylogFormatter`. The structured ``payload`` carries the
        fields that the formatter turns into ``<cookie> SHARED_SECRET <hex>``
        lines; Wireshark performs the RFC 4253 §7.2 KDF internally.
        """
        self._event_bus.emit(KeylogEvent(
            protocol="ssh",
            payload={
                "cookie": str(payload.get("cookie", "")),
                "peer_cookie": str(payload.get("peer_cookie", "")),
                "shared_secret": str(payload.get("shared_secret", "")),
                "direction": str(payload.get("direction", "")),
                "session_tag": str(payload.get("session_tag", "")),
            },
        ))

    def _emit_ssh_newkeys(self, payload: dict) -> None:
        """Forward SSH newkeys activation notifications to the console handler."""
        direction = payload.get("direction", "")
        msg = payload.get("message") or f"SSH newkeys activated ({direction})"
        self._event_bus.emit(ConsoleEvent(message=msg, level="info"))

    def _emit_ohttp(self, payload: dict, data: bytes) -> None:
        self._event_bus.emit(OhttpEvent(
            data=data,
            direction=payload.get("direction", ""),
            source=payload.get("source", ""),
            protocol=payload.get("protocol", "ohttp"),
        ))

    def _check_data_filter(
        self, src_addr: str, src_port: int,
        dst_addr: str, dst_port: int, protocol: str,
    ) -> bool:
        """Check if a datalog event passes the display filter via canonical accessors."""
        try:
            from .schemas.canonical import Endpoint
            proxy = _CanonicalProxy(
                src=Endpoint(src_addr, src_port),
                dst=Endpoint(dst_addr, dst_port),
                protocol=protocol,
            )
            return self._data_filter.matches_canonical(proxy)
        except Exception:
            return True

    def _emit_lifecycle(self, payload: dict) -> None:
        src_addr_str, src_port, dst_addr_str, dst_port, *_ = self._resolve_addresses(payload)
        conn_id = f"{src_addr_str}:{src_port}-{dst_addr_str}:{dst_port}"

        self._event_bus.emit(SessionEvent(
            session_id=str(payload.get("ssl_session_id", "")),
            event_type=payload.get("event", ""),
            client_random=str(payload.get("client_random", "")),
            connection_id=conn_id,
            src_addr=src_addr_str,
            src_port=src_port,
            dst_addr=dst_addr_str,
            dst_port=dst_port,
            protocol=payload.get("protocol", "tls"),
        ))
