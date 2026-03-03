#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""JSON session output handler."""

from __future__ import annotations
import json
import logging
from datetime import datetime, timezone
from typing import IO, Optional, TYPE_CHECKING

from .base import OutputHandler

if TYPE_CHECKING:
    from ..events import (
        EventBus, KeylogEvent, DatalogEvent, SessionEvent, ErrorEvent,
        LibraryDetectedEvent,
    )


class JsonOutputHandler(OutputHandler):
    """Collects session data and writes a JSON summary on close."""

    def __init__(self, json_path: str, session_info: Optional[dict] = None) -> None:
        self._path = json_path
        self._file: Optional[IO] = None
        self._logger = logging.getLogger("friTap.output.json")
        self._data = {
            "session_info": session_info or {},
            "ssl_sessions": [],
            "connections": [],
            "key_extractions": [],
            "errors": [],
            "libraries_detected": [],
            "statistics": {
                "total_sessions": 0,
                "total_connections": 0,
                "total_bytes_captured": 0,
            },
        }

    def setup(self, event_bus: "EventBus") -> None:
        from ..events import (
            KeylogEvent, DatalogEvent, SessionEvent, ErrorEvent,
            LibraryDetectedEvent,
        )
        try:
            self._file = open(self._path, "w")
        except OSError as e:
            self._logger.warning("Failed to open JSON output file '%s': %s", self._path, e)
            self._file = None
        event_bus.subscribe(KeylogEvent, self.on_keylog)
        event_bus.subscribe(DatalogEvent, self.on_data)
        event_bus.subscribe(SessionEvent, self.on_session)
        event_bus.subscribe(ErrorEvent, self.on_error)
        event_bus.subscribe(LibraryDetectedEvent, self._on_library)

    def on_keylog(self, event: "KeylogEvent") -> None:
        self._data["key_extractions"].append({
            "timestamp": event.timestamp,
            "type": "key_extraction",
            "key_data": event.key_data,
        })

    def on_data(self, event: "DatalogEvent") -> None:
        data_length = len(event.data) if event.data else 0
        self._data["connections"].append({
            "timestamp": event.timestamp,
            "function": event.function,
            "ssl_session_id": event.ssl_session_id,
            "src_addr": event.src_addr,
            "src_port": event.src_port,
            "dst_addr": event.dst_addr,
            "dst_port": event.dst_port,
            "ss_family": event.ss_family,
            "data_length": data_length,
        })
        self._data["statistics"]["total_connections"] += 1
        self._data["statistics"]["total_bytes_captured"] += data_length

    def on_session(self, event: "SessionEvent") -> None:
        self._data["ssl_sessions"].append({
            "timestamp": event.timestamp,
            "session_id": event.session_id,
            "event_type": event.event_type,
            "cipher_suite": event.cipher_suite,
            "protocol_version": event.protocol_version,
            "server_name": event.server_name,
        })
        self._data["statistics"]["total_sessions"] += 1

    def on_error(self, event: "ErrorEvent") -> None:
        self._data["errors"].append({
            "timestamp": event.timestamp,
            "description": event.description,
            "error": event.error,
            "stack": event.stack,
        })

    def _on_library(self, event: "LibraryDetectedEvent") -> None:
        lib_info = {"name": event.library, "path": event.path, "detected_at": event.timestamp}
        if lib_info not in self._data["libraries_detected"]:
            self._data["libraries_detected"].append(lib_info)

    def close(self) -> None:
        if self._file:
            try:
                self._data["session_info"]["end_time"] = datetime.now(timezone.utc).isoformat()
                json.dump(self._data, self._file, indent=2, ensure_ascii=False)
                self._file.close()
                self._logger.info("JSON output saved to %s", self._path)
            except Exception as e:
                self._logger.error("Error writing JSON output: %s", e)
            self._file = None
