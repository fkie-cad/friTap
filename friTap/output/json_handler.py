#!/usr/bin/env python3

"""JSON session output handler."""

from __future__ import annotations

import json
import logging
import threading
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Optional

from .base import OutputHandler

if TYPE_CHECKING:
    from ..events import (
        DatalogEvent,
        ErrorEvent,
        EventBus,
        KeylogEvent,
        LibraryDetectedEvent,
        SessionEvent,
    )
    from .shared_output_file import SharedOutputFile


def _new_document(session_info: dict) -> dict:
    return {
        "session_info": session_info,
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


class JsonOutputHandler(OutputHandler):
    """Collects session data and writes a JSON summary on close.

    The document is shared per path (:mod:`friTap.output.shared_output_file`):
    the Windows LSASS session is configured with the same ``--json`` path, so
    both sessions fill ONE in-memory document and every release rewrites the
    whole file, the last one with the complete document. An *auxiliary*
    session (LSASS) records its session_info under ``auxiliary_sessions`` so
    ``session_info`` stays the target session's. With a single session the file
    content is unchanged.
    """

    def __init__(self, json_path: str, session_info: Optional[dict] = None,
                 auxiliary: bool = False) -> None:
        self._path = json_path
        self._file: Optional["SharedOutputFile"] = None
        self._logger = logging.getLogger("friTap.output.json")
        self._session_info = session_info or {}
        self._auxiliary = auxiliary
        # Replaced by the shared file's lock once set up.
        self._lock = threading.RLock()
        self._data = _new_document({} if auxiliary else self._session_info)

    def setup(self, event_bus: "EventBus") -> None:
        from ..events import (
            DatalogEvent,
            ErrorEvent,
            KeylogEvent,
            LibraryDetectedEvent,
            SessionEvent,
        )
        self._join_shared_document()
        event_bus.subscribe(KeylogEvent, self.on_keylog)
        event_bus.subscribe(DatalogEvent, self.on_data)
        event_bus.subscribe(SessionEvent, self.on_session)
        event_bus.subscribe(ErrorEvent, self.on_error)
        event_bus.subscribe(LibraryDetectedEvent, self._on_library)

    def _join_shared_document(self) -> None:
        """Open (first session) or join (later session) the document for this path."""
        from .shared_output_file import acquire_shared_output_file
        try:
            self._file, _created = acquire_shared_output_file(
                self._path, "w", initializer=lambda _f: self._data)
        except OSError as e:
            self._logger.warning("Failed to open JSON output file '%s': %s", self._path, e)
            self._file = None
            return
        self._lock = self._file.lock
        with self._lock:
            self._data = self._file.state
            if self._auxiliary:
                self._data.setdefault("auxiliary_sessions", []).append(self._session_info)
            else:
                self._data["session_info"] = self._session_info

    def on_keylog(self, event: "KeylogEvent") -> None:
        record = {
            "timestamp": event.timestamp,
            "type": "key_extraction",
            "key_data": event.key_data,
        }
        # Heap memory-scan findings ride in on a KeylogEvent tagged
        # protocol="memscan"; surface their provenance in the JSON output.
        # Protocol-specific memory-scan keys (protocol="mtproto"/"rc4") are
        # deliberately left as plain "key_extraction" records with their full
        # key_data preserved: they are recovered protocol keys, not the generic
        # TLS-secret findings the "memory_scan_finding" shape (label/tier/source)
        # describes. Both mtproto and rc4 behave identically here on purpose.
        if event.protocol == "memscan":
            payload = event.payload or {}
            record["type"] = "memory_scan_finding"
            record.update({
                "label": payload.get("label", ""),
                "client_random": payload.get("client_random", ""),
                "tier": payload.get("tier", ""),
                "source": payload.get("source", ""),
            })
        with self._lock:
            self._data["key_extractions"].append(record)

    def on_data(self, event: "DatalogEvent") -> None:
        data_length = len(event.data) if event.data else 0
        with self._lock:
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
        with self._lock:
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
        with self._lock:
            self._data["errors"].append({
                "timestamp": event.timestamp,
                "description": event.description,
                "error": event.error,
                "stack": event.stack,
            })

    def _on_library(self, event: "LibraryDetectedEvent") -> None:
        lib_info = {"name": event.library, "path": event.path, "detected_at": event.timestamp}
        with self._lock:
            if lib_info not in self._data["libraries_detected"]:
                self._data["libraries_detected"].append(lib_info)

    def close(self) -> None:
        shared, self._file = self._file, None
        if shared is None:
            return
        from .shared_output_file import release_shared_output_file
        try:
            with self._lock:
                self._session_info["end_time"] = datetime.now(timezone.utc).isoformat()
                # Every release rewrites the whole document, so the file is valid
                # JSON even if another session sharing it is never released.
                shared.rewrite(json.dumps(self._data, indent=2, ensure_ascii=False))
            self._logger.info("JSON output saved to %s", self._path)
        except Exception as e:
            self._logger.error("Error writing JSON output: %s", e)
        finally:
            release_shared_output_file(shared)
