#!/usr/bin/env python3

"""JSON session output handler."""

from __future__ import annotations

import logging
import threading
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Optional

from .base import OutputHandler
from .key_material import apply_key_material_policy

if TYPE_CHECKING:
    from ..events import (
        DatalogEvent,
        ErrorEvent,
        EventBus,
        KeylogEvent,
        LibraryDetectedEvent,
        SessionEvent,
    )
    from .json_stream import JsonStreamWriter


# Top-level document order (unchanged schema). The high-volume arrays are
# streamed to the sidecar; the small ones (errors, libraries_detected) and the
# metadata stay in memory.
_DOCUMENT_ORDER = [
    "session_info",
    "ssl_sessions",
    "connections",
    "key_extractions",
    "errors",
    "libraries_detected",
    "statistics",
]
_STREAM_KEYS = ["ssl_sessions", "connections", "key_extractions"]


def _new_values(session_info: dict) -> dict:
    """In-memory (non-streamed) part of the document: metadata + small arrays."""
    return {
        "session_info": session_info,
        "errors": [],
        "libraries_detected": [],
        "statistics": {
            "total_sessions": 0,
            "total_connections": 0,
            "total_bytes_captured": 0,
        },
    }


class JsonOutputHandler(OutputHandler):
    """Streams session data to a crash-safe JSON document, bounded in memory.

    Events are appended to a ``<path>.events.jsonl`` sidecar (see
    :mod:`friTap.output.json_stream`); memory holds only counters and small
    metadata. The document is shared per path: the Windows LSASS session is
    configured with the same ``--json`` path, so both sessions fill ONE document
    and every release re-assembles the whole file, the last one completing it.
    An *auxiliary* session (LSASS) records its session_info under
    ``auxiliary_sessions`` so ``session_info`` stays the target session's. With a
    single session the file content is unchanged.

    ``key_extractions`` records carry raw key material (``key_data``) only when
    *include_key_material* is set (``-k`` or ``--json-keys``); otherwise they
    are redacted (see :mod:`friTap.output.key_material`).
    """

    # The JSON document is the primary machine-readable input (AI agents,
    # scripts) and serialises every data event, so -j alone turns the agent's
    # plaintext read/write hooks on.
    consumes_plaintext = True

    def __init__(self, json_path: str, session_info: Optional[dict] = None,
                 auxiliary: bool = False, include_key_material: bool = False) -> None:
        self._path = json_path
        self._include_key_material = include_key_material
        self._writer: Optional["JsonStreamWriter"] = None
        self._logger = logging.getLogger("friTap.output.json")
        self._session_info = session_info or {}
        self._auxiliary = auxiliary
        # Replaced by the shared writer's lock once set up.
        self._lock = threading.RLock()
        self._data: dict = _new_values({} if auxiliary else self._session_info)

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
        from .json_stream import acquire_json_stream_writer
        values = _new_values({} if self._auxiliary else self._session_info)
        try:
            self._writer, _created = acquire_json_stream_writer(
                self._path,
                lambda: (list(_DOCUMENT_ORDER), list(_STREAM_KEYS), values),
            )
        except OSError as e:
            self._logger.warning("Failed to open JSON output file '%s': %s", self._path, e)
            self._writer = None
            return
        self._lock = self._writer.lock
        with self._lock:
            self._data = self._writer.data
            if self._auxiliary:
                aux_list = self._data.get("auxiliary_sessions")
                if aux_list is None:
                    aux_list = []
                    self._writer.add_value_key("auxiliary_sessions", aux_list)
                aux_list.append(self._session_info)
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
        # key_data preserved (subject to the key-material policy applied below,
        # like every other key record): they are recovered protocol keys, not the generic
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
        elif event.protocol == "ipsec" and event.payload:
            # IPsec IKE/ESP SA key material is structured (no NSS key_data
            # line). Surface the whole payload so -j carries the SA; "payload"
            # is a KEY_MATERIAL_FIELD, so it is redacted unless -k/--json-keys.
            record["payload"] = dict(event.payload)
        if self._writer is None:
            return
        record = apply_key_material_policy(record, self._include_key_material)
        with self._lock:
            self._data["key_extractions"].append(record)

    def on_data(self, event: "DatalogEvent") -> None:
        if self._writer is None:
            return
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
        if self._writer is None:
            return
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
        if self._writer is None:
            return
        with self._lock:
            self._data["errors"].append({
                "timestamp": event.timestamp,
                "description": event.description,
                "error": event.error,
                "stack": event.stack,
            })

    def _on_library(self, event: "LibraryDetectedEvent") -> None:
        if self._writer is None:
            return
        lib_info = {"name": event.library, "path": event.path, "detected_at": event.timestamp}
        with self._lock:
            if lib_info not in self._data["libraries_detected"]:
                self._data["libraries_detected"].append(lib_info)

    def close(self) -> None:
        """Finalize and release the shared document. Idempotent.

        Safe to call from the normal teardown, an ``atexit`` hook and any
        target-death path; a second call is a no-op.
        """
        writer, self._writer = self._writer, None
        if writer is None:
            return
        from .json_stream import release_json_stream_writer
        try:
            with self._lock:
                self._session_info["end_time"] = datetime.now(timezone.utc).isoformat()
            self._logger.info("JSON output saved to %s", self._path)
        except Exception as e:
            self._logger.error("Error writing JSON output: %s", e)
        finally:
            # Every release re-assembles the whole document atomically, so the
            # file is valid JSON even if another session sharing it is never
            # released.
            release_json_stream_writer(writer)
