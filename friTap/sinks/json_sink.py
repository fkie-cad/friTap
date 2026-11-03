#!/usr/bin/env python3

"""JSON/JSONL output sink for friTap pipeline."""

from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING

from ..output.key_material import apply_key_material_policy

if TYPE_CHECKING:
    from ..schemas.canonical import DataCanonical, KeylogCanonical, MetaCanonical


class JsonSink:
    """Writes session data as a JSON file.

    Streams events to a ``<path>.events.jsonl`` sidecar (see
    :mod:`friTap.output.json_stream`) so memory stays bounded and a crash leaves
    a recoverable skeleton + sidecar rather than a 0-byte file. The output
    document schema (``key_extractions`` / ``connections``) is unchanged.
    Key records carry ``key_data`` only with *include_key_material* (``-k`` /
    ``--json-keys``), else they are redacted (:mod:`friTap.output.key_material`).
    """

    _ORDER = ["key_extractions", "connections"]
    _STREAM_KEYS = ["key_extractions", "connections"]

    def __init__(self, path: str, include_key_material: bool = False) -> None:
        self._path = path
        self._include_key_material = include_key_material
        self._writer = None
        self._logger = logging.getLogger("friTap.sinks.json")

    def open(self) -> None:
        from ..output.json_stream import JsonStreamWriter
        self._writer = JsonStreamWriter(
            self._path, list(self._ORDER), list(self._STREAM_KEYS), {})

    def on_keylog(self, event: "KeylogCanonical") -> None:
        if self._writer is None:
            return
        self._writer.data["key_extractions"].append(apply_key_material_policy({
            "key_data": event.key_data,
            "protocol": event.protocol,
            "timestamp": event.timestamp,
        }, self._include_key_material))

    def on_data(self, event: "DataCanonical") -> None:
        if self._writer is None:
            return
        self._writer.data["connections"].append({
            "direction": event.direction.value,
            "src": f"{event.src.addr}:{event.src.port}",
            "dst": f"{event.dst.addr}:{event.dst.port}",
            "protocol": event.protocol,
            "bytes": len(event.data),
            "timestamp": event.timestamp,
        })

    def on_meta(self, event: "MetaCanonical") -> None:
        pass

    def flush(self) -> None:
        if self._writer is not None:
            self._writer.assemble()

    def close(self) -> None:
        if self._writer is not None:
            self._writer.close()
            self._writer = None


class JsonlSink:
    """Writes events as newline-delimited JSON (JSONL).

    Each event is written as a single JSON line immediately. Key lines carry
    ``key_data`` only with *include_key_material* (``-k`` / ``--json-keys``).
    """

    def __init__(self, path: str, include_key_material: bool = False) -> None:
        self._path = path
        self._include_key_material = include_key_material
        self._file = None
        self._logger = logging.getLogger("friTap.sinks.jsonl")

    def open(self) -> None:
        self._file = open(self._path, "a")

    def on_keylog(self, event: "KeylogCanonical") -> None:
        self._write_line(apply_key_material_policy({
            "type": "keylog",
            "key_data": event.key_data,
            "protocol": event.protocol,
            "timestamp": event.timestamp,
        }, self._include_key_material))

    def on_data(self, event: "DataCanonical") -> None:
        self._write_line({
            "type": "data",
            "direction": event.direction.value,
            "src": f"{event.src.addr}:{event.src.port}",
            "dst": f"{event.dst.addr}:{event.dst.port}",
            "protocol": event.protocol,
            "bytes": len(event.data),
            "timestamp": event.timestamp,
        })

    def on_meta(self, event: "MetaCanonical") -> None:
        self._write_line({
            "type": "meta",
            "event_type": event.event_type,
            "message": event.message,
            "level": event.level,
            "timestamp": event.timestamp,
        })

    def _write_line(self, obj: dict) -> None:
        if self._file:
            self._file.write(json.dumps(obj) + "\n")

    def flush(self) -> None:
        if self._file:
            self._file.flush()

    def close(self) -> None:
        if self._file:
            self.flush()
            self._file.close()
            self._file = None
