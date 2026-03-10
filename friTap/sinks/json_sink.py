#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""JSON/JSONL output sink for friTap pipeline."""

from __future__ import annotations
import json
import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..schemas.canonical import KeylogCanonical, DataCanonical, MetaCanonical


class JsonSink:
    """Writes session data as a JSON file.

    Accumulates events and writes a complete JSON document on close.
    """

    def __init__(self, path: str) -> None:
        self._path = path
        self._file = None
        self._keylogs: list[dict] = []
        self._connections: list[dict] = []
        self._logger = logging.getLogger("friTap.sinks.json")

    def open(self) -> None:
        self._file = open(self._path, "w")

    def on_keylog(self, event: "KeylogCanonical") -> None:
        self._keylogs.append({
            "key_data": event.key_data,
            "protocol": event.protocol,
            "timestamp": event.timestamp,
        })

    def on_data(self, event: "DataCanonical") -> None:
        self._connections.append({
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
        pass

    def close(self) -> None:
        if self._file:
            json.dump({
                "key_extractions": self._keylogs,
                "connections": self._connections,
            }, self._file, indent=2)
            self._file.close()
            self._file = None


class JsonlSink:
    """Writes events as newline-delimited JSON (JSONL).

    Each event is written as a single JSON line immediately.
    """

    def __init__(self, path: str) -> None:
        self._path = path
        self._file = None
        self._logger = logging.getLogger("friTap.sinks.jsonl")

    def open(self) -> None:
        self._file = open(self._path, "a")

    def on_keylog(self, event: "KeylogCanonical") -> None:
        self._write_line({
            "type": "keylog",
            "key_data": event.key_data,
            "protocol": event.protocol,
            "timestamp": event.timestamp,
        })

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
            self._file.close()
            self._file = None
