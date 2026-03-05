#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Streaming JSON Lines output handler for pipeline processing."""

from __future__ import annotations
import json
import logging
from typing import IO, Optional, TYPE_CHECKING

from .base import OutputHandler

if TYPE_CHECKING:
    from ..events import EventBus, FriTapEvent


class JsonlOutputHandler(OutputHandler):
    """Writes one JSON object per line for streaming pipelines."""

    def __init__(self, output_path: str) -> None:
        self._path = output_path
        self._file: Optional[IO] = None
        self._logger = logging.getLogger("friTap.output.jsonl")

    def setup(self, event_bus: "EventBus") -> None:
        from ..events import FriTapEvent
        self._file = open(self._path, "w")
        event_bus.subscribe(FriTapEvent, self._on_any_event)

    def _on_any_event(self, event: "FriTapEvent") -> None:
        if not self._file:
            return
        record = {
            "event_type": type(event).__name__,
            "timestamp": event.timestamp,
            "protocol": event.protocol,
        }
        # Add all dataclass fields except timestamp/protocol (already added)
        for key, value in event.__dict__.items():
            if key.startswith("_") or key in ("timestamp", "protocol"):
                continue
            if isinstance(value, bytes):
                record[key] = value.hex()
            else:
                record[key] = value
        try:
            self._file.write(json.dumps(record, ensure_ascii=False) + "\n")
            self._file.flush()
        except Exception as e:
            self._logger.error("JSONL write error: %s", e)

    def close(self) -> None:
        if self._file:
            try:
                self._file.close()
            except Exception:
                pass
            self._file = None
