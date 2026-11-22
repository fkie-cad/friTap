#!/usr/bin/env python3

"""``<pcap>.request_contexts.jsonl``: live request contexts for an offline .tap build.

A full capture (``-f -k``) has no live FlowCollector, so ``--attribute-sdk``
request contexts would be lost. This appender writes every
:class:`~friTap.events.RequestContextEvent` as one JSON object per line; the
offline pipeline replays them to attribute flows. ``timestamp`` is the host
receive time; the offline loader prefers the agent's ``t_ms`` (the device clock
the packets carry) and falls back to it.
"""

from __future__ import annotations

import dataclasses
import json
import logging
import os
import threading
from typing import IO, Iterator, Optional

from ..events import RequestContextEvent

REQUEST_CONTEXTS_SUFFIX = ".request_contexts.jsonl"
#: Largest sidecar :func:`read_request_context_rows` reads; a bigger one yields nothing.
REQUEST_CONTEXTS_MAX_BYTES = 64 * 1024 * 1024
#: Longest line it parses; longer lines are skipped.
REQUEST_CONTEXT_LINE_MAX_CHARS = 256 * 1024


def request_contexts_sidecar_path(pcap_path: str) -> str:
    return str(pcap_path) + REQUEST_CONTEXTS_SUFFIX


#: Public init fields, in declaration order (``_cancelled`` is bus state, not data).
_ROW_FIELDS = tuple(f.name for f in dataclasses.fields(RequestContextEvent)
                    if f.init and not f.name.startswith("_"))
_KNOWN_FIELDS = frozenset(_ROW_FIELDS)


def request_context_row(event: RequestContextEvent) -> dict:
    """The event's public dataclass fields."""
    # getattr instead of dataclasses.asdict: no per-event deep copy on the hot path.
    return {name: getattr(event, name) for name in _ROW_FIELDS}


def read_request_context_rows(path: str) -> Iterator[dict]:
    """Yield the sidecar's rows restricted to known event fields; unparseable or
    overlong lines are skipped, and a file over :data:`REQUEST_CONTEXTS_MAX_BYTES`
    yields nothing. Rows are untrusted and not type-checked here.
    Raises ``OSError`` when the file cannot be read."""
    if os.path.getsize(path) > REQUEST_CONTEXTS_MAX_BYTES:
        logging.getLogger(__name__).warning(
            "Ignoring request-context sidecar %s: over %d bytes", path, REQUEST_CONTEXTS_MAX_BYTES)
        return
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            if len(line) > REQUEST_CONTEXT_LINE_MAX_CHARS:
                continue
            try:
                row = json.loads(line)
            except ValueError:
                continue
            if isinstance(row, dict):
                yield {k: v for k, v in row.items() if k in _KNOWN_FIELDS}


class RequestContextSidecar:
    """Appends request-context events to a JSONL file. Never raises into the bus."""

    def __init__(self, path: str, logger: Optional[logging.Logger] = None):
        self._path = str(path)
        self._logger = logger or logging.getLogger(__name__)
        self._file: Optional[IO[str]] = None
        self._lock = threading.Lock()
        self._closed = False
        self._failed = False
        self.rows_written = 0

    @property
    def path(self) -> str:
        return self._path

    def attach(self, event_bus) -> None:
        event_bus.subscribe(RequestContextEvent, self.on_event)

    def on_event(self, event: RequestContextEvent) -> None:
        try:
            line = json.dumps(request_context_row(event), ensure_ascii=False) + "\n"
            with self._lock:
                if self._closed or self._failed:
                    return
                if self._file is None:
                    # Opened on the first event so a run without any leaves no file.
                    self._file = open(self._path, "w", encoding="utf-8")
                self._file.write(line)
                self._file.flush()
                self.rows_written += 1
        except Exception as exc:  # noqa: BLE001 - a bus subscriber must not raise
            self._fail(exc)

    def _fail(self, exc: Exception) -> None:
        if self._failed:
            return
        self._failed = True
        self._logger.warning("request-context sidecar %s disabled: %s", self._path, exc)

    def close(self) -> None:
        with self._lock:
            self._closed = True
            if self._file is None:
                return
            try:
                self._file.close()
            except Exception as exc:  # noqa: BLE001 - teardown must not raise
                self._logger.debug("request-context sidecar close failed: %s", exc)
            self._file = None
