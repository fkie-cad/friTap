#!/usr/bin/env python3

"""``-j -``: stream friTap events as JSON Lines on stdout (for scripts / AI agents).

Every line is one JSON object with a stable envelope::

    {"schema": "fritap.events/1", "type": "<kind>", "event": "<EventClass>",
     "timestamp": <epoch float>, "protocol": "<proto>", ...event fields...}

``type`` is a short snake_case kind (``keylog``, ``data``, ``session``,
``library``, ``console``, ``error``, ``detach``, ...); the stream is bracketed by
``stream_start`` / ``stream_end`` records. ``bytes`` fields (decrypted
plaintext in ``data`` records) are hex-encoded, as in the ``.jsonl`` file output.

Key material policy: ``keylog`` records carry the secret (``key_data`` /
``payload``) ONLY when explicitly requested with ``-k`` or ``--json-keys``.
Otherwise the record is kept (so consumers still learn that a key was seen) but
redacted to its label (and the public client_random for NSS lines), with
``"redacted": true``. The policy is shared with the file outputs, see
:mod:`friTap.output.key_material`.
"""

from __future__ import annotations

import functools
import json
import re
import threading
from typing import IO, TYPE_CHECKING, Optional

from .jsonl_handler import JsonlOutputHandler, is_internal_event
from .stdout_stream import (
    JSON_STREAM_STDOUT,
    envelope,
    final_exit_code,
    is_stream_closed,
    mark_stream_closed,
    mark_stream_opened,
    runtime_error_fields,
    stream_end_fields,
)

if TYPE_CHECKING:
    from ..events import EventBus, FriTapEvent


# Explicit names for the common kinds; anything else is derived from the class.
_TYPE_NAMES = {
    "KeylogEvent": "keylog",
    "DatalogEvent": "data",
    "SessionEvent": "session",
    "LibraryDetectedEvent": "library",
    "ErrorEvent": "error",
    "ConsoleEvent": "console",
    "DetachEvent": "detach",
}

_CAMEL_BOUNDARY = re.compile(r"(?<!^)(?=[A-Z])")


@functools.lru_cache(maxsize=None)
def event_type_name(class_name: str) -> str:
    """``SocketTraceEvent`` -> ``socket_trace`` (explicit names win).

    Cached: called once per streamed event, but the set of event classes is small.
    """
    if class_name in _TYPE_NAMES:
        return _TYPE_NAMES[class_name]
    stem = class_name[:-len("Event")] if class_name.endswith("Event") else class_name
    return _CAMEL_BOUNDARY.sub("_", stem).lower()


def _json_default(value):
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).hex()
    return repr(value)


class JsonlStdoutHandler(JsonlOutputHandler):
    """JSONL event stream on the (claimed) stdout; see the module docstring."""

    consumes_plaintext = True

    def __init__(self, include_key_material: bool = False,
                 stream: Optional[IO] = None) -> None:
        super().__init__(JSON_STREAM_STDOUT, include_key_material=include_key_material)
        self._stream = stream
        self._write_lock = threading.Lock()

    def setup(self, event_bus: "EventBus") -> None:
        from ..events import FriTapEvent
        from .stdout_stream import claim_stdout_for_json_stream
        self._file = self._stream or claim_stdout_for_json_stream()
        event_bus.subscribe(FriTapEvent, self._on_any_event)
        self._write_record(envelope("stream_start", {
            "key_material": self._include_key_material,
        }))
        if self._uses_claimed_stdout():
            mark_stream_opened()

    def _uses_claimed_stdout(self) -> bool:
        """True when this handler writes the process-wide claimed stdout stream
        (not a stream injected by a test), so it owns the envelope state."""
        return self._stream is None

    def _on_any_event(self, event: "FriTapEvent") -> None:
        if not self._file:
            return
        if is_internal_event(event):
            return
        class_name = type(event).__name__
        # _build_record already applied the key-material policy (redaction).
        record = self._build_record(event)
        # "event" carries the class name: the base record's "event_type" is
        # overwritten by SessionEvent's own event_type field ("started"/...).
        # setdefault: an event's own field of the same name still wins.
        record.setdefault("event", class_name)
        self._write_record(envelope(event_type_name(class_name), record))

    def _write_record(self, record: dict) -> None:
        line = json.dumps(record, ensure_ascii=False, default=_json_default) + "\n"
        with self._write_lock:
            if not self._file:
                return
            try:
                self._file.write(line)
                self._file.flush()
            except Exception as e:  # noqa: BLE001 - e.g. a closed pipe reader
                self._logger.error("JSONL stdout write error: %s", e)

    def close(self) -> None:
        """Write the closing records and flush; stdout stays open. Idempotent.

        The single place where a run's outcome reaches the stream: a failed run
        gets one ``error`` record (cause noted via
        :func:`~friTap.output.stdout_stream.note_runtime_error`), and
        ``stream_end`` carries the final ``exit_code`` (null when unknown) and,
        when known, ``ended_by`` (see :func:`~friTap.output.stdout_stream.ended_by`).
        """
        if not self._file:
            return
        if self._uses_claimed_stdout() and is_stream_closed():
            # The emergency writer already ended the stream (finish_unclosed_stream).
            with self._write_lock:
                self._file = None
            return
        exit_code = final_exit_code()
        error = runtime_error_fields(exit_code)
        if error is not None:
            self._write_record(envelope("error", error))
        self._write_record(envelope("stream_end", stream_end_fields(exit_code)))
        if self._uses_claimed_stdout():
            mark_stream_closed()
        with self._write_lock:
            self._file = None
