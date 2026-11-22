#!/usr/bin/env python3

"""Memory-bounded, crash-safe assembly of friTap's JSON session documents.

Memory-bounded, crash-safe assembly of friTap's JSON session documents.

Used by :class:`friTap.output.json_handler.JsonOutputHandler`,
:class:`friTap.sinks.json_sink.JsonSink` and the legacy message handler.

:class:`JsonStreamWriter` guarantees:

* Never 0 bytes: a valid skeleton is written atomically (temp file + :func:`os.replace`) on creation.
* Bounded memory: high-volume arrays stream to a sidecar ``<path>.events.jsonl``.
* Crash-safe: after ``SIGKILL`` the skeleton plus sidecar survive; :func:`recover_json_output` reassembles them.
* Byte-identical to ``json.dumps(doc, indent=2, ensure_ascii=False)`` of the in-memory document.

A ref-counted registry (like :mod:`friTap.output.shared_output_file`) lets the
Windows LSASS helper and the target session share ONE document for a ``--json`` path.
"""

from __future__ import annotations

import json
import logging
import os
import threading
from typing import Any, Callable, Dict, Iterator, List, Tuple

from .shared_keylog_writer import normalize_keylog_path

_logger = logging.getLogger("friTap.output.json_stream")

SIDECAR_SUFFIX = ".events.jsonl"
_TMP_SUFFIX = ".tmp"


def _coerce(value: Any) -> Any:
    """``default=`` for :func:`json.dumps`: a hostile process may hand us raw ``bytes``; decode with ``replace`` to keep the line valid."""
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).decode("utf-8", "replace")
    return repr(value)


def _reindent(blob: str, spaces: int) -> str:
    """Indent *blob*'s continuation lines so it embeds at a deeper column, byte-identical to ``json.dumps`` in place."""
    pad = " " * spaces
    lines = blob.split("\n")
    if len(lines) == 1:
        return blob
    return "\n".join([lines[0]] + [pad + line for line in lines[1:]])


def _dump_value(value: Any) -> str:
    """Serialise a non-streamed top-level value (indent 2)."""
    return _reindent(json.dumps(value, indent=2, ensure_ascii=False, default=_coerce), 2)


def _dump_element(element: Any) -> str:
    """Serialise one streamed-array element (indent 4)."""
    blob = json.dumps(element, indent=2, ensure_ascii=False, default=_coerce)
    return "    " + _reindent(blob, 4)


class StreamedList:
    """List-like facade (``append``, ``len``, iteration, indexing) whose events live in the sidecar.

    Only a count is held in memory; iteration and indexing re-read the sidecar, so keep them off hot paths.
    """

    def __init__(self, writer: "JsonStreamWriter", key: str) -> None:
        self._writer = writer
        self._key = key
        self._count = 0

    def append(self, obj: Any) -> None:
        self._writer._append(self._key, obj)
        self._count += 1

    def __len__(self) -> int:
        return self._count

    def __iter__(self) -> Iterator[Any]:
        return self._writer._iter_events(self._key)

    def __getitem__(self, index: int) -> Any:
        return list(self)[index]

    def __repr__(self) -> str:  # pragma: no cover - debug aid
        return f"StreamedList(key={self._key!r}, count={self._count})"


class JsonStreamWriter:
    """One memory-bounded, crash-safe JSON document shared by path.

    *order* is the top-level key order; *stream_keys* become sidecar-backed
    :class:`StreamedList`\\ s, the rest stay in :attr:`data` as small metadata.
    :meth:`assemble` builds the final document without loading every event.
    """

    def __init__(self, path: str, order: List[str], stream_keys: List[str],
                 values: Dict[str, Any]) -> None:
        self.path = path
        self.sidecar_path = path + SIDECAR_SUFFIX
        self._order: List[str] = list(order)
        self._stream_keys = set(stream_keys)
        self.lock = threading.RLock()
        self._refcount = 0
        self._closed = False
        self.data: Dict[str, Any] = {}
        for key in self._order:
            if key in self._stream_keys:
                self.data[key] = StreamedList(self, key)
            else:
                self.data[key] = values.get(key)
        # Truncate the sidecar first, then lay down the skeleton so the target is never 0 bytes.
        self._sidecar = open(self.sidecar_path, "w", encoding="utf-8")
        self.assemble()

    @property
    def refcount(self) -> int:
        return self._refcount

    def add_value_key(self, key: str, value: Any) -> None:
        """Append a late metadata key (e.g. ``auxiliary_sessions``) to the order."""
        with self.lock:
            if key not in self.data:
                self._order.append(key)
            self.data[key] = value

    def _append(self, key: str, obj: Any) -> None:
        """Write one streamed event as a flushed JSONL line. Never raises."""
        with self.lock:
            if self._sidecar is None:
                return
            try:
                self._sidecar.write(
                    json.dumps({"k": key, "v": obj}, ensure_ascii=False,
                               default=_coerce) + "\n")
                self._sidecar.flush()
            except OSError as exc:
                _logger.warning("Failed to append JSON event to %s: %s",
                                self.sidecar_path, exc)

    def _iter_events(self, key: str) -> Iterator[Any]:
        """Yield the streamed events for *key* by re-reading the sidecar."""
        with self.lock:
            if self._sidecar is not None:
                try:
                    self._sidecar.flush()
                except OSError:
                    pass
        try:
            with open(self.sidecar_path, "r", encoding="utf-8") as handle:
                for line in handle:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        record = json.loads(line)
                    except ValueError:
                        continue
                    if record.get("k") == key:
                        yield record.get("v")
        except OSError:
            return

    def assemble(self) -> bool:
        """Write the full document to :attr:`path` atomically; idempotent (every handler close calls it). True on success."""
        with self.lock:
            if self._sidecar is not None:
                try:
                    self._sidecar.flush()
                except OSError:
                    pass
            try:
                _stream_document(self.path, self._order, self._stream_keys,
                                 self.data, self.sidecar_path)
                return True
            except OSError as exc:
                _logger.error("Failed to assemble JSON document %s: %s",
                              self.path, exc)
                return False

    def close(self, *, delete_sidecar: bool = True) -> None:
        """Assemble, close the sidecar handle and (optionally) delete it. Idempotent."""
        with self.lock:
            if self._closed:
                return
            self._closed = True
            self.assemble()
            if self._sidecar is not None:
                try:
                    self._sidecar.close()
                except OSError:
                    pass
                self._sidecar = None
            if delete_sidecar:
                try:
                    os.remove(self.sidecar_path)
                except OSError:
                    pass


def _stream_document(path: str, order: List[str], stream_keys, values: Dict[str, Any],
                     sidecar_path: str) -> None:
    """Assemble into ``<path>.tmp`` then :func:`os.replace`, streaming sidecar lines so no array is held in memory."""
    tmp_path = path + _TMP_SUFFIX
    with open(tmp_path, "w", encoding="utf-8") as out:
        out.write("{\n")
        for index, key in enumerate(order):
            if index:
                out.write(",\n")
            out.write("  " + json.dumps(key, ensure_ascii=False) + ": ")
            if key in stream_keys:
                _write_stream_array(out, key, sidecar_path)
            else:
                out.write(_dump_value(values.get(key)))
        out.write("\n}")
        out.flush()
        try:
            os.fsync(out.fileno())
        except (OSError, ValueError, TypeError):
            # Best-effort: pipes and test doubles have no real descriptor.
            pass
    os.replace(tmp_path, path)


def _write_stream_array(out, key: str, sidecar_path: str) -> None:
    """Write a streamed array by scanning the sidecar for *key*'s events."""
    first = True
    try:
        handle = open(sidecar_path, "r", encoding="utf-8")
    except OSError:
        out.write("[]")
        return
    with handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except ValueError:
                continue
            if record.get("k") != key:
                continue
            if first:
                out.write("[\n")
                first = False
            else:
                out.write(",\n")
            out.write(_dump_element(record.get("v")))
    if first:
        out.write("[]")
    else:
        out.write("\n  ]")


def recover_json_output(path: str) -> bool:
    """Rebuild a crashed run's document in place from its sidecar, then remove it.

    Streamed arrays are the keys found in the sidecar. Returns ``True`` when
    a sidecar was assembled, ``False`` (harmlessly) when nothing needs recovering.
    """
    sidecar_path = path + SIDECAR_SUFFIX
    if not os.path.isfile(sidecar_path) or os.path.getsize(sidecar_path) == 0:
        return False
    try:
        with open(path, "r", encoding="utf-8") as handle:
            skeleton = json.load(handle)
    except (OSError, ValueError):
        skeleton = {}
    if not isinstance(skeleton, dict):
        skeleton = {}
    # Stream keys are those in the sidecar; sidecar-only keys go after the skeleton's order.
    stream_keys: List[str] = []
    try:
        with open(sidecar_path, "r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except ValueError:
                    continue
                key = record.get("k")
                if key is not None and key not in stream_keys:
                    stream_keys.append(key)
    except OSError:
        return False
    order = list(skeleton.keys())
    for key in stream_keys:
        if key not in order:
            order.append(key)
    try:
        _stream_document(path, order, set(stream_keys), skeleton, sidecar_path)
    except OSError as exc:
        _logger.error("Failed to recover JSON document %s: %s", path, exc)
        return False
    try:
        os.remove(sidecar_path)
    except OSError:
        pass
    return True


# Process-wide ref-counted registry (shared --json path: target + LSASS helper).
_registry: Dict[str, JsonStreamWriter] = {}
_registry_lock = threading.Lock()


def acquire_json_stream_writer(
    path: str,
    layout_factory: Callable[[], Tuple[List[str], List[str], Dict[str, Any]]],
) -> Tuple[JsonStreamWriter, bool]:
    """Take a reference on the shared writer for *path*; returns ``(writer, created)``.

    The first acquirer builds it from ``layout_factory() -> (order, stream_keys,
    values)``, after rescuing a crashed run's sidecar to ``<path>.recovered.json``.
    Raises ``OSError`` if the skeleton cannot be written.
    """
    key = normalize_keylog_path(path)
    with _registry_lock:
        writer = _registry.get(key)
        created = writer is None
        if created:
            _rescue_stale_sidecar(path)
            order, stream_keys, values = layout_factory()
            writer = JsonStreamWriter(path, order, stream_keys, values)
            _registry[key] = writer
        writer._refcount += 1
        return writer, created


def release_json_stream_writer(writer: JsonStreamWriter) -> bool:
    """Assemble and drop one reference; the last one closes and deletes the sidecar.

    Assembling on every release keeps the file complete if a co-writer is never released.
    Idempotent past zero; never raises.
    """
    with _registry_lock:
        if writer._refcount <= 0:
            return False
        writer._refcount -= 1
        last = writer._refcount <= 0
        if last:
            key = normalize_keylog_path(writer.path)
            if _registry.get(key) is writer:
                del _registry[key]
    if last:
        writer.close(delete_sidecar=True)
        return True
    writer.assemble()
    return False


def is_json_stream_open(path: str) -> bool:
    """Whether a writer in this process still holds *path* open."""
    with _registry_lock:
        return normalize_keylog_path(path) in _registry


def _rescue_stale_sidecar(path: str) -> None:
    """Best effort: recover a leftover sidecar into ``<path>.recovered.json`` before the new skeleton overwrites *path*."""
    sidecar_path = path + SIDECAR_SUFFIX
    if not os.path.isfile(sidecar_path) or os.path.getsize(sidecar_path) == 0:
        return
    try:
        if recover_json_output(path):
            recovered = path + ".recovered.json"
            os.replace(path, recovered)
            _logger.warning(
                "Recovered a previous crashed JSON session to %s", recovered)
    except OSError:
        pass
