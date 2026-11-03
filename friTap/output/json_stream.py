#!/usr/bin/env python3

"""Memory-bounded, crash-safe assembly of friTap's JSON session documents.

The three JSON writers (:class:`friTap.output.json_handler.JsonOutputHandler`,
:class:`friTap.sinks.json_sink.JsonSink` and the legacy
:func:`friTap.legacy.message_handler.handle_message_legacy` path) used to keep
every connection / session / key event in memory until close and serialise the
whole document in one shot. In a long run memory grew without bound, and a
crash before close left a 0-byte or half-written file.

:class:`JsonStreamWriter` fixes both:

* **Never 0 bytes.** On creation it writes a *valid* skeleton document
  atomically (temp file + :func:`os.replace`), so the target path always holds
  parseable JSON even moments after the run starts.
* **Bounded memory.** High-volume arrays are *streamed* to a sidecar
  ``<path>.events.jsonl`` (one flushed JSON object per line). Memory holds only
  counters and small metadata, never the events themselves.
* **Crash-safe.** If the process is ``SIGKILL``-ed, the skeleton plus the
  sidecar survive on disk; :func:`recover_json_output` reassembles them.
* **Byte-identical output.** :meth:`JsonStreamWriter.assemble` streams the
  final document so its bytes match exactly what
  ``json.dumps(doc, indent=2, ensure_ascii=False)`` of the equivalent in-memory
  document would have produced, so downstream consumers see no schema change.

A process-wide, ref-counted registry (mirroring
:mod:`friTap.output.shared_output_file`) lets the Windows LSASS helper session
and the target session share ONE document/sidecar for the same ``--json`` path.
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
    """``default=`` for :func:`json.dumps` so non-UTF-8 bytes never break it.

    Events normally carry only JSON-native values, but a hostile process could
    hand us raw ``bytes``; decoding with ``errors="replace"`` keeps the sidecar
    line valid JSON instead of raising ``TypeError``.
    """
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).decode("utf-8", "replace")
    return repr(value)


def _reindent(blob: str, spaces: int) -> str:
    """Prefix every line of *blob* after the first with *spaces* spaces.

    :func:`json.dumps` with ``indent`` lays a value out from column 0; this
    shifts its continuation lines so it can be embedded at a deeper column while
    staying byte-identical to what ``json.dumps`` would emit in place.
    """
    pad = " " * spaces
    lines = blob.split("\n")
    if len(lines) == 1:
        return blob
    return "\n".join([lines[0]] + [pad + line for line in lines[1:]])


def _dump_value(value: Any) -> str:
    """Serialise a non-streamed top-level value at base indent 2."""
    return _reindent(json.dumps(value, indent=2, ensure_ascii=False, default=_coerce), 2)


def _dump_element(element: Any) -> str:
    """Serialise one streamed-array element at base indent 4 (array depth)."""
    blob = json.dumps(element, indent=2, ensure_ascii=False, default=_coerce)
    return "    " + _reindent(blob, 4)


class StreamedList:
    """List-like facade whose appends flow to the writer's sidecar.

    Supports the subset of ``list`` the JSON writers rely on (``append``,
    ``len``, iteration, indexing) while holding only a count in memory. Iteration
    and indexing read the events back from the sidecar, so they stay correct but
    are not meant for hot paths.
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

    *order* is the top-level key order of the document. Keys in *stream_keys*
    become :class:`StreamedList` instances backed by the sidecar; the rest are
    kept in :attr:`data` as ordinary (small) metadata and serialised on
    assembly. Callers mutate :attr:`data` in place and append to its streamed
    lists; :meth:`assemble` turns the skeleton plus the sidecar into the final
    document without loading every event into memory.
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
        # Open the sidecar first (truncating any stale one), then lay down a
        # valid skeleton atomically so the target is never 0 bytes.
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

    # -- event ingestion ---------------------------------------------------

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

    # -- document assembly -------------------------------------------------

    def assemble(self) -> bool:
        """Write the current full document to :attr:`path` atomically.

        Idempotent and safe to call repeatedly (every handler close calls it, so
        the file is complete even if another session sharing the path is never
        released). Returns ``True`` on success.
        """
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
    """Assemble the document into ``<path>.tmp`` then :func:`os.replace` it.

    Streams each sidecar line into its array so no array is ever fully held in
    memory, and reproduces ``json.dumps(..., indent=2, ensure_ascii=False)``
    byte-for-byte.
    """
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
            # Best-effort durability; some file objects (pipes, test doubles)
            # have no real descriptor.
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
    """Reassemble a crashed run's document from its leftover sidecar.

    The skeleton at *path* is valid JSON written at start; the sidecar holds the
    events a crash never got to assemble. This rebuilds the full document in
    place (the streamed arrays are whatever keys appear in the sidecar) and then
    removes the sidecar. Returns ``True`` when a sidecar was found and assembled.

    Safe to call when nothing needs recovering (returns ``False``).
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
    # Stream keys = keys present in the sidecar; keep the skeleton's order and
    # append any sidecar-only keys at the end.
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


# ---------------------------------------------------------------------------
# Process-wide ref-counted registry (shared --json path: target + LSASS helper)
# ---------------------------------------------------------------------------

_registry: Dict[str, JsonStreamWriter] = {}
_registry_lock = threading.Lock()


def acquire_json_stream_writer(
    path: str,
    layout_factory: Callable[[], Tuple[List[str], List[str], Dict[str, Any]]],
) -> Tuple[JsonStreamWriter, bool]:
    """Take a reference on the shared :class:`JsonStreamWriter` for *path*.

    The FIRST acquirer builds the writer from ``layout_factory() -> (order,
    stream_keys, values)`` (which also writes the skeleton); later acquirers
    share it. If a leftover sidecar from a crashed previous run exists, it is
    rescued to ``<path>.recovered.json`` before the fresh run truncates it.
    Returns ``(writer, created)``. Raises ``OSError`` if the skeleton cannot be
    written.
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
    """Assemble, drop one reference, and on the last one close + delete the sidecar.

    Assembling on every release keeps the file complete even if a co-writer
    (LSASS helper) is never released. Idempotent past zero; never raises.
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
    """Whether any writer in this process still holds *path*'s document open."""
    with _registry_lock:
        return normalize_keylog_path(path) in _registry


def _rescue_stale_sidecar(path: str) -> None:
    """Preserve a crashed previous run before a new run reuses *path*.

    Best effort: if a leftover sidecar exists, recover it into
    ``<path>.recovered.json`` so its data is not lost when the fresh skeleton
    overwrites the target.
    """
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
