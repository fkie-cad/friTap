#!/usr/bin/env python3

"""Process-wide shared handles for capture output files (pcap, pcapng, json, jsonl).

On Windows the main SSL_Logger and the LSASS SSL_Logger use the SAME ``-p`` and
``--json`` paths; a second ``open(path, "w")`` would truncate the first session's
output and the two file offsets would overwrite each other.

One open handle is kept per normalized path (like
:mod:`friTap.output.shared_keylog_writer`):

* the first acquirer opens (truncates) the file and runs the optional *initializer*
  under the registry lock, so a format header (pcap global header, pcapng SHB+IDB) is
  written once before any record; its return value is :attr:`SharedOutputFile.state`;
* later acquirers share the handle and state;
* :meth:`SharedOutputFile.write` is atomic w.r.t. other acquirers;
* :func:`release_shared_output_file` flushes, drops a reference, closes on the last.

With a single acquirer the bytes match a private ``open()``.
"""

from __future__ import annotations

import threading
from typing import IO, Any, Callable, Dict, Optional, Tuple

from .shared_keylog_writer import normalize_keylog_path


class SharedOutputFile:
    """One open output file shared by every writer of the same path."""

    def __init__(self, path: str, file: IO) -> None:
        self.path = path
        self._file: Optional[IO] = file
        # Re-entrant: a writer may hold it to update ``state`` and rewrite.
        self.lock = threading.RLock()
        self.state: Any = None
        self._refcount = 0

    @property
    def refcount(self) -> int:
        return self._refcount

    @property
    def closed(self) -> bool:
        return self._file is None

    def write(self, data) -> bool:
        """Write *data* atomically w.r.t. other writers; ``False`` once closed. Raises ``OSError``."""
        with self.lock:
            if self._file is None:
                return False
            self._file.write(data)
            return True

    def flush(self) -> None:
        with self.lock:
            if self._file is not None:
                self._file.flush()

    def rewrite(self, data) -> bool:
        """Replace the whole file content with *data* (whole-document formats). Raises ``OSError``."""
        with self.lock:
            if self._file is None:
                return False
            self._file.seek(0)
            self._file.truncate()
            self._file.write(data)
            self._file.flush()
            return True

    def _close(self) -> None:
        with self.lock:
            if self._file is None:
                return
            try:
                self._file.close()
            except Exception:  # noqa: BLE001 - closing must never raise
                pass
            self._file = None


class SharedOutputFileHandle:
    """File-like view (``write``/``flush``/``close``) of a :class:`SharedOutputFile` owned by ONE acquirer.

    ``close()`` releases its reference exactly once.
    """

    def __init__(self, shared: SharedOutputFile) -> None:
        self._shared: Optional[SharedOutputFile] = shared
        self.name = shared.path

    @property
    def shared(self) -> Optional[SharedOutputFile]:
        return self._shared

    @property
    def closed(self) -> bool:
        return self._shared is None or self._shared.closed

    def write(self, data):
        if self._shared is None:
            raise ValueError("I/O operation on closed shared output file")
        self._shared.write(data)
        return len(data)

    def flush(self) -> None:
        if self._shared is not None:
            self._shared.flush()

    def close(self) -> None:
        shared, self._shared = self._shared, None
        if shared is not None:
            release_shared_output_file(shared)


_registry: Dict[str, SharedOutputFile] = {}
_registry_lock = threading.Lock()


def acquire_shared_output_file(
    path: str,
    mode: str = "wb",
    buffering: int = -1,
    initializer: Optional[Callable[[IO], Any]] = None,
) -> Tuple[SharedOutputFile, bool]:
    """Take a reference on the shared file for *path*; returns ``(shared, created)``.

    ``created`` means this call opened (truncated) the file and ran *initializer*
    (its result becomes ``shared.state``). *mode*/*buffering* apply to the first acquirer
    only. Raises ``OSError`` if it cannot open; a failing initializer closes the file and re-raises.
    """
    key = normalize_keylog_path(path)
    with _registry_lock:
        shared = _registry.get(key)
        created = shared is None
        if created:
            raw = open(path, mode) if buffering == -1 else open(path, mode, buffering)
            try:
                shared = SharedOutputFile(path, raw)
                if initializer is not None:
                    shared.state = initializer(raw)
            except BaseException:
                raw.close()
                raise
            _registry[key] = shared
        shared._refcount += 1
        return shared, created


def open_shared_output_file(path: str, mode: str = "wb", buffering: int = -1,
                            initializer: Optional[Callable[[IO], Any]] = None
                            ) -> Tuple[SharedOutputFileHandle, bool]:
    """:func:`acquire_shared_output_file`, wrapped in a per-acquirer file-like handle."""
    shared, created = acquire_shared_output_file(path, mode, buffering, initializer)
    return SharedOutputFileHandle(shared), created


def release_shared_output_file(shared: SharedOutputFile) -> bool:
    """Flush, drop one reference on *shared*, close on the last; returns True when it closed.

    Flushing on every release keeps a never-released writer (``os._exit``) from holding
    back the others' buffered records. Idempotent past zero; never raises.
    """
    with _registry_lock:
        if shared._refcount <= 0:
            return False
        shared._refcount -= 1
        try:
            shared.flush()
        except Exception:  # noqa: BLE001 - releasing must never raise
            pass
        if shared._refcount > 0:
            return False
        key = normalize_keylog_path(shared.path)
        if _registry.get(key) is shared:
            del _registry[key]
        shared._close()
        return True


def is_output_path_open(path: str) -> bool:
    """Whether any writer in this process still holds *path* open."""
    with _registry_lock:
        return normalize_keylog_path(path) in _registry
