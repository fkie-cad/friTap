#!/usr/bin/env python3

"""Process-wide shared writers for keylog files.

Several independent writers can target the SAME keylog path inside one Python
process. The canonical case is a Windows full capture: the main SSL_Logger and
the LSASS SSL_Logger (``hook_lsass`` in friTap.py) both write the ``-k`` file.
If each opened the path itself with ``"w"``, whichever received its first key
later would truncate everything the other already wrote, and two handles would
then interleave/overwrite each other.

This module keeps exactly one open handle per normalized path:

* the FIRST acquirer of a path truncates it (a new capture starts a fresh
  keylog, as before); every later acquirer shares the same handle;
* writes are line-atomic under a per-path lock and flushed after each batch;
* :func:`release_keylog_writer` drops a reference and the file is closed once
  the last reference is gone. A later acquisition (e.g. a new TUI capture run
  in the same process) truncates again.
"""

from __future__ import annotations

import os
import threading
from typing import IO, Dict, Iterable, Optional, Set, Tuple


def normalize_keylog_path(path: str) -> str:
    """Return the registry key for *path* (absolute, symlink-resolved, case-normalized)."""
    return os.path.normcase(os.path.realpath(os.path.abspath(path)))


class SharedKeylogWriter:
    """One open keylog file shared by every writer of the same path."""

    def __init__(self, path: str, file: IO) -> None:
        self.path = path
        self._file: Optional[IO] = file
        self._lock = threading.Lock()
        self._refcount = 0
        self._headers_written: Set[str] = set()

    @property
    def file(self) -> Optional[IO]:
        """The underlying handle, or ``None`` once the writer is closed."""
        return self._file

    @property
    def refcount(self) -> int:
        return self._refcount

    def write_header_once(self, header: str) -> bool:
        """Write *header* unless an identical header was already written.

        Returns ``True`` when it was written now. Raises ``OSError`` on I/O errors.
        """
        with self._lock:
            if self._file is None or header in self._headers_written:
                return False
            self._headers_written.add(header)
            self._file.write(header + "\n")
            self._file.flush()
            return True

    def write_lines(self, lines: Iterable[str]) -> bool:
        """Write *lines* atomically w.r.t. other writers, then flush.

        Returns ``False`` (writing nothing) when the file is already closed.
        Raises ``OSError`` on I/O errors.
        """
        with self._lock:
            if self._file is None:
                return False
            for line in lines:
                self._file.write(line + "\n")
            self._file.flush()
            return True

    def _close(self) -> None:
        with self._lock:
            if self._file is None:
                return
            try:
                self._file.close()
            except Exception:  # noqa: BLE001 - closing must never raise
                pass
            self._file = None


_registry: Dict[str, SharedKeylogWriter] = {}
_registry_lock = threading.Lock()


def acquire_keylog_writer(path: str) -> Tuple[SharedKeylogWriter, bool]:
    """Take a reference on the shared writer for *path*.

    Returns ``(writer, created)``: ``created`` is ``True`` when this call opened
    (and truncated) the file. Raises ``OSError`` when the file cannot be opened.
    """
    key = normalize_keylog_path(path)
    with _registry_lock:
        writer = _registry.get(key)
        created = writer is None
        if created:
            writer = SharedKeylogWriter(path, open(path, "w"))
            _registry[key] = writer
        writer._refcount += 1
        return writer, created


def release_keylog_writer(writer: SharedKeylogWriter) -> bool:
    """Drop one reference on *writer*; close it when the last one is gone.

    Returns ``True`` when this call closed the file. Idempotent past zero.
    """
    with _registry_lock:
        if writer._refcount <= 0:
            return False
        writer._refcount -= 1
        if writer._refcount > 0:
            return False
        key = normalize_keylog_path(writer.path)
        if _registry.get(key) is writer:
            del _registry[key]
        writer._close()
        return True


def is_keylog_path_open(path: str) -> bool:
    """Whether any writer in this process still holds *path* open."""
    with _registry_lock:
        return normalize_keylog_path(path) in _registry


def open_keylog_paths() -> list:
    """The paths (as first opened) that are currently held open."""
    with _registry_lock:
        return [writer.path for writer in _registry.values()]
