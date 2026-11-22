#!/usr/bin/env python3

"""Process-wide shared writers for keylog files.

Several writers can target the SAME keylog path in one process (Windows full
capture: the main and LSASS SSL_Loggers both write ``-k``). Each opening it with
``"w"`` would truncate what the other wrote and interleave handles.

One open handle is kept per normalized path:

* the first acquirer truncates it (a new capture starts a fresh keylog); later ones share it;
* writes are line-atomic under a per-path lock and flushed per batch;
* :func:`release_keylog_writer` drops a reference and closes on the last; a later
  acquisition (e.g. a new TUI run in the same process) truncates again.
"""

from __future__ import annotations

import os
import threading
from typing import IO, Dict, Iterable, Optional, Set, Tuple

from .keylog_format import filter_safe_keylog_lines


def normalize_keylog_path(path: str) -> str:
    """Registry key for *path* (absolute, symlink-resolved, case-normalized)."""
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
        """Write *header* unless an identical one was written; True when written now. Raises ``OSError``."""
        with self._lock:
            if self._file is None or header in self._headers_written:
                return False
            self._headers_written.add(header)
            self._file.write(header + "\n")
            self._file.flush()
            return True

    def write_lines(self, lines: Iterable[str]) -> bool:
        """Write *lines* atomically w.r.t. other writers, then flush; ``False`` once closed. Raises ``OSError``.

        Lines that are not a single safe keylog line (control characters, non-``str``) are
        dropped: the last defense against agent-injected keylog lines.
        """
        safe_lines = filter_safe_keylog_lines(lines)
        with self._lock:
            if self._file is None:
                return False
            for line in safe_lines:
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
    """Take a reference on the shared writer for *path*; ``(writer, created)``, ``created`` when this call opened (truncated) the file. Raises ``OSError``."""
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
    """Drop one reference on *writer*, closing it on the last; True when this call closed it. Idempotent past zero."""
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
