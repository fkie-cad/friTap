"""Shared helpers for friTap's on-disk cache files.

Stdlib-only leaf (``platformdirs`` is optional): nothing from friTap is imported here.
"""

from __future__ import annotations

import contextlib
import os
import tempfile
import time
from typing import Iterator, Optional, Tuple, Union

PathLike = Union[str, "os.PathLike[str]"]

#: Mode for shared cache files: what the old ``open()`` writes produced under
#: the usual 022 umask, so a later non-root run can still read a sudo-written cache.
CACHE_FILE_MODE = 0o644
#: ``write_atomic`` keyword arguments for files under :func:`fritap_cache_dir`.
CACHE_WRITE_OPTIONS = {"mode": CACHE_FILE_MODE, "sudo_owner": True}

_LOCK_TIMEOUT_S = 2.0
_LOCK_POLL_S = 0.05


def fritap_cache_dir() -> str:
    """friTap's per-user cache directory (platformdirs, else ``~/.cache/friTap``)."""
    try:
        from platformdirs import user_cache_dir
        return user_cache_dir("friTap")
    except Exception:
        return os.path.join(os.path.expanduser("~"), ".cache", "friTap")


def write_atomic(path: PathLike, data: bytes, fsync: bool = True,
                 mode: Optional[int] = None, sudo_owner: bool = False) -> None:
    """Write *data* to *path* via a temp file in the same directory + rename.

    The file is 0600 (mkstemp) unless *mode* is given. With *sudo_owner*, a
    root-via-sudo write inside the invoking user's home (file and any dirs it
    creates) is handed back to that user. Readers see
    the old file or the new one, never a torn write. Raises OSError; the temp
    file is removed on any failure.
    """
    path = os.fspath(path)
    directory = os.path.dirname(os.path.abspath(path))
    if sudo_owner:
        _makedirs_for_sudo_user(directory)
    else:
        os.makedirs(directory, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(prefix=f".{os.path.basename(path)}.", suffix=".tmp", dir=directory)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            if fsync:
                handle.flush()
                os.fsync(handle.fileno())
            if mode is not None:
                os.chmod(tmp_path, mode)
            if sudo_owner:
                _chown_fd_to_sudo_user(handle.fileno(), directory)
        os.replace(tmp_path, path)
    except BaseException:
        _remove_quietly(tmp_path)
        raise


@contextlib.contextmanager
def cache_file_lock(path: PathLike, timeout: float = _LOCK_TIMEOUT_S) -> Iterator[bool]:
    """Best-effort exclusive lock on ``<path>.lock``; yields whether it is held.

    POSIX only (fcntl); elsewhere, or when the lock cannot be taken within
    *timeout*, the body runs unlocked: the atomic write still prevents torn files.
    """
    try:
        import fcntl
    except ImportError:
        yield False
        return
    lock_path = os.fspath(path) + ".lock"
    try:
        directory = os.path.dirname(os.path.abspath(lock_path))
        _makedirs_for_sudo_user(directory)
        fd = os.open(lock_path, os.O_RDWR | os.O_CREAT, CACHE_FILE_MODE)
    except OSError:
        yield False
        return
    try:
        _chown_fd_to_sudo_user(fd, directory)
        held = _acquire_flock(fcntl, fd, timeout)
        try:
            yield held
        finally:
            if held:
                fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)


def _acquire_flock(fcntl, fd: int, timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    while True:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return True
        except OSError:
            if time.monotonic() >= deadline:
                return False
            time.sleep(_LOCK_POLL_S)


def _sudo_owner_for(directory: str) -> Optional[Tuple[int, int, str]]:
    """``(uid, gid, home)`` when root-via-sudo writes inside the invoker's home."""
    if os.name != "posix" or os.geteuid() != 0:
        return None
    try:
        uid = int(os.environ["SUDO_UID"])
        gid = int(os.environ["SUDO_GID"])
        import pwd
        home = os.path.realpath(pwd.getpwuid(uid).pw_dir)
    except (KeyError, ValueError, ImportError):
        return None
    if uid == 0 or not _is_strictly_inside(os.path.realpath(directory), home):
        return None
    return uid, gid, home


def _is_strictly_inside(path: str, root: str) -> bool:
    return path != root and os.path.commonpath([path, root]) == root


def _makedirs_for_sudo_user(directory: str) -> None:
    owner = _sudo_owner_for(directory)
    missing = _missing_dirs(directory) if owner else []
    os.makedirs(directory, exist_ok=True)
    for created in missing:
        # Only dirs this call created, and never via a symlink: no chown of foreign paths.
        try:
            os.lchown(created, owner[0], owner[1])
        except OSError:
            pass


def _missing_dirs(directory: str) -> list:
    missing = []
    current = os.path.abspath(directory)
    while not os.path.exists(current):
        missing.append(current)
        parent = os.path.dirname(current)
        if parent == current:
            break
        current = parent
    return list(reversed(missing))


def _chown_fd_to_sudo_user(fd: int, directory: str) -> None:
    owner = _sudo_owner_for(directory)
    if owner is None:
        return
    try:
        os.fchown(fd, owner[0], owner[1])
    except OSError:
        pass


def _remove_quietly(path: str) -> None:
    try:
        os.unlink(path)
    except OSError:
        pass
