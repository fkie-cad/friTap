"""Keep the inputs that crashed or hung the decoder worker for later study.

Files land in ``<platformdirs user log dir>/decoder_crashes/`` (override with
``FRITAP_DECODER_QUARANTINE_DIR``), at most :data:`MAX_FILES` of them and at
most :data:`MAX_SAMPLE_BYTES` each. The bytes are attacker-controlled: they
are only written, never parsed, and the file name is built from
parent-side values alone.
"""

from __future__ import annotations

import hashlib
import os
import re
import time
from pathlib import Path

QUARANTINE_DIR_ENV = "FRITAP_DECODER_QUARANTINE_DIR"
MAX_FILES = 20
MAX_SAMPLE_BYTES = 16 * 1024 * 1024
SUFFIX = ".bin"

_UNSAFE_NAME_CHARS = re.compile(r"[^a-z0-9-]+")


def quarantine_dir() -> Path:
    """The directory crash samples go to (not created here)."""
    override = os.environ.get(QUARANTINE_DIR_ENV, "").strip()
    if override:
        return Path(override)
    import platformdirs
    return Path(platformdirs.user_log_dir("friTap", appauthor=False)) / "decoder_crashes"


def quarantine_input(data: bytes, encoding: str, reason: str) -> Path | None:
    """Write (the first 16 MiB of) *data*; return its path, or None on failure."""
    try:
        directory = quarantine_dir()
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        path = directory / _sample_name(data, encoding, reason)
        _write_private(path, bytes(data[:MAX_SAMPLE_BYTES]))
        _hand_to_sudo_user(directory, path)
        _prune(directory)
        return path
    except Exception:
        return None


def _sample_name(data: bytes, encoding: str, reason: str) -> str:
    """``<utc>_<reason>_<encoding>_<len>[t]_<sha256-prefix>.bin``."""
    now_ns = time.time_ns()
    stamp = time.strftime("%Y%m%dT%H%M%S", time.gmtime(now_ns // 1_000_000_000))
    stamp = f"{stamp}.{now_ns % 1_000_000_000:09d}Z"
    digest = hashlib.sha256(data).hexdigest()[:16]
    truncated = "t" if len(data) > MAX_SAMPLE_BYTES else ""
    return (f"{stamp}_{_name_token(reason)}_{_name_token(encoding)}_"
            f"{len(data)}{truncated}_{digest}{SUFFIX}")


def _name_token(text: str) -> str:
    """*text* reduced to ``[a-z0-9-]``, at most 24 characters."""
    return _UNSAFE_NAME_CHARS.sub("-", str(text).lower()).strip("-")[:24] or "none"


def _write_private(path: Path, data: bytes) -> None:
    """Create *path* exclusively with mode 0600 and write *data*."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(data)


def _hand_to_sudo_user(directory: Path, path: Path) -> None:
    """Under ``sudo``, chown the sample so the analyst can open it."""
    if not hasattr(os, "geteuid") or os.geteuid() != 0:
        return
    try:
        uid, gid = int(os.environ["SUDO_UID"]), int(os.environ["SUDO_GID"])
    except (KeyError, ValueError):
        return
    for target in (directory, path):
        try:
            os.chown(target, uid, gid)
        except OSError:
            pass


def _prune(directory: Path) -> None:
    """Delete the oldest samples beyond :data:`MAX_FILES`."""
    samples = sorted(directory.glob(f"*{SUFFIX}"), key=lambda p: p.stat().st_mtime)
    for stale in samples[:-MAX_FILES]:
        try:
            stale.unlink()
        except OSError:
            pass
