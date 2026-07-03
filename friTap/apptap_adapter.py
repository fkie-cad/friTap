"""Adapter exposing friTap's ADB transport as an ``apptap.Executor``.

This lets friTap delegate UID-scoped packet capture to the standalone **AppTap**
library (``--owner-capture``) while reusing friTap's own, battle-tested adb/root
plumbing (``RootADB``/``SuADB``/``MagiskADB``) instead of duplicating it.

AppTap is an *optional* dependency: if it isn't installed, :func:`apptap_available`
returns False and callers fall back to the legacy whole-device tcpdump capture.
"""

from __future__ import annotations

import logging
import shlex
from typing import Optional

logger = logging.getLogger("friTap")


def apptap_available() -> bool:
    """True when the AppTap library can be imported."""
    try:
        import apptap  # noqa: F401

        return True
    except Exception:
        return False


class FritapAdbExecutor:
    """Wrap a friTap ``ADB`` object so AppTap can drive it as an ``Executor``.

    Mirrors the ``apptap.Executor`` Protocol (``run``/``shell``/``push_file``/
    ``pull_file``/``is_rooted``/``platform``). Shell args are quoted per-arg so a
    tcpdump BPF (or any arg with spaces/parentheses) survives the *device* shell
    intact, then passed to friTap's ``ADB.shell`` as a single command string.
    """

    def __init__(self, adb) -> None:
        self._adb = adb

    @property
    def platform(self) -> str:
        return "android"

    @property
    def is_rooted(self) -> bool:
        try:
            return bool(self._adb.is_rooted)
        except Exception:
            return False

    def _conv(self, cp):
        """Convert a friTap ``subprocess.CompletedProcess`` to ``apptap.CmdResult``."""
        from apptap.executors.base import CmdResult

        return CmdResult(
            getattr(cp, "returncode", 1),
            getattr(cp, "stdout", "") or "",
            getattr(cp, "stderr", "") or "",
        )

    def run(self, *args, timeout: Optional[float] = None):
        cp = self._adb.run(*args, timeout=timeout) if timeout is not None else self._adb.run(*args)
        return self._conv(cp)

    def shell(self, *args, background: bool = False, timeout: Optional[float] = None):
        cmd = " ".join(shlex.quote(a) for a in args)
        if background:
            return self._adb.shell(cmd, background=True)
        cp = self._adb.shell(cmd, timeout=timeout) if timeout is not None else self._adb.shell(cmd)
        return self._conv(cp)

    def push_file(self, local: str, remote: str):
        return self._conv(self._adb.run("push", local, remote))

    def pull_file(self, remote: str, local: str):
        return self._conv(self._adb.run("pull", remote, local))
