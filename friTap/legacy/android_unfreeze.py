"""Thaw Android processes frozen by the cached-apps freezer before teardown.

Android (12+) freezes cached app processes through the cgroup v2 freezer
(``/sys/fs/cgroup/uid_<uid>/pid_<pid>/cgroup.freeze``). A frozen process runs
no thread, so the agent cannot answer ``graceful_detach`` or ``script.unload()``
and Frida leaves its agent mapped until the process thaws. A launcher app such
as Gemini (``com.google.android.apps.bard``) hands off to another package and
goes to the background within seconds, so it is usually frozen at Ctrl+C.

Thawing needs root (``su``); without it the command fails and teardown goes on
as before. Writing ``cgroup.freeze`` directly also keeps ActivityManager from
re-freezing at once: it still believes the process is frozen.
"""

import logging
import subprocess
from typing import Callable, Iterable, Optional

from ..android import run_adb

logger = logging.getLogger("friTap")

# Bound for the single adb call; teardown must not wait on a hung adb.
UNFREEZE_TIMEOUT = 3.0

# cgroup v2 freezer files of one pid (Android 12+ layout, with and without the
# "apps" parent some vendors use). Unmatched globs stay literal; ``[ -e ]`` skips them.
_FREEZE_FILE_GLOBS = (
    "/sys/fs/cgroup/uid_*/pid_$p/cgroup.freeze",
    "/sys/fs/cgroup/apps/uid_*/pid_$p/cgroup.freeze",
)


def _valid_pids(pids: Iterable) -> list:
    """Distinct positive int pids in order; anything else is dropped (never reaches a shell)."""
    seen = []
    for pid in pids:
        if isinstance(pid, int) and not isinstance(pid, bool) and pid > 0 and pid not in seen:
            seen.append(pid)
    return seen


def build_unfreeze_command(pids: Iterable) -> Optional[str]:
    """The ``adb shell`` command that thaws *pids* as root, or None when there is no valid pid."""
    valid = _valid_pids(pids)
    if not valid:
        return None
    files = " ".join(_FREEZE_FILE_GLOBS)
    script = (f"for p in {' '.join(str(pid) for pid in valid)}; do "
              f"for f in {files}; do [ -e $f ] && echo 0 > $f; done; done; true")
    return f"su -c '{script}'"


def unfreeze_android_pids(serial: Optional[str], pids: Iterable,
                          timeout: float = UNFREEZE_TIMEOUT,
                          runner: Callable = run_adb) -> bool:
    """Best effort: thaw *pids* on the adb device *serial*; True when adb ran the command.

    Bounded by *timeout*; never raises (no adb, no root, device gone)."""
    command = build_unfreeze_command(pids)
    if command is None:
        return False
    base = ["adb", "-s", serial] if serial else ["adb"]
    try:
        result = runner([*base, "shell", command], capture_output=True, text=True,
                        timeout=timeout, check=False)
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        logger.debug("unfreeze of pids %s failed: %s", _valid_pids(pids), exc)
        return False
    ok = getattr(result, "returncode", 1) == 0
    logger.debug("unfreeze of pids %s: %s", _valid_pids(pids),
                 "done" if ok else f"failed ({(getattr(result, 'stderr', '') or '').strip()[:200]})")
    return ok
