"""Best-effort self-restriction of the decoder worker process.

Stdlib-only: loaded by path inside the worker, never imported by friTap code
paths that run in the parent. Every step is best effort and reports what it
achieved; a step that is unavailable on the current OS is skipped quietly.

What each OS gets (in this order):

* all POSIX: inherited fds closed except the worker pipe, stdin/stdout to
  ``/dev/null``; privileges dropped when running as root (``SUDO_UID`` /
  ``SUDO_GID``, else ``nobody``); ``RLIMIT_CORE=0``, small ``RLIMIT_NOFILE``,
  ``RLIMIT_NPROC=0`` (no new processes) and ``RLIMIT_FSIZE=0`` (no file
  writes) where the platform accepts them; ``nice(10)``.
* Linux: additionally ``RLIMIT_AS`` (2 GiB), a private empty network
  namespace when started as root (``unshare(CLONE_NEWNET)``),
  ``PR_SET_NO_NEW_PRIVS`` and ``PR_SET_PDEATHSIG(SIGKILL)``.
* macOS: additionally the ``pure-computation`` sandbox profile
  (``sandbox_init``): no file system, network or process creation. macOS
  does not enforce ``RLIMIT_AS``, so it is not set there.
* Windows: process separation only (nothing below applies).
"""

from __future__ import annotations

import os
import signal
import stat
import sys

# Imported up front: after the privilege drop or the macOS sandbox, the worker
# may no longer be able to read module files.
try:
    import ctypes
except ImportError:
    ctypes = None

try:
    import pwd
    import resource
except ImportError:  # Windows
    pwd = resource = None

ADDRESS_SPACE_LIMIT = 2 << 30
OPEN_FILES_LIMIT = 64
NICE_INCREMENT = 10

_CLONE_NEWNET = 0x40000000
_PR_SET_PDEATHSIG = 1
_PR_SET_NO_NEW_PRIVS = 38
_SANDBOX_NAMED = 0x0001


def harden_worker(keep_fds: tuple[int, ...]) -> list[str]:
    """Apply every hardening step; return the names of the steps that took effect."""
    if os.name != "posix":
        return ["process-separation-only"]
    report: list[str] = []
    for step in (lambda: _close_inherited_fds(keep_fds), _redirect_stdio,
                 _unshare_network, _set_no_new_privs, _drop_privileges,
                 _set_parent_death_signal, _apply_rlimits, _lower_priority,
                 _enter_macos_sandbox):
        report.extend(_run_step(step))
    return report


def _run_step(step) -> list[str]:
    """Run one hardening step; a failure skips it rather than aborting."""
    try:
        return step() or []
    except Exception:
        return []


def _close_inherited_fds(keep_fds: tuple[int, ...]) -> list[str]:
    """Close every fd >= 3 except *keep_fds* (spawn already closes most)."""
    max_fd = _max_fd()
    start = 3
    for fd in sorted(set(fd for fd in keep_fds if fd >= 3)):
        os.closerange(start, fd)
        start = fd + 1
    os.closerange(start, max_fd)
    return ["close-fds"]


def _max_fd() -> int:
    """Upper bound for fd closing, capped so the loop stays cheap."""
    try:
        soft = os.sysconf("SC_OPEN_MAX")
    except (ValueError, OSError):
        soft = 1024
    return max(256, min(int(soft), 65536))


def _redirect_stdio() -> list[str]:
    """Point stdin/stdout at ``/dev/null``; stderr too if it is a regular file.

    The worker talks only over its pipe. A regular-file stderr would also
    trip ``RLIMIT_FSIZE=0`` on the first traceback.
    """
    devnull = os.open(os.devnull, os.O_RDWR)
    targets = [0, 1]
    try:
        if stat.S_ISREG(os.fstat(2).st_mode):
            targets.append(2)
    except OSError:
        pass
    for fd in targets:
        os.dup2(devnull, fd)
    os.close(devnull)
    return ["stdio-devnull"]


def _libc():
    """The C library via ctypes (raises when ctypes is unavailable)."""
    return ctypes.CDLL(None, use_errno=True)


def _unshare_network() -> list[str]:
    """Linux + root: move into a fresh network namespace (no interfaces up)."""
    if not sys.platform.startswith("linux") or os.geteuid() != 0:
        return []
    if hasattr(os, "unshare"):
        os.unshare(_CLONE_NEWNET)
    elif _libc().unshare(_CLONE_NEWNET) != 0:
        return []
    return ["netns"]


def _set_no_new_privs() -> list[str]:
    """Linux: forbid gaining privileges through setuid binaries or file caps."""
    if not sys.platform.startswith("linux"):
        return []
    if _libc().prctl(_PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
        return []
    return ["no-new-privs"]


def _drop_privileges() -> list[str]:
    """As root: switch to ``SUDO_UID``/``SUDO_GID``, else to ``nobody``."""
    if os.geteuid() != 0:
        return []
    target = _sudo_ids() or _nobody_ids()
    if target is None:
        return []
    uid, gid = target
    if hasattr(os, "setgroups"):
        os.setgroups([])
    os.setgid(gid)
    os.setuid(uid)
    if _can_regain_root():
        raise OSError("privilege drop did not stick")
    return [f"uid={uid}", f"gid={gid}"]


def _sudo_ids() -> tuple[int, int] | None:
    """Non-root ``(uid, gid)`` from ``SUDO_UID``/``SUDO_GID``, or None."""
    try:
        uid = int(os.environ["SUDO_UID"])
        gid = int(os.environ["SUDO_GID"])
    except (KeyError, ValueError):
        return None
    return (uid, gid) if uid > 0 and gid > 0 else None


def _nobody_ids() -> tuple[int, int] | None:
    """``(uid, gid)`` of the ``nobody`` account, or None."""
    try:
        entry = pwd.getpwnam("nobody")
    except KeyError:
        return None
    return entry.pw_uid, entry.pw_gid


def _can_regain_root() -> bool:
    """True when ``setuid(0)`` still succeeds (the drop failed)."""
    try:
        os.setuid(0)
    except OSError:
        return False
    return True


def _set_parent_death_signal() -> list[str]:
    """Linux: SIGKILL the worker when the parent dies (set after setuid,
    which clears it). EOF on the pipe covers the other platforms."""
    if not sys.platform.startswith("linux"):
        return []
    if _libc().prctl(_PR_SET_PDEATHSIG, int(signal.SIGKILL), 0, 0, 0) != 0:
        return []
    if os.getppid() == 1:  # parent already gone before the prctl took effect
        os._exit(0)
    return ["pdeathsig"]


def _apply_rlimits() -> list[str]:
    """Core dumps off, few fds, no new processes, no file writes, bounded memory."""
    if resource is None:
        return []
    # With RLIMIT_FSIZE=0 a write fails with EFBIG instead of killing the worker.
    if hasattr(signal, "SIGXFSZ"):
        signal.signal(signal.SIGXFSZ, signal.SIG_IGN)
    limits = [("core", resource.RLIMIT_CORE, 0),
              ("nofile", resource.RLIMIT_NOFILE, OPEN_FILES_LIMIT),
              ("fsize", resource.RLIMIT_FSIZE, 0)]
    if hasattr(resource, "RLIMIT_NPROC") and os.geteuid() != 0:
        limits.append(("nproc", resource.RLIMIT_NPROC, 0))
    if sys.platform.startswith("linux"):
        limits.append(("as", resource.RLIMIT_AS, ADDRESS_SPACE_LIMIT))
    return [f"rlimit-{name}" for name, which, value in limits
            if _lower_rlimit(which, value)]


def _lower_rlimit(which: int, value: int) -> bool:
    """Set soft and hard limit to *value* (never raising an existing hard cap)."""
    try:
        _soft, hard = resource.getrlimit(which)
        if hard != resource.RLIM_INFINITY:
            value = min(value, hard)
        resource.setrlimit(which, (value, value))
    except (ValueError, OSError):
        return False
    return True


def _lower_priority() -> list[str]:
    """Run at a lower CPU priority than the capture process."""
    os.nice(NICE_INCREMENT)
    return ["nice"]


def _enter_macos_sandbox() -> list[str]:
    """macOS: apply the built-in ``pure-computation`` sandbox profile.

    Must run last: afterwards no file can be opened (so no further imports),
    no socket created and no process spawned; already-open fds keep working.
    """
    if sys.platform != "darwin":
        return []
    libc = _libc()
    libc.sandbox_init.argtypes = [ctypes.c_char_p, ctypes.c_uint64,
                                  ctypes.POINTER(ctypes.c_char_p)]
    error = ctypes.c_char_p()
    if libc.sandbox_init(b"pure-computation", _SANDBOX_NAMED, ctypes.byref(error)) != 0:
        return []
    return ["macos-sandbox"]
