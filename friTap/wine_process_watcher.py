"""Follow the processes of a Wine app from the host (fkie-cad/friTap#52).

Frida's child gating does not see the processes a Wine app starts: Wine's
CreateProcess goes through the Unix-side loader and the new process is
re-parented (observed: every cefclient.exe process has a ppid outside the
launched tree), so ``child-added`` only ever reports the initial wine64
re-exec. A Chromium-based launcher does its TLS in such a child (the network
service), so friTap watches ``/proc`` instead and hands every new process of the
same Wine prefix to the normal attach + instrument worker.

Matching rules (see :func:`classify_wine_cmdline`):
  * argv[0] is a Windows ``.exe`` (Wine sets the process's argv to the Windows
    command line) and not a Wine system process (services.exe, winedevice.exe,
    explorer.exe, ...);
  * Chromium children that never do TLS are skipped (renderer, gpu-process,
    crashpad-handler, ...); utility processes only when they host the network
    service (or carry no sub-type);
  * the process runs in the same ``WINEPREFIX``;
  * it did not exist before the watch started.
"""

from __future__ import annotations

import glob
import logging
import os
import re
import threading
import time
from typing import Callable, Dict, Iterable, Optional, Set

logger = logging.getLogger("friTap.wine_watch")

#: Wine's own processes in every prefix; never instrumented.
WINE_SYSTEM_EXES = frozenset({
    "services.exe", "winedevice.exe", "plugplay.exe", "explorer.exe",
    "rpcss.exe", "svchost.exe", "conhost.exe", "start.exe", "wineboot.exe",
    "winemenubuilder.exe", "tabtip.exe", "mscorsvw.exe", "rundll32.exe",
    "winedbg.exe", "wineconsole.exe", "cmd.exe",
})

#: Chromium ``--type=`` values whose processes never do TLS.
CHROMIUM_NON_TLS_TYPES = frozenset({
    "renderer", "gpu-process", "crashpad-handler", "broker", "zygote",
    "ppapi", "ppapi-broker", "nacl-loader", "nacl-broker",
})

#: Re-check a process that is not yet identifiable or not yet bootstrapped
#: (mid-exec of the Wine loader, exe/kernel32 not mapped) this many polls
#: (~10 s at the default interval), then give up on it.
_MAX_PENDING_POLLS = 200


def split_cmdline(raw: bytes):
    """argv of a raw /proc/<pid>/cmdline (NUL-separated)."""
    return [a.decode("utf-8", "replace") for a in raw.split(b"\0") if a]


def classify_wine_cmdline(argv) -> Optional[str]:
    """A short label for a Wine app process worth instrumenting, else None.

    Labels look like ``cefclient.exe`` or ``cefclient.exe [network service]``.
    """
    if not argv:
        return None
    exe = argv[0]
    if not exe.lower().endswith(".exe"):
        return None
    base = re.split(r"[\\/]", exe)[-1]
    if base.lower() in WINE_SYSTEM_EXES:
        return None
    ptype = None
    subtype = None
    for arg in argv[1:]:
        if arg.startswith("--type="):
            ptype = arg.split("=", 1)[1]
        elif arg.startswith("--utility-sub-type="):
            subtype = arg.split("=", 1)[1]
    if ptype is None:
        return base
    if ptype in CHROMIUM_NON_TLS_TYPES:
        return None
    if ptype == "utility":
        if subtype and "network" not in subtype.lower():
            return None
        return f"{base} [network service]" if subtype else f"{base} [utility]"
    return f"{base} [{ptype}]"


def process_wine_prefix(pid) -> Optional[str]:
    """The WINEPREFIX a process runs in (its environment, defaulting to
    ``$HOME/.wine``), realpath'd; None if unreadable."""
    try:
        with open(f"/proc/{pid}/environ", "rb") as fh:
            env = dict(
                kv.split(b"=", 1) for kv in fh.read().split(b"\0") if b"=" in kv
            )
    except OSError:
        return None
    prefix = env.get(b"WINEPREFIX")
    if prefix:
        return os.path.realpath(prefix.decode("utf-8", "replace"))
    home = env.get(b"HOME")
    if home:
        return os.path.realpath(os.path.join(home.decode("utf-8", "replace"), ".wine"))
    return None


def wine_process_ready(maps_text: str, exe_basename: str) -> bool:
    """Has Wine finished bootstrapping this process? True once its exe image
    and kernelbase/kernel32 are mapped. Attaching (and injecting the agent)
    earlier, while the preloader/ntdll still set up the address space, kills
    the process — and with a Chromium browser process the whole app."""
    low = maps_text.lower()
    return exe_basename.lower() in low and ("kernelbase.dll" in low or "kernel32.dll" in low)


#: Attaching (injecting the full agent) while Wine/Chromium still initialise a
#: process kills it — observed for the browser process and the network service
#: alike when attaching as soon as kernel32 is mapped, and still when attaching
#: as soon as Wine's libgnutls is loaded. Every run that attached >= ~1.5 s
#: after bootstrap survived; 2 s is the margin used. Consequence: TLS the
#: network service does in its first ~2-3 s (e.g. a launcher's start page) is
#: not captured — only an in-process (gadget-style) agent could close that.
SETTLE_SECONDS = 2.0
#: Non-network processes (e.g. the Chromium browser process, which does no TLS
#: of its own) are reported only after a network service was, or after this
#: many seconds: the instrument worker is serial, and a browser attach queued
#: first delayed the network-service hook by >1 s.
NON_NETWORK_DEFER_SECONDS = 5.0


def is_network_process(label: str) -> bool:
    return "[network service]" in label or "[utility]" in label


def read_proc_maps(pid) -> Optional[str]:
    try:
        with open(f"/proc/{pid}/maps") as fh:
            return fh.read()
    except OSError:
        return None


def current_pids() -> Set[str]:
    return {p.rsplit("/", 1)[-1] for p in glob.glob("/proc/[0-9]*")}


class WineProcessWatcher:
    """Poll /proc and report each new process of a Wine app once.

    *on_new(pid, label)* runs on the watcher thread; it must be quick (the
    friTap instrument worker queue is). *prefix* restricts matches to one
    WINEPREFIX (None: any). *exclude* are PIDs (strings) never to report, e.g.
    the snapshot taken before launching the app.
    """

    def __init__(self, on_new: Callable[[int, str], None], *, prefix: Optional[str],
                 exclude: Iterable[str] = (), poll_interval: float = 0.05,
                 list_pids: Callable[[], Iterable[str]] = current_pids,
                 read_cmdline: Optional[Callable[[str], Optional[bytes]]] = None,
                 read_prefix: Callable[[str], Optional[str]] = process_wine_prefix,
                 read_maps: Callable[[str], Optional[str]] = read_proc_maps,
                 settle_seconds: Optional[float] = None,
                 non_network_defer_seconds: Optional[float] = None,
                 clock: Callable[[], float] = time.monotonic):
        self._on_new = on_new
        self._prefix = os.path.realpath(prefix) if prefix else None
        self._done: Set[str] = set(exclude)
        self._pending: Dict[str, int] = {}
        self._poll = poll_interval
        self._list_pids = list_pids
        self._read_cmdline = read_cmdline or self._read_proc_cmdline
        self._read_prefix = read_prefix
        self._read_maps = read_maps
        self._settle = SETTLE_SECONDS if settle_seconds is None else settle_seconds
        self._defer = (NON_NETWORK_DEFER_SECONDS if non_network_defer_seconds is None
                       else non_network_defer_seconds)
        self._network_seen = False
        self._clock = clock
        self._ready_since: Dict[str, float] = {}
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self.reported: Dict[int, str] = {}

    @staticmethod
    def _read_proc_cmdline(pid: str) -> Optional[bytes]:
        try:
            with open(f"/proc/{pid}/cmdline", "rb") as fh:
                return fh.read()
        except OSError:
            return None

    def poll_once(self) -> None:
        """One pass over /proc (public for tests)."""
        for pid in self._list_pids():
            if pid in self._done:
                continue
            raw = self._read_cmdline(pid)
            if not raw:
                # Exited, a kernel thread, or a process caught mid-fork/exec
                # (its cmdline briefly reads empty): only the last is retried.
                if raw is None:
                    self._done.add(pid)
                else:
                    self._retry_or_drop(pid)
                continue
            argv = split_cmdline(raw)
            if not argv or not argv[0].lower().endswith(".exe"):
                # Possibly a Wine process still exec'ing its loader: retry a while.
                self._retry_or_drop(pid)
                continue
            label = classify_wine_cmdline(argv)
            if label is None:
                self._done.add(pid)
                logger.debug("wine-watch: skip pid %s (%s)", pid, " ".join(argv[:3])[:120])
                continue
            if self._prefix is not None and self._read_prefix(pid) != self._prefix:
                self._done.add(pid)
                logger.debug("wine-watch: skip pid %s %s (other prefix)", pid, label)
                continue
            exe_base = re.split(r"[\\/]", argv[0])[-1]
            maps = self._read_maps(pid) or ""
            if not wine_process_ready(maps, exe_base):
                self._retry_or_drop(pid)  # still bootstrapping: attach later
                continue
            network = is_network_process(label)
            since = self._ready_since.setdefault(pid, self._clock())
            elapsed = self._clock() - since
            if elapsed < self._settle:
                continue  # let it settle past the fragile init before injecting
            if not network and not self._network_seen and elapsed < self._defer:
                continue  # keep the serial instrument worker free for the network service
            if network:
                self._network_seen = True
            self._ready_since.pop(pid, None)
            self._pending.pop(pid, None)
            self._done.add(pid)
            self.reported[int(pid)] = label
            logger.debug("wine-watch: report pid %s %s", pid, label)
            try:
                self._on_new(int(pid), label)
            except Exception:
                logger.exception("Wine process handler failed for pid %s", pid)

    def _retry_or_drop(self, pid: str) -> None:
        n = self._pending.get(pid, 0) + 1
        if n >= _MAX_PENDING_POLLS:
            self._pending.pop(pid, None)
            self._done.add(pid)
            logger.debug("wine-watch: gave up on pid %s (never identifiable/ready)", pid)
        else:
            self._pending[pid] = n

    def _run(self) -> None:
        while not self._stop.is_set():
            self.poll_once()
            self._stop.wait(self._poll)

    def start(self) -> None:
        if self._thread is None:
            self._thread = threading.Thread(target=self._run, daemon=True, name="fritap-wine-watch")
            self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None and self._thread is not threading.current_thread():
            self._thread.join(timeout=2)

    def alive_reported(self) -> Set[int]:
        """Reported PIDs that are still running."""
        return {pid for pid in self.reported if os.path.exists(f"/proc/{pid}")}
