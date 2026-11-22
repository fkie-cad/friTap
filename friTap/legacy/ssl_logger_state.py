"""Plain records shared by :class:`SSL_Logger` and its mixins, plus the call-time
accessor of ``ssl_logger_core`` (mirrors ``friTap.flow.collector_state``)."""

import sys
from dataclasses import dataclass
from typing import NamedTuple, Optional


def core_module():
    """``friTap.legacy.ssl_logger_core``, looked up at call time so tests patching its names take effect."""
    return sys.modules["friTap.legacy.ssl_logger_core"]


@dataclass(slots=True)
class _InstrumentRequest:
    """A gated child/spawned process waiting for the instrument worker.

    Plain values only: the process may be gone by the time the worker runs.
    """
    pid: int
    label: str
    identifier: object = None
    # False for processes never Frida-suspended (the Wine process watcher
    # attaches to running ones): nothing to resume.
    resume: bool = True
    # True for the exec'd image of a process friTap already instruments (same
    # pid): it replaces that process's session (the main one for the target)
    # instead of joining as an extra child.
    exec_handover: bool = False
    # Watch role across exec() (see SSL_Logger._watch_process): True for the
    # main target (its loss ends the capture), False for a child, None when
    # not watched (e.g. the Wine process watcher).
    watch_as_main: Optional[bool] = None


@dataclass(slots=True)
class _ChildAgent:
    """The agent loaded into any instrumented process except the main target (whose agent is ``SSL_Logger.script``)."""
    pid: Optional[int]  # None when the session is not tracked (Wine watcher)
    session: object
    script: object
    # graceful_detach result (SSL_Logger.GRACEFUL_*), None until attempted;
    # decides whether teardown may unload the script.
    graceful_outcome: Optional[str] = None


class TargetOS(NamedTuple):
    """What frida reports about the target platform: ``os.id`` plus ``access``.

    Empty strings mean "could not find out" (no device yet, backend error); the crash path
    must degrade quietly rather than raise.

    ``access == "jailed"`` means a Gadget-injected app (one app embedding frida-gadget, no
    device-wide frida-server, so no arbitrary spawn), not "device not jailbroken". frida 17
    also reports it for a USB device with no frida-server running (ADB-only fallback);
    ``"full"`` is a device-wide frida-server. Crash-report retrieval is unaffected:
    ``idevicecrashreport`` talks to usbmuxd, not frida.
    """

    os_id: str = ""
    access: str = ""


#: Returned by _query_os_id() whenever the lookup fails.
UNKNOWN_TARGET_OS = TargetOS()
