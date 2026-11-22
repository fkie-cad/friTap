#!/usr/bin/env python3

"""Local macOS crash-report lookup.

When a LOCAL macOS target dies of a signal, frida often delivers no ``Crash``
object (e.g. the process died just after friTap detached), yet macOS'
ReportCrash still writes a ``.ips`` report to ``~/Library/Logs/DiagnosticReports``.
This module finds that report for a given pid so the crash handler can name the
real cause instead of "no crash evidence".

The ``.ips`` format is the same two-part JSON (header line + payload) iOS uses,
so parsing is delegated to :mod:`friTap.ios`. ReportCrash writes the file
asynchronously, usually a second or so AFTER the process is gone, hence the
short bounded poll in :func:`wait_for_local_crash_report`.

Best-effort forensics on a dead process: nothing here raises.
"""

import logging
import os
import time
from typing import Callable, Iterable, List, Optional

from .ios import (
    CRASH_REPORT_SUFFIXES,
    IOSCrashReport,
    parse_crash_report,
    parse_report_timestamp,
)

#: Per-user reports (the normal case) and system-wide reports (root targets).
USER_DIAGNOSTIC_REPORTS = "~/Library/Logs/DiagnosticReports"
SYSTEM_DIAGNOSTIC_REPORTS = "/Library/Logs/DiagnosticReports"

#: Bounded wait for ReportCrash's asynchronous write.
LOCAL_CRASH_REPORT_TIMEOUT = 3.0
LOCAL_CRASH_REPORT_POLL_INTERVAL = 0.25

#: Slack between the session start and the report's capture time (same host
#: clock, but the header timestamp is rounded).
LOCAL_CRASH_REPORT_CLOCK_TOLERANCE = 2.0

_logger = logging.getLogger("friTap")


def diagnostic_report_dirs() -> List[str]:
    """Directories ReportCrash may write the target's report to, deduplicated.

    Under ``sudo`` the invoking user's directory is included too, because the
    target usually runs as that user while ``~`` may resolve to root's home.
    """
    candidates = [os.path.expanduser(USER_DIAGNOSTIC_REPORTS)]
    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user:
        candidates.append(os.path.expanduser(f"~{sudo_user}/Library/Logs/DiagnosticReports"))
    candidates.append(SYSTEM_DIAGNOSTIC_REPORTS)
    unique = []
    for path in candidates:
        if path not in unique:
            unique.append(path)
    return unique


def _recent_report_paths(directory: str, newer_than: Optional[float]) -> List[str]:
    """Report files directly in *directory* modified at/after *newer_than*."""
    try:
        names = os.listdir(directory)
    except OSError:
        return []
    paths = []
    for name in names:
        if not name.endswith(CRASH_REPORT_SUFFIXES):
            continue
        path = os.path.join(directory, name)
        try:
            if newer_than is not None and os.path.getmtime(path) < newer_than:
                continue
        except OSError:
            continue
        paths.append(path)
    return paths


def _report_matches(report: Optional[IOSCrashReport], pid: int,
                    newer_than: Optional[float]) -> bool:
    """True when *report* belongs to *pid* and was captured after *newer_than*."""
    if report is None or report.pid != pid:
        return False
    if newer_than is None:
        return True
    stamp = parse_report_timestamp(report.timestamp)
    return stamp is None or stamp >= newer_than


def find_local_crash_report(pid: int, newer_than: Optional[float] = None,
                            directories: Optional[Iterable[str]] = None
                            ) -> Optional[IOSCrashReport]:
    """The newest ``.ips`` report whose body ``pid`` equals *pid*, or ``None``.

    *newer_than* (POSIX seconds, typically the session start minus
    :data:`LOCAL_CRASH_REPORT_CLOCK_TOLERANCE`) drops stale reports of an
    earlier process that happened to have the same pid.
    """
    if not pid:
        return None
    try:
        dirs = list(directories) if directories is not None else diagnostic_report_dirs()
        matches = []
        for directory in dirs:
            for path in _recent_report_paths(directory, newer_than):
                report = parse_crash_report(path)
                if _report_matches(report, pid, newer_than):
                    matches.append((os.path.getmtime(path), report))
        if not matches:
            return None
        matches.sort(key=lambda item: item[0], reverse=True)
        return matches[0][1]
    except Exception:
        _logger.debug("find_local_crash_report failed", exc_info=True)
        return None


def wait_for_local_crash_report(pid: int, newer_than: Optional[float] = None,
                                directories: Optional[Iterable[str]] = None,
                                timeout: float = LOCAL_CRASH_REPORT_TIMEOUT,
                                interval: float = LOCAL_CRASH_REPORT_POLL_INTERVAL,
                                sleep: Callable[[float], None] = time.sleep,
                                clock: Callable[[], float] = time.monotonic
                                ) -> Optional[IOSCrashReport]:
    """Poll :func:`find_local_crash_report` for up to *timeout* seconds."""
    dirs = list(directories) if directories is not None else None
    deadline = clock() + max(0.0, timeout)
    while True:
        report = find_local_crash_report(pid, newer_than, dirs)
        if report is not None or clock() >= deadline:
            return report
        sleep(interval)


def describe_local_crash_cause(report: Optional[IOSCrashReport]):
    """``(cause, detail)`` for the crash headline, e.g.
    ``("SIGSEGV (EXC_BAD_ACCESS)", "KERN_INVALID_ADDRESS at 0x0")``."""
    if report is None:
        return None, None
    collapse = lambda text: " ".join(str(text or "").split())  # noqa: E731
    signal_name = collapse(report.signal)
    exception_type = collapse(report.exception_type)
    if signal_name and exception_type:
        cause = f"{signal_name} ({exception_type})"
    else:
        cause = signal_name or exception_type
    # The subtype ("KERN_INVALID_ADDRESS at 0x0") is more specific than the
    # generic termination line ("SIGNAL 0xb Segmentation fault: 11").
    detail = collapse(report.exception_subtype) or collapse(report.termination_reason)
    return cause or None, detail or None
