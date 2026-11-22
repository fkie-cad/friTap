#!/usr/bin/env python3

"""iOS crash-report retrieval and decoding.

Counterpart of :mod:`friTap.android`'s tombstone pull: the post-mortem artifact
on iOS is the ReportCrash ``.ips`` report. This module owns the host-side
knowledge (libimobiledevice invocation, report layout, ``.ips`` formats).

Best-effort forensics on a dead process: every public entry point catches its
own errors and returns ``None`` / an empty result, and reports are pulled with
``idevicecrashreport -k`` (keep on device) so no evidence is destroyed.

Even on rootless jailbreaks (palera1n, Dopamine) reports live at
``/var/mobile/Library/Logs/CrashReporter``; that path does not move under
``/var/jb``. Retrieval goes only through ``idevicecrashreport`` (usbmuxd), so no
SSH/root shell is needed.
"""

import json
import logging
import os
import re
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Retrieval tuning.
#
# ReportCrash writes the ``.ips`` file ASYNCHRONOUSLY: the report is generated
# by a separate daemon after the process is already gone, so at the moment
# friTap observes the death the file usually does not exist yet (and a
# JetsamEvent report can lag even further behind). Hence a short bounded retry
# instead of a single shot — bounded because a crash handler must not stall the
# session for long, and 3 x 2s is enough for the common case while adding at
# most ~6s to the teardown of an already-broken run.
# ---------------------------------------------------------------------------
CRASH_REPORT_RETRIES = 3
CRASH_REPORT_RETRY_DELAY = 2.0

#: Where ReportCrash stores the reports on the device (rootless-safe, see above).
CRASH_REPORT_DEVICE_DIR = "/var/mobile/Library/Logs/CrashReporter"

IDEVICECRASHREPORT = "idevicecrashreport"
IDEVICE_ID = "idevice_id"
LIBIMOBILEDEVICE_INSTALL_HINT = "brew install libimobiledevice"

#: Hard bound on every libimobiledevice subprocess (seconds).
IDEVICE_COMMAND_TIMEOUT = 60

#: File name suffixes ReportCrash uses for the artifacts we care about.
CRASH_REPORT_SUFFIXES = (".ips", ".ips.beta", ".crash", ".panic")

#: Prefix of a jetsam/watchdog kill report — written under its own name rather
#: than the process name, so name-based matching alone would miss it.
JETSAM_REPORT_PREFIX = "JetsamEvent"

#: ``bug_type`` values that identify a jetsam report in the iOS 16+ JSON header.
JETSAM_BUG_TYPES = ("298",)

#: Cap on how much of a report we read for matching/parsing (reports with full
#: thread backtraces can be large; the fields we need are at the top).
MAX_REPORT_BYTES = 1024 * 1024

#: Timestamp formats used by ``.ips`` headers and legacy ``Date/Time:`` lines.
_TIMESTAMP_FORMATS = (
    "%Y-%m-%d %H:%M:%S.%f %z",
    "%Y-%m-%d %H:%M:%S %z",
    "%Y-%m-%d %H:%M:%S.%f",
    "%Y-%m-%d %H:%M:%S",
)

#: ``MyApp-2026-08-03-120000.ips`` — the fallback time source when the report
#: body carries no parseable timestamp.
_FILENAME_TIME_RE = re.compile(r"(\d{4}-\d{2}-\d{2})-(\d{2})(\d{2})(\d{2})")


@dataclass
class IOSCrashVerdict:
    """Human-readable outcome of :func:`decode_terminator`.

    ``verdict`` is a single short sentence naming what killed the process;
    ``next_step`` is the friTap-specific thing to try next (empty when there is
    no useful advice beyond the verdict itself).
    """

    verdict: str
    next_step: str = ""

    def __str__(self) -> str:
        return f"{self.verdict} ({self.next_step})" if self.next_step else self.verdict


@dataclass
class IOSCrashReport:
    """Structured view of an iOS crash report (``.ips`` or legacy text).

    Only the fields a crash handler needs are extracted; ``raw`` keeps the full
    (bounded) text so it can be written verbatim into friTap's debug log the way
    the Android path writes the tombstone.
    """

    path: str = ""
    process_name: str = ""
    pid: Optional[int] = None
    bug_type: str = ""
    incident_id: str = ""
    timestamp: str = ""
    exception_type: str = ""
    signal: str = ""
    exception_subtype: str = ""
    termination_namespace: str = ""
    termination_code: str = ""
    termination_indicator: str = ""
    termination_reasons: List[str] = field(default_factory=list)
    termination_reason: str = ""
    triggered_thread: Optional[int] = None
    asi: str = ""
    vm_summary: str = ""
    os_version: str = ""
    raw: str = ""

    @property
    def summary(self) -> str:
        """A single line naming process, exception, terminator and time."""
        who = self.process_name or os.path.basename(self.path) or "<unknown process>"
        if self.pid:
            who = f"{who} [{self.pid}]"
        parts = [who]
        exception = " ".join(x for x in (self.exception_type, self.signal) if x)
        if exception:
            parts.append(exception)
        if self.termination_reason:
            parts.append(f"termination: {_shorten(self.termination_reason)}")
        if self.bug_type:
            parts.append(f"bug_type {self.bug_type}")
        if self.timestamp:
            parts.append(self.timestamp)
        return " | ".join(parts)

    @property
    def is_jetsam(self) -> bool:
        """True when this report is a jetsam (memory-pressure) event."""
        basename = os.path.basename(self.path)
        return (
            basename.startswith(JETSAM_REPORT_PREFIX)
            or self.bug_type in JETSAM_BUG_TYPES
            or JETSAM_REPORT_PREFIX.lower() in self.bug_type.lower()
            or "jetsam" in self.termination_namespace.lower()
        )


def _shorten(text: str, limit: int = 160) -> str:
    """Collapse *text* to one line, truncated to *limit* characters."""
    flat = " ".join(str(text).split())
    return flat if len(flat) <= limit else flat[: limit - 3] + "..."


# ---------------------------------------------------------------------------
# Parsing — pure functions on text, so they are unit-testable without a device.
# ---------------------------------------------------------------------------
def parse_report_timestamp(value: str) -> Optional[float]:
    """Return the POSIX timestamp for an iOS report time string, or ``None``.

    Handles the offset-aware forms used by ``.ips`` headers and legacy
    ``Date/Time:`` lines (``2026-08-03 12:00:00.00 +0200``). Naive values are
    interpreted as local time. Never raises.
    """
    text = " ".join(str(value or "").split())
    if not text:
        return None
    for fmt in _TIMESTAMP_FORMATS:
        try:
            return datetime.strptime(text, fmt).timestamp()
        except (ValueError, OverflowError, OSError):
            continue
    return None


def _coerce_termination_code(code: Any) -> str:
    """Normalize a termination code to a lowercase hex string.

    The JSON payload carries it as an integer (``2343432205``), the legacy text
    format as a decimal or hex token; the well-known terminators everybody
    recognises (``0x8badf00d``, ``0xdead10cc``) are hex, so hex is what we keep.
    """
    if code is None or code == "":
        return ""
    if isinstance(code, bool):
        return str(code)
    if isinstance(code, int):
        return hex(code)
    text = str(code).strip()
    if text.lower().startswith("0x"):
        return text.lower()
    try:
        return hex(int(text, 10))
    except ValueError:
        return text


def _split_ips(text: str) -> Tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]]]:
    """Split an iOS 16+ two-part ``.ips`` into (header, payload) dicts.

    The format is a single-line JSON header followed by a JSON payload body.
    Either part may be missing or truncated; whatever parses is returned.
    """
    stripped = text.lstrip()
    if not stripped.startswith("{"):
        return None, None
    header_line, _, remainder = stripped.partition("\n")
    header = _loads_or_none(header_line)
    payload = _loads_or_none(remainder) if remainder.strip() else None
    if header is None and payload is None:
        # Single JSON object spanning several lines (no separate header).
        payload = _loads_or_none(stripped)
    return header, payload


def _loads_or_none(text: str) -> Optional[Dict[str, Any]]:
    try:
        value = json.loads(text)
    except (ValueError, TypeError):
        return None
    return value if isinstance(value, dict) else None


def _flatten_asi(asi: Any) -> str:
    """Flatten the ``asi`` mapping (``{lib: [line, ...]}``) into one string."""
    if isinstance(asi, dict):
        lines = []
        for library, entries in asi.items():
            if isinstance(entries, (list, tuple)):
                lines.extend(f"{library}: {entry}" for entry in entries)
            else:
                lines.append(f"{library}: {entries}")
        return "\n".join(lines)
    if isinstance(asi, (list, tuple)):
        return "\n".join(str(entry) for entry in asi)
    return str(asi) if asi else ""


def _parse_ips_json(report: IOSCrashReport, header: Optional[Dict[str, Any]],
                    payload: Optional[Dict[str, Any]]) -> None:
    """Fill *report* from the iOS 16+ JSON header/payload pair (in place)."""
    header = header or {}
    payload = payload or {}

    report.bug_type = str(header.get("bug_type") or "")
    report.incident_id = str(header.get("incident_id") or "")
    report.timestamp = str(header.get("timestamp") or payload.get("captureTime") or "")
    report.os_version = str(header.get("os_version") or "")
    report.process_name = str(
        payload.get("procName") or header.get("name") or header.get("app_name") or ""
    )
    pid = payload.get("pid")
    report.pid = pid if isinstance(pid, int) else None

    exception = payload.get("exception")
    if isinstance(exception, dict):
        report.exception_type = str(exception.get("type") or "")
        report.signal = str(exception.get("signal") or "")
        report.exception_subtype = str(exception.get("subtype") or "")

    termination = payload.get("termination")
    if isinstance(termination, dict):
        report.termination_namespace = str(termination.get("namespace") or "")
        report.termination_code = _coerce_termination_code(termination.get("code"))
        report.termination_indicator = str(termination.get("indicator") or "")
        reasons = termination.get("reasons")
        if isinstance(reasons, (list, tuple)):
            report.termination_reasons = [str(reason) for reason in reasons]
        elif reasons:
            report.termination_reasons = [str(reasons)]
        report.termination_reason = " ".join(
            part for part in (
                report.termination_namespace,
                report.termination_code,
                report.termination_indicator,
                " ".join(report.termination_reasons),
            ) if part
        ).strip()

    thread = payload.get("faultingThread")
    if thread is None:
        thread = payload.get("triggered_thread")
    report.triggered_thread = thread if isinstance(thread, int) else None

    report.asi = _flatten_asi(payload.get("asi"))
    report.vm_summary = str(payload.get("vmSummary") or "")


_LEGACY_FIELD_RE = {
    "incident_id": re.compile(r"^Incident Identifier:\s*(.+)$", re.M),
    "timestamp": re.compile(r"^Date/Time:\s*(.+)$", re.M),
    "os_version": re.compile(r"^OS Version:\s*(.+)$", re.M),
    "exception_subtype": re.compile(r"^Exception Subtype:\s*(.+)$", re.M),
    "termination_reason": re.compile(r"^Termination Reason:\s*(.+)$", re.M),
}
_LEGACY_PROCESS_RE = re.compile(r"^Process:\s*(\S+)\s*(?:\[(\d+)\])?", re.M)
_LEGACY_EXCEPTION_RE = re.compile(r"^Exception Type:\s*(\S+)(?:\s*\(([^)]+)\))?", re.M)
_LEGACY_THREAD_RE = re.compile(r"^Triggered by Thread:\s*(\d+)", re.M)
_LEGACY_ASI_RE = re.compile(
    r"^Application Specific Information:\s*\n(.*?)(?:\n\s*\n|\Z)", re.M | re.S)


def _parse_legacy_text(report: IOSCrashReport, text: str) -> None:
    """Fill *report* from a legacy plain-text crash report (in place)."""
    for attribute, pattern in _LEGACY_FIELD_RE.items():
        match = pattern.search(text)
        if match:
            setattr(report, attribute, match.group(1).strip())

    match = _LEGACY_PROCESS_RE.search(text)
    if match:
        report.process_name = match.group(1)
        if match.group(2):
            report.pid = int(match.group(2))

    match = _LEGACY_EXCEPTION_RE.search(text)
    if match:
        report.exception_type = match.group(1)
        report.signal = (match.group(2) or "").strip()

    match = _LEGACY_THREAD_RE.search(text)
    if match:
        report.triggered_thread = int(match.group(1))

    match = _LEGACY_ASI_RE.search(text)
    if match:
        report.asi = match.group(1).strip()

    if report.termination_reason:
        tokens = report.termination_reason.split()
        report.termination_namespace = tokens[0] if tokens else ""
        if len(tokens) > 1:
            report.termination_code = _coerce_termination_code(tokens[1])
        report.termination_reasons = [report.termination_reason]


def parse_crash_report_text(text: str, path: str = "") -> IOSCrashReport:
    """Parse an iOS crash report from *text*.

    Handles both the iOS 16+ two-part ``.ips`` (JSON header line + JSON payload)
    and the legacy plain-text format. A malformed or truncated report yields a
    best-effort :class:`IOSCrashReport` (possibly with only ``raw`` filled) —
    this never raises, because it is called from a crash handler.
    """
    text = text or ""
    report = IOSCrashReport(path=path, raw=text)
    try:
        header, payload = _split_ips(text)
        if header is not None or payload is not None:
            _parse_ips_json(report, header, payload)
        else:
            _parse_legacy_text(report, text)
    except Exception:
        logging.getLogger('friTap').debug("parse_crash_report_text failed", exc_info=True)

    basename = os.path.basename(path)
    if not report.bug_type and basename.startswith(JETSAM_REPORT_PREFIX):
        report.bug_type = JETSAM_REPORT_PREFIX
    if not report.process_name and basename:
        report.process_name = basename.split("-")[0]
    return report


def parse_crash_report(path: str) -> Optional[IOSCrashReport]:
    """Parse the crash report at *path*, or return ``None`` when unreadable."""
    text = read_report_text(path)
    if text is None:
        return None
    return parse_crash_report_text(text, path=path)


def read_report_text(path: str, max_bytes: int = MAX_REPORT_BYTES) -> Optional[str]:
    """Read at most *max_bytes* of the report at *path*; ``None`` on any error."""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            return handle.read(max_bytes)
    except Exception:
        logging.getLogger('friTap').debug("cannot read crash report %s", path, exc_info=True)
        return None


# ---------------------------------------------------------------------------
# Terminator decoding — a pure function on the parsed report. These codes are
# exactly what tells a friTap user what happened, so they are decoded
# explicitly instead of being dumped as raw hex.
# ---------------------------------------------------------------------------
def _decode_blob(report: IOSCrashReport) -> str:
    """Lowercased haystack built from the *parsed* fields (never the backtrace),
    so the decode stays deterministic and cannot be tripped by unrelated text
    appearing in a thread dump."""
    parts = [
        report.bug_type,
        report.exception_type,
        report.signal,
        report.exception_subtype,
        report.termination_namespace,
        report.termination_code,
        report.termination_indicator,
        " ".join(report.termination_reasons),
        report.termination_reason,
        report.asi,
        os.path.basename(report.path),
    ]
    return " ".join(part for part in parts if part).lower()


def decode_terminator(report: IOSCrashReport) -> IOSCrashVerdict:
    """Explain *why* the process died, in friTap terms.

    A pure function of the parsed report (no I/O, no device), returning a short
    verdict plus — where one exists — the next thing to try. Order matters: the
    specific terminator codes are checked before the generic exception classes,
    because a watchdog kill also presents as ``EXC_CRASH`` under
    ``SPRINGBOARD``/``FRONTBOARD``.
    """
    blob = _decode_blob(report)

    if "codesigning" in blob or "code signature invalid" in blob or "cs_invalid" in blob:
        return IOSCrashVerdict(
            "codesigning / entitlement failure - the binary's signature was "
            "rejected by AMFI",
            "re-sign the app and frida-server with valid entitlements "
            "(e.g. `ldid -S<entitlements.xml>`) and verify with `ldid -e`; on a "
            "jailbroken device an improperly signed frida-server or a resigned "
            "app is the usual cause",
        )

    if "8badf00d" in blob:
        return IOSCrashVerdict(
            "watchdog timeout (0x8badf00d, \"ate bad food\") - the app was "
            "suspended or blocked for too long and was killed by the watchdog",
            "this is the signature of a gated/suspended app that was never "
            "resumed: make sure friTap resumes the spawned process after the "
            "hooks are installed, or attach to the already running app instead "
            "of spawning it",
        )

    if "dead10cc" in blob:
        return IOSCrashVerdict(
            "0xdead10cc (\"dead lock\") - the app held a file lock or an SQLite "
            "database open while being suspended in the background",
            "release file locks / close database handles before the app is "
            "suspended, or keep the app in the foreground during the capture",
        )

    if report.is_jetsam or "jetsam" in blob or "per-process-limit" in blob:
        return IOSCrashVerdict(
            "killed for memory pressure (jetsam)",
            "free memory on the device (reboot, close other apps) and reduce "
            "friTap's on-device footprint; large full-capture buffers make this "
            "more likely",
        )

    if "exc_bad_access" in blob:
        return IOSCrashVerdict(
            "bad memory access (EXC_BAD_ACCESS) - a hook read or wrote an "
            "invalid address, which usually means a wrong hook offset",
            "verify the offsets/patterns for this exact library build "
            "(re-run with --debug and check the pattern-based offsets), or "
            "disable the suspect hook to confirm",
        )

    if "exc_crash" in blob and ("springboard" in blob or "frontboard" in blob):
        return IOSCrashVerdict(
            "killed by the system watchdog / launch services "
            "(SPRINGBOARD/FRONTBOARD) - the app did not come up in time under "
            "instrumentation",
            "reduce the work done at startup (fewer hooks, no pattern scanning "
            "at launch) or attach to the running app instead of spawning it",
        )

    if "exc_bad_instruction" in blob:
        return IOSCrashVerdict(
            "illegal instruction (EXC_BAD_INSTRUCTION) - execution reached a "
            "non-instruction, typically a bad hook address or a failed inline "
            "patch",
            "verify the hook addresses for this library build",
        )

    if "exc_guard" in blob:
        return IOSCrashVerdict(
            "guarded resource violation (EXC_GUARD) - a protected file "
            "descriptor or object was misused",
            "",
        )

    exception = " ".join(x for x in (report.exception_type, report.signal) if x)
    if exception:
        return IOSCrashVerdict(f"terminated with {exception}", "")
    return IOSCrashVerdict("no recognizable terminator in the crash report", "")


# ---------------------------------------------------------------------------
# Device I/O — libimobiledevice only, always gated on shutil.which, always
# bounded by a subprocess timeout, never fatal.
# ---------------------------------------------------------------------------
class IOS:
    """Host-side iOS device plumbing for crash-report retrieval.

    Mirrors :class:`friTap.android.Android`'s crash-diagnostics role: it owns the
    tool invocation and report layout knowledge, and is safe to construct and
    call from a crash handler (no frida session, no device required — every
    method degrades to an empty result).
    """

    def __init__(self, device_id=None):
        self.device_id = device_id
        self.logger = logging.getLogger('friTap')

    # -- tooling ----------------------------------------------------------
    def _tool_path(self, binary, log_missing=True):
        """Return the absolute path of *binary*, or ``None`` with an actionable
        message. Gating on :func:`shutil.which` keeps a missing libimobiledevice
        a warning instead of a ``FileNotFoundError`` inside a crash handler."""
        path = shutil.which(binary)
        if path:
            return path
        if log_missing:
            self.logger.warning(
                "can't find %s in your path - skipping iOS crash-report retrieval. "
                "Install libimobiledevice to let friTap collect iOS crash reports: %s",
                binary, LIBIMOBILEDEVICE_INSTALL_HINT,
            )
        return None

    def check_idevicecrashreport_availability(self):
        """True when ``idevicecrashreport`` is usable (logs the install hint if not)."""
        return self._tool_path(IDEVICECRASHREPORT) is not None

    def check_idevice_id_availability(self):
        """True when ``idevice_id`` is usable (logs the install hint if not)."""
        return self._tool_path(IDEVICE_ID) is not None

    def _run(self, argv, timeout=IDEVICE_COMMAND_TIMEOUT):
        """Run *argv* capturing output; return the CompletedProcess or ``None``.

        Every failure mode a crash handler could hit (missing binary, hang,
        permission error) is swallowed here and reported as ``None``.
        """
        self.logger.debug("Running `%s`", " ".join(argv))
        try:
            return subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            self.logger.warning("%s timed out after %ss", argv[0], timeout)
        except (FileNotFoundError, OSError):
            self.logger.debug("running %s failed", argv[0], exc_info=True)
        except Exception:
            self.logger.debug("running %s failed", argv[0], exc_info=True)
        return None

    # -- devices ----------------------------------------------------------
    def list_devices(self, timeout=10):
        """Return the UDIDs of connected iOS devices (``idevice_id -l``).

        Returns ``[]`` when libimobiledevice is missing or no device answers.
        """
        if not self._tool_path(IDEVICE_ID):
            return []
        result = self._run([IDEVICE_ID, "-l"], timeout=timeout)
        if result is None or result.returncode != 0:
            return []
        return [line.strip() for line in (result.stdout or "").splitlines() if line.strip()]

    def resolve_udid(self):
        """Return the UDID to target: the configured one, else the only device
        connected, else ``None`` (which makes ``idevicecrashreport`` pick the
        default device itself)."""
        if self.device_id:
            return self.device_id
        devices = self.list_devices()
        if not devices:
            return None
        if len(devices) > 1:
            self.logger.warning(
                "multiple iOS devices connected (%s) - using %s for crash-report "
                "retrieval; pass the device id explicitly to choose another one",
                ", ".join(devices), devices[0],
            )
        return devices[0]

    # -- retrieval --------------------------------------------------------
    def pull_crash_reports(self, dest_dir, timeout=IDEVICE_COMMAND_TIMEOUT):
        """Copy the device's crash reports into *dest_dir*; True on success.

        Uses ``idevicecrashreport -k -e``: ``-k`` keeps the reports on the device
        (friTap must never destroy the user's evidence) and ``-e`` extracts /
        decodes them into readable files. Returns ``False`` — never raises — when
        the tool is missing, times out or errors.
        """
        try:
            if not self._tool_path(IDEVICECRASHREPORT):
                return False
            os.makedirs(dest_dir, exist_ok=True)
            argv = [IDEVICECRASHREPORT, "-k", "-e"]
            udid = self.resolve_udid()
            if udid:
                argv += ["-u", udid]
            argv.append(dest_dir)
            result = self._run(argv, timeout=timeout)
            if result is None:
                return False
            if result.returncode != 0:
                self.logger.debug(
                    "%s exited with %s: %s", IDEVICECRASHREPORT, result.returncode,
                    _shorten(result.stderr or result.stdout or ""),
                )
                return False
            return True
        except Exception:
            self.logger.debug("pull_crash_reports failed", exc_info=True)
            return False

    # -- matching ---------------------------------------------------------
    def report_time(self, path, text=None):
        """Best available POSIX timestamp for the report at *path*.

        Preference order: the report's own (offset-aware) timestamp, then the
        date embedded in the file name, then the host file mtime. The mtime is
        the *last* resort on purpose: ``idevicecrashreport`` does not preserve
        the device-side modification time, so a freshly pulled old report would
        otherwise look brand new.
        """
        try:
            if text is None:
                text = read_report_text(path, max_bytes=8192) or ""
            report = parse_crash_report_text(text, path=path)
            stamp = parse_report_timestamp(report.timestamp)
            if stamp is not None:
                return stamp
            match = _FILENAME_TIME_RE.search(os.path.basename(path))
            if match:
                day, hour, minute, second = match.groups()
                stamp = parse_report_timestamp(f"{day} {hour}:{minute}:{second}")
                if stamp is not None:
                    return stamp
            return os.path.getmtime(path)
        except Exception:
            self.logger.debug("report_time failed for %s", path, exc_info=True)
            return 0.0

    def _process_tokens(self, process_name):
        """Candidate names a report may use for *process_name*.

        A friTap target is often a bundle id (``com.example.MyApp``) while the
        report is named after the executable (``MyApp``), so both are tried.
        """
        name = (process_name or "").strip()
        if not name:
            return []
        tokens = [name]
        if "." in name:
            tail = name.rsplit(".", 1)[-1]
            if tail and tail not in tokens:
                tokens.append(tail)
        return tokens

    def _matches_process(self, path, text, tokens):
        """True when the report at *path* belongs to one of *tokens*."""
        basename = os.path.basename(path)
        lowered = basename.lower()
        if any(lowered.startswith(token.lower()) for token in tokens):
            return True
        haystack = (text or "").lower()
        if basename.startswith(JETSAM_REPORT_PREFIX):
            # A jetsam report is not named after the process; its payload lists
            # the killed processes instead.
            return any(token.lower() in haystack for token in tokens)
        for token in tokens:
            quoted = re.escape(token.lower())
            if re.search(rf'"procname"\s*:\s*"{quoted}"', haystack):
                return True
            if re.search(rf"^process:\s*{quoted}\b", haystack, re.M):
                return True
        return False

    def find_crash_reports(self, directory, process_name, pid=None, newer_than=None):
        """Return matching report paths in *directory*, newest first.

        Matches reports named after *process_name* (or its bundle-id tail), plus
        ``JetsamEvent-*.ips`` reports that mention it — a watchdog/jetsam kill is
        one of the likeliest outcomes for a suspended or wedged app and is
        written under a different name than a normal crash. Reports older than
        *newer_than* (POSIX seconds) are dropped so a stale, unrelated crash is
        never presented as the current one. When *pid* is given, a report whose
        body mentions that pid is preferred over an otherwise newer one.
        Returns ``[]`` on any error.
        """
        try:
            tokens = self._process_tokens(process_name)
            if not tokens or not os.path.isdir(directory):
                return []
            candidates = []
            for root, _dirs, files in os.walk(directory):
                for name in files:
                    if not name.endswith(CRASH_REPORT_SUFFIXES):
                        continue
                    path = os.path.join(root, name)
                    text = read_report_text(path)
                    if text is None or not self._matches_process(path, text, tokens):
                        continue
                    stamp = self.report_time(path, text=text)
                    if newer_than is not None and stamp < newer_than:
                        self.logger.debug(
                            "ignoring crash report older than the target's death: %s", path)
                        continue
                    pid_match = bool(pid) and self._mentions_pid(text, pid)
                    candidates.append((pid_match, stamp, path))
            candidates.sort(key=lambda item: (item[0], item[1]), reverse=True)
            return [path for _pid_match, _stamp, path in candidates]
        except Exception:
            self.logger.debug("find_crash_reports failed", exc_info=True)
            return []

    @staticmethod
    def _mentions_pid(text, pid):
        """True when *text* references *pid* the way a report would."""
        return re.search(rf'(?:"pid"\s*:\s*|\[){pid}\b', text or "") is not None

    def get_latest_crash_report(self, process_name, pid=None, newer_than=None,
                                dest_dir=None, retries=CRASH_REPORT_RETRIES,
                                delay=CRASH_REPORT_RETRY_DELAY,
                                timeout=IDEVICE_COMMAND_TIMEOUT):
        """Pull and parse the crash report for a just-died iOS target.

        The one call a crash handler needs: it resolves the device, pulls the
        reports with ``idevicecrashreport -k -e`` into *dest_dir* (a temporary
        directory when omitted — the pulled files are deliberately kept so the
        user still has the evidence), retries while ReportCrash is still writing
        the ``.ips``, and returns the parsed newest matching report.

        Returns ``None`` — never raises, never fatal — when libimobiledevice is
        missing, no device answers, or no matching report appears in time.
        """
        try:
            if not self.check_idevicecrashreport_availability():
                return None
            workdir = dest_dir or tempfile.mkdtemp(prefix="fritap-ios-crash-")
            attempts = max(1, int(retries))
            for attempt in range(1, attempts + 1):
                self.pull_crash_reports(workdir, timeout=timeout)
                matches = self.find_crash_reports(
                    workdir, process_name, pid=pid, newer_than=newer_than)
                if matches:
                    self.logger.debug(
                        "found iOS crash report on attempt %s/%s: %s",
                        attempt, attempts, matches[0])
                    return parse_crash_report(matches[0])
                if attempt < attempts:
                    # ReportCrash writes the .ips asynchronously; give it a moment.
                    self.logger.debug(
                        "no iOS crash report for %s yet (attempt %s/%s), waiting %ss",
                        process_name, attempt, attempts, delay)
                    self._sleep(delay)
            self.logger.debug(
                "no iOS crash report for %s found in %s after %s attempts",
                process_name, workdir, attempts)
            return None
        except Exception:
            self.logger.debug("get_latest_crash_report failed", exc_info=True)
            return None

    def _sleep(self, seconds):
        """Indirection so the retry backoff can be neutralized in tests."""
        time.sleep(seconds)

    def describe_crash(self, report):
        """Return ``(summary_line, verdict)`` for a parsed *report*.

        Convenience for a crash handler that wants both the one-line summary and
        the decoded terminator; ``(\"\", None)`` for a missing report.
        """
        if report is None:
            return "", None
        try:
            return report.summary, decode_terminator(report)
        except Exception:
            self.logger.debug("describe_crash failed", exc_info=True)
            return "", None
