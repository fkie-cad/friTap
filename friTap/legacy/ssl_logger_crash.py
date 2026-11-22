"""Target platform queries and crash attribution for :class:`SSL_Logger`:
frida Crash parsing, Android/iOS/macOS crash evidence, the crash headline and guidance.

The host class owns the state.
"""

import calendar
import os
import re
import time
from datetime import datetime
from typing import List, Optional, Tuple

from ..exit_codes import EXIT_TARGET_DETACHED
from .ssl_logger_state import UNKNOWN_TARGET_OS, TargetOS

#: Seconds before session start an iOS crash report is still accepted. Report
#: times are device-clock, often naive local times, so an exact cut-off would
#: drop the wanted report; process-name + pid matching in friTap.ios keeps the
#: wider window harmless.
IOS_CRASH_REPORT_CLOCK_TOLERANCE = 120.0


class CrashReportMixin:
    """Platform queries plus the unexpected-target-death report."""

    def _is_android_target(self) -> bool:
        """Cached: is the Frida device Android? Gates the Android-only PairIP hint."""
        cached = getattr(self, "_android_target_cached", None)
        if cached is not None:
            return cached
        result = False
        try:
            device = getattr(self, "device", None)
            if device is not None:
                params = device.query_system_parameters()
                result = (params.get("os", {}).get("id", "") or "").lower() == "android"
        except Exception:
            result = False
        self._android_target_cached = result
        return result

    def _query_os_id(self) -> TargetOS:
        """Cached ``(os_id, access)`` of the frida target, e.g. ``("ios", "full")``.

        Cached separately from ``_android_target_cached``, which tests set to
        disable Android enrichment. Never raises: an unusable device yields
        :data:`UNKNOWN_TARGET_OS`.
        """
        cached = getattr(self, "_target_os_cached", None)
        if cached is not None:
            return cached
        result = UNKNOWN_TARGET_OS
        try:
            params = self._query_system_parameters()
            os_info = params.get("os", {}) if isinstance(params, dict) else {}
            result = TargetOS(
                os_id=str(os_info.get("id", "") or "").lower(),
                access=str(params.get("access", "") or "").lower(),
            )
        except Exception:
            result = UNKNOWN_TARGET_OS
        self._target_os_cached = result
        return result

    def _query_system_parameters(self) -> dict:
        """Raw frida system parameters for the current device (may raise)."""
        device = getattr(self, "device", None)
        if device is None:
            return {}
        backend = getattr(self, "_backend", None)
        if backend is not None:
            return backend.query_system_parameters(device) or {}
        return device.query_system_parameters() or {}

    def _is_ios_target(self) -> bool:
        """Cached: is the Frida device iOS? Gates iOS crash enrichment and guidance."""
        return self._query_os_id().os_id == "ios"

    def _parse_crash_cause(self, report, summary):
        """Best-effort ``(signal, abort_message)`` from a frida Crash report/summary,
        tombstone or logcat dump; either may be None. The abort message is one line.
        """
        text = "\n".join(t for t in (summary, report) if t)
        if not text:
            return None, None
        sig = None
        m = re.search(r"signal\s+\d+\s+\((SIG[A-Z]+)\)", text)
        if m:
            sig = m.group(1)
        else:
            # Only real fatal signal names: a generic SIG[A-Z]+ also matches "SIGNAL".
            m = re.search(
                r"\b(SIGSEGV|SIGABRT|SIGILL|SIGBUS|SIGFPE|SIGTRAP|SIGSYS|SIGKILL|SIGQUIT)\b",
                text)
            if m:
                sig = m.group(1)
        abort = None
        # To end-of-line: ART abort messages can contain quotes ('Lcom/foo;').
        m = re.search(r"Abort message:\s*(.+)", text)
        if m:
            abort = m.group(1).strip().strip("'").strip()
        else:
            m = re.search(r"(JNI DETECTED ERROR[^\n]*)", text)
            if m:
                abort = m.group(1).strip()
        if abort:
            abort = " ".join(abort.split())
        return sig, abort

    @staticmethod
    def _write_crash_section(writer, title, body):
        """Append a titled section to the crash debug log; no-op without a writer, never raises."""
        if writer is None or not body.strip():
            return
        try:
            writer.write(f"\n===== {title} =====\n{body}\n")
        except Exception:
            pass

    # Clock slack when comparing device timestamps with the session start.
    CRASH_EVIDENCE_CLOCK_TOLERANCE = 60.0
    # logcat "threadtime" line: "MM-DD HH:MM:SS.mmm  PID  TID LEVEL TAG: msg".
    _LOGCAT_THREADTIME_RE = re.compile(
        r"^\s*(\d{2})-(\d{2})\s+(\d{2}):(\d{2}):(\d{2})(?:\.\d+)?\s+(\d+)\s+\d+\s")
    _TOMBSTONE_TIMESTAMP_RE = re.compile(
        r"^Timestamp:\s*(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})(?:\.\d+)?([+-]\d{4})?",
        re.MULTILINE)

    def _crash_evidence_since(self, device_clock=None) -> Optional[float]:
        """Device-clock epoch before which crash evidence is not from this run, or None.

        The host session start is shifted by *device_clock* ``(device_epoch,
        host_epoch)`` because the two clocks may disagree.
        """
        start = getattr(self, "_session_start_time", None)
        if not start or device_clock is None:
            return None
        device_epoch, host_epoch = device_clock
        return start + (device_epoch - host_epoch) - self.CRASH_EVIDENCE_CLOCK_TOLERANCE

    @staticmethod
    def _read_device_clock(andy):
        """``((device_epoch, host_epoch), device_utc_offset)``, or ``(None, None)``."""
        get_clock = getattr(andy, "get_device_clock", None)
        try:
            host_before = time.time()
            reading = get_clock() if get_clock is not None else None
            host_epoch = (host_before + time.time()) / 2
        except Exception:
            return None, None
        if not reading:
            return None, None
        device_epoch, utc_offset = reading
        return (float(device_epoch), host_epoch), int(utc_offset)

    @staticmethod
    def _logcat_line_epoch(month, day, hour, minute, second, utc_offset,
                           now=None) -> Optional[float]:
        """Epoch of a year-less logcat timestamp at the device's *utc_offset* (s east of UTC).

        A future date belongs to the previous year; *now* is the device epoch."""
        now = now if now is not None else time.time()
        year = time.gmtime(now + utc_offset).tm_year
        for candidate_year in (year, year - 1):
            try:
                stamp = calendar.timegm(
                    (candidate_year, month, day, hour, minute, second, 0, 0, 0)) - utc_offset
            except (OverflowError, ValueError):
                return None
            if stamp <= now + 86400:
                return stamp
        return None

    @classmethod
    def _crash_buffer_lines_for(cls, crash_buf: str, pid, since: Optional[float],
                                utc_offset: Optional[int] = None,
                                now: Optional[float] = None) -> str:
        """The ``logcat -b crash`` lines that belong to *pid*'s crash in this run.

        Keeps lines from *pid* (libc "Fatal signal") and from the crash_dump
        process whose "pid: <pid>" header names it, not older than *since*.
        Without *since*/*utc_offset* only the pid filter applies; without a pid
        nothing is kept.
        """
        if not crash_buf or not pid:
            return ""
        parsed = []
        for line in crash_buf.splitlines():
            m = cls._LOGCAT_THREADTIME_RE.match(line)
            if m:
                parsed.append((line, tuple(int(g) for g in m.groups())))
        header = re.compile(rf"\bpid:\s*{int(pid)}\b")
        writers = {fields[5] for line, fields in parsed if header.search(line)}
        time_filter = since is not None and utc_offset is not None
        kept = []
        for line, (month, day, hour, minute, second, line_pid) in parsed:
            if line_pid != int(pid) and line_pid not in writers:
                continue
            if time_filter:
                stamp = cls._logcat_line_epoch(
                    month, day, hour, minute, second, utc_offset, now)
                if stamp is not None and stamp < since:
                    continue
            kept.append(line)
        return "\n".join(kept)

    @classmethod
    def _tombstone_predates(cls, tombstone: str, since: Optional[float],
                            utc_offset: Optional[int] = None) -> bool:
        """True when the tombstone's ``Timestamp:`` is older than *since* (device epoch).

        An offset-less timestamp uses *utc_offset*; with neither, False."""
        if since is None or not tombstone:
            return False
        m = cls._TOMBSTONE_TIMESTAMP_RE.search(tombstone)
        if not m:
            return False
        try:
            if m.group(2):
                stamp = datetime.strptime(m.group(1) + m.group(2),
                                          "%Y-%m-%d %H:%M:%S%z").timestamp()
            elif utc_offset is not None:
                stamp = calendar.timegm(
                    time.strptime(m.group(1), "%Y-%m-%d %H:%M:%S")) - utc_offset
            else:
                return False
        except (ValueError, OverflowError):
            return False
        return stamp < since

    # Without a device clock reading, minidump mtimes (device epoch) are
    # compared with the HOST session start under this wider slack.
    MINIDUMP_FALLBACK_CLOCK_TOLERANCE = 600.0
    _STAT_LINE_RE = re.compile(r"^\s*(\d+)\s+(/.*\.dmp)\s*$")
    # events buffer: "... I am_crash: [user,pid,process,flags,...]"
    _AM_EVENT_RE = re.compile(r"\bam_(crash|anr)\s*:\s*\[(.*)\]\s*$")
    # Evidence labels, strongest first (see _select_crash_evidence).
    CRASH_EVIDENCE_PRIORITY = ("tombstone", "minidump", "am_crash", "ANR")

    def _minidump_since(self, device_since: Optional[float]) -> Optional[float]:
        """Minidump cut-off: *device_since*, else host start minus the fallback slack, else None."""
        if device_since is not None:
            return device_since
        start = getattr(self, "_session_start_time", None)
        return start - self.MINIDUMP_FALLBACK_CLOCK_TOLERANCE if start else None

    @classmethod
    def _new_minidumps_from_stat(cls, stat_out: str, since: Optional[float]) -> List[str]:
        """Paths from ``stat -c '%Y %n'`` lines not older than *since*, newest first.

        Without *since* returns nothing: apps keep old pending dumps for weeks."""
        if not stat_out or since is None:
            return []
        dumps = []
        for line in stat_out.splitlines():
            m = cls._STAT_LINE_RE.match(line)
            if m and int(m.group(1)) >= since:
                dumps.append((int(m.group(1)), m.group(2)))
        return [path for _, path in sorted(dumps, reverse=True)]

    @staticmethod
    def _parse_am_event_payload(kind: str, payload: str):
        """``(pid, process, detail)`` of an ``am_crash`` / ``am_anr`` payload, or None.

        am_crash: user,pid,process,flags,exception,message,file,line,recoverable
        am_anr:   user,pid,process,flags,reason  (free text may hold commas)
        """
        head = payload.split(",", 4)
        if len(head) < 5 or not head[1].strip().isdigit():
            return None
        pid, process, rest = int(head[1]), head[2].strip(), head[4]
        if kind == "anr":
            return pid, process, rest.strip()
        exception, _, tail = rest.partition(",")
        message = tail.rsplit(",", 3)[0] if tail.count(",") >= 3 else tail
        detail = ": ".join(p for p in (exception.strip(), message.strip()) if p)
        return pid, process, detail

    @classmethod
    def _am_event_records_for(cls, events_buf: str, package: str, pid,
                              since: Optional[float], utc_offset: Optional[int] = None,
                              now: Optional[float] = None) -> List[Tuple[str, str]]:
        """``(label, detail)`` of the target's am_crash / am_anr events, oldest first.

        Matched by *pid*, else by *package* or ``package:sub``; lines older than
        *since* are dropped when timeable."""
        if not events_buf or not (pid or package):
            return []
        records = []
        for line in events_buf.splitlines():
            m = cls._AM_EVENT_RE.search(line)
            parsed = cls._parse_am_event_payload(m.group(1), m.group(2)) if m else None
            if parsed is None or not cls._am_event_is_target(parsed, package, pid):
                continue
            if cls._logcat_line_too_old(line, since, utc_offset, now):
                continue
            label = "ANR" if m.group(1) == "anr" else "am_crash"
            records.append((label, parsed[2] or parsed[1]))
        return records

    @staticmethod
    def _am_event_is_target(parsed, package: str, pid) -> bool:
        event_pid, process, _ = parsed
        if pid:
            return event_pid == int(pid)
        return bool(package) and (process == package or process.startswith(package + ":"))

    @classmethod
    def _logcat_line_too_old(cls, line: str, since: Optional[float],
                             utc_offset: Optional[int], now: Optional[float]) -> bool:
        """True when a threadtime logcat *line* is provably older than *since*."""
        if since is None or utc_offset is None:
            return False
        m = cls._LOGCAT_THREADTIME_RE.match(line)
        if not m:
            return False
        month, day, hour, minute, second = (int(g) for g in m.groups()[:5])
        stamp = cls._logcat_line_epoch(month, day, hour, minute, second, utc_offset, now)
        return stamp is not None and stamp < since

    @classmethod
    def _select_crash_evidence(cls, tombstone_path: Optional[str], minidumps: List[str],
                               am_records: List[Tuple[str, str]]) -> Optional[Tuple[str, str]]:
        """Strongest ``(label, detail)``: tombstone > newest minidump > latest am_crash > ANR."""
        candidates = {}
        if tombstone_path:
            candidates["tombstone"] = tombstone_path
        if minidumps:
            candidates["minidump"] = minidumps[0]
        for label, detail in am_records:
            candidates[label] = detail  # later records win
        for label in cls.CRASH_EVIDENCE_PRIORITY:
            if candidates.get(label):
                return label, candidates[label]
        return None

    def _android_crash_helper(self):
        """The capture's :class:`Android` helper, else a new one; may raise."""
        existing = getattr(self.pcap_obj, "android_Instance", None) if self.pcap_obj else None
        if existing is not None:
            return existing
        from ..android import Android
        serial = self.device_id or getattr(self.device, "id", None)
        return Android(device_id=serial)

    def _crash_target_package(self, target: str) -> str:
        """Package whose app-private crash evidence to search.

        A PID attach uses the resolved process name, minus any ``:sub`` suffix
        (data dirs are per package)."""
        target = (target or "").strip()
        if target and not target.isdigit():
            return target
        resolved = getattr(self, "resolved_process_name", None) or ""
        return resolved.split(":", 1)[0].strip() or target

    def _collect_app_minidumps(self, andy, package, since, writer) -> List[str]:
        """New app-private Gecko/Crashpad minidumps of *package*, logged; never raises."""
        lister = getattr(andy, "list_app_minidumps", None)
        try:
            listing = lister(package) if lister is not None else ""
            dumps = self._new_minidumps_from_stat(
                listing if isinstance(listing, str) else "", since)
        except Exception:
            self.logger.debug("app minidump discovery failed", exc_info=True)
            return []
        if dumps:
            self._write_crash_section(writer, "app minidumps (new this session)",
                                      "\n".join(dumps))
        return dumps

    def _collect_am_events(self, andy, package, pid, since, utc_offset, now,
                           writer) -> List[Tuple[str, str]]:
        """The target's am_crash / am_anr records from the events buffer, logged; never raises."""
        reader = getattr(andy, "get_events_logcat", None)
        try:
            buf = reader() if reader is not None else ""
            records = self._am_event_records_for(
                buf if isinstance(buf, str) else "", package, pid, since, utc_offset, now)
        except Exception:
            self.logger.debug("events-buffer crash lookup failed", exc_info=True)
            return []
        if records:
            self._write_crash_section(writer, "logcat -b events (am_crash/am_anr)",
                                      "\n".join(f"{lbl}: {d}" for lbl, d in records))
        return records

    def _enrich_crash_log_android(self, crash, writer):
        """Log the tombstone and ``logcat -b crash`` of the crashed process; return
        ``(signal, abort_message)`` parsed from them.

        frida's own report often lacks the ART "Abort message". ``(None, None)``
        off Android; never raises. Device I/O lives on :class:`Android`.
        """
        self._android_crash_evidence = None
        if not self._is_android_target():
            return None, None
        try:
            andy = self._android_crash_helper()
            rooted = andy.adb_check_root()
        except Exception:
            return None, None

        pid = self.pid or (getattr(crash, "pid", None) if crash is not None else None)
        keep = (self.target_app or "").split()[-1] if self.target_app else ""
        sig = abort = None

        # Compare on the device's own clock and timezone, or not at all.
        device_clock, utc_offset = self._read_device_clock(andy)
        since = self._crash_evidence_since(device_clock)
        device_now = device_clock[0] if device_clock else None

        if not rooted:
            # Tombstones, the crash buffer and app-private minidumps need root;
            # the events buffer (am_crash / am_anr) is readable as shell.
            if writer is not None:
                writer.write("\n# Android crash enrichment skipped: device not rooted\n")
            am_records = self._collect_am_events(
                andy, self._crash_target_package(keep), pid, since, utc_offset,
                device_now, writer)
            self._android_crash_evidence = self._select_crash_evidence(None, [], am_records)
            return None, None

        # The crash buffer has ART's 'Fatal signal' + 'Abort message' right away
        # (no tombstone-write race).
        crash_buf = andy.get_crash_logcat()
        if crash_buf:
            # The buffer is device-wide and keeps hours of entries: only this
            # pid's (or its crash_dump's) lines from this session count, else an
            # older SIGSEGV of another app is reported as ours.
            ours = self._crash_buffer_lines_for(
                crash_buf, pid, since, utc_offset, device_now)
            self._write_crash_section(
                writer, "logcat -b crash", ours or (
                    f"# no crash-buffer entries for pid {pid} since the session "
                    "started (unrelated entries ignored)"))
            s, a = self._parse_crash_cause(ours, None)
            sig, abort = sig or s, abort or a

        # Newest tombstone matched to the target by pid / cmdline.
        tombstone_path, tombstone = andy.get_latest_tombstone(pid, keep)
        if tombstone and self._tombstone_predates(tombstone, since, utc_offset):
            self._write_crash_section(
                writer, f"tombstone {tombstone_path}",
                "# ignored: written before this session started")
            tombstone = ""
        if tombstone:
            self._write_crash_section(writer, f"tombstone {tombstone_path}", tombstone)
            s, a = self._parse_crash_cause(tombstone, None)
            sig, abort = sig or s, abort or a

        # Gecko / Crashpad apps write their own minidumps and often no tombstone.
        package = self._crash_target_package(keep)
        minidumps = self._collect_app_minidumps(
            andy, package, self._minidump_since(since), writer)
        am_records = self._collect_am_events(
            andy, package, pid, since, utc_offset, device_now, writer)
        self._android_crash_evidence = self._select_crash_evidence(
            tombstone_path if tombstone else None, minidumps, am_records)

        if writer is not None:
            try:
                writer.flush()
            except Exception:
                pass
        return sig, abort

    @staticmethod
    def _parse_crash_cause_ios(report) -> Tuple[Optional[str], Optional[str]]:
        """``(signal, abort_message)`` of a parsed iOS crash report (parsing is in friTap.ios).

        Signal falls back to the Mach exception type, which may be all a report has.
        """
        if report is None:
            return None, None
        collapse = lambda text: " ".join(str(text or "").split())  # noqa: E731
        signal_name = collapse(getattr(report, "signal", "")) or \
            collapse(getattr(report, "exception_type", ""))
        abort = (
            collapse(getattr(report, "termination_reason", ""))
            or collapse(getattr(report, "asi", ""))
            or collapse(getattr(report, "exception_subtype", ""))
        )
        return signal_name or None, abort or None

    def _enrich_crash_log_ios(self, crash, writer):
        """Log the crashed iOS process's ReportCrash ``.ips``; return ``(signal, abort_message)``.

        ``(None, None)`` off iOS or without libimobiledevice; never raises.
        Stores the decoded verdict for the guidance block.
        """
        if not self._is_ios_target():
            return None, None
        try:
            from ..ios import IOS
            # Explicit device id wins, else the frida device id (the UDID).
            serial = self.device_id or getattr(self.device, "id", None)
            helper = IOS(device_id=serial)
            if not helper.check_idevicecrashreport_availability():
                if writer is not None:
                    writer.write(
                        "\n# iOS crash enrichment skipped: idevicecrashreport not available\n")
                return None, None
        except Exception:
            return None, None

        try:
            pid = self.pid or (getattr(crash, "pid", None) if crash is not None else None)
            process_name = (self.target_app or "").split()[-1] if self.target_app else ""
            # Reports accumulate for weeks; newer_than drops older ones.
            newer_than = (getattr(self, "_session_start_time", None) or time.time()) \
                - IOS_CRASH_REPORT_CLOCK_TOLERANCE
            report = helper.get_latest_crash_report(
                process_name, pid=pid, newer_than=newer_than)
            if report is None:
                return None, None
            self._ios_crash_report = report
            self._write_crash_section(
                writer, f"iOS crash report {report.path}", report.raw)
            summary, verdict = helper.describe_crash(report)
            self._ios_crash_verdict = verdict
            self._write_crash_section(writer, "iOS crash summary", summary)
            if writer is not None:
                try:
                    writer.flush()
                except Exception:
                    pass
            return self._parse_crash_cause_ios(report)
        except Exception:
            self.logger.debug("iOS crash enrichment failed", exc_info=True)
            return None, None

    def _is_local_macos_target(self) -> bool:
        """True when the target runs on this macOS host, so reports land in its DiagnosticReports."""
        if self._query_os_id().os_id != "macos":
            return False
        return getattr(getattr(self, "device", None), "type", "") == "local"

    def _enrich_crash_log_macos(self, crash, writer):
        """Log the local ReportCrash ``.ips`` of the dead macOS target; return ``(signal, detail)``.

        ``(None, None)`` off local macOS or if no report appears within the bounded wait.
        """
        self._macos_crash_report = None
        if not self._is_local_macos_target():
            return None, None
        from ..macos_crash import (
            LOCAL_CRASH_REPORT_CLOCK_TOLERANCE,
            describe_local_crash_cause,
            wait_for_local_crash_report,
        )
        pid = self.pid or (getattr(crash, "pid", None) if crash is not None else None)
        start = getattr(self, "_session_start_time", None)
        newer_than = start - LOCAL_CRASH_REPORT_CLOCK_TOLERANCE if start else None
        report = wait_for_local_crash_report(pid, newer_than)
        if report is None:
            return None, None
        self._macos_crash_report = report
        self._write_crash_section(writer, f"macOS crash report {report.path}", report.raw)
        return describe_local_crash_cause(report)

    @staticmethod
    def _ios_crash_guidance(breadcrumb, verdict, spawn, access="") -> List[str]:
        """User-facing guidance lines for a dead iOS target (pure, for tests).

        Order: the breadcrumb first (no hook installed vs a hook broke the app),
        then the OS's decoded reason, then what to try next.
        """
        breadcrumb = breadcrumb or ""
        lines = ["iOS target died while friTap was instrumenting it."]

        # Must match the wording in friTap.friTap._script_load_timeout_hints.
        if breadcrumb.startswith("agent-init"):
            lines.append(
                f"  The agent died before any hook was installed "
                f"(last agent stage: {breadcrumb})."
            )
        elif breadcrumb.startswith("install-phase"):
            lines.append(
                f"  The agent died while installing hooks "
                f"(last agent stage: {breadcrumb})."
            )
        elif breadcrumb:
            lines.append(f"  Last agent stage: {breadcrumb}.")
        else:
            lines.append("  The agent never reported a startup stage.")

        # Decoded by friTap.ios.decode_terminator.
        if verdict is not None:
            lines.append(f"  Crash report says: {getattr(verdict, 'verdict', verdict)}")
            next_step = getattr(verdict, "next_step", "")
            if next_step:
                lines.append(f"  -> {next_step}")
        else:
            lines.append(
                "  No iOS crash report could be decoded (install libimobiledevice "
                "and keep the device connected so friTap can pull the ReportCrash "
                ".ips file)."
            )

        if spawn:
            lines.append(
                "  -> Start the app yourself, then ATTACH friTap (run WITHOUT -s): "
                "spawn-time instrumentation of a gated app is the most fragile "
                "path on iOS."
            )
        else:
            lines.append(
                "  -> friTap was attaching (no -s), so the app was already up: "
                "retry the other way round (spawn with -s) to instrument before "
                "the app's own startup work runs."
            )
        lines.append(
            "  -> Re-run with --probe to isolate the failing agent stage."
        )
        lines.append(
            "  -> Re-run with `fritap --modern`: the modern path does not write "
            "into the SSL_CTX struct at all, so if that run survives, the crash "
            "is a wrong keylog-callback offset for this library build."
        )
        if access == "jailed":
            lines.append(
                "  Note: frida reports jailed access. Either no frida-server is "
                "running on the device (frida-core fell back to its ADB/USB-only "
                "mode) — start it, e.g. via the TUI's Server Check -> Install "
                "or `afrim` — or the target is a "
                "frida-gadget-injected app: then spawning other apps is not "
                "possible, so relaunch the Gadget-patched app manually and "
                "re-check that it was re-signed with the Gadget embedded."
            )
        elif access == "full":
            lines.append(
                "  Note: frida reports full device access (device-wide "
                "frida-server). Verify frida-server itself is healthy and "
                "properly signed (`frida-ps -Ua`) before blaming the hooks."
            )
        return lines

    def _report_target_crash(self, reason: str, crash=None) -> None:
        """Report an unexpected target death with its real cause.

        A hook crash or native abort arrives as a ``process-terminated`` detach
        (else only as "Backend transport error: the connection is closed"). The
        cause comes from frida's Crash plus platform evidence, all written to a
        debug log opened even without --debug. Sets ``_crash_reported`` so the
        transport-error handler stays quiet.
        """
        self._crash_reported = True
        crumb = self._last_hook_breadcrumb

        log_path, writer = self._open_crash_debug_log()

        crash_report = getattr(crash, "report", None) if crash is not None else None
        crash_summary = getattr(crash, "summary", None) if crash is not None else None
        self._write_native_crash_report(writer, crash_report)
        signal_name, abort_msg, macos_report_path = self._decode_crash_cause(
            crash, writer, crash_report, crash_summary)

        have_real_cause = bool(signal_name or abort_msg)
        # Tombstone / minidump / am_crash / ANR prove a crash even without a signal.
        android_evidence = getattr(self, "_android_crash_evidence", None)
        # Clean exit: no evidence, attach mode, and the agent fully initialised
        # with no hook in flight (a short-lived target that finished). An empty
        # or partial breadcrumb means it died before init completed: a crash.
        clean_exit = (not have_real_cause and not self.spawn
                      and crumb == "agent-init: complete" and not android_evidence)
        # Hooks are blamed only on evidence (a frida Crash, signal or abort), and
        # "inside a hook" only when the native report names an instrumented
        # module. A bare 'process-terminated' (kill -9, ANR kill, normal exit) is
        # reported neutrally.
        crash_evidence = have_real_cause or crash is not None or bool(android_evidence)
        plain_termination = not crash_evidence and not clean_exit
        hook_module = (self._instrumented_module_in_crash(crash_report, crumb)
                       if crash_evidence else None)
        headline = self._crash_headline(
            signal_name, abort_msg, crash_evidence, clean_exit, hook_module, crumb,
            report_path=macos_report_path, evidence=android_evidence)
        # Quoted by _report_death_before_capture as the specific reason.
        self._termination_headline = headline
        # Clean exit: info, no guidance or crash pointer. Plain termination:
        # warning, since nothing proves a crash.
        if clean_exit:
            self.logger.info(headline)
        elif plain_termination:
            self.logger.warning(headline)
        else:
            self.logger.error(headline)

        # Guidance applies to attach-mode crashes too. Anti-tamper is claimed
        # only on evidence; PairIP is never guessed for a normal app.
        if reason == "process-terminated" and not clean_exit:
            self._log_crash_guidance(crumb, plain_termination, have_real_cause)

        # A clean exit must not mark the session as crashed.
        if not clean_exit:
            self._log_crash_outcome(log_path, plain_termination, crash_evidence, headline)

    def _open_crash_debug_log(self):
        """Arm the debug log (even without --debug); ``(log_path, writer)``, each None on failure."""
        log_path = None
        writer = None
        try:
            from ..fritap_utility import (
                attach_file_handlers,
                get_debug_log_writer,
                open_debug_log,
            )
            log_path = open_debug_log()
            attach_file_handlers()
            writer = get_debug_log_writer()
        except Exception:
            pass
        return log_path, writer

    @staticmethod
    def _write_native_crash_report(writer, crash_report) -> None:
        """Persist frida's native crash report to the debug log (never raises)."""
        if writer is not None and crash_report:
            try:
                writer.write("\n===== NATIVE CRASH REPORT (frida) =====\n")
                writer.write(str(crash_report) + "\n")
                writer.write("=======================================\n")
            except Exception:
                pass

    def _decode_crash_cause(self, crash, writer, crash_report, crash_summary):
        """``(signal_name, abort_msg, macos_report_path)`` from frida's report and the platform evidence."""
        # Must not raise: _crash_reported is already True, so a raise would
        # leave neither the headline nor the transport-error hint.
        try:
            signal_name, abort_msg = self._parse_crash_cause(crash_report, crash_summary)
        except Exception:
            signal_name, abort_msg = None, None
            self.logger.debug("crash cause parsing failed", exc_info=True)

        # Android also yields the ART abort message frida's report may lack.
        self._android_crash_evidence = None
        try:
            enrich_sig, enrich_abort = self._enrich_crash_log_android(crash, writer)
            signal_name = signal_name or enrich_sig
            abort_msg = abort_msg or enrich_abort
        except Exception:
            self.logger.debug("android crash enrichment failed", exc_info=True)

        try:
            enrich_sig, enrich_abort = self._enrich_crash_log_ios(crash, writer)
            signal_name = signal_name or enrich_sig
            abort_msg = abort_msg or enrich_abort
        except Exception:
            self.logger.debug("ios crash enrichment failed", exc_info=True)

        # macOS only without a signal so far: it may poll briefly for ReportCrash.
        macos_report_path = None
        if not signal_name:
            try:
                enrich_sig, enrich_abort = self._enrich_crash_log_macos(crash, writer)
                signal_name = signal_name or enrich_sig
                abort_msg = abort_msg or enrich_abort
                if enrich_sig or enrich_abort:
                    macos_report_path = self._macos_crash_report.path
            except Exception:
                self.logger.debug("macos crash enrichment failed", exc_info=True)
        return signal_name, abort_msg, macos_report_path

    def _log_crash_guidance(self, crumb, plain_termination, have_real_cause) -> None:
        """Platform-aware guidance for a 'process-terminated' that was not a clean exit."""
        if self._is_ios_target():
            # The iOS crash report beats any heuristic and exists in attach mode too.
            ios_report = getattr(self, "_ios_crash_report", None)
            if ios_report is not None:
                self.logger.error("iOS crash report: %s", ios_report.summary)
            for line in self._ios_crash_guidance(
                    crumb, getattr(self, "_ios_crash_verdict", None), self.spawn,
                    self._query_os_id().access):
                self.logger.error(line)
        elif self.spawn:
            self._log_spawn_crash_guidance(crumb, plain_termination, have_real_cause)

    def _log_spawn_crash_guidance(self, crumb, plain_termination, have_real_cause) -> None:
        """Spawn-mode guidance: anti-tamper evidence, a Wine launch, or the attach-mode advice."""
        if self._anti_tamper_seen:
            self.logger.error(
                f"Anti-tamper protection was detected in this process "
                f"({self._anti_tamper_seen}). It self-destructs when friTap's hooks "
                f"are present during startup.")
            self.logger.error(
                "  -> Spawn (-s) capture is unreliable on such apps even with "
                "--no-loader-hook, because the TLS-library hooks themselves are "
                "present during the startup integrity scan.")
            self.logger.error(
                "  -> Start the app first, then ATTACH friTap (run WITHOUT -s). "
                "See fkie-cad/friTap#64.")
        elif self._target_is_wine():
            self._log_wine_crash_hint()
        else:
            if plain_termination and self._capture_produced_output():
                # A short-lived target (e.g. curl) finished its work: no advice.
                pass
            elif plain_termination:
                # No crash evidence: do not guess a hook crash or PairIP.
                self.logger.warning(
                    "  -> If nothing stopped the target externally, try starting "
                    "the app first, then ATTACH friTap (run WITHOUT -s). "
                    "See fkie-cad/friTap#64.")
            elif have_real_cause:
                # Cause is in the headline: no PairIP guess. The breadcrumb may
                # come from a different thread than the crashing one.
                if crumb:
                    self.logger.error(
                        f"  Note: the last agent hook activity was '{crumb}', but it may "
                        f"have run on a different thread and be unrelated to the crash above.")
                self.logger.error(
                    "  -> Spawn-time instrumentation can destabilize fragile app startup. "
                    "Try starting the app first, then ATTACH friTap (run WITHOUT -s). "
                    "See fkie-cad/friTap#64.")
            elif self._is_android_target():
                # No cause on Android: anti-tamper (PairIP) offered only as a possibility.
                self.logger.error(
                    "This may be an anti-tamper protection (e.g. Google PairIP / "
                    "libpairipcore.so) self-destructing in response to friTap's hooks "
                    "during app startup.")
                self.logger.error(
                    "  -> Try starting the app first, then ATTACH friTap (run WITHOUT -s). "
                    "See fkie-cad/friTap#64.")
            else:
                self.logger.error(
                    "  -> Spawn-time instrumentation can destabilize fragile app startup. "
                    "Try starting the app first, then ATTACH friTap (run WITHOUT -s). "
                    "See fkie-cad/friTap#64.")

    def _log_wine_crash_hint(self) -> None:
        """Hint for a spawned Wine target that terminated (root + WINEPREFIX, or common Wine causes)."""
        import os as _os
        running_as_root = False
        try:
            running_as_root = _os.geteuid() == 0
        except Exception:
            running_as_root = False
        if running_as_root:
            self.logger.error(
                "Hint: target was launched via Wine and friTap is running as "
                "root. The most common cause is sudo + a user-owned WINEPREFIX "
                "(Wine refuses the prefix and exits before any TLS hook runs).")
            self.logger.error(
                "  -> Recommended: drop sudo and run friTap as your desktop user "
                "(ensure `sysctl kernel.yama.ptrace_scope=0` so Frida can attach).")
            self.logger.error(
                "  -> Alternative: set WINEPREFIX=/root/.wine so Wine creates a "
                "fresh root-owned prefix. See docs/platforms/wine.md.")
        else:
            self.logger.error(
                "Hint: Wine target terminated unexpectedly. Common Wine causes: "
                "(a) the target is a single-instance app (e.g. VLC) that handed "
                "off to an existing instance and exited; (b) the spawned binary "
                "needs a prefix init (`wine wineboot`); (c) an early-startup "
                "anti-cheat / DRM aborted.")
            self.logger.error(
                "  -> Try attach mode: start the app yourself with `wine ...`, "
                "then `fritap -k keys.log your_app.exe`. See "
                "docs/platforms/wine.md.")

    def _log_crash_outcome(self, log_path, plain_termination, crash_evidence, headline) -> None:
        """Point at the debug log and, on crash evidence, emit the fatal ErrorEvent."""
        if log_path and plain_termination:
            self.logger.warning(f"Hook activity written to: {log_path}")
        elif log_path:
            self.logger.error(f"Full crash report + hook activity written to: {log_path}")
        # Only crash evidence is an error. A kill or exit is already carried by
        # on_detach's DetachEvent and the exit code, not a fatal `error` record.
        if crash_evidence:
            try:
                from ..events import ERROR_SEVERITY_FATAL, ErrorEvent
                self._event_bus.emit(ErrorEvent(
                    error="Target process crashed",
                    description=headline,
                    severity=ERROR_SEVERITY_FATAL,
                ))
            except Exception:
                pass

    # Native-report markers of friTap's own injected code (agent / Gum
    # trampolines): a crash with one of these on the stack happened in a hook.
    _FRIDA_AGENT_STACK_MARKERS = ("frida-agent", "frida-gadget", "frida_agent_main",
                                  "gum-js-loop", "gumjs")

    def _instrumented_module_names(self, crumb: str) -> List[str]:
        """Agent markers, detected libraries and the breadcrumb's module.

        No Frida calls: runs on the fritap-detach thread."""
        names = list(self._FRIDA_AGENT_STACK_MARKERS)
        try:
            detected = list(getattr(self, "_detected_libraries", None) or ())
        except RuntimeError:  # set mutated concurrently by the router thread
            detected = []
        names.extend(os.path.basename(str(lib)) for lib in detected if lib)
        if crumb and ":" in crumb:
            tail = crumb.rsplit(":", 1)[1].strip()
            if re.search(r"\.(so|dll|dylib)\b", tail):
                names.append(os.path.basename(tail))
        return [n for n in names if n]

    def _instrumented_module_in_crash(self, crash_report, crumb: str) -> Optional[str]:
        """The first instrumented module named in the native crash report, if any."""
        if not crash_report:
            return None
        report = str(crash_report).lower()
        for name in self._instrumented_module_names(crumb):
            if name.lower() in report:
                return name
        return None

    @staticmethod
    def _crash_headline(signal_name, abort_msg, crash_evidence, clean_exit,
                        hook_module, crumb, report_path=None, evidence=None) -> str:
        """One-line verdict for an unexpected target death.

        *report_path* is the OS crash report used; *evidence* the Android
        ``(label, detail)`` from :meth:`_select_crash_evidence`."""
        evidence_note = f" ({evidence[0]}: {evidence[1]})" if evidence else ""
        if signal_name or abort_msg:
            cause = signal_name or "native crash"
            if abort_msg:
                cause += f": {abort_msg}"
            headline = f"Target process terminated unexpectedly — {cause}"
            if hook_module:
                headline += f" (native stack in instrumented module {hook_module})"
            if report_path:
                headline += f" (crash report: {report_path})"
            return headline + evidence_note
        if clean_exit and not evidence:
            return ("Target process exited "
                    "(no crash detected; last agent stage: agent-init: complete)")
        if not crash_evidence and not evidence:
            headline = ("Target process terminated (no crash evidence; possibly "
                        "killed/force-stopped)")
            return headline + (f" (last agent stage: {crumb})" if crumb else "")
        if hook_module:
            headline = ("Target process terminated unexpectedly — it crashed inside an "
                        f"instrumented hook (native stack in {hook_module})") + evidence_note
            return headline + (f" (last instrumented: {crumb})" if crumb else "")
        if evidence:
            headline = ("Target process terminated — not responding" if evidence[0] == "ANR"
                        else "Target process crashed") + evidence_note
            return headline + (f" (last agent stage: {crumb})" if crumb else "")
        headline = "Target process terminated unexpectedly — native crash (cause not decoded)"
        return headline + (f" (last agent stage: {crumb})" if crumb else "")

    def on_process_crashed(self, crash) -> None:
        """Device ``process-crashed`` handler: stash frida's Crash for the ``detached`` report.

        The signal is device-wide, so a crash whose pid differs from the target's
        (both known) is ignored rather than misattributed.
        """
        crash_pid = getattr(crash, "pid", None) if crash is not None else None
        if self.pid is not None and crash_pid is not None and crash_pid != self.pid:
            return
        self._pending_crash = crash

    # Android only: an ART abort caused by the detach (e.g. "attempting to
    # detach while still running code") lands about 1 s after it.
    POST_DETACH_WATCH_SECONDS = 2.5
    POST_DETACH_POLL_SECONDS = 0.5

    # Whether the target pid ran when friTap's detach began: None = not checked.
    _target_alive_at_detach = None

    def _is_watchable_target(self) -> bool:
        """An Android target with a known pid that friTap has not reported as gone."""
        return (self.pid is not None
                and not getattr(self, "_target_gone", False)
                and not getattr(self, "_crash_reported", False)
                and self._is_android_target())

    def _should_watch_after_detach(self) -> bool:
        """True when friTap itself detached from a live Android target it has not reported as gone."""
        return getattr(self, "_main_session_detached", False) and self._is_watchable_target()

    def _note_target_alive_at_detach(self) -> None:
        """Record whether the target still ran when the detach began (one device query).

        Lets the post-detach report tell a death during the earlier teardown
        (e.g. a long capture pull) from one caused by the detach. Never raises."""
        try:
            if self._target_alive_at_detach is None and self._is_watchable_target():
                self._target_alive_at_detach = self._target_pid_alive()
        except Exception:  # noqa: BLE001 - teardown must not break on the check
            self.logger.debug("pre-detach liveness check failed", exc_info=True)

    def _target_pid_alive(self) -> Optional[bool]:
        """Whether the target pid still runs on the device; None when the device cannot tell."""
        try:
            processes = self._backend.enumerate_processes(self.device)
        except Exception:  # noqa: BLE001 - a failed check must not break teardown
            self.logger.debug("post-detach liveness check failed", exc_info=True)
            return None
        return any(p.pid == self.pid for p in processes)

    def _target_died_after_detach(self) -> bool:
        """Poll the target for POST_DETACH_WATCH_SECONDS; True as soon as it is gone."""
        deadline = time.monotonic() + self.POST_DETACH_WATCH_SECONDS
        while True:
            alive = self._target_pid_alive()
            if alive is None:
                return False
            if not alive:
                return True
            if time.monotonic() >= deadline:
                return False
            time.sleep(self.POST_DETACH_POLL_SECONDS)

    def _report_crash_after_detach(self) -> None:
        """Report a target that died during friTap's teardown or detach.

        on_detach ignores events once teardown has begun, and after
        session.detach() frida sends none, so without this check such a crash
        ended in a clean-looking exit. Never raises.
        """
        try:
            if not self._should_watch_after_detach():
                return
            self._post_detach_check_running = True
            if not self._target_died_after_detach():
                return
            self._crash_reported = True
            crash = getattr(self, "_pending_crash", None)
            if crash is not None:
                # frida's Crash already proves it: set the status before the slow
                # device enrichment, which a main-thread exit could cut short.
                self.set_exit_status(EXIT_TARGET_DETACHED)
            log_path, writer = self._open_crash_debug_log()
            crash_report = getattr(crash, "report", None) if crash is not None else None
            self._write_native_crash_report(writer, crash_report)
            signal_name, abort_msg, _ = self._decode_crash_cause(
                crash, writer, crash_report, getattr(crash, "summary", None))
            evidence = getattr(self, "_android_crash_evidence", None)
            crashed = bool(signal_name or abort_msg or evidence or crash is not None)
            cause = ": ".join(c for c in (signal_name, abort_msg) if c)
            if not cause and evidence:
                cause = f"{evidence[0]}: {evidence[1]}"
            verdict = "crashed" if crashed else "exited"
            when = ("during friTap's teardown, before its detach"
                    if self._target_alive_at_detach is False
                    else "during or right after friTap's detach")
            headline = (f"Target process {self.pid} {verdict} {when}"
                        + (f" ({cause})" if cause else "")
                        + "; the capture itself is complete")
            self._termination_headline = headline
            if crashed:
                self.logger.error(headline)
                self._log_crash_outcome(log_path, False, True, headline)
                self.set_exit_status(EXIT_TARGET_DETACHED)
            else:
                self.logger.warning(headline)
        except Exception:  # noqa: BLE001 - teardown must not break on the report
            self.logger.debug("post-detach crash check failed", exc_info=True)
        finally:
            self._post_detach_check_running = False
