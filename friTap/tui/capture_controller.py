#!/usr/bin/env python3

"""
Capture controller -- manages the capture lifecycle extracted from MainScreen.

Handles config building, session start/stop, background worker management,
and post-session UI cleanup.
"""

from __future__ import annotations

import logging
import os
import shlex
import time

from friTap.constants import build_infrastructure_display_filter
from friTap.events import ERROR_SEVERITY_ERROR, ERROR_SEVERITY_FATAL
from friTap.tui.themes import c

from .modals.alert_modal import AlertModal

logger = logging.getLogger("friTap.tui.capture")

try:
    from textual.widgets import Static
    TEXTUAL_AVAILABLE = True
except ImportError:
    TEXTUAL_AVAILABLE = False


from friTap.flow.models import format_byte_size  # noqa: E402
from friTap.protocols.mtproto_hints import ATTACH_MEMORY_SCAN_RECOVERY  # noqa: E402

# Shown whenever a STOPPED capture is asked to start again: only an explicit
# wizard restart (r) may launch a new attach/session.
CAPTURE_STOPPED_RESTART_HINT = "Capture stopped — press r to restart the wizard."


def _tokenize_spawn_command(command: str) -> list[str] | None:
    """Split a free-text spawn command into argv tokens, shell-style.

    Unlike the CLI (where the user's shell already tokenized into argv), the TUI
    spawn modal receives one raw string. Tokenize it like a shell so a target
    path with spaces survives when quoted, e.g.
    ``wine "/.../Program Files/App/app.exe"`` -> ['wine', '/.../Program Files/App/app.exe'].

    Backslashes are treated as literal (escape disabled) so Windows-style paths
    such as ``wine "C:\\Program Files\\App\\app.exe"`` are NOT mangled — unlike a
    plain ``shlex.split``, which only preserves them inside quotes.

    Returns the token list, or None on unbalanced quotes (the caller then falls
    back to the legacy whitespace split).
    """
    lex = shlex.shlex(command, posix=True)
    lex.whitespace_split = True
    lex.escape = ""  # backslash is a literal path separator, not an escape
    try:
        return list(lex)
    except ValueError:
        # Unbalanced quotes — let the caller fall back to target.split(" ").
        return None


def _selected_protocols(state) -> list[str]:
    """The TUI state's protocol set, with the primary ``state.protocol`` first.

    Falls back to ``[state.protocol]`` when ``state.protocols`` is missing or
    out of sync with the primary (a caller that only set ``state.protocol``).
    """
    primary = getattr(state, 'protocol', 'tls')
    protocols = list(getattr(state, 'protocols', None) or [])
    if not protocols or protocols[0] != primary:
        return [primary]
    return protocols


def _count_keys(path: str) -> int | None:
    """Count non-empty, non-comment lines in a keylog file."""
    try:
        with open(path) as f:
            return sum(
                1 for line in f
                if (s := line.strip()) and not s.startswith("#")
            )
    except OSError:
        return None


# Results-modal line for the distinct key total across several keylog files.
KEYLOG_TOTAL_STAT = "Distinct keys (all keylogs)"


def _key_count_label(count: int) -> str:
    """``"1 key"`` / ``"N keys"`` (including ``"0 keys"``)."""
    return f"{count} key{'s' if count != 1 else ''}"


def _same_file_key(path: str) -> str:
    """Normalised path so two spellings of one file compare equal."""
    try:
        return os.path.normcase(os.path.realpath(path))
    except (OSError, ValueError):
        return path


def _get_file_size(path: str) -> int | None:
    """Return file size in bytes, or None if file doesn't exist."""
    try:
        return os.path.getsize(path)
    except OSError:
        return None


def _pcapng_has_packets(f) -> bool:
    """Return True if a pcapng stream contains >=1 packet block."""
    import struct

    head = f.read(12)  # block type (4) + block length (4) + byte-order magic (4)
    if len(head) < 12:
        return False
    bom = head[8:12]
    if bom == b"\x1a\x2b\x3c\x4d":
        endian = ">"
    elif bom == b"\x4d\x3c\x2b\x1a":
        endian = "<"
    else:
        return True  # unknown byte order -> fail open, don't hide a real capture
    packet_block_types = {0x00000006, 0x00000003, 0x00000002}  # EPB, SPB, obsolete PB
    f.seek(0)
    while True:
        block_hdr = f.read(8)
        if len(block_hdr) < 8:
            break
        block_type, block_len = struct.unpack(endian + "II", block_hdr)
        if block_len < 12:
            break  # malformed
        if block_type in packet_block_types:
            return True
        f.seek(block_len - 8, 1)  # advance past the rest of this block
    return False


def _pcap_has_packets(path: str) -> bool:
    """Best-effort check whether a capture file holds >=1 packet.

    Supports pcapng and classic pcap. Fails open (returns True) on any parsing
    uncertainty so a real capture is never hidden; returns False only when the
    file is confidently empty (header only, no packet records).
    """
    try:
        with open(path, "rb") as f:
            magic = f.read(4)
            if len(magic) < 4:
                return False
            if magic == b"\x0a\x0d\x0d\x0a":  # pcapng Section Header Block
                f.seek(0)
                return _pcapng_has_packets(f)
            classic_magics = {
                b"\xa1\xb2\xc3\xd4", b"\xd4\xc3\xb2\xa1",  # microsecond
                b"\xa1\xb2\x3c\x4d", b"\x4d\x3c\xb2\xa1",  # nanosecond
            }
            if magic in classic_magics:
                f.seek(24)  # skip 24-byte global header
                return len(f.read(16)) == 16  # one full record header present
    except OSError:
        return True
    return True


class CaptureController:
    """Manages capture lifecycle -- extracted from MainScreen."""

    # Explicit capture lifecycle state (UI intent), kept distinct from the
    # backend ``SSL_Logger.running`` flag. ``running`` flips synchronously on stop
    # while the UI reset is deferred to the end of a blocking teardown, and a
    # self-terminating scan can leave ``running`` stale — both left a window where
    # the Enter toggle (which only checked ``running``) silently RE-STARTED the
    # capture. This state gates start/stop deterministically instead.
    STATE_IDLE = "idle"
    STATE_RUNNING = "running"
    STATE_STOPPING = "stopping"
    STATE_STOPPED = "stopped"

    def __init__(self, screen) -> None:
        self._screen = screen
        self._ssl_logger = None
        # Capture lifecycle state. IDLE = never started / reset for a fresh run;
        # RUNNING = session live; STOPPING = stop requested, teardown in flight;
        # STOPPED = finished (Enter is a no-op until the wizard is restarted).
        self._capture_state: str = self.STATE_IDLE
        # Generation of the most recently started capture. Each worker remembers
        # the generation it was started with, so a late teardown of an OLD
        # session can never clobber the shared UI state of a newer one.
        self._session_generation: int = 0
        # Set by a stop request. Closes the "starting" window: start_capture
        # enters RUNNING before the worker has built SSL_Logger, so a stop that
        # arrives then has no logger to call request_stop on. The worker checks
        # this flag right after it builds the logger (see _run_session).
        self._stop_requested: bool = False
        # Callback to run once the in-flight session has fully ended (set by a
        # wizard restart requested mid-capture; see restart_when_stopped).
        self._restart_after_stop = None
        self._tui_handler = None
        self._capture_mode: str = ""
        self._flow_collector = None
        self._tap_writer = None
        self._debug_log_file = None
        self._debug_log_writer = None
        self._debug_log_handler = None
        self._debug_log_path: str = ""
        self._prior_friTap_level: int | None = None
        self._session_error: str = ""
        # Severity of the most recent session error. Drives whether the
        # AlertModal at session-end is shown; recovered parser errors
        # (severity="warning") never reach _session_error so the modal
        # stays an exceptional event.
        self._session_error_severity: str = ERROR_SEVERITY_FATAL
        # Category and original exception are populated when the backend
        # raises a BackendError (frida_denied, backend_bug, ...). They
        # remain ``None`` for legacy/unknown error sources.
        self._session_error_category: str | None = None
        self._session_error_original: BaseException | None = None
        # Set when the EventBus reports the target process crashed/terminated
        # (fatal ErrorEvent or process-terminated DetachEvent). The capture
        # worker loop exits NORMALLY on a target crash — no Python exception is
        # raised — so without this flag the results modal would falsely claim
        # the capture "completed". See _run_session / _on_session_ended.
        self._session_crashed: bool = False
        self._session_crash_message: str = ""
        # UI update batching to prevent call_from_thread() storm
        import threading
        self._ui_lock = threading.Lock()
        self._pending_ui_updates: dict[str, tuple] = {}
        self._ui_flush_scheduled: bool = False

    # ----------------------------------------------------------
    # Public properties
    # ----------------------------------------------------------

    @property
    def ssl_logger(self):
        return self._ssl_logger

    @property
    def tui_handler(self):
        return self._tui_handler

    @property
    def capture_mode(self) -> str:
        return self._capture_mode

    @capture_mode.setter
    def capture_mode(self, value: str) -> None:
        self._capture_mode = value

    @property
    def flow_collector(self):
        return self._flow_collector

    @property
    def is_running(self) -> bool:
        """True while a capture is starting or live (a stop would take effect)."""
        return self._capture_state == self.STATE_RUNNING

    @property
    def capture_in_flight(self) -> bool:
        """True from start until the worker's teardown has fully finished."""
        return self._capture_state in (self.STATE_RUNNING, self.STATE_STOPPING)

    # ----------------------------------------------------------
    # Actions
    # ----------------------------------------------------------

    def _warn(
        self, message: str,
        title: str = "Warning", severity: str = "warning",
    ) -> None:
        """Show a warning alert modal and log the message."""
        self._screen.app.push_screen(
            AlertModal(message=message, title=title, severity=severity)
        )
        self._screen._get_activity_log().log_warning(message.replace("\n", " "))

    def _toast(self, message: str, severity: str = "information") -> None:
        """Show a Textual toast notification (visible even in flow view)."""
        try:
            self._screen.app.notify(message, severity=severity)
        except Exception:
            pass

    def reset_capture_state(self) -> None:
        """Return the controller to IDLE so a fresh capture can be started.

        Called when the wizard is restarted (see ``MainScreen.action_restart_wizard``):
        after a capture STOPPED, a bare Enter never re-attaches (the ended session
        cleared target and mode); the wizard restart resets to IDLE here.
        """
        self._capture_state = self.STATE_IDLE

    def restart_when_stopped(self, restart) -> None:
        """Stop the in-flight capture and call ``restart`` once it has ENDED.

        Restarting the wizard while the old worker is still tearing down (frida
        detach, pcap pull, ... — seconds) let that worker's late
        ``_on_session_ended`` wipe the wizard's freshly chosen target, push the
        old results over the wizard, or tear down a NEW session. So the restart
        is deferred: ``_on_session_ended`` runs ``restart`` after the old
        session's results have been shown.
        """
        already_pending = self._restart_after_stop is not None
        self._restart_after_stop = restart
        log = self._screen._get_activity_log()
        if already_pending:
            log.log_info("Stopping capture — please wait…")
            return
        log.log_info("Stopping capture before restart…")
        if self._capture_state == self.STATE_RUNNING:
            self.action_stop_capture()

    @staticmethod
    def _has_manual_capture_setup(state) -> bool:
        """True when a target and a capture mode are configured (IDLE's checks)."""
        has_mode = bool(
            getattr(state, "keylog_path", "")
            or getattr(state, "pcap_path", "")
            or getattr(state, "live", False)
        )
        return bool(getattr(state, "target", "")) and has_mode

    def action_start_capture(self) -> None:
        """Build config, create SSL_Logger, wire handler, start session."""
        # RUNNING/STOPPING refuse. STOPPED starts only when the user has
        # configured a NEW capture by hand (a/s target + 1-6 mode): the ended
        # session cleared target and mode, so a bare Enter can never silently
        # re-attach the old session; with nothing configured it points at r.
        if self._capture_state == self.STATE_RUNNING:
            self._warn(
                "Capture already running.\nPress [bold]Enter[/] to stop first.",
            )
            return
        state = self._screen._get_state()
        if self._capture_state == self.STATE_STOPPING or (
            self._capture_state == self.STATE_STOPPED
            and not self._has_manual_capture_setup(state)
        ):
            self._screen._get_activity_log().log_info(CAPTURE_STOPPED_RESTART_HINT)
            return

        if not state.target:
            self._warn(
                "No target selected.\nPress [bold]a[/] to attach or [bold]s[/] to spawn.",
            )
            return

        if self._ssl_logger and self._ssl_logger.running:
            self._warn(
                "Capture already running.\nPress [bold]Enter[/] to stop first.",
            )
            return

        if not state.keylog_path and not state.pcap_path and not state.live:
            self._warn(
                "No capture mode set.\nPress [bold]1[/]-[bold]4[/] to select a mode.",
            )
            return

        self._check_plugin_compatibility(state)
        self.start_capture(state)

    def _check_plugin_compatibility(self, state) -> None:
        """Warn the user if loaded plugins are incompatible with the selected backend."""
        plugin_loader = getattr(self._screen.app, "_plugin_loader", None)
        if plugin_loader is None:
            return

        backend_name = getattr(state, "backend_name", "frida")
        incompatible = plugin_loader.check_backend_compatibility(backend_name)
        if incompatible:
            names = ", ".join(incompatible)
            self._warn(
                f"The following plugins require the Frida backend "
                f"and will be skipped:\n\n[bold]{names}[/]",
                title="Plugin Warning",
            )

    def action_stop_capture(self) -> None:
        """Stop the active capture session.

        Requests the stop, moves to STOPPING immediately, and gives instant
        feedback (log line + status bar) so the user sees the capture is ending
        without waiting for the blocking teardown to finish. A second press while
        STOPPING/STOPPED is a no-op — this is what stops the old "press again and
        it re-starts" behaviour. ``running`` is flipped synchronously by
        ``request_stop``; the worker ``finally`` block does the actual cleanup and
        ``_on_session_ended`` moves us to STOPPED.

        While the worker is still building SSL_Logger there is no logger to stop
        yet; ``_stop_requested`` makes the worker stop it as soon as it exists.
        """
        if self._capture_state == self.STATE_RUNNING:
            self._capture_state = self.STATE_STOPPING
            # Set BEFORE reading self._ssl_logger: the worker assigns the logger
            # BEFORE reading the flag, so at least one side always sees the other.
            self._stop_requested = True
            self._screen._get_activity_log().log_info("Stopping capture...")
            try:
                mode_display = self._capture_mode or "Custom"
                self._screen._get_status_bar().update_capture("STOPPING", mode_display)
            except Exception:
                pass
            if self._ssl_logger:
                self._ssl_logger.request_stop()
        elif self._capture_state == self.STATE_STOPPING:
            self._screen._get_activity_log().log_info("Stopping capture — please wait…")
        else:
            self._screen._get_activity_log().log_warning("No capture running.")

    def action_toggle_capture(self) -> None:
        """Toggle capture: start when idle, stop when running, no-op otherwise."""
        if self._screen._wizard_guard():
            return
        # Each action owns its per-state feedback: stop handles RUNNING (stop) and
        # STOPPING ("please wait"); start handles IDLE (start) and STOPPED (starts
        # a newly configured capture, else points at the wizard restart).
        if self._capture_state in (self.STATE_RUNNING, self.STATE_STOPPING):
            self.action_stop_capture()
        else:
            self.action_start_capture()

    def action_escape_action(self) -> None:
        """Esc stops capture if running, otherwise does nothing."""
        if self._screen._wizard_guard():
            return
        if self._capture_state == self.STATE_RUNNING:
            self.action_stop_capture()

    # ----------------------------------------------------------
    # Tap recording
    # ----------------------------------------------------------

    def start_tap_recording(self, path: str) -> None:
        """Wire a TapWriter to the active flow collector.

        If capture is still running, subscribes for future COMPLETED events.
        If capture has already ended, writes all flows and closes immediately.
        """
        if self._flow_collector is None:
            self._warn("No flow collector active. Start a capture first.")
            return

        # Close any existing writer before starting a new one
        if self._tap_writer is not None:
            self.stop_tap_recording()

        from friTap.flow.tap_writer import TapWriter

        writer = TapWriter()
        state = self._screen._get_state()
        target = state.target_display or state.target or ""
        writer.open(path, target=target)

        # Write all existing complete flows
        from friTap.flow.models import FlowState
        for flow in self._flow_collector.get_flows():
            if flow.state == FlowState.COMPLETE:
                writer.write_flow(flow)

        session_running = self._ssl_logger and self._ssl_logger.running
        if session_running:
            # Subscribe for future completed flows during live capture
            self._flow_collector.subscribe(writer.on_flow_event)
            self._tap_writer = writer
            self._screen._get_activity_log().log_info(
                f"Saving capture to: [bold]{path}[/]"
            )
            self._toast(f"Recording to {path}")
        else:
            # Capture already ended — close immediately
            writer.close()
            self._screen._get_activity_log().log_info(
                f"Capture saved: [bold]{writer.path}[/] "
                f"({writer.flow_count} flows)"
            )
            self._toast(f"Saved {writer.flow_count} flows to {writer.path}")

    def stop_tap_recording(self) -> None:
        """Close the active TapWriter if any."""
        if self._tap_writer is not None:
            try:
                path = self._tap_writer.path
                self._tap_writer.close()
                count = self._tap_writer.flow_count
                self._screen._get_activity_log().log_info(
                    f"Capture saved: [bold]{path}[/] ({count} flows)"
                )
                self._toast(f"Saved {count} flows to {path}")
            except Exception as e:
                # Surface the save failure as a dismissible modal (via _warn,
                # which also logs it) instead of a transient error toast.
                self._warn(
                    f"Error saving .tap: {e}",
                    title="Save Failed",
                    severity="error",
                )
            finally:
                self._tap_writer = None

    # ----------------------------------------------------------
    # Debug log file
    # ----------------------------------------------------------

    def _open_debug_log_file(self) -> bool:
        """Open the per-session debug file and attach a FileHandler to the
        ``friTap`` logger. Must be called BEFORE ``SSL_Logger.__init__`` so
        the protocol-registry / pattern-loader / device-acquisition records
        emitted during init also land in the file.

        Returns ``True`` if the file is open and the handler is attached.
        """
        import logging as _logging

        try:
            ts = time.strftime("%Y%m%d_%H%M%S")
            self._debug_log_path = f"fritap_debug_{ts}.log"
            self._debug_log_file = open(self._debug_log_path, "w", buffering=1)
            self._debug_log_file.write(
                f"# friTap debug log — started {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n"
            )
        except OSError:
            self._debug_log_file = None
            self._debug_log_writer = None
            return False

        # Make frida-core's GLib output verbose (env var is read by helper
        # subprocesses spawned after this point). This is the only knob
        # frida actually honours; ``FRIDA_DEBUG`` etc. do not exist.
        os.environ.setdefault("G_MESSAGES_DEBUG", "all")

        # Force the friTap logger to DEBUG for the duration of this capture
        # so DEBUG records (e.g. ``Attaching to pre-enumerated device``)
        # actually reach the handler. ``setup_fritap_logging()`` left it at
        # INFO when no debug flag was passed at app start.
        fritap_logger = _logging.getLogger("friTap")
        self._prior_friTap_level = fritap_logger.level
        fritap_logger.setLevel(_logging.DEBUG)
        fritap_logger.propagate = False

        from friTap.fritap_utility import _DEBUG_LOG_FORMATTER
        handler = _logging.StreamHandler(self._debug_log_file)
        handler.setLevel(_logging.DEBUG)
        handler.setFormatter(_DEBUG_LOG_FORMATTER)
        fritap_logger.addHandler(handler)
        self._debug_log_handler = handler
        return True

    def _setup_debug_log(self, event_bus):
        """Subscribe EventBus events to the already-opened debug log.

        ``_open_debug_log_file()`` opened the file and attached the Python
        logging handler before ``SSL_Logger`` was constructed; this method
        layers the EventBus-event prose on top once the bus exists.
        Failures are non-fatal — debug logging never aborts the capture.
        """
        import dataclasses as _dc

        if self._debug_log_file is None:
            # File never opened (open failed or debug logging not requested).
            return

        def _log_event(event):
            target = self._debug_log_file
            if target is None:
                return
            try:
                ts_str = time.strftime("%H:%M:%S")
                evt_name = type(event).__name__
                parts = [f"{ts_str} [{evt_name}]"]
                for f in _dc.fields(event):
                    val = getattr(event, f.name, None)
                    if val is None or val == "" or val == 0:
                        continue
                    if isinstance(val, (bytes, bytearray)):
                        parts.append(f"  {f.name}=<{len(val)} bytes>")
                    else:
                        s = str(val)
                        if len(s) > 200:
                            s = s[:200] + "..."
                        parts.append(f"  {f.name}={s}")
                target.write("\n".join(parts) + "\n\n")
            except Exception:
                pass

        from friTap.events import (
            ConsoleEvent,
            DatalogEvent,
            DetachEvent,
            ErrorEvent,
            KeylogEvent,
            LibraryDetectedEvent,
            OhttpEvent,
            SessionEvent,
        )
        for evt_type in (DatalogEvent, KeylogEvent, ConsoleEvent, ErrorEvent,
                         LibraryDetectedEvent, SessionEvent, DetachEvent,
                         OhttpEvent):
            event_bus.subscribe(evt_type, _log_event)

        try:
            from friTap.events import FlowEvent
            event_bus.subscribe(FlowEvent, _log_event)
        except ImportError:
            pass

        def _notify_ui():
            log = self._screen._get_activity_log()
            if log and self._debug_log_path:
                log.log_info(f"Debug log: [bold]{self._debug_log_path}[/]")
        self._screen.app.call_from_thread(_notify_ui)

    def _close_debug_log(self):
        """Close the per-session debug log file and detach its handler."""
        import logging as _logging

        handler = getattr(self, "_debug_log_handler", None)
        fritap_logger = _logging.getLogger("friTap")
        if handler is not None:
            try:
                fritap_logger.removeHandler(handler)
            except Exception:
                pass
            self._debug_log_handler = None

        # Restore the friTap logger level so subsequent non-debug captures
        # don't keep paying for DEBUG-level processing.
        prior = getattr(self, "_prior_friTap_level", None)
        if prior is not None:
            try:
                fritap_logger.setLevel(prior)
            except Exception:
                pass
            self._prior_friTap_level = None

        if self._debug_log_file is not None:
            try:
                self._debug_log_file.write(
                    f"\n# Capture session ended — {time.strftime('%Y-%m-%d %H:%M:%S')}\n"
                )
                self._debug_log_file.close()
            except Exception:
                pass
            self._debug_log_file = None
        self._debug_log_writer = None

    # ----------------------------------------------------------
    # Config & session
    # ----------------------------------------------------------

    def build_config(self, state):
        """Build a FriTapConfig from AppState."""
        from friTap.config import (
            DeviceConfig,
            FriTapConfig,
            HookingConfig,
            OutputConfig,
        )

        device = DeviceConfig(spawn=state.spawn)
        if state.device_id:
            device.device_id = state.device_id  # Use Frida device ID for pre-enumerated devices
        if state.device_type == "usb":
            # Mark the target as mobile so a full capture routes to the on-device
            # tcpdump path (PCAP.FullCaptureThread.full_mobile_capture) instead of
            # the host-side Scapy /dev/bpf path, which both needs root and cannot
            # see the phone's traffic. Carry the concrete Frida/ADB device id so
            # tcpdump targets the right phone; fall back to True (auto-detect the
            # first USB device). Device selection itself still prefers device_id
            # (see session_manager: the `elif logger.mobile` branch only runs when
            # no device_id is set), so this does not change which device is used.
            device.mobile = state.device_id or True

        output = OutputConfig(
            pcap=state.pcap_path or None,
            keylog=state.keylog_path or None,
            json_output=state.json_path or None,
            verbose=state.verbose,
            live=state.live,
            live_mode=state.live_mode,
            full_capture=state.full_capture,
            owner_capture=getattr(state, "owner_capture", False),
        )

        # In spawn mode, tokenize the typed command into argv so a target path
        # containing spaces survives to device.spawn() (quoted by the user, as in
        # a shell). Attach mode uses state.target verbatim as a process name/PID,
        # so it is never tokenized. None falls back to the legacy split in
        # session_manager for the simple single-token case.
        target_argv = None
        if state.spawn and state.target:
            target_argv = _tokenize_spawn_command(state.target)

        return FriTapConfig(
            target=state.target,
            target_argv=target_argv,
            device=device,
            output=output,
            hooking=HookingConfig(
                library_scan=getattr(state, 'library_scan', False),
                pairip_safe=getattr(state, 'pairip_safe', False),
                intercept=getattr(state, 'intercept', True),
                memory_scan=getattr(state, 'memory_scan', False),
                memory_scan_patterns=getattr(state, 'memory_scan_patterns', None),
                encapsulated_protocols=getattr(
                    state, 'encapsulated_protocols', {"ohttp": True}
                ),
                quic_capture_mode=getattr(state, 'quic_capture_mode', 'stream'),
            ),
            protocol=getattr(state, 'protocol', 'tls'),
            protocols=_selected_protocols(state),
            debug_output=getattr(state, 'debug_log', False),
        )

    def start_capture(self, state) -> None:
        """Build config, wire TUI handler, start session on background thread.

        SSL_Logger creation (which includes FIFO setup) runs on the
        background thread to prevent the blocking FIFO open from
        freezing the Textual event loop.
        """
        from friTap.tui.handlers import TuiOutputHandler

        self._pending_config = self.build_config(state)
        self._tui_handler = TuiOutputHandler(self._screen.app)

        # Create FlowCollector for data-producing modes
        data_modes = {"full", "plaintext", "wireshark", "live_pcapng"}
        if self._capture_mode in data_modes:
            try:
                from friTap.flow.collector import FlowCollector
                # Live Signal message decoding is opt-in: only build the Signal
                # decryptor when 'signal' is among the selected protocols. Live
                # decoding only catches keys arriving before/at the DATA; late
                # keys are recovered by the session-end offline reprocess below.
                signal_messages = "signal" in _selected_protocols(state)
                self._flow_collector = FlowCollector(signal_messages=signal_messages)
                self._flow_collector.set_capture_target(state.target or "")
                self._flow_collector.subscribe(self._on_flow_update)
            except ImportError:
                self._flow_collector = None
        else:
            self._flow_collector = None

        # A capture is now in flight — deterministic state for the Enter toggle.
        self._capture_state = self.STATE_RUNNING
        self._session_generation += 1
        self._stop_requested = False

        # Update UI state to STARTING
        mode_display = self._capture_mode or "Custom"
        self._screen._get_status_bar().update_capture("STARTING", mode_display)
        menu = self._screen._get_menu_panel()
        menu.capture_active = True
        menu.target_name = state.target_display or state.target

        log = self._screen._get_activity_log()
        mode_action = "Spawning" if state.spawn else "Attaching to"
        log.log_info(f"{mode_action}: [bold {c('target')}]{state.target_display or state.target}[/]...")

        # MTProto/Telegram's obfuscated transport normally needs each connection
        # captured from byte 0. Memory scanning changes that: Tier E recovers the
        # live CTR state and the offline decryptor seeks it into a mid-stream
        # capture, so attach + memory scan DOES decrypt already-open connections.
        # Tailor the message to whether memory scanning is on for this run.
        if not state.spawn and getattr(state, "protocol", "tls") in ("telegram", "mtproto"):
            if getattr(state, "memory_scan", False):
                log.log_info(f"Attach mode + memory scan: {ATTACH_MEMORY_SCAN_RECOVERY}")
            else:
                log.log_warning(
                    "Attach mode: connections already open won't decrypt — use spawn "
                    "mode for byte-0 capture, or force-stop + relaunch the app first. "
                    "Or enable memory scanning (-ms) to recover keys for already-open "
                    "connections."
                )

        # CRITICAL: Do NOT call install_signal_handler() -- it calls os._exit(0)
        self._screen.run_worker(self._run_session, thread=True)

    def _run_session(self) -> None:
        """Run the SSL_Logger session in a background thread.

        SSL_Logger is created here (not on the Textual thread) so that
        the blocking FIFO open in live mode doesn't freeze the UI.
        """
        result_stats: dict[str, str] = {}
        # Teardown uses THIS run's own logger and generation, never whatever
        # self.* points at by the time the (slow) teardown finishes.
        generation = self._session_generation
        session_logger = None
        self._session_error = ""
        self._session_error_category = None
        self._session_error_original = None
        self._session_crashed = False
        self._session_crash_message = ""
        lsass_started = False
        lsass_params = None
        try:
            from friTap.ssl_logger import SSL_Logger
            debug_output_enabled = self._pending_config.debug_output
            # On Windows the Schannel session/traffic secrets live in lsass, not in
            # the target process, so key extraction needs a separate lsass hook. The
            # CLI starts it in friTap.main(); the TUI path never reached that block,
            # so a TUI capture produced traffic but NO keys. Snapshot the params now
            # (the config is cleared right after SSL_Logger is built) and — exactly as
            # the CLI does — disable the target session's own lsass hook so only the
            # dedicated LsassHookWorker touches lsass.
            cfg = self._pending_config
            try:
                from friTap.fritap_utility import are_we_running_on_windows
                # LSASS is a local-Windows-only service hook: never for a mobile
                # (Android/iOS) or remote (--host frida-server) target, even when
                # the analyst's own OS is Windows.
                if (are_we_running_on_windows() and not cfg.device.mobile
                        and not cfg.device.host and cfg.install_lsass_hook):
                    lsass_params = dict(
                        pcap_name=cfg.output.pcap, verbose=cfg.output.verbose,
                        keylog=cfg.output.keylog, live=cfg.output.live,
                        debug_mode=cfg.debug, host=cfg.device.host or False,
                        debug_output=cfg.debug_output,
                        enable_default_fd=cfg.hooking.enable_default_fd,
                        patterns=cfg.hooking.patterns,
                        custom_hook_script=cfg.custom_hook_script,
                        json_output=cfg.output.json_output,
                        full_capture=cfg.output.full_capture)
                    cfg.install_lsass_hook = False
            except Exception:
                logger.debug("TUI lsass pre-check failed", exc_info=True)
            # Open the debug log + attach the file handler BEFORE SSL_Logger
            # is constructed so the protocol-registry / pattern-loader /
            # device-acquisition records emitted during init also land in
            # the file. The EventBus subscription happens later, once the
            # bus exists.
            if debug_output_enabled:
                self._open_debug_log_file()
            session_logger = self._ssl_logger = SSL_Logger(config=self._pending_config)
            self._ssl_logger._tui_mode = True
            self._pending_config = None
            # A stop requested while the logger was being built had nothing to
            # stop yet — honour it now (request_stop flips `running`, which
            # SSL_Logger.__init__ set True) and skip straight to teardown.
            if self._stop_requested:
                session_logger.request_stop()

            # Wire TUI output handler to the event bus BEFORE connect_live()
            # so it receives LiveReadyEvent and can launch Wireshark
            self._tui_handler.setup(self._ssl_logger._event_bus)
            self._ssl_logger._output_handlers.append(self._tui_handler)

            # Detect a target-process crash. On crash the session emits a fatal
            # ErrorEvent + a process-terminated DetachEvent and stops `running`,
            # so the worker loop below exits normally (no exception). Record it
            # here so _on_session_ended reports failure instead of "completed".
            from friTap.events import DetachEvent as _DetachEvent
            from friTap.events import ErrorEvent as _ErrorEvent
            self._ssl_logger._event_bus.subscribe(_ErrorEvent, self._on_session_error_event)
            self._ssl_logger._event_bus.subscribe(_DetachEvent, self._on_session_detach_event)

            # Wire FlowCollector to event bus for data events
            if self._flow_collector is not None:
                from friTap.events import (
                    DatalogEvent,
                    KeylogEvent,
                    LibraryDetectedEvent,
                    OhttpEvent,
                    SessionEvent,
                )
                self._ssl_logger._event_bus.subscribe(
                    DatalogEvent, self._flow_collector.on_data
                )
                # Feed Signal key material to the live decryptor. A no-op unless
                # the collector was built with signal_messages=True.
                self._ssl_logger._event_bus.subscribe(
                    KeylogEvent, self._flow_collector.on_keylog
                )
                self._ssl_logger._event_bus.subscribe(
                    OhttpEvent, self._flow_collector.on_ohttp
                )
                self._ssl_logger._event_bus.subscribe(
                    LibraryDetectedEvent, self._flow_collector.on_library_detected
                )
                self._ssl_logger._event_bus.subscribe(
                    SessionEvent, self._flow_collector.on_session_event
                )
                # Give FlowCollector access to EventBus for emitting FlowEvents
                self._flow_collector.set_event_bus(self._ssl_logger._event_bus)

            # Set up debug log file if enabled
            if debug_output_enabled:
                self._setup_debug_log(self._ssl_logger._event_bus)

            if self._stop_requested:
                # Stopped during start-up: never attach / start the session.
                return

            # Connect live Wireshark handler (emits LiveReadyEvent → TUI
            # launches Wireshark → blocks until FIFO connected or timeout)
            self._ssl_logger.connect_live()

            # Update UI to CAPTURING now that SSL_Logger is ready
            def _update_capturing():
                mode_display = self._capture_mode or "Custom"
                self._screen._get_status_bar().update_capture("CAPTURING", mode_display)
                try:
                    title = self._screen.query_one("#activity-title", Static)
                    title.update(f"[bold {c('success')}]friTap Console[/]  [bold green on {c('bg-capture')}] CAPTURING [/]")
                except Exception:
                    pass
                # Activate flow view if selected in wizard
                state = self._screen._get_state()
                if getattr(state, 'view_mode', 'legacy') == 'flow' and self._flow_collector is not None:
                    self._screen._activate_flow_view()

                # Register OHTTP tab if OHTTP decryption is enabled
                if getattr(state, 'encapsulated_protocols', {}).get("ohttp", True):
                    try:
                        from friTap.tui.widgets.flow_detail import FlowDetailWidget
                        from friTap.tui.widgets.ohttp_tab import OhttpTabProvider
                        flow_detail = self._screen.query_one("#flow-detail", FlowDetailWidget)
                        if not any(t.tab_id == "ohttp" for t in flow_detail._extra_tabs):
                            flow_detail.register_tab(OhttpTabProvider())
                    except Exception:
                        pass
            self._screen.app.call_from_thread(_update_capturing)

            # Bring up the dedicated lsass key-extraction worker BEFORE the target
            # handshake so the Schannel secrets are captured (see the pre-check above).
            # start_lsass_hook runs on its own daemon thread and blocks ~2s until the
            # hook is live; running it here (background worker) won't freeze the UI.
            if lsass_params is not None:
                try:
                    from friTap.friTap import hook_lsass
                    hook_lsass(**lsass_params)
                    lsass_started = True
                    if not getattr(self, "_lsass_atexit_registered", False):
                        import atexit
                        from friTap.friTap import cleanup_lsass_hook as _cleanup_lsass
                        atexit.register(_cleanup_lsass)
                        self._lsass_atexit_registered = True
                except Exception as e:
                    self._screen.app.call_from_thread(
                        lambda err=e: self._screen._get_activity_log().log_warning(
                            f"LSASS key extraction unavailable: {err}"))

            session_logger.start_fritap_session()
            while session_logger.running:
                time.sleep(0.2)
            # The loop exits normally on a target crash (running flipped to
            # False by the detach/error handler). Promote the recorded crash to
            # a fatal session error so _on_session_ended surfaces it.
            if self._session_crashed and not self._session_error:
                self._session_error = (
                    self._session_crash_message
                    or "Target process crashed during capture."
                )
                self._session_error_severity = ERROR_SEVERITY_FATAL
        except (Exception, SystemExit) as e:
            # Prefer the rich BackendError diagnostic (includes the original
            # frida exception class + euid/SIP/target/server context) when
            # the wrapper produced one. Fall back to ``str`` for everything
            # else so unexpected exceptions still surface meaningfully.
            if hasattr(e, "diagnostic_summary"):
                self._session_error = e.diagnostic_summary()
            else:
                self._session_error = str(e)
            self._session_error_category = getattr(e, "category", None)
            self._session_error_original = getattr(e, "original_exception", e)
            self._session_error_severity = ERROR_SEVERITY_FATAL
            # Make sure the traceback lands in the debug log file even if
            # the modal is the only thing the user sees in the TUI.
            logger.exception("Capture session failed: %s", e)
            # Emit ErrorEvent so the EventBus debug-log subscriber (and
            # any other consumer) records the failure too.
            try:
                if self._ssl_logger is not None:
                    bus = getattr(self._ssl_logger, "_event_bus", None)
                    if bus is not None:
                        import traceback as _tb

                        from friTap.events import ErrorEvent
                        bus.emit(ErrorEvent(
                            error=type(e).__name__,
                            description=self._session_error,
                            stack="".join(_tb.format_exception(type(e), e, e.__traceback__)),
                            severity=ERROR_SEVERITY_FATAL,
                        ))
            except Exception:
                logger.debug("Failed to emit session-error ErrorEvent", exc_info=True)

            def _log_error(msg=self._session_error):
                self._screen._get_activity_log().log_error(msg)
            self._screen.app.call_from_thread(_log_error)
        finally:
            # Stop the dedicated lsass key-extraction worker (if we started it)
            # before tearing down the target session.
            if lsass_started:
                try:
                    from friTap.friTap import cleanup_lsass_hook
                    cleanup_lsass_hook()
                except Exception:
                    logger.debug("lsass hook cleanup failed", exc_info=True)
            # All blocking I/O runs here on the background thread
            if session_logger is not None:
                self._close_debug_log()
                try:
                    sl = session_logger
                    # finish_fritap() drains the message queue, stops proxy,
                    # and unloads the Frida script — safe to block here.
                    sl.finish_fritap()
                    sl.pcap_cleanup(sl.full_capture, sl.mobile, sl.pcap_name)
                    sl.cleanup(sl.live, sl.socket_trace, sl.full_capture, sl.debug_output)
                except Exception as e:
                    def _log_cleanup(err=e):
                        self._screen._get_activity_log().log_error(f"Cleanup error: {err}")
                    self._screen.app.call_from_thread(_log_cleanup)

                # Gather file stats on background thread to avoid blocking UI
                result_stats = self._gather_result_stats()

            def _finalize(stats=result_stats, gen=generation):
                self._on_session_ended(stats, generation=gen)
            self._screen.app.call_from_thread(_finalize)

    def _on_session_error_event(self, event) -> None:
        """Record a fatal target-process error reported on the EventBus.

        Runs on the friTap message-consumer thread. Only fatal errors mark the
        session as crashed; recovered/parser warnings are left to the activity
        log + debug file.
        """
        try:
            if getattr(event, "severity", None) == ERROR_SEVERITY_FATAL:
                self._session_crashed = True
                desc = getattr(event, "description", None) or getattr(event, "error", None)
                if desc and not self._session_crash_message:
                    self._session_crash_message = str(desc)
        except Exception:
            logger.debug("Failed to handle session ErrorEvent", exc_info=True)

    def _on_session_detach_event(self, event) -> None:
        """Mark the session crashed only when the target died INSIDE a hook.

        A plain process exit — e.g. a short-lived target that finished its work —
        is not a crash: the agent breadcrumb still reads ``agent-init*``/empty
        because no hook was executing. Only a crumb naming a real hook marks the
        session as crashed; otherwise the session ends as completed, not failed.
        """
        try:
            reason = getattr(event, "reason", "")
            if reason in ("process-terminated", "process-replaced"):
                crumb = getattr(self._ssl_logger, "_last_hook_breadcrumb", "") or ""
                spawn = getattr(self._ssl_logger, "spawn", False)
                # A clean exit only when the agent fully initialised in attach mode;
                # an empty/partial crumb (esp. a spawn startup crash) marks crashed.
                looks_clean = (not spawn) and crumb == "agent-init: complete"
                if not looks_clean:
                    self._session_crashed = True
                    if not self._session_crash_message:
                        msg = ("Target process terminated unexpectedly — it most "
                               "likely crashed inside an instrumented hook")
                        if crumb and not crumb.startswith("agent-init"):
                            msg += f" (last instrumented: {crumb})"
                        self._session_crash_message = msg + "."
        except Exception:
            logger.debug("Failed to handle session DetachEvent", exc_info=True)

    def _on_flow_update(self, flow, event_type: str) -> None:
        """Batch flow updates to avoid overwhelming Textual's event loop.

        Under heavy load (many TLS connections), individual call_from_thread()
        per data chunk starves the event loop, making the TUI unresponsive.
        Coalesce updates per flow_id and flush in batches.
        """
        with self._ui_lock:
            self._pending_ui_updates[flow.flow_id] = (flow, event_type)
            if self._ui_flush_scheduled:
                return
            self._ui_flush_scheduled = True
        try:
            self._screen.app.call_from_thread(self._flush_ui_updates)
        except Exception:
            with self._ui_lock:
                self._ui_flush_scheduled = False

    def _flush_ui_updates(self) -> None:
        """Process batched updates on the Textual thread."""
        with self._ui_lock:
            updates = dict(self._pending_ui_updates)
            self._pending_ui_updates.clear()
            self._ui_flush_scheduled = False
        with self._screen.app.batch_update():
            for flow_id, (flow, event_type) in updates.items():
                self._screen._update_flow_ui(flow, event_type)
        with self._ui_lock:
            if self._pending_ui_updates and not self._ui_flush_scheduled:
                self._ui_flush_scheduled = True
                try:
                    self._screen.app.set_timer(0.1, self._flush_ui_updates)
                except Exception:
                    self._ui_flush_scheduled = False

    def _memory_scan_keylog_files(self) -> dict[str, str]:
        """Protocol -> memory-scan sidecar keylog written this capture, if any.

        These hold the keys the *scanner* recovered (e.g. MTProto OBF + perm auth
        keys) — distinct from the hook keylog. Read from the live SSL_Logger's
        config. The sidecar names are derived (stable across runs), so only
        files this session actually wrote are kept — non-empty and modified
        since the session start, the same rule the capture manifest applies —
        so a stale sidecar left by an earlier run is neither listed nor counted.
        Each file appears once (under the first protocol mapping to it —
        mtproto and telegram share one sidecar). Total: any failure yields ``{}``.
        """
        try:
            from friTap.memory_scanning import memory_scan_protocol_keylogs
            from friTap.pcap import _existing_keylog_files
            mapping = memory_scan_protocol_keylogs(self._ssl_logger._config)
            started = getattr(self._ssl_logger, "_session_start_time", None)
            written = _existing_keylog_files(
                mapping,
                not_before=started if isinstance(started, (int, float)) else None)
        except Exception:
            return {}
        files: dict[str, str] = {}
        for proto, path in written.items():
            if path not in files.values():
                files[proto] = path
        return files

    def _memory_scan_keylog_paths(self) -> list[str]:
        """The memory-scan sidecar keylog file(s) written this capture, if any.

        Feeds the results key count so it reflects the scanner's keys too, not
        just the hook file. Total: any failure yields ``[]`` (hook-only count).
        """
        return list(self._memory_scan_keylog_files().values())

    def _keylog_result_rows(self, base_keylog: str, protocols) -> dict[str, str]:
        """Results-modal keylog rows: ``{label: path}``, each file listed once.

        The hook keylog(s) (split per protocol on a multi-protocol run, else the
        base ``-k`` path) followed by the memory-scan sidecar(s). A sidecar that
        IS a hook keylog (memory-scan-only mode writes the tls sidecar to the
        ``-k`` path) is not listed a second time. Shared by the stats gathering
        and the results modal so every stat lands on the row of its own file.
        """
        rows: dict[str, str] = {}
        keylog_files = self._resolve_keylog_files(base_keylog, protocols)
        if keylog_files:
            multi = len(keylog_files) > 1
            for proto, path in keylog_files.items():
                rows[f"Key log ({proto})" if multi else "Key log"] = path
        elif base_keylog:
            rows["Key log"] = base_keylog
        listed = {_same_file_key(path) for path in rows.values()}
        for proto, path in self._memory_scan_keylog_files().items():
            if _same_file_key(path) not in listed:
                listed.add(_same_file_key(path))
                rows[f"Memory-scan keys ({proto})"] = path
        return rows

    def _gather_result_stats(self) -> dict[str, str]:
        """Gather capture statistics (file I/O). Must run on background thread.

        Each keylog row gets the count of ITS OWN file (``0 keys`` for an empty
        one); with several keylog files a distinct-union total is added too.
        """
        stats: dict[str, str] = {}
        state = self._screen._get_state()
        if state.keylog_path:
            stats.update(self._keylog_row_stats(
                self._keylog_result_rows(state.keylog_path, _selected_protocols(state))
            ))
        if state.pcap_path:
            size = _get_file_size(state.pcap_path)
            if size is None:
                dirname, basename = os.path.split(state.pcap_path)
                size = _get_file_size(os.path.join(dirname, f"_{basename}"))
            if size is not None:
                stats["PCAP"] = format_byte_size(size)
        return stats

    @staticmethod
    def _keylog_row_stats(rows: dict[str, str]) -> dict[str, str]:
        """Per-row key counts for existing keylog files, plus a distinct total."""
        from friTap.offline.keylog_picker import count_distinct_keys
        stats: dict[str, str] = {}
        existing = [path for path in rows.values() if os.path.isfile(path)]
        for label, path in rows.items():
            if os.path.isfile(path):
                stats[label] = _key_count_label(count_distinct_keys([path]))
        if len(existing) > 1:
            stats[KEYLOG_TOTAL_STAT] = _key_count_label(count_distinct_keys(existing))
        return stats

    def _show_modals_sequentially(self, items: list, on_complete=None) -> None:
        """Show queued ``(screen, on_result)`` modals one at a time.

        Each modal is pushed only after the previous one is dismissed, so the
        post-capture dialogs never render on top of each other (textual's
        ``push_screen`` is non-blocking). ``on_result`` (if not None) receives
        the dismissed screen's result before the next modal is shown. Mirrors
        the callback-chaining pattern used in wizard.py. ``on_complete`` (if not
        None) runs once the last modal was dismissed (immediately if none).
        """
        if not items:
            if on_complete is not None:
                on_complete()
            return
        screen, on_result = items[0]
        rest = items[1:]

        def _advance(result, _on_result=on_result, _rest=rest) -> None:
            if _on_result is not None:
                try:
                    _on_result(result)
                except Exception:
                    logger.exception("post-capture modal callback failed")
            self._show_modals_sequentially(_rest, on_complete)

        self._screen.app.push_screen(screen, callback=_advance)

    def _resolve_keylog_files(self, base_keylog: str, protocols) -> dict[str, str]:
        """Resolve the keylog file(s) actually written this capture, that exist.

        A single-protocol run writes the base ``-k`` path directly; a
        multi-protocol run (e.g. ``--protocol signal``, which also emits TLS
        keys) splits it into ``<stem>.<proto>.log`` per protocol. Returns
        ``{protocol: path}`` for files present on disk so the results modal and
        the decrypt-to-flow offer reflect what is on disk — not the base path,
        which a split run never writes verbatim.

        ``protocols`` is the protocol SET this capture wrote keys for (a list, or
        a single string for back-compat). It is fed to the SAME
        :func:`active_keylog_paths` helper the factory uses on the WRITE side, so
        the read side splits identically to the write side by construction.
        """
        if not base_keylog:
            return {}
        proto_list = [protocols] if isinstance(protocols, str) else list(protocols)
        fallback_proto = proto_list[0] if proto_list else "tls"
        registry = getattr(self._ssl_logger, "_protocol_registry", None)
        try:
            from friTap.output.factory import active_keylog_paths
            candidates = active_keylog_paths(base_keylog, proto_list, registry)
        except Exception:
            candidates = {fallback_proto: base_keylog}
        existing = {proto: path for proto, path in candidates.items()
                    if path and os.path.isfile(path)}
        if not existing and os.path.isfile(base_keylog):
            existing = {fallback_proto: base_keylog}
        return existing

    def _maybe_reprocess_signal_late_keys(
        self,
        tap_path: str,
        pcap_path: str,
        keylog_files: dict,
        protocols,
    ) -> None:
        """Session-end safety net: re-decode Signal offline to catch LATE keys.

        Live Signal decoding (``FlowCollector(signal_messages=True)``) only
        decodes a message whose ratchet key arrived BEFORE or WITH its ciphertext
        DATA — the common live ordering. A key that lands strictly AFTER its
        message's bytes is missed live. The offline pipeline re-reads the whole
        pcap with the complete keylog and recovers those, so at session end we
        rewrite the live ``.tap`` in place from the captured pcap + keylog,
        headlessly (no modal), in a background worker.

        Best-effort: fully guarded and never raises, so a failed reprocess never
        breaks the normal capture-end flow. No-op unless 'signal' was captured
        and a Signal keylog + a pcap are present on disk.
        """
        if "signal" not in (protocols or []):
            return
        if not tap_path or not pcap_path or not os.path.isfile(pcap_path):
            return
        keylog_files = keylog_files or {}
        if not keylog_files.get("signal"):
            return

        tls_keylog = keylog_files.get("tls", "")
        protocol_keylogs = {
            proto: path for proto, path in keylog_files.items() if proto != "tls"
        }

        def _reprocess() -> None:
            try:
                from friTap.offline.pcap_to_tap import pcap_to_tap
                pcap_to_tap(
                    pcap_path,
                    keylog_path=tls_keylog or None,
                    tap_path=tap_path,
                    protocol_keylogs=protocol_keylogs or None,
                    use_manifest=True,
                )
            except Exception:
                logger.debug(
                    "Signal late-key offline reprocess failed", exc_info=True
                )

        # Runs off the Textual event loop; the interactive DecryptConfirmModal
        # offer below is a separate, user-driven path and writes its own .tap.
        self._screen.run_worker(_reprocess, thread=True)

    def _on_session_ended(
        self,
        result_stats: dict[str, str] | None = None,
        generation: int | None = None,
    ) -> None:
        """Called when the capture session ends (on Textual thread).

        ``generation`` is the ending worker's session generation; an end report
        from a stale (superseded) session must not touch the current session's
        shared state, so it is ignored. ``None`` means "the current session".
        """
        if generation is not None and generation != self._session_generation:
            logger.debug(
                "Ignoring end of stale capture session %d (current: %d)",
                generation, self._session_generation,
            )
            return
        # A wizard restart requested mid-capture runs once this session's
        # results have been shown (see restart_when_stopped).
        restart = self._restart_after_stop
        self._restart_after_stop = None
        if result_stats is None:
            result_stats = {}
        state = self._screen._get_state()

        # Capture paths/flags for an optional post-capture decrypt offer
        # (a full capture writes both a pcap and a keylog) BEFORE the reset.
        decrypt_pcap = getattr(state, "pcap_path", "")
        decrypt_keylog = getattr(state, "keylog_path", "")
        decrypt_protocol = getattr(state, "protocol", "tls")
        # The protocol SET the WRITE side split by (config.protocols); fall back to
        # the primary scalar so a state that never set the list still resolves.
        decrypt_protocols = getattr(state, "protocols", None) or [decrypt_protocol]
        decrypt_was_full = getattr(state, "full_capture", False)

        # The base -k path may never be written verbatim: a multi-protocol run
        # (e.g. --protocol signal, which also emits TLS keys) splits it into
        # <stem>.<proto>.log per protocol. Resolve the real files so the results
        # modal and the decrypt offer below reflect what is on disk. Done BEFORE
        # the reset (and while self._ssl_logger is still set for its registry).
        keylog_files = self._resolve_keylog_files(decrypt_keylog, decrypt_protocols)

        # Save paths BEFORE resetting. The memory-scan sidecar(s) are surfaced too
        # (deduped against the hook keylogs), so the user sees the file that holds
        # the scanner-recovered keys (OBF/perm auth). Done while self._ssl_logger
        # is still set (before the reset).
        result_paths = self._keylog_result_rows(decrypt_keylog, decrypt_protocols)
        if state.pcap_path:
            result_paths["PCAP"] = state.pcap_path
        target_display = state.target_display or state.target or "unknown"
        saved_live_mode = state.live_mode
        is_mobile = state.device_type == "usb"

        # Did the capture actually record any traffic? A full capture can finish
        # with only the empty pcapng header (e.g. tcpdump unavailable, no traffic).
        # Resolve the real file, mirroring _gather_result_stats' "_"-temp fallback.
        pcap_expected = bool(decrypt_pcap)
        pcap_has_packets = True
        if pcap_expected:
            pcap_check_path = decrypt_pcap
            if not os.path.isfile(pcap_check_path):
                _d, _b = os.path.split(decrypt_pcap)
                _alt = os.path.join(_d, f"_{_b}")
                if os.path.isfile(_alt):
                    pcap_check_path = _alt
            pcap_has_packets = (
                _pcap_has_packets(pcap_check_path)
                if os.path.isfile(pcap_check_path)
                else False
            )
        pcap_empty = pcap_expected and not pcap_has_packets

        # Reset AppState (preserve device info)
        state.target = ""
        state.target_display = ""
        state.spawn = False
        state.pcap_path = ""
        state.keylog_path = ""
        state.json_path = ""
        state.live = False
        state.live_mode = ""
        state.full_capture = False

        # Reset status bar
        status = self._screen._get_status_bar()
        status.update_capture("STOPPED")
        status.update_target("", "")
        status.capture_mode = ""

        # Reset menu panel (batch to avoid 7 redundant rebuilds)
        menu = self._screen._get_menu_panel()
        with menu.batch_update():
            menu.capture_active = False
            menu.has_target = False
            menu.target_name = ""
            menu.target_mode = ""
            menu.current_mode = ""
            menu.keylog_path = ""
            menu.pcap_path = ""

        self._capture_mode = ""
        # The capture is fully torn down. Move to STOPPED: Enter won't re-attach
        # (target/mode were just cleared) until the user configures a new capture
        # by hand (a/s + 1-6) or restarts the wizard.
        self._capture_state = self.STATE_STOPPED

        self._screen._get_activity_log().log_session("Capture session ended")
        if restart is None:
            self._screen._get_activity_log().log_info(CAPTURE_STOPPED_RESTART_HINT)

        # Revert console title (or refresh flow view title to remove "stop capture" hint)
        try:
            flow_list = self._screen.query_one("#flow-list")
            if flow_list.display:
                self._screen._update_flow_title()
            else:
                title = self._screen.query_one("#activity-title", Static)
                title.update(f"[bold {c('success')}]friTap Console[/]")
        except Exception:
            pass

        # Teardown handler and clear references
        saved_key_count = self._tui_handler.key_count if self._tui_handler else 0
        if self._tui_handler is not None:
            self._tui_handler.teardown()
            self._tui_handler = None

        # Flush flow collector so ACTIVE flows become COMPLETE
        flow_count = 0
        if self._flow_collector is not None:
            self._flow_collector.flush()
            flow_count = len(self._flow_collector.get_flows())

        # flush() marks flows COMPLETE but does not call _notify(), so the
        # TapWriter callback was never triggered for those remaining flows.
        # Write any flows not yet in the writer's index.
        if self._tap_writer is not None and self._flow_collector is not None:
            written_ids = self._tap_writer.written_flow_ids
            for flow in self._flow_collector.get_flows():
                if flow.flow_id not in written_ids:
                    self._tap_writer.write_flow(flow)

        # Capture the live .tap path before stop_tap_recording() clears the
        # writer, so the Signal late-key safety net can rewrite it offline.
        reprocess_tap_path = (
            self._tap_writer.path if self._tap_writer is not None else ""
        )

        # Close tap writer after catching up remaining flows
        self.stop_tap_recording()

        # Late-key safety net: if this was a Signal capture, re-decode the pcap
        # offline into the same .tap so messages whose keys arrived AFTER their
        # ciphertext (missed by live decoding) are still recovered.
        self._maybe_reprocess_signal_late_keys(
            reprocess_tap_path, decrypt_pcap, keylog_files, decrypt_protocols
        )

        if flow_count > 0:
                self._screen._get_activity_log().log_info(
                    f"Captured {flow_count} flow{'s' if flow_count != 1 else ''}"
                )

        # Switch to legacy view if no results — menu is only visible there
        if not result_paths and flow_count == 0:
            self._screen._activate_legacy_view()

        # Build the ordered queue of post-capture dialogs and show them one at a
        # time (textual push_screen is non-blocking, so pushing several inline
        # makes them overlap). Order: results/live/no-libs summary -> error ->
        # decrypt offer (last), matching the "results first, decrypt after" flow.
        modal_queue: list = []

        # Suggest library scan if no libraries detected
        if self._ssl_logger and not self._ssl_logger._detected_libraries:
            if not result_paths:
                modal_queue.append((
                    AlertModal(
                        message="No TLS libraries were detected.\n\n"
                                "Consider enabling [bold]Library Scan[/] (press [bold]l[/] in the start screen) "
                                "to discover renamed or statically linked libraries.",
                        title="No Libraries Found",
                        severity="warning",
                    ),
                    None,
                ))

        # Show results summary with pre-computed statistics
        if result_paths:
            if self._session_crashed:
                lines = [
                    f"Capture of [bold]{target_display}[/] did NOT complete — "
                    "the target process crashed.\n",
                    "Any files below are partial and may be empty:\n",
                ]
                results_severity = "warning"
            elif pcap_empty:
                lines = [
                    f"Capture of [bold]{target_display}[/] finished, but "
                    "[bold]no traffic was captured[/].\n",
                    "The PCAP is empty (0 packets).\n",
                ]
                if is_mobile and decrypt_was_full:
                    lines.append(
                        "On Android, full capture records traffic with on-device "
                        "[bold]tcpdump[/] — ensure the device is rooted and tcpdump "
                        "is available.\n"
                    )
                results_severity = "warning"
            else:
                lines = [f"Capture of [bold]{target_display}[/] completed.\n"]
                results_severity = "info"
            for label, path in result_paths.items():
                stat = result_stats.get(label)
                suffix = f" ({stat})" if stat else ""
                lines.append(f"  {label}: [bold]{path}[/]{suffix}")
            total = result_stats.get(KEYLOG_TOTAL_STAT)
            if total:
                lines.append(f"  {KEYLOG_TOTAL_STAT}: [bold]{total}[/]")
            modal_queue.append((
                AlertModal(message="\n".join(lines), title="Capture Results", severity=results_severity),
                None,
            ))

        # Mode 5: live auto-decrypt has no file output — show save instructions
        elif saved_live_mode == "live_pcapng":
            key_count = saved_key_count
            key_label = f"{key_count} key{'s' if key_count != 1 else ''}" if key_count else "No keys"

            lines = [
                f"Live capture of [bold]{target_display}[/] completed.\n",
                f"[bold {c('success')}]TLS secrets extracted:[/] [bold]{key_label}[/]",
                "  Secrets are already embedded in the PCAPNG stream.\n",
                f"[bold {c('warning-amber')}]Save your capture:[/]",
                "  In Wireshark: [bold]File → Save As → .pcapng[/]\n",
                f"[bold {c('secondary')}]Note:[/] This was a full network capture.",
                "  Packets from other applications may be present.",
                "  Wireshark auto-decrypts only traffic with matching TLS keys.",
            ]
            if not is_mobile:
                display_filter = build_infrastructure_display_filter()
                lines.append("")
                lines.append(f"[bold {c('success')}]Filter out Frida/ADB traffic:[/]")
                lines.append(f"  Display filter: [bold]{display_filter}[/]")
            modal_queue.append((
                AlertModal(message="\n".join(lines), title="Live Capture Complete", severity="info"),
                None,
            ))

        # Mode 4: plaintext Wireshark — also no file output
        elif saved_live_mode == "wireshark":
            lines = [
                f"Live capture of [bold]{target_display}[/] completed.\n",
                f"[bold {c('warning-amber')}]Save your capture:[/]",
                "  In Wireshark: [bold]File → Save As[/]",
            ]
            modal_queue.append((
                AlertModal(message="\n".join(lines), title="Live Capture Complete", severity="info"),
                None,
            ))

        # Error modal, queued after the results summary so the user sees the
        # capture context first. Only fatal/error session failures pop a blocking
        # modal. Recovered parser-level warnings reach the activity log + debug
        # file via ErrorEvent(severity="warning") and never set _session_error.
        if self._session_error and self._session_error_severity in (
            ERROR_SEVERITY_FATAL, ERROR_SEVERITY_ERROR,
        ):
            body = self._session_error
            # Discoverability: show the user where the diagnostic log lives
            # so they can attach it when reporting the issue.
            try:
                from friTap.fritap_utility import get_debug_log_path
                log_path = get_debug_log_path() or self._debug_log_path
            except Exception:
                log_path = self._debug_log_path
            if log_path:
                body = (
                    f"{self._session_error}\n\n"
                    f"Debug log: {log_path}\n"
                    "Please attach when reporting at "
                    "https://github.com/fkie-cad/friTap/issues"
                )
            modal_queue.append((
                AlertModal(
                    message=body,
                    title="Capture Error",
                    severity="error",
                ),
                None,
            ))

        self._session_error = ""
        self._session_error_severity = ERROR_SEVERITY_FATAL
        self._session_error_category = None
        self._session_error_original = None
        self._ssl_logger = None

        # Offer to decrypt the captured pcap into a layered flow view, but only
        # for full captures that produced both a pcap and a keylog on disk AND
        # that actually captured traffic. Plaintext-hook captures (no keylog) and
        # empty pcaps (which would decrypt to 0 flows) get no prompt. This is
        # protocol-agnostic: ``keylog_files`` resolves the real (possibly split)
        # keylog files for ANY supported protocol — Signal, MTProto/Telegram,
        # plain TLS, and future plugins — so the offer is no longer skipped just
        # because a split run never wrote the base ``-k`` path verbatim.
        # Skipped when a wizard restart is pending: the user asked for a fresh
        # session, and a decrypt run would race the new wizard.
        if (
            restart is None
            and decrypt_was_full
            and keylog_files
            and decrypt_pcap and os.path.isfile(decrypt_pcap)
            and pcap_has_packets
        ):
            from .modals.decrypt_confirm_modal import DecryptConfirmModal

            def _on_decrypt_choice(ok: bool) -> None:
                if ok:
                    # Pass the AUTHORITATIVE per-protocol keylog map resolved above
                    # (same source as the results modal), NOT the raw base keylog.
                    # Re-resolving a single path inside start_decrypt_to_flow can
                    # misroute a split capture's protocol keylog to the TLS log
                    # (Signal then decrypts 0 messages).
                    self._screen.start_decrypt_to_flow_multi(
                        decrypt_pcap, keylog_files
                    )

            modal_queue.append((DecryptConfirmModal(), _on_decrypt_choice))

        # Present every queued dialog sequentially — never overlapping — and only
        # then relaunch the wizard, so no old-session modal lands on top of it.
        self._show_modals_sequentially(modal_queue, on_complete=restart)
