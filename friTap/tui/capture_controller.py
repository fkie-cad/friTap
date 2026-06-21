#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Capture controller -- manages the capture lifecycle extracted from MainScreen.

Handles config building, session start/stop, background worker management,
and post-session UI cleanup.
"""

from __future__ import annotations

import logging
import os
import time

from .modals.alert_modal import AlertModal
from friTap.constants import build_infrastructure_display_filter
from friTap.events import ERROR_SEVERITY_ERROR, ERROR_SEVERITY_FATAL
from friTap.tui.themes import c

logger = logging.getLogger("friTap.tui.capture")

try:
    from textual.widgets import Static
    TEXTUAL_AVAILABLE = True
except ImportError:
    TEXTUAL_AVAILABLE = False


from friTap.flow.models import format_byte_size  # noqa: E402


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

    def __init__(self, screen) -> None:
        self._screen = screen
        self._ssl_logger = None
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

    def action_start_capture(self) -> None:
        """Build config, create SSL_Logger, wire handler, start session."""
        state = self._screen._get_state()

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

        Sets ``running = False`` **immediately** so the TUI stays responsive
        even when the Frida session or message consumer is busy.  The
        background worker thread's ``finally`` block handles the actual cleanup
        (queue drain, PCAP close, Frida detach).
        """
        if self._ssl_logger and self._ssl_logger.running:
            self._screen._get_activity_log().log_info("Stopping capture...")
            self._ssl_logger.request_stop()
        else:
            self._screen._get_activity_log().log_warning("No capture running.")

    def action_toggle_capture(self) -> None:
        """Toggle capture: start if idle, stop if running."""
        if self._screen._wizard_guard():
            return
        if self._ssl_logger and self._ssl_logger.running:
            self.action_stop_capture()
        else:
            self.action_start_capture()

    def action_escape_action(self) -> None:
        """Esc stops capture if running, otherwise does nothing."""
        if self._screen._wizard_guard():
            return
        if self._ssl_logger and self._ssl_logger.running:
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
                self._screen._get_activity_log().log_error(f"Error saving .tap: {e}")
                self._toast(f"Error saving .tap: {e}", severity="error")
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
            DatalogEvent, KeylogEvent, ConsoleEvent, ErrorEvent,
            LibraryDetectedEvent, SessionEvent, DetachEvent,
            OhttpEvent,
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
        from friTap.config import FriTapConfig, DeviceConfig, OutputConfig, HookingConfig

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
        )

        return FriTapConfig(
            target=state.target,
            device=device,
            output=output,
            hooking=HookingConfig(
                library_scan=getattr(state, 'library_scan', False),
                encapsulated_protocols=getattr(
                    state, 'encapsulated_protocols', {"ohttp": True}
                ),
                quic_capture_mode=getattr(state, 'quic_capture_mode', 'stream'),
            ),
            protocol=getattr(state, 'protocol', 'tls'),
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
                self._flow_collector = FlowCollector()
                self._flow_collector.set_capture_target(state.target or "")
                self._flow_collector.subscribe(self._on_flow_update)
            except ImportError:
                self._flow_collector = None
        else:
            self._flow_collector = None

        # Update UI state to STARTING
        mode_display = self._capture_mode or "Custom"
        self._screen._get_status_bar().update_capture("STARTING", mode_display)
        menu = self._screen._get_menu_panel()
        menu.capture_active = True
        menu.target_name = state.target_display or state.target

        log = self._screen._get_activity_log()
        mode_action = "Spawning" if state.spawn else "Attaching to"
        log.log_info(f"{mode_action}: [bold {c('target')}]{state.target_display or state.target}[/]...")

        # MTProto/Telegram's obfuscated transport can only be decrypted offline
        # when each connection is captured from byte 0. Attaching to a running app
        # misses that on already-open connections, so warn the user to prefer spawn.
        if not state.spawn and getattr(state, "protocol", "tls") in ("telegram", "mtproto"):
            log.log_warning(
                "Attach mode: connections already open won't decrypt — use spawn mode "
                "for byte-0 capture, or force-stop + relaunch the app first."
            )

        # CRITICAL: Do NOT call install_signal_handler() -- it calls os._exit(0)
        self._screen.run_worker(self._run_session, thread=True)

    def _run_session(self) -> None:
        """Run the SSL_Logger session in a background thread.

        SSL_Logger is created here (not on the Textual thread) so that
        the blocking FIFO open in live mode doesn't freeze the UI.
        """
        result_stats: dict[str, str] = {}
        self._session_error = ""
        self._session_error_category = None
        self._session_error_original = None
        self._session_crashed = False
        self._session_crash_message = ""
        try:
            from friTap.ssl_logger import SSL_Logger
            debug_output_enabled = self._pending_config.debug_output
            # Open the debug log + attach the file handler BEFORE SSL_Logger
            # is constructed so the protocol-registry / pattern-loader /
            # device-acquisition records emitted during init also land in
            # the file. The EventBus subscription happens later, once the
            # bus exists.
            if debug_output_enabled:
                self._open_debug_log_file()
            self._ssl_logger = SSL_Logger(config=self._pending_config)
            self._ssl_logger._tui_mode = True
            self._pending_config = None

            # Wire TUI output handler to the event bus BEFORE connect_live()
            # so it receives LiveReadyEvent and can launch Wireshark
            self._tui_handler.setup(self._ssl_logger._event_bus)
            self._ssl_logger._output_handlers.append(self._tui_handler)

            # Detect a target-process crash. On crash the session emits a fatal
            # ErrorEvent + a process-terminated DetachEvent and stops `running`,
            # so the worker loop below exits normally (no exception). Record it
            # here so _on_session_ended reports failure instead of "completed".
            from friTap.events import ErrorEvent as _ErrorEvent, DetachEvent as _DetachEvent
            self._ssl_logger._event_bus.subscribe(_ErrorEvent, self._on_session_error_event)
            self._ssl_logger._event_bus.subscribe(_DetachEvent, self._on_session_detach_event)

            # Wire FlowCollector to event bus for data events
            if self._flow_collector is not None:
                from friTap.events import (
                    DatalogEvent, OhttpEvent, LibraryDetectedEvent, SessionEvent,
                )
                self._ssl_logger._event_bus.subscribe(
                    DatalogEvent, self._flow_collector.on_data
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
                        from friTap.tui.widgets.ohttp_tab import OhttpTabProvider
                        from friTap.tui.widgets.flow_detail import FlowDetailWidget
                        flow_detail = self._screen.query_one("#flow-detail", FlowDetailWidget)
                        if not any(t.tab_id == "ohttp" for t in flow_detail._extra_tabs):
                            flow_detail.register_tab(OhttpTabProvider())
                    except Exception:
                        pass
            self._screen.app.call_from_thread(_update_capturing)

            self._ssl_logger.start_fritap_session()
            while self._ssl_logger.running:
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
            # All blocking I/O runs here on the background thread
            if self._ssl_logger:
                self._close_debug_log()
                try:
                    sl = self._ssl_logger
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

            def _finalize(stats=result_stats):
                self._on_session_ended(stats)
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
        """Mark the session crashed when the target process terminates."""
        try:
            reason = getattr(event, "reason", "")
            if reason in ("process-terminated", "process-replaced"):
                self._session_crashed = True
                if not self._session_crash_message:
                    self._session_crash_message = (
                        "Target process terminated unexpectedly — it most "
                        "likely crashed inside an instrumented hook."
                    )
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

    def _gather_result_stats(self) -> dict[str, str]:
        """Gather capture statistics (file I/O). Must run on background thread."""
        stats: dict[str, str] = {}
        state = self._screen._get_state()
        if state.keylog_path:
            key_count = _count_keys(state.keylog_path)
            if key_count is not None:
                stats["Key log"] = f"{key_count} key{'s' if key_count != 1 else ''}"
        if state.pcap_path:
            size = _get_file_size(state.pcap_path)
            if size is None:
                dirname, basename = os.path.split(state.pcap_path)
                size = _get_file_size(os.path.join(dirname, f"_{basename}"))
            if size is not None:
                stats["PCAP"] = format_byte_size(size)
        return stats

    def _show_modals_sequentially(self, items: list) -> None:
        """Show queued ``(screen, on_result)`` modals one at a time.

        Each modal is pushed only after the previous one is dismissed, so the
        post-capture dialogs never render on top of each other (textual's
        ``push_screen`` is non-blocking). ``on_result`` (if not None) receives
        the dismissed screen's result before the next modal is shown. Mirrors
        the callback-chaining pattern used in wizard.py.
        """
        if not items:
            return
        screen, on_result = items[0]
        rest = items[1:]

        def _advance(result, _on_result=on_result, _rest=rest) -> None:
            if _on_result is not None:
                try:
                    _on_result(result)
                except Exception:
                    logger.exception("post-capture modal callback failed")
            self._show_modals_sequentially(_rest)

        self._screen.app.push_screen(screen, callback=_advance)

    def _resolve_keylog_files(self, base_keylog: str, protocol: str) -> dict[str, str]:
        """Resolve the keylog file(s) actually written this capture, that exist.

        A single-protocol run writes the base ``-k`` path directly; a
        multi-protocol run (e.g. ``--protocol signal``, which also emits TLS
        keys) splits it into ``<stem>.<proto>.log`` per protocol. Returns
        ``{protocol: path}`` for files present on disk so the results modal and
        the decrypt-to-flow offer reflect what is on disk — not the base path,
        which a split run never writes verbatim.
        """
        if not base_keylog:
            return {}
        registry = getattr(self._ssl_logger, "_protocol_registry", None)
        try:
            from friTap.output.factory import active_keylog_paths
            candidates = active_keylog_paths(base_keylog, protocol, registry)
        except Exception:
            candidates = {protocol: base_keylog}
        existing = {proto: path for proto, path in candidates.items()
                    if path and os.path.isfile(path)}
        if not existing and os.path.isfile(base_keylog):
            existing = {protocol: base_keylog}
        return existing

    def _on_session_ended(self, result_stats: dict[str, str] | None = None) -> None:
        """Called when the capture session ends (on Textual thread)."""
        if result_stats is None:
            result_stats = {}
        state = self._screen._get_state()

        # Capture paths/flags for an optional post-capture decrypt offer
        # (a full capture writes both a pcap and a keylog) BEFORE the reset.
        decrypt_pcap = getattr(state, "pcap_path", "")
        decrypt_keylog = getattr(state, "keylog_path", "")
        decrypt_protocol = getattr(state, "protocol", "tls")
        decrypt_was_full = getattr(state, "full_capture", False)

        # The base -k path may never be written verbatim: a multi-protocol run
        # (e.g. --protocol signal, which also emits TLS keys) splits it into
        # <stem>.<proto>.log per protocol. Resolve the real files so the results
        # modal and the decrypt offer below reflect what is on disk. Done BEFORE
        # the reset (and while self._ssl_logger is still set for its registry).
        keylog_files = self._resolve_keylog_files(decrypt_keylog, decrypt_protocol)

        # Save paths BEFORE resetting
        result_paths = {}
        if keylog_files:
            multi = len(keylog_files) > 1
            for proto, path in keylog_files.items():
                label = f"Key log ({proto})" if multi else "Key log"
                result_paths[label] = path
        elif decrypt_keylog:
            result_paths["Key log"] = decrypt_keylog
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

        self._screen._get_activity_log().log_session("Capture session ended")

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

        # Close tap writer after catching up remaining flows
        self.stop_tap_recording()

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
        if (
            decrypt_was_full
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

        # Present every queued dialog sequentially — never overlapping.
        self._show_modals_sequentially(modal_queue)
