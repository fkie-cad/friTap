#!/usr/bin/env python3

"""Capture lifecycle for the TUI: config building, session start/stop and the
worker that runs a session.

Sessions run on a Textual worker thread; every UI touch from that thread goes
through ``app.call_from_thread``. Cohesive parts live in mixins next to this
module: session end (capture_session_end), result files and stats
(capture_results), the debug log (capture_debug_log) and the frida-server
pre-flight (capture_server_preflight).
"""

from __future__ import annotations

import logging
import shlex
import time

from friTap.events import ERROR_SEVERITY_FATAL
from friTap.tui.themes import c

from .capture_debug_log import DebugLogMixin
from .capture_results import (  # noqa: F401 - helpers re-exported for tests and callers
    KEYLOG_TOTAL_STAT,
    CaptureResultsMixin,
    _count_keys,
    _get_file_size,
    _key_count_label,
    _pcap_has_packets,
    _pcapng_has_packets,
    _same_file_key,
    _selected_protocols,
)
from .capture_server_preflight import FridaServerPreflightMixin
from .capture_session_end import SessionEndMixin
from .modals.alert_modal import AlertModal

logger = logging.getLogger("friTap.tui.capture")

try:
    from textual.widgets import Static
    TEXTUAL_AVAILABLE = True
except ImportError:
    TEXTUAL_AVAILABLE = False


from friTap.flow.models import format_byte_size  # noqa: E402,F401 - re-exported
from friTap.protocols.mtproto_hints import ATTACH_MEMORY_SCAN_RECOVERY  # noqa: E402

# Shown when a STOPPED capture is asked to start again; only a wizard restart (r)
# may launch a new attach/session.
CAPTURE_STOPPED_RESTART_HINT = "Capture stopped — press r to restart the wizard."


def _tokenize_spawn_command(command: str) -> list[str] | None:
    """Split the spawn modal's raw string into argv tokens, shell-style.

    Quoted paths with spaces survive. Backslashes are literal (escape disabled)
    so Windows paths such as ``wine "C:\\Program Files\\App\\app.exe"`` are not
    mangled. Returns None on unbalanced quotes (caller falls back to a plain split).
    """
    lex = shlex.shlex(command, posix=True)
    lex.whitespace_split = True
    lex.escape = ""  # backslash is a literal path separator, not an escape
    try:
        return list(lex)
    except ValueError:
        # Unbalanced quotes: caller falls back to target.split(" ").
        return None


def _pid_target_process_name(state) -> str | None:
    """The picker-resolved process name (``state.target_display``) for a numeric-PID target, else None.

    The PID alone tells the flow collector's transport classifier nothing, and
    the picker already knows the name, so no device round-trip is needed.
    """
    target = str(getattr(state, "target", "") or "")
    display = getattr(state, "target_display", "") or ""
    return display if target.isdigit() and display else None


class CaptureController(
    SessionEndMixin,
    CaptureResultsMixin,
    DebugLogMixin,
    FridaServerPreflightMixin,
):
    """Owns the capture lifecycle for MainScreen."""

    # UI-intent state, distinct from the backend ``SSL_Logger.running`` flag.
    # ``running`` flips synchronously on stop while the UI reset waits for the
    # blocking teardown, and a self-terminating scan can leave it stale. Gating
    # the Enter toggle on ``running`` alone could silently re-start a capture.
    STATE_IDLE = "idle"
    STATE_RUNNING = "running"
    STATE_STOPPING = "stopping"
    STATE_STOPPED = "stopped"

    def __init__(self, screen) -> None:
        self._screen = screen
        self._ssl_logger = None
        # IDLE: fresh. RUNNING: live. STOPPING: teardown in flight.
        # STOPPED: finished (Enter does not re-attach until a new setup or restart).
        self._capture_state: str = self.STATE_IDLE
        # Each worker remembers the generation it started with, so a late teardown
        # of an old session cannot clobber the UI state of a newer one.
        self._session_generation: int = 0
        # start_capture enters RUNNING before the worker has built SSL_Logger, so
        # an early stop has no logger to call. The worker checks this flag right
        # after building it (see _run_session).
        self._stop_requested: bool = False
        # Runs once the in-flight session has ended (see restart_when_stopped).
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
        # Decides whether the session-end AlertModal shows; recovered parser
        # errors (severity="warning") never reach _session_error.
        self._session_error_severity: str = ERROR_SEVERITY_FATAL
        # Set only when the backend raises a BackendError (frida_denied, ...).
        self._session_error_category: str | None = None
        self._session_error_original: BaseException | None = None
        # Set on a fatal ErrorEvent or process-terminated DetachEvent. The worker
        # loop exits normally on a target crash (no exception), so without this
        # the results modal would claim the capture "completed".
        self._session_crashed: bool = False
        self._session_crash_message: str = ""
        # frida-server pre-flight (see _ensure_frida_server): (device_id, device_name)
        # for USB/remote devices, None skips it. Tests flip server_preflight_enabled.
        self.server_preflight_enabled: bool = True
        self._preflight_target: tuple[str, str] | None = None
        # Coalesces flow updates so call_from_thread() is not called per chunk.
        import threading
        self._ui_lock = threading.Lock()
        self._pending_ui_updates: dict[str, tuple] = {}
        self._ui_flush_scheduled: bool = False

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
        """Return to IDLE; called by ``MainScreen.action_restart_wizard``."""
        self._capture_state = self.STATE_IDLE

    def restart_when_stopped(self, restart) -> None:
        """Stop the in-flight capture and call ``restart`` once it has ended.

        The old worker's teardown (frida detach, pcap pull) takes seconds. Its
        late ``_on_session_ended`` would wipe the wizard's new target or tear
        down a new session, so ``_on_session_ended`` runs ``restart`` itself.
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
        """True when a target and a capture mode are configured."""
        has_mode = bool(
            getattr(state, "keylog_path", "")
            or getattr(state, "pcap_path", "")
            or getattr(state, "live", False)
        )
        return bool(getattr(state, "target", "")) and has_mode

    def action_start_capture(self) -> None:
        """Validate the setup and start a capture."""
        # RUNNING/STOPPING refuse. STOPPED starts only after a new manual setup
        # (a/s target + 1-6 mode): the ended session cleared target and mode, so
        # a bare Enter never re-attaches the old session.
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
        """Warn if loaded plugins are incompatible with the selected backend."""
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
        """Request a stop and move to STOPPING with instant UI feedback.

        A second press while STOPPING/STOPPED is a no-op. The worker's ``finally``
        block does the cleanup and ``_on_session_ended`` moves to STOPPED. If the
        logger is not built yet, ``_stop_requested`` stops it once it exists.
        """
        if self._capture_state == self.STATE_RUNNING:
            self._capture_state = self.STATE_STOPPING
            # Set before reading self._ssl_logger; the worker assigns the logger
            # before reading the flag, so at least one side sees the other.
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
        # Stop owns RUNNING and STOPPING feedback; start owns IDLE and STOPPED.
        if self._capture_state in (self.STATE_RUNNING, self.STATE_STOPPING):
            self.action_stop_capture()
        else:
            self.action_start_capture()

    def action_escape_action(self) -> None:
        """Esc stops a running capture."""
        if self._screen._wizard_guard():
            return
        if self._capture_state == self.STATE_RUNNING:
            self.action_stop_capture()

    def start_tap_recording(self, path: str) -> None:
        """Wire a TapWriter to the flow collector.

        Live capture subscribes for future COMPLETE events; an ended capture
        writes all flows and closes immediately.
        """
        if self._flow_collector is None:
            self._warn("No flow collector active. Start a capture first.")
            return

        if self._tap_writer is not None:
            self.stop_tap_recording()

        from friTap.flow.tap_writer import TapWriter

        writer = TapWriter()
        state = self._screen._get_state()
        target = state.target_display or state.target or ""
        writer.open(path, target=target)

        from friTap.flow.models import FlowState
        for flow in self._flow_collector.get_flows():
            if flow.state == FlowState.COMPLETE:
                writer.write_flow(flow)

        session_running = self._ssl_logger and self._ssl_logger.running
        if session_running:
            self._flow_collector.subscribe(writer.on_flow_event)
            # Finished Java request contexts (--attribute-sdk) become .tap records.
            self._flow_collector.set_request_context_sink(writer.write_request_context)
            self._tap_writer = writer
            self._screen._get_activity_log().log_info(
                f"Saving capture to: [bold]{path}[/]"
            )
            self._toast(f"Recording to {path}")
        else:
            writer.close()
            self._screen._get_activity_log().log_info(
                f"Capture saved: [bold]{writer.path}[/] "
                f"({writer.flow_count} flows)"
            )
            self._toast(f"Saved {writer.flow_count} flows to {writer.path}")

    def stop_tap_recording(self) -> None:
        """Close the active TapWriter if any."""
        if self._tap_writer is not None:
            if self._flow_collector is not None:
                self._flow_collector.set_request_context_sink(None)
            try:
                path = self._tap_writer.path
                self._tap_writer.close()
                count = self._tap_writer.flow_count
                self._screen._get_activity_log().log_info(
                    f"Capture saved: [bold]{path}[/] ({count} flows)"
                )
                self._toast(f"Saved {count} flows to {path}")
            except Exception as e:
                # A modal (which _warn also logs) outlasts a transient toast.
                self._warn(
                    f"Error saving .tap: {e}",
                    title="Save Failed",
                    severity="error",
                )
            finally:
                self._tap_writer = None

    def build_config(self, state):
        """Build a FriTapConfig from the TUI AppState."""
        from friTap.config import (
            DeviceConfig,
            FriTapConfig,
            HookingConfig,
            OutputConfig,
        )

        device = DeviceConfig(spawn=state.spawn)
        if state.device_id:
            device.device_id = state.device_id
        if state.device_type == "usb":
            # Mobile routes a full capture to on-device tcpdump
            # (PCAP.FullCaptureThread.full_mobile_capture); the host-side Scapy
            # /dev/bpf path needs root and cannot see the phone's traffic. The
            # concrete device id picks the right phone, True auto-detects the
            # first USB device. Device selection still prefers device_id
            # (session_manager's `elif logger.mobile` only runs without one).
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

        # Spawn tokenizes the typed command so a quoted path with spaces survives
        # to device.spawn(). Attach uses state.target verbatim (name/PID). None
        # falls back to session_manager's plain split.
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
        """Build config, wire the TUI handler and start the session on a worker thread.

        SSL_Logger is built on that thread because the live-mode FIFO open blocks.
        """
        from friTap.tui.handlers import TuiOutputHandler

        self._pending_config = self.build_config(state)
        self._tui_handler = TuiOutputHandler(self._screen.app)
        self._preflight_target = self._preflight_target_for(state)

        data_modes = {"full", "plaintext", "wireshark", "live_pcapng"}
        if self._capture_mode in data_modes:
            try:
                from friTap.flow.collector import FlowCollector
                # Live Signal decoding is opt-in. It only catches keys arriving
                # before or with the DATA; the session-end offline reprocess
                # recovers late keys.
                signal_messages = "signal" in _selected_protocols(state)
                self._flow_collector = FlowCollector(signal_messages=signal_messages)
                process_name = _pid_target_process_name(state)
                if process_name:
                    self._flow_collector.set_capture_target(
                        state.target or "", process_name=process_name)
                else:
                    self._flow_collector.set_capture_target(state.target or "")
                self._flow_collector.subscribe(self._on_flow_update)
            except ImportError:
                self._flow_collector = None
        else:
            self._flow_collector = None

        self._capture_state = self.STATE_RUNNING
        self._session_generation += 1
        self._stop_requested = False

        mode_display = self._capture_mode or "Custom"
        self._screen._get_status_bar().update_capture("STARTING", mode_display)
        menu = self._screen._get_menu_panel()
        menu.capture_active = True
        menu.target_name = state.target_display or state.target

        log = self._screen._get_activity_log()
        mode_action = "Spawning" if state.spawn else "Attaching to"
        log.log_info(f"{mode_action}: [bold {c('target')}]{state.target_display or state.target}[/]...")

        # MTProto obfuscation normally needs each connection from byte 0. With
        # memory scanning, Tier E recovers the live CTR state and the offline
        # decryptor seeks into a mid-stream capture, so the hint depends on it.
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

        # Never call install_signal_handler() here: its CLI signal handler ends the
        # whole process with os._exit (after the teardown, or forced on repeated
        # signals), which would kill the TUI.
        self._screen.run_worker(self._run_session, thread=True)

    def _run_session(self) -> None:
        """Worker-thread body: build SSL_Logger, run the session, tear down, report.

        Built here, not on the Textual thread, because the live FIFO open blocks.
        """
        # Teardown uses this run's own logger and generation, not self.* values
        # that may point at a newer session by the time it finishes.
        generation = self._session_generation
        session_logger = None
        self._reset_session_error_state()
        lsass_started = False
        try:
            from friTap.ssl_logger import SSL_Logger
            debug_output_enabled = self._pending_config.debug_output
            lsass_params = self._take_lsass_params(self._pending_config)
            # Raises a clear RuntimeError (Capture Error modal) instead of a
            # cryptic "closed" at attach.
            self._ensure_frida_server()
            # Before SSL_Logger exists so init-time records land in the file;
            # the EventBus subscription follows once the bus exists.
            if debug_output_enabled:
                self._open_debug_log_file()
            session_logger = self._ssl_logger = SSL_Logger(config=self._pending_config)
            self._embed_session_logger(session_logger)
            self._subscribe_session_outputs(debug_output_enabled)

            if self._stop_requested:
                # Stopped during start-up: never attach.
                return

            # Emits LiveReadyEvent (TUI launches Wireshark); blocks until the
            # FIFO connects or times out.
            self._ssl_logger.connect_live()
            self._screen.app.call_from_thread(self._show_capturing_ui)

            # Before the target handshake so the Schannel secrets are captured.
            # Blocks ~2s until the hook is live; fine on this worker thread.
            if lsass_params is not None:
                try:
                    from friTap.friTap import hook_lsass
                    hook_lsass(**lsass_params)
                    lsass_started = True
                    self._register_lsass_cleanup_at_exit()
                except Exception as e:
                    self._screen.app.call_from_thread(
                        lambda err=e: self._screen._get_activity_log().log_warning(
                            f"LSASS key extraction unavailable: {err}"))

            self._run_until_session_stops(session_logger)
        except (Exception, SystemExit) as e:
            self._record_session_failure(e)
        finally:
            self._finish_session(session_logger, lsass_started, generation)

    def _reset_session_error_state(self) -> None:
        """Clear the error and crash fields a previous session may have left."""
        self._session_error = ""
        self._session_error_category = None
        self._session_error_original = None
        self._session_crashed = False
        self._session_crash_message = ""

    @staticmethod
    def _take_lsass_params(cfg) -> dict | None:
        """hook_lsass() kwargs for a local Windows capture, else None.

        On Windows the Schannel secrets live in lsass, not in the target, so key
        extraction needs a separate lsass hook (the CLI starts it in
        friTap.main()). Snapshot the params now because the config is cleared
        after SSL_Logger is built, and disable the session's own lsass hook so
        only the dedicated LsassHookWorker touches lsass.
        """
        lsass_params = None
        try:
            from friTap.fritap_utility import are_we_running_on_windows
            # lsass is local-Windows only: never for a mobile or remote
            # (--host) target, even when the analyst's own OS is Windows.
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
        return lsass_params

    def _embed_session_logger(self, session_logger) -> None:
        """Mark the new logger as TUI-hosted and honour a stop requested during the build."""
        self._ssl_logger._tui_mode = True
        # The TUI hosts the session: never os._exit on a target death.
        self._ssl_logger._embedded = True  # see SSL_Logger.set_embedded
        self._pending_config = None
        # A stop requested during the build had no logger to call; honour it
        # now (request_stop flips `running`, which __init__ set True).
        if self._stop_requested:
            session_logger.request_stop()

    def _subscribe_session_outputs(self, debug_output_enabled: bool) -> None:
        """Wire the TUI handler, crash tracking, flow collector and debug log to the bus."""
        # Before connect_live() so the handler sees LiveReadyEvent and can
        # launch Wireshark.
        self._tui_handler.setup(self._ssl_logger._event_bus)
        self._ssl_logger._output_handlers.append(self._tui_handler)

        # On a target crash the session emits a fatal ErrorEvent and a
        # process-terminated DetachEvent and stops `running`, so the run loop
        # exits without an exception. Record it for _on_session_ended.
        from friTap.events import DetachEvent as _DetachEvent
        from friTap.events import ErrorEvent as _ErrorEvent
        self._ssl_logger._event_bus.subscribe(_ErrorEvent, self._on_session_error_event)
        self._ssl_logger._event_bus.subscribe(_DetachEvent, self._on_session_detach_event)

        if self._flow_collector is not None:
            self._flow_collector.subscribe_to(self._ssl_logger._event_bus)
            self._flow_collector.set_event_bus(self._ssl_logger._event_bus)

        if debug_output_enabled:
            self._setup_debug_log(self._ssl_logger._event_bus)

    def _show_capturing_ui(self) -> None:
        """Switch the status bar and title to CAPTURING (Textual thread)."""
        mode_display = self._capture_mode or "Custom"
        self._screen._get_status_bar().update_capture("CAPTURING", mode_display)
        try:
            title = self._screen.query_one("#activity-title", Static)
            title.update(f"[bold {c('success')}]friTap Console[/]  [bold green on {c('bg-capture')}] CAPTURING [/]")
        except Exception:
            pass
        state = self._screen._get_state()
        if getattr(state, 'view_mode', 'legacy') == 'flow' and self._flow_collector is not None:
            self._screen._activate_flow_view()

        if getattr(state, 'encapsulated_protocols', {}).get("ohttp", True):
            try:
                from friTap.tui.widgets.flow_detail import FlowDetailWidget
                from friTap.tui.widgets.ohttp_tab import OhttpTabProvider
                flow_detail = self._screen.query_one("#flow-detail", FlowDetailWidget)
                if not any(t.tab_id == "ohttp" for t in flow_detail._extra_tabs):
                    flow_detail.register_tab(OhttpTabProvider())
            except Exception:
                pass

    def _register_lsass_cleanup_at_exit(self) -> None:
        """Register the lsass hook cleanup with atexit once per controller."""
        if not getattr(self, "_lsass_atexit_registered", False):
            import atexit

            from friTap.friTap import cleanup_lsass_hook as _cleanup_lsass
            atexit.register(_cleanup_lsass)
            self._lsass_atexit_registered = True

    def _run_until_session_stops(self, session_logger) -> None:
        """Start the session and poll until it stops; a crash becomes a fatal error."""
        session_logger.start_fritap_session()
        while session_logger.running:
            time.sleep(0.2)
        # The loop exits normally on a crash; promote it to a fatal error.
        if self._session_crashed and not self._session_error:
            self._session_error = (
                self._session_crash_message
                or "Target process crashed during capture."
            )
            self._session_error_severity = ERROR_SEVERITY_FATAL

    def _record_session_failure(self, e: BaseException) -> None:
        """Store the failure for the Capture Error modal, log it and emit an ErrorEvent."""
        # BackendError carries the original frida class plus euid/SIP/target/
        # server context; anything else falls back to str().
        if hasattr(e, "diagnostic_summary"):
            self._session_error = e.diagnostic_summary()
        else:
            self._session_error = str(e)
        self._session_error_category = getattr(e, "category", None)
        self._session_error_original = getattr(e, "original_exception", e)
        self._session_error_severity = ERROR_SEVERITY_FATAL
        # The modal shows no traceback; keep it in the debug log.
        logger.exception("Capture session failed: %s", e)
        # Lets the EventBus debug-log subscriber record the failure too.
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

    def _finish_session(self, session_logger, lsass_started: bool, generation: int) -> None:
        """Worker-thread teardown, then hand the results to ``_on_session_ended``."""
        # Stop the lsass worker before tearing down the target session.
        if lsass_started:
            try:
                from friTap.friTap import cleanup_lsass_hook
                cleanup_lsass_hook()
            except Exception:
                logger.debug("lsass hook cleanup failed", exc_info=True)
        result_stats: dict[str, str] = {}
        # Blocking I/O stays on this worker thread.
        if session_logger is not None:
            self._close_debug_log()
            self._cleanup_session_logger(session_logger)
            # File I/O off the UI thread.
            result_stats = self._gather_result_stats()

        def _finalize(stats=result_stats, gen=generation):
            self._on_session_ended(stats, generation=gen)
        self._screen.app.call_from_thread(_finalize)

    def _cleanup_session_logger(self, sl) -> None:
        """Drain the message queue, stop the proxy and unload the Frida script (blocking)."""
        try:
            sl.finish_fritap()
            sl.pcap_cleanup(sl.full_capture, sl.mobile, sl.pcap_name)
            sl.cleanup(sl.live, sl.socket_trace, sl.full_capture, sl.debug_output)
        except Exception as e:
            def _log_cleanup(err=e):
                self._screen._get_activity_log().log_error(f"Cleanup error: {err}")
            self._screen.app.call_from_thread(_log_cleanup)

    def _on_session_error_event(self, event) -> None:
        """Mark the session crashed on a fatal ErrorEvent (message-consumer thread).

        Recovered parser warnings only reach the activity log and debug file.
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
        """Mark the session crashed only when the target died inside a hook.

        A plain exit (e.g. a short-lived target) leaves the agent breadcrumb at
        ``agent-init*``/empty because no hook was running; that is not a crash.
        """
        try:
            reason = getattr(event, "reason", "")
            if reason in ("process-terminated", "process-replaced"):
                crumb = getattr(self._ssl_logger, "_last_hook_breadcrumb", "") or ""
                spawn = getattr(self._ssl_logger, "spawn", False)
                # Clean only if the agent fully initialised in attach mode; an
                # empty/partial crumb (esp. a spawn startup crash) counts as a crash.
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
        """Coalesce updates per flow_id and flush in batches.

        A call_from_thread() per data chunk starves Textual's event loop under
        heavy load.
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
        """Apply batched updates on the Textual thread."""
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
