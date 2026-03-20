#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Capture controller -- manages the capture lifecycle extracted from MainScreen.

Handles config building, session start/stop, background worker management,
and post-session UI cleanup.
"""

from __future__ import annotations

import os
import time

from .modals.alert_modal import AlertModal

try:
    from textual.widgets import Static
    TEXTUAL_AVAILABLE = True
except ImportError:
    TEXTUAL_AVAILABLE = False


def _format_size(size_bytes: int) -> str:
    """Format a byte count as a human-readable string."""
    size = float(size_bytes)
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024:
            return f"{int(size)} B" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"


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


class CaptureController:
    """Manages capture lifecycle -- extracted from MainScreen."""

    def __init__(self, screen) -> None:
        self._screen = screen
        self._ssl_logger = None
        self._tui_handler = None
        self._capture_mode: str = ""

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
        """Stop the active capture session."""
        if self._ssl_logger and self._ssl_logger.running:
            self._screen._get_activity_log().log_info("Stopping capture...")
            try:
                self._ssl_logger.finish_fritap()
            except Exception as e:
                self._screen._get_activity_log().log_error(f"Error stopping: {e}")
            finally:
                self._ssl_logger.running = False
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
    # Config & session
    # ----------------------------------------------------------

    def build_config(self, state):
        """Build a FriTapConfig from AppState."""
        from friTap.config import FriTapConfig, DeviceConfig, OutputConfig, HookingConfig

        device = DeviceConfig(spawn=state.spawn)
        if state.device_type == "usb":
            device.mobile = state.device_id if state.device_id else True
        elif state.device_type == "remote":
            device.host = state.device_id or None

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
            hooking=HookingConfig(library_scan=getattr(state, 'library_scan', False)),
            protocol=getattr(state, 'protocol', 'tls'),
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

        # Update UI state to STARTING
        mode_display = self._capture_mode or "Custom"
        self._screen._get_status_bar().update_capture("STARTING", mode_display)
        menu = self._screen._get_menu_panel()
        menu.capture_active = True
        menu.target_name = state.target_display or state.target

        log = self._screen._get_activity_log()
        mode_action = "Spawning" if state.spawn else "Attaching to"
        log.log_info(f"{mode_action}: [bold #d4945a]{state.target_display or state.target}[/]...")

        # CRITICAL: Do NOT call install_signal_handler() -- it calls os._exit(0)
        self._screen.run_worker(self._run_session, thread=True)

    def _run_session(self) -> None:
        """Run the SSL_Logger session in a background thread.

        SSL_Logger is created here (not on the Textual thread) so that
        the blocking FIFO open in live mode doesn't freeze the UI.
        """
        result_stats: dict[str, str] = {}
        try:
            from friTap.ssl_logger import SSL_Logger
            self._ssl_logger = SSL_Logger(config=self._pending_config)
            self._ssl_logger._tui_mode = True
            self._pending_config = None

            # Wire TUI output handler to the event bus BEFORE connect_live()
            # so it receives LiveReadyEvent and can launch Wireshark
            self._tui_handler.setup(self._ssl_logger._event_bus)
            self._ssl_logger._output_handlers.append(self._tui_handler)

            # Connect live Wireshark handler (emits LiveReadyEvent → TUI
            # launches Wireshark → blocks until FIFO connected or timeout)
            self._ssl_logger.connect_live()

            # Update UI to CAPTURING now that SSL_Logger is ready
            def _update_capturing():
                mode_display = self._capture_mode or "Custom"
                self._screen._get_status_bar().update_capture("CAPTURING", mode_display)
                try:
                    title = self._screen.query_one("#activity-title", Static)
                    title.update("[bold #4ade80]friTap Console[/]  [bold green on #1a3a1a] CAPTURING [/]")
                except Exception:
                    pass
            self._screen.app.call_from_thread(_update_capturing)

            self._ssl_logger.start_fritap_session()
            while self._ssl_logger.running:
                time.sleep(0.2)
        except (Exception, SystemExit) as e:
            def _log_error(err=e):
                self._screen._get_activity_log().log_error(str(err))
            self._screen.app.call_from_thread(_log_error)
        finally:
            # All blocking I/O runs here on the background thread
            if self._ssl_logger:
                try:
                    sl = self._ssl_logger
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
                stats["PCAP"] = _format_size(size)
        return stats

    def _on_session_ended(self, result_stats: dict[str, str] | None = None) -> None:
        """Called when the capture session ends (on Textual thread)."""
        if result_stats is None:
            result_stats = {}
        state = self._screen._get_state()

        # Save paths BEFORE resetting
        result_paths = {}
        if state.keylog_path:
            result_paths["Key log"] = state.keylog_path
        if state.pcap_path:
            result_paths["PCAP"] = state.pcap_path
        target_display = state.target_display or state.target or "unknown"
        saved_live_mode = state.live_mode
        is_mobile = state.device_type == "usb"

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

        # Revert console title
        try:
            title = self._screen.query_one("#activity-title", Static)
            title.update("[bold #4ade80]friTap Console[/]")
        except Exception:
            pass

        # Teardown handler and clear references
        saved_key_count = self._tui_handler.key_count if self._tui_handler else 0
        if self._tui_handler is not None:
            self._tui_handler.teardown()
            self._tui_handler = None

        # Suggest library scan if no libraries detected
        if self._ssl_logger and not self._ssl_logger._detected_libraries:
            if not result_paths:
                self._screen.app.push_screen(
                    AlertModal(
                        message="No TLS libraries were detected.\n\n"
                                "Consider enabling [bold]Library Scan[/] (press [bold]l[/] in the start screen) "
                                "to discover renamed or statically linked libraries.",
                        title="No Libraries Found",
                        severity="warning",
                    )
                )

        # Show results summary with pre-computed statistics
        if result_paths:
            lines = [f"Capture of [bold]{target_display}[/] completed.\n"]
            for label, path in result_paths.items():
                stat = result_stats.get(label)
                suffix = f" ({stat})" if stat else ""
                lines.append(f"  {label}: [bold]{path}[/]{suffix}")
            self._screen.app.push_screen(
                AlertModal(message="\n".join(lines), title="Capture Results", severity="info")
            )

        # Mode 5: live auto-decrypt has no file output — show save instructions
        elif saved_live_mode == "live_pcapng":
            key_count = saved_key_count
            key_label = f"{key_count} key{'s' if key_count != 1 else ''}" if key_count else "No keys"

            lines = [
                f"Live capture of [bold]{target_display}[/] completed.\n",
                f"[bold #4ade80]TLS secrets extracted:[/] [bold]{key_label}[/]",
                "  Secrets are already embedded in the PCAPNG stream.\n",
                "[bold #f59e0b]Save your capture:[/]",
                "  In Wireshark: [bold]File → Save As → .pcapng[/]\n",
                "[bold #818cf8]Note:[/] This was a full network capture.",
                "  Packets from other applications may be present.",
                "  Wireshark auto-decrypts only traffic with matching TLS keys.",
            ]
            if not is_mobile:
                display_filter = "not tcp.port == 27042"
                lines.append("")
                lines.append(f"[bold #4ade80]Filter out Frida traffic:[/]")
                lines.append(f"  Display filter: [bold]{display_filter}[/]")
            self._screen.app.push_screen(
                AlertModal(message="\n".join(lines), title="Live Capture Complete", severity="info")
            )

        # Mode 4: plaintext Wireshark — also no file output
        elif saved_live_mode == "wireshark":
            lines = [
                f"Live capture of [bold]{target_display}[/] completed.\n",
                "[bold #f59e0b]Save your capture:[/]",
                "  In Wireshark: [bold]File → Save As[/]",
            ]
            self._screen.app.push_screen(
                AlertModal(message="\n".join(lines), title="Live Capture Complete", severity="info")
            )

        self._ssl_logger = None
