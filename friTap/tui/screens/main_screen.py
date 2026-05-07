#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Main screen for friTap TUI -- single split-pane layout.

Replaces the 5-screen sequential flow with a permanent main screen.
Left panel: StatusBar + MenuPanel. Right panel: ActivityLog.
Device/process selection via modals.
"""

from __future__ import annotations

import sys
from typing import Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from ..app import AppState

try:
    from textual.app import ComposeResult
    from textual.binding import Binding  # noqa: F401
    from textual.screen import Screen
    from textual.widgets import Header, Footer, Static, TabbedContent
    from textual.containers import Horizontal, Vertical
    TEXTUAL_AVAILABLE = True
except ImportError:
    TEXTUAL_AVAILABLE = False

if TEXTUAL_AVAILABLE:
    from ..widgets.activity_log import ActivityLog
    from ..widgets.status_bar import StatusBar
    from ..widgets.menu_panel import MenuPanel
    from ..widgets.flow_list import FlowListWidget
    from ..widgets.flow_detail import FlowDetailWidget
    from ..widgets.filter_bar import FilterBar
    from ..modals.device_modal import DeviceSelectModal
    from ..modals.process_modal import ProcessSelectModal
    from ..modals.spawn_modal import SpawnInputModal
    from ..modals.help_modal import HelpScreen
    from ..modals.protocol_modal import ProtocolSelectModal
    from ..modals.filter_modal import FilterModal, FilterResult
    from ..wizard import CaptureWizard
    from ..capture_controller import CaptureController
    from ..mode_controller import ModeController
    from ..themes import c

    def _needs_reparse(flow, summary) -> bool:
        """Check if a flow should be re-parsed with current parser code.

        Triggers re-parse for:
        - Unknown protocol (legacy .tap files without proper detection)
        - HTTP/2 ghost flows (old code skipped SETTINGS-only control frames)
        - WebSocket TEXT flows (old code missed permessage-deflate decompression)
        """
        proto = flow.display_protocol
        if proto == "unknown":
            return True
        # HTTP/2 ghost flows: protocol detected but no request (SETTINGS-only)
        if "HTTP/2" in proto and flow.request is None:
            return True
        # HTTP/2 control frames from old .tap files: method matches but is_control_frame not set
        if "HTTP/2" in proto and flow.request is not None:
            if flow.request.method in ("SETTINGS", "PING", "GOAWAY", "WINDOW_UPDATE"):
                if not flow.request.is_control_frame:
                    return True
        # WebSocket TEXT: always re-parse to apply decompression + content detection
        # (Old .tap files stored compressed body; new parser decompresses + detects JSON)
        if proto == "WebSocket" and summary.method == "TEXT":
            return True
        return False

    class MainScreen(Screen):
        """Single-screen split-pane layout for friTap TUI."""

        BINDINGS = [
            Binding("f", "toggle_view", "Toggle View", show=False),
            Binding("slash", "focus_filter", "Filter", show=False),
            Binding("shift+escape", "clear_filter", "Clear Filter", show=False),
        ]

        def __init__(self, replay_file: str | None = None, **kwargs) -> None:
            super().__init__(**kwargs)
            self._replay_file = replay_file
            self._replay_filename: str | None = None
            self._replay_ctrl = None
            self._wizard = CaptureWizard(self)
            self._capture = CaptureController(self)
            self._mode_ctrl = ModeController(self)

        # ----------------------------------------------------------
        # Layout
        # ----------------------------------------------------------

        def compose(self) -> ComposeResult:
            yield Header(show_clock=True)
            with Horizontal(id="main-split"):
                with Vertical(id="left-panel"):
                    yield StatusBar(id="status-bar")
                    yield MenuPanel(id="menu-panel")
                with Vertical(id="right-panel"):
                    with Horizontal(id="activity-title-row"):
                        yield Static("", id="capture-indicator")
                        yield Static(f"[bold {c('success')}]friTap Console[/]", id="activity-title")
                        yield Static("", id="title-spacer")
                    yield FilterBar(id="filter-bar")
                    yield ActivityLog(id="activity-log")
                    yield FlowListWidget(id="flow-list")
                    yield FlowDetailWidget(id="flow-detail")
            yield Footer()

        def on_mount(self) -> None:
            """Initialize the screen with welcome message and device info."""
            self._get_state()  # ensure state is initialized

            # Hide flow widgets and filter bar initially
            self.query_one("#filter-bar").display = False
            self.query_one("#flow-list").display = False
            self.query_one("#flow-detail").display = False

            # Replay mode — skip wizard, load .tap file directly
            if self._replay_file:
                self._init_replay_mode()
                return

            # Show welcome banner
            activity = self.query_one("#activity-log", ActivityLog)
            try:
                from friTap.about import __version__
                activity.show_welcome(version=__version__)
            except ImportError:
                activity.show_welcome()

            # Initialize status bar with local device
            status = self.query_one("#status-bar", StatusBar)
            platform_name = {"darwin": "macOS", "win32": "Windows"}.get(
                sys.platform, "Linux"
            )
            status.update_device(platform_name, "[L]")

            # Launch guided setup wizard
            self._start_wizard()

        # ----------------------------------------------------------
        # Replay mode
        # ----------------------------------------------------------

        def _init_replay_mode(self) -> None:
            """Initialize replay mode from a .tap file."""
            from pathlib import Path
            from ..replay_controller import ReplayController
            from friTap.flow.models import Flow, FlowState

            path = self._replay_file
            filename = Path(path).name
            self._replay_filename = filename

            try:
                self._replay_ctrl = ReplayController(path)
                meta = self._replay_ctrl.load()
            except Exception as e:
                from ..modals.alert_modal import AlertModal
                self.app.push_screen(
                    AlertModal(
                        message=f"Failed to open {filename}:\n\n{e}",
                        title="Replay Error",
                        severity="error",
                    )
                )
                return

            # Activate flow view immediately (hides left panel + activity log)
            self._activate_flow_view()

            # Update title for replay mode
            count = self._replay_ctrl.flow_count
            try:
                title = self.query_one("#activity-title", Static)
                title.update(
                    f"[bold {c('primary')}]friTap Replay[/]  "
                    f"[dim]{filename} ({count} flow{'s' if count != 1 else ''})"
                    f" | Enter: details | /: filter | Esc: back | w: export | q: quit[/]"
                )
            except Exception:
                pass
            self._update_capture_indicator()

            # Populate flow list from summaries
            from friTap.parsers.base import ParseResult
            from friTap.flow.reparse import reparse_flow
            flow_list = self.query_one("#flow-list", FlowListWidget)
            for summary in self._replay_ctrl.get_summaries():
                flow = Flow(
                    flow_id=summary.flow_id,
                    connection_id=summary.connection_id,
                    src_addr=summary.src_addr,
                    src_port=summary.src_port,
                    dst_addr=summary.dst_addr,
                    dst_port=summary.dst_port,
                    ssl_session_id=summary.ssl_session_id,
                    state=FlowState.COMPLETE,
                    started=summary.started,
                    ended=summary.ended,
                )
                has_parsed_request = (
                    summary.method or summary.url or summary.host
                    or summary.protocol not in ("unknown", "")
                )
                if has_parsed_request:
                    flow.request = ParseResult(
                        protocol=summary.protocol,
                        method=summary.method,
                        url=summary.url,
                        host=summary.host,
                        is_request=True,
                        is_complete=True,
                        is_control_frame=summary.is_control_frame,
                    )
                if summary.status_code > 0:
                    flow.response = ParseResult(
                        status_code=summary.status_code,
                        status_text=summary.status_text,
                        body_size=summary.body_size,
                        is_request=False,
                        is_complete=True,
                    )
                # Re-parse flows that can benefit from updated parsers:
                # - Unknown protocol (legacy .tap files)
                # - HTTP/2 ghost flows (old code skipped control frames)
                # - WebSocket with non-UTF-8 TEXT body (old code missed decompression)
                if summary.total_size > 0 and _needs_reparse(flow, summary):
                    full_flow = self._replay_ctrl.get_flow(summary.flow_id)
                    if full_flow is not None and reparse_flow(full_flow):
                        flow.request = full_flow.request
                        flow.response = full_flow.response
                        self._replay_ctrl.store_reparse(
                            summary.flow_id, full_flow.request, full_flow.response,
                        )

                flow._total_bytes = summary.total_size
                flow_list.add_or_update_flow(flow)

        def _present_flow_detail(self, flow) -> None:
            """Show the flow detail widget for a given Flow object."""
            self.query_one("#flow-list").display = False
            self.query_one("#left-panel").display = False
            detail = self.query_one("#flow-detail", FlowDetailWidget)
            detail.show_flow(flow)
            detail.display = True
            self._update_detail_title()

            def _focus_tabs():
                try:
                    inner_tabs = detail.query_one("#flow-tabs Tabs")
                    inner_tabs.focus()
                except Exception:
                    detail.focus()
                detail.scroll_to_top()

            self.call_after_refresh(_focus_tabs)

        def action_save_tap(self) -> None:
            """Show save dialog for .tap file export."""
            # In replay mode, re-export is available too
            if self._replay_ctrl is not None:
                collector_has_flows = self._replay_ctrl.flow_count > 0
            else:
                collector_has_flows = (
                    self._capture.flow_collector is not None
                    and len(self._capture.flow_collector.get_flows()) > 0
                )

            if not collector_has_flows:
                from ..modals.alert_modal import AlertModal
                self.app.push_screen(
                    AlertModal(
                        message="No flows to save.\nStart a capture with flow view first.",
                        title="Save Capture",
                        severity="warning",
                    )
                )
                return

            from ..modals.save_tap_modal import SaveTapModal
            self.app.push_screen(SaveTapModal(), callback=self._on_save_tap_result)

        def _on_save_tap_result(self, path: str | None) -> None:
            """Handle the result from SaveTapModal."""
            if path is None:
                return

            if self._replay_ctrl is not None:
                # Re-export from replay: write all flows to new file
                self._export_replay_to_tap(path)
            else:
                # Live capture: wire the TapWriter to the FlowCollector
                self._capture.start_tap_recording(path)

        def _export_replay_to_tap(self, path: str) -> None:
            """Export all replay flows to a new .tap file."""
            from friTap.flow.tap_writer import TapWriter

            try:
                writer = TapWriter()
                header = self._replay_ctrl.header
                target = header.capture_target if header else ""
                writer.open(path, target=target)

                for flow in self._replay_ctrl.get_flows():
                    writer.write_flow(flow)

                writer.close()

                from ..modals.alert_modal import AlertModal
                self.app.push_screen(
                    AlertModal(
                        message=f"Exported {writer.flow_count} flows to:\n[bold]{path}[/]",
                        title="Export Complete",
                        severity="info",
                    )
                )
            except Exception as e:
                from ..modals.alert_modal import AlertModal
                self.app.push_screen(
                    AlertModal(
                        message=f"Export failed:\n{e}",
                        title="Export Error",
                        severity="error",
                    )
                )

        # ----------------------------------------------------------
        # State helpers
        # ----------------------------------------------------------

        def _get_state(self) -> "AppState":
            """Return the shared AppState from the app."""
            return self.app.app_state

        def _get_activity_log(self) -> ActivityLog:
            return self.query_one("#activity-log", ActivityLog)

        def _get_status_bar(self) -> StatusBar:
            return self.query_one("#status-bar", StatusBar)

        def _get_menu_panel(self) -> MenuPanel:
            return self.query_one("#menu-panel", MenuPanel)

        # ----------------------------------------------------------
        # Background checks
        # ----------------------------------------------------------

        def _check_server_status(self) -> None:
            """Check frida-server status in a worker thread (USB/remote only)."""
            state = self._get_state()
            if state.device_type == "local" or not state.device_id:
                return
            try:
                from friTap.backends import get_backend
                backend = get_backend()
                device = backend.get_device(mobile=state.device_id)
                is_running = backend.check_connectivity(device)
            except Exception:
                is_running = False
            server_status = "running" if is_running else "not running"
            def _update_ui():
                status = self._get_status_bar()
                status.update_device(status.device_name, status.device_type, server_status)
                self._get_menu_panel().server_running = is_running
            self.app.call_from_thread(_update_ui)

        # ----------------------------------------------------------
        # Wizard delegation
        # ----------------------------------------------------------

        def _wizard_guard(self) -> bool:
            """Return True if wizard is active (blocks manual actions)."""
            return self._wizard.guard()

        def _start_wizard(self) -> None:
            """Launch the guided setup wizard."""
            self._wizard.start()

        @property
        def _wizard_active(self) -> bool:
            return self._wizard.active

        @_wizard_active.setter
        def _wizard_active(self, value: bool) -> None:
            self._wizard.active = value

        # ----------------------------------------------------------
        # Capture delegation
        # ----------------------------------------------------------

        @property
        def _ssl_logger(self):
            return self._capture.ssl_logger

        @property
        def _tui_handler(self):
            return self._capture.tui_handler

        @property
        def _capture_mode(self) -> str:
            return self._capture.capture_mode

        @_capture_mode.setter
        def _capture_mode(self, value: str) -> None:
            self._capture.capture_mode = value

        def _build_config(self, state):
            return self._capture.build_config(state)

        def _start_capture(self, state) -> None:
            self._capture.start_capture(state)

        def action_start_capture(self) -> None:
            self._capture.action_start_capture()

        def action_stop_capture(self) -> None:
            self._capture.action_stop_capture()

        def stop_if_capturing(self) -> None:
            """Stop capture if one is running. Also cleans up replay. Safe to call from app shutdown."""
            if self._ssl_logger and self._ssl_logger.running:
                self._capture.action_stop_capture()
            if self._replay_ctrl is not None:
                self._replay_ctrl.close()
                self._replay_ctrl = None

        def action_toggle_capture(self) -> None:
            self._capture.action_toggle_capture()

        def action_escape_action(self) -> None:
            flow_detail = self.query_one("#flow-detail")
            if flow_detail.display:
                self._back_to_flow_list()
                return
            if self._ssl_logger and self._ssl_logger.running:
                self._capture.action_escape_action()
                return
            # Not capturing → trigger quit confirmation
            self.app.action_quit()

        # ----------------------------------------------------------
        # Device selection
        # ----------------------------------------------------------

        def action_device_select(self) -> None:
            """Open the device selection modal."""
            if self._wizard_guard():
                return
            state = self._get_state()

            def _on_result(device_id: Optional[str]) -> None:
                if device_id is None:
                    return
                self._apply_device_selection(device_id)

            self.app.push_screen(
                DeviceSelectModal(current_device_id=state.device_id),
                callback=_on_result,
            )

        _DEVICE_TYPE_TAGS = {"local": "[L]", "usb": "[U]"}

        _PLATFORM_MAP = {"darwin": "macos", "win32": "windows"}

        def _apply_device_selection(self, device_id: str) -> None:
            """Apply the selected device to AppState and update UI."""
            state = self._get_state()
            state.device_id = device_id

            try:
                from friTap.backends import get_backend
                device = get_backend().get_device(mobile=device_id)
                state.device_name = device.name
                state.device_type = device.type if device.type in ("local", "usb") else "remote"
                type_tag = self._DEVICE_TYPE_TAGS.get(state.device_type, "[R]")

                if state.device_type == "local":
                    state.device_platform = self._PLATFORM_MAP.get(sys.platform, "linux")
                elif state.device_type == "usb":
                    try:
                        params = device.query_system_parameters()
                        os_info = params.get("os", {})
                        state.device_platform = (
                            os_info.get("id", "unknown")
                            if isinstance(os_info, dict)
                            else "unknown"
                        )
                    except Exception:
                        state.device_platform = "unknown"
                else:
                    state.device_platform = "unknown"

                status = self._get_status_bar()
                status.update_device(device.name, type_tag)
                status.server_status = ""

                self._get_activity_log().log_success(f"Device selected: {type_tag} {device.name}")

                menu = self._get_menu_panel()
                menu.server_running = (state.device_type == "local")

                if state.device_type != "local" and not self._wizard_active:
                    self.run_worker(self._check_server_status, thread=True)

            except Exception as e:
                self._get_activity_log().log_error(f"Failed to select device: {e}")

        # ----------------------------------------------------------
        # Process attach / spawn
        # ----------------------------------------------------------

        def _apply_target(self, display_name: str, frida_target: str, is_spawn: bool) -> None:
            """Apply target selection to state and update UI widgets."""
            state = self._get_state()
            mode = "spawn" if is_spawn else "attach"
            mode_tag = mode.upper()

            state.target = frida_target
            state.target_display = display_name
            state.spawn = is_spawn
            self._get_status_bar().update_target(display_name, mode_tag)
            menu = self._get_menu_panel()
            menu.has_target = True
            menu.target_name = display_name
            menu.target_mode = mode
            self._get_activity_log().log_info(
                f"Target: [bold {c('target')}]{display_name}[/] [{mode_tag}]"
            )

        def _guard_target_change(self) -> bool:
            """Return True if target change should be blocked."""
            if self._wizard_guard():
                return True
            if self._ssl_logger and self._ssl_logger.running:
                self._get_activity_log().log_warning("Stop capture before changing target.")
                return True
            return False

        def action_attach(self) -> None:
            """Open the process selection modal."""
            if self._guard_target_change():
                return

            state = self._get_state()

            def _on_result(result) -> None:
                if result is None:
                    return
                display_name, frida_target, is_pid = result
                self._apply_target(display_name, frida_target, is_spawn=False)

            self.app.push_screen(
                ProcessSelectModal(
                    device_id=state.device_id,
                    device_type=state.device_type,
                ),
                callback=_on_result,
            )

        def action_spawn(self) -> None:
            """Open the spawn input modal."""
            if self.query_one("#flow-detail").display:
                return
            if self._guard_target_change():
                return

            def _on_result(target: Optional[str]) -> None:
                if target is None:
                    return
                self._apply_target(target, target, is_spawn=True)

            state = self._get_state()
            self.app.push_screen(
                SpawnInputModal(
                    device_id=state.device_id,
                    device_type=state.device_type,
                ),
                callback=_on_result,
            )

        # ----------------------------------------------------------
        # Capture mode presets
        # ----------------------------------------------------------

        def action_set_mode_1(self) -> None:
            """Full capture (keys + pcap)."""
            self._mode_ctrl.set_mode(1)

        def action_set_mode_2(self) -> None:
            """Key extraction only."""
            self._mode_ctrl.set_mode(2)

        def action_set_mode_3(self) -> None:
            """Plaintext pcap."""
            self._mode_ctrl.set_mode(3)

        def action_set_mode_4(self) -> None:
            """Live Wireshark pipe."""
            self._mode_ctrl.set_mode(4)

        def action_set_mode_5(self) -> None:
            """Live Wireshark with auto-decrypt (PCAPNG+DSB)."""
            self._mode_ctrl.set_mode(5)

        def _apply_mode(self, mode_id: str, display: str, config: dict) -> None:
            """Apply a capture mode from the modal result."""
            state = self._get_state()
            state.keylog_path = config.get("keylog", "")
            state.pcap_path = config.get("pcap", "")
            state.live = config.get("live", False)
            state.live_mode = config.get("live_mode", "")
            state.full_capture = config.get("full_capture", False)

            self._capture_mode = mode_id
            self._get_status_bar().update_capture("IDLE", display)
            menu = self._get_menu_panel()
            menu.current_mode = mode_id
            menu.keylog_path = state.keylog_path
            menu.pcap_path = state.pcap_path
            self._get_activity_log().log_info(f"Capture mode: [bold]{display}[/]")
            if state.keylog_path:
                self._get_activity_log().log_info(f"  -> Keys: {state.keylog_path}")
            if state.pcap_path:
                self._get_activity_log().log_info(f"  -> Output: {state.pcap_path}")

        # ----------------------------------------------------------
        # Log management
        # ----------------------------------------------------------

        def action_clear_log(self) -> None:
            """Clear the activity log."""
            self._get_activity_log().clear()

        def action_copy_log(self) -> None:
            """Copy activity log to clipboard."""
            log = self._get_activity_log()
            text = log.get_plain_text()
            if text:
                self.app.copy_to_clipboard(text)
                log.log_success(f"Copied {log.get_line_count()} lines to clipboard")
            else:
                log.log_warning("Nothing to copy -- log is empty.")

        # ----------------------------------------------------------
        # Setup / server management
        # ----------------------------------------------------------

        def action_install_server(self) -> None:
            """Install frida-server on the selected device."""
            if self._wizard_guard():
                return
            state = self._get_state()
            if self._get_menu_panel().server_running:
                self._get_activity_log().log_info("frida-server is already running.")
                return
            if state.device_type == "local":
                self._get_activity_log().log_warning("Local device does not need frida-server.")
                return

            if not state.device_id:
                self._get_activity_log().log_warning("Select a device first (press [bold]d[/]).")
                return

            self._get_activity_log().log_info("Installing frida-server...")
            self.run_worker(lambda: self._do_install_server(state.device_id), thread=True)

        def _do_install_server(self, device_id: str) -> None:
            """Background worker for frida-server installation."""
            try:
                from friTap.backends import get_backend
                device = get_backend().get_device(mobile=device_id)
                from friTap.server_manager.factory import get_server_manager
                mgr = get_server_manager(device)

                self.app.call_from_thread(
                    lambda: self._get_activity_log().log_info(
                        f"Installing frida-server for {device.name} ({mgr.platform_name})..."
                    )
                )

                def _progress(msg: str) -> None:
                    self.app.call_from_thread(
                        lambda: self._get_activity_log().log_info(msg)
                    )

                mgr.install(device, callback=_progress)

                self.app.call_from_thread(
                    lambda: self._get_activity_log().log_info("Starting frida-server...")
                )
                mgr.start(device)

                def _on_install_success():
                    self._get_activity_log().log_success("frida-server installed and started!")
                    self._get_menu_panel().server_running = True
                    self._get_status_bar().server_status = "running"
                self.app.call_from_thread(_on_install_success)
            except Exception as e:
                def _log_install_error(err=e):
                    self._get_activity_log().log_error(f"Install failed: {err}")
                self.app.call_from_thread(_log_install_error)

        # ----------------------------------------------------------
        # Options toggles
        # ----------------------------------------------------------

        def action_verbose_toggle(self) -> None:
            """Toggle verbose mode."""
            state = self._get_state()
            state.verbose = not state.verbose
            menu = self._get_menu_panel()
            menu.verbose = state.verbose
            label = "ON" if state.verbose else "OFF"
            self._get_activity_log().log_info(f"Verbose: {label}")

        def action_experimental_toggle(self) -> None:
            """Toggle experimental mode."""
            state = self._get_state()
            # Store experimental in a simple attribute
            if not hasattr(state, '_experimental'):
                state._experimental = False
            state._experimental = not state._experimental
            menu = self._get_menu_panel()
            menu.experimental = state._experimental
            label = "ON" if state._experimental else "OFF"
            self._get_activity_log().log_info(f"Experimental: {label}")

        def action_protocol_select(self) -> None:
            """Open the protocol selection modal."""
            if self.query_one("#flow-detail").display:
                return
            if self._wizard_guard():
                return
            state = self._get_state()

            def _on_result(protocol: Optional[str]) -> None:
                if protocol is None:
                    return
                state.protocol = protocol
                self._get_status_bar().protocol = protocol
                self._get_activity_log().log_info(f"Protocol: {protocol.upper()}")

            self.app.push_screen(ProtocolSelectModal(), callback=_on_result)

        # ----------------------------------------------------------
        # Flow view management
        # ----------------------------------------------------------

        def _activate_flow_view(self) -> None:
            """Switch right panel to full-screen flow list view."""
            self.query_one("#activity-log").display = False
            self.query_one("#flow-detail").display = False
            self.query_one("#flow-list").display = True
            self.query_one("#filter-bar").display = True
            self.query_one("#left-panel").display = False
            self.query_one("#right-panel").add_class("flow-mode")
            self.query_one("#flow-list").focus()
            self._update_flow_title()

        @property
        def _mode_label(self) -> str:
            return "friTap Replay" if self._replay_ctrl else "friTap Flow View"

        def _set_title_hints(self, hint_str: str) -> None:
            """Update the activity title bar with the given hint text.

            The caller is responsible for any inline markup (e.g. [dim]).
            """
            try:
                title = self.query_one("#activity-title", Static)
                title.update(
                    f"[bold {c('primary')}]{self._mode_label}[/]  {hint_str}"
                )
            except Exception:
                pass

        def _update_flow_title(self) -> None:
            """Update the flow view title bar based on current state."""
            capturing = self._ssl_logger and self._ssl_logger.running
            hints: list[str] = [
                "[dim]Enter: flow details[/]",
                "[dim]/: filter[/]",
            ]
            try:
                filter_bar = self.query_one("#filter-bar", FilterBar)
                if filter_bar.has_active_filter:
                    hints.append("[dim]Shift+Esc: clear filter[/]")
            except Exception:
                pass
            hints.append("[dim]w: save .tap[/]")
            if self._replay_ctrl is None:
                hints.append("[dim]f: console view[/]")
            if capturing:
                hints.append(f"[bold {c('success')}]Esc: stop capture[/]")
            self._set_title_hints(" [dim]|[/] ".join(hints))
            self._update_capture_indicator()

        def _update_capture_indicator(self) -> None:
            """Refresh the left-pinned indicator: ▣ TAP / ● CAPTURING / ■ stopped."""
            try:
                ind = self.query_one("#capture-indicator", Static)
            except Exception:
                return

            if self._replay_ctrl is not None:
                ind.update(f"[bold {c('info')}]▣ TAP: {self._replay_filename or 'tap'}[/]")
                return

            capturing = self._ssl_logger and self._ssl_logger.running
            if capturing:
                ind.update(f"[bold {c('error')}]● CAPTURING[/]")
            else:
                ind.update("[dim]■ stopped[/]")

        def _clear_title_indicators(self) -> None:
            """Blank the left indicator and right spacer (used outside flow view)."""
            try:
                self.query_one("#capture-indicator", Static).update("")
                self.query_one("#title-spacer", Static).update("")
            except Exception:
                pass

        def _update_detail_title(self) -> None:
            """Update the title bar with detail-view hints."""
            self._clear_title_indicators()
            self._set_title_hints("[dim]Esc: back | Tab: switch tabs | p: parse | s: save body[/]")

        def _activate_legacy_view(self) -> None:
            """Switch right panel to legacy activity log view."""
            self.query_one("#flow-list").display = False
            self.query_one("#flow-detail").display = False
            self.query_one("#filter-bar").display = False
            self.query_one("#activity-log").display = True
            self.query_one("#left-panel").display = True
            self.query_one("#right-panel").remove_class("flow-mode")
            self._clear_title_indicators()
            try:
                title = self.query_one("#activity-title", Static)
                capturing = self._ssl_logger and self._ssl_logger.running
                suffix = f"  [bold {c('success')} on {c('bg-capture')}] CAPTURING [/]" if capturing else ""
                title.update(f"[bold {c('success')}]friTap Console[/]{suffix}  [dim]press f to toggle[/]")
            except Exception:
                pass

        def _show_flow_detail(self, flow_id: str) -> None:
            """Show detail view for a specific flow."""
            if self._replay_ctrl is not None:
                flow = self._replay_ctrl.get_flow(flow_id)
            else:
                collector = self._capture.flow_collector
                flow = collector.get_flow(flow_id) if collector else None
            if not flow:
                return
            self._present_flow_detail(flow)

        def _back_to_flow_list(self) -> None:
            """Return from detail view to flow list."""
            self.query_one("#flow-detail").display = False
            self.query_one("#flow-list").display = True
            self.query_one("#flow-list").focus()
            self._update_flow_title()

        def on_flow_list_widget_flow_selected(self, event: FlowListWidget.FlowSelected) -> None:
            """Handle flow selection from the flow list."""
            self._show_flow_detail(event.flow_id)

        def on_flow_detail_widget_back_requested(self, event: FlowDetailWidget.BackRequested) -> None:
            """Handle back request from flow detail."""
            self._back_to_flow_list()

        def action_focus_filter(self) -> None:
            """Open the filter modal (/ key)."""
            try:
                filter_bar = self.query_one("#filter-bar", FilterBar)
                if not filter_bar.display:
                    return
                self.app.push_screen(
                    FilterModal(
                        current_text=filter_bar.filter_text,
                        active_toggles=filter_bar.active_toggles,
                    ),
                    callback=self._on_filter_result,
                )
            except Exception:
                pass

        def action_clear_filter(self) -> None:
            """Clear the active filter (Shift+Esc)."""
            try:
                filter_bar = self.query_one("#filter-bar", FilterBar)
                if not filter_bar.display:
                    return
                filter_bar.clear_filter()
            except Exception:
                pass

        def _on_filter_result(self, result: FilterResult | None) -> None:
            """Handle the result from the FilterModal."""
            if result is None:
                return
            try:
                filter_bar = self.query_one("#filter-bar", FilterBar)
                filter_bar.apply_result(
                    text=result.text,
                    text_engine=result.text_engine,
                    toggle_engine=result.toggle_engine,
                    active_toggles=result.active_toggles,
                )
            except Exception:
                pass

        def on_filter_bar_filter_changed(self, event: FilterBar.FilterChanged) -> None:
            """Handle filter changes from the filter bar."""
            try:
                flow_list = self.query_one("#flow-list", FlowListWidget)
                flow_list.set_filter(event.engine, event.toggle_engine)
            except Exception:
                pass
            self._update_flow_title()

        def action_toggle_view(self) -> None:
            """Toggle between legacy and flow views."""
            flow_list = self.query_one("#flow-list")
            flow_detail = self.query_one("#flow-detail")

            if flow_detail.display:
                # In detail view → back to flow list
                self._back_to_flow_list()
            elif flow_list.display:
                # In replay mode, legacy view is not available
                if self._replay_ctrl is not None:
                    return
                # In flow view → switch to legacy
                self._activate_legacy_view()
            else:
                # In legacy view → switch to flow
                self._activate_flow_view()

        def _update_flow_ui(self, flow, event_type: str) -> None:
            """Update flow list/detail widgets with a flow change (called on Textual thread)."""
            try:
                flow_list = self.query_one("#flow-list", FlowListWidget)
                if flow_list.display:
                    flow_list.add_or_update_flow(flow)
                flow_detail = self.query_one("#flow-detail", FlowDetailWidget)
                if flow_detail.display:
                    flow_detail.refresh_flow(flow)
            except Exception:
                pass

        # ----------------------------------------------------------
        # Help
        # ----------------------------------------------------------

        def action_show_help(self) -> None:
            """Show the help overlay."""
            self.app.push_screen(HelpScreen())
