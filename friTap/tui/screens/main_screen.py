#!/usr/bin/env python3

"""
Main screen for friTap TUI -- single split-pane layout.

Replaces the 5-screen sequential flow with a permanent main screen.
Left panel: StatusBar + MenuPanel. Right panel: ActivityLog.
Device/process selection via modals.
"""

from __future__ import annotations

import sys
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from ..app import AppState

try:
    from textual.app import ComposeResult
    from textual.binding import Binding
    from textual.containers import Horizontal, Vertical
    from textual.screen import Screen
    from textual.widgets import Footer, Header, Static
    TEXTUAL_AVAILABLE = True
except ImportError:
    TEXTUAL_AVAILABLE = False

if TEXTUAL_AVAILABLE:
    from friTap.flow.replay_rows import iter_replay_rows

    from ..capture_controller import CaptureController
    from ..modals.device_modal import DeviceSelectModal
    from ..modals.help_modal import HelpScreen
    from ..modals.process_modal import ProcessSelectModal
    from ..modals.spawn_modal import SpawnInputModal
    from ..mode_controller import ModeController
    from ..themes import c
    from ..widgets.activity_log import ActivityLog
    from ..widgets.analyzer_finding_detail import AnalyzerFindingDetailWidget
    from ..widgets.analyzer_panel import AnalyzerPanel
    from ..widgets.filter_bar import FilterBar
    from ..widgets.findings_filter_bar import FindingsFilterBar
    from ..widgets.findings_list import FindingsListWidget
    from ..widgets.flow_detail import FlowDetailWidget
    from ..widgets.flow_list import FlowListWidget
    from ..widgets.menu_panel import MenuPanel
    from ..widgets.status_bar import StatusBar
    from ..wizard import CaptureWizard, PcapToTapWizard
    from .viewer_mixins import (
        AnalyzerMixin,
        ConversationSiblingsMixin,
        DecryptMixin,
        ExportMixin,
        FilterMixin,
        FindingsMixin,
        FlowNavigationMixin,
        ViewerHostDefaults,
    )

    class MainScreen(
        DecryptMixin, FindingsMixin, AnalyzerMixin, FilterMixin, FlowNavigationMixin,
        ExportMixin, ConversationSiblingsMixin, ViewerHostDefaults, Screen
    ):
        """Single-screen split-pane layout for friTap TUI."""

        BINDINGS = [
            Binding("f", "toggle_view", "Toggle View", show=False),
            Binding("slash", "focus_filter", "Filter", show=False),
            Binding("shift+escape", "clear_filter", "Clear Filter", show=False),
            Binding("shift+f", "toggle_findings_view", "Findings", show=False),
            Binding("a", "analyzer_panel", "Analyzers", show=False),
            Binding("c", "findings_quick_creds", "Creds", show=False),
            Binding("p", "findings_quick_pii", "PII", show=False),
            Binding("1", "findings_quick_critical", "Critical", show=False),
            Binding("r", "restart_wizard", "Restart Wizard", show=False),
            Binding("R", "report_digest", "Report", show=False),
        ]

        def __init__(
            self,
            replay_file: str | None = None,
            pcap_to_tap_file: str | None = None,
            **kwargs,
        ) -> None:
            # Flow-list columns / detail tabs are read from the extension
            # registry in compose(), which runs before on_mount/reload_replay;
            # load_extensions() is idempotent and logs+skips failing plugins.
            from friTap.extensions import load_extensions

            load_extensions(offline_decryptors=False)
            super().__init__(**kwargs)
            self._replay_file = replay_file
            self._pcap_to_tap_file = pcap_to_tap_file
            self._replay_filename: str | None = None
            self._replay_ctrl = None
            self._findings_cache: list | None = None
            # Monotonic token: each analyzer run / clear bumps it so a stale
            # (superseded or cleared) worker's late completion is ignored.
            self._analyzer_run_id = 0
            # Where a flow-detail view was opened from: "flow" (flow list) or
            # "finding" (analyzer finding-detail) — drives Esc back-navigation.
            self._detail_origin = "flow"
            # Live flows changed while the flow list was hidden; applied when it is shown.
            self._hidden_flow_updates: dict = {}
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
                    yield AnalyzerPanel(id="analyzer-panel")
                    yield ActivityLog(id="activity-log")
                    yield FlowListWidget(id="flow-list")
                    yield FlowDetailWidget(id="flow-detail")
                    yield FindingsFilterBar(id="findings-filter-bar")
                    yield FindingsListWidget(id="findings-list")
                    yield AnalyzerFindingDetailWidget(id="finding-detail")
            yield Footer()

        def on_mount(self) -> None:
            """Initialize the screen with welcome message and device info."""
            self._get_state()  # ensure state is initialized

            # Hide flow widgets and filter bar initially
            self.query_one("#filter-bar").display = False
            self.query_one("#flow-list").display = False
            self.query_one("#flow-detail").display = False
            self.query_one("#findings-filter-bar").display = False
            self.query_one("#findings-list").display = False
            self.query_one("#finding-detail").display = False
            self.query_one("#analyzer-panel").display = False
            # ``frame contains`` filters load flow content through the same
            # replay/live lookup the detail view uses.
            self.query_one("#flow-list", FlowListWidget).set_flow_lookup(self._lookup_flow)

            # Replay mode — skip wizard, load .tap file directly
            if self._replay_file:
                self._init_replay_mode()
                return

            # pcap-to-tap mode — this is an offline read/replay flow, not a live
            # capture, so show an empty flow view as the backdrop (instead of the
            # live-hooking console) and launch the guided conversion wizard on top
            # of it. After conversion, reload_replay repopulates the same view.
            if self._pcap_to_tap_file:
                self._activate_flow_view()
                self._start_pcap_to_tap_wizard(self._pcap_to_tap_file)
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
            self.reload_replay(self._replay_file)

        def reload_replay(self, path: str) -> None:
            """Load *path* (.tap) into the running replay/flow view.

            Reusable entry point: used both for the initial replay launch and
            to swap in a freshly decrypted .tap produced from a capture.
            The new file is opened first: if that fails only an alert is
            shown and the file, flows and controller shown stay untouched.
            """
            from pathlib import Path

            from ..widgets.wire_text import safe_static_text

            filename = safe_static_text(Path(path).name)
            ctrl = self._open_source_or_alert(path, filename)
            if ctrl is None:
                return
            self._replay_file = path
            self._replay_filename = filename
            # Forget the previous file's rows/findings/analyzer run, swap in
            # the new controller, then close the previous one (MainScreen
            # always opened its controller itself).
            self._swap_in_source(ctrl, close_previous=True)

            # Activate flow view immediately (hides left panel + activity log)
            self._activate_flow_view()

            # Update title for replay mode
            count = self._replay_ctrl.flow_count
            try:
                title = self.query_one("#activity-title", Static)
                title.update(
                    self._replay_banner_markup(filename, count, self._replay_banner_hints())
                )
            except Exception:
                pass
            self._update_capture_indicator()

            # Populate flow list from summaries
            flow_list = self.query_one("#flow-list", FlowListWidget)
            for flow, row in iter_replay_rows(self._replay_ctrl):
                flow_list.add_or_update_flow(flow, summary=row)

        # ----------------------------------------------------------
        # Host hooks — the only capture/replay branches viewer logic uses.
        # Each one is an override point for the replay-only viewer
        # (TapViewerScreen: no wizard, no capture controller, no AppState).
        # The replay-only defaults live in viewer_mixins.host_defaults
        # .ViewerHostDefaults; the capture-aware variants below win via the MRO.
        # ----------------------------------------------------------

        def _live_flow_collector(self):
            """The live-capture FlowCollector, or None when there is none.

            Override point for the replay-only viewer (returns None there).
            """
            return self._capture.flow_collector

        def _has_flows(self) -> bool:
            """True when there is at least one flow to export.

            Override point for the replay-only viewer. Replay counts the .tap's
            flows; live capture counts the collector's flows.
            """
            if self._replay_ctrl is not None:
                return self._replay_ctrl.flow_count > 0
            collector = self._live_flow_collector()
            return collector is not None and len(collector.get_flows()) > 0

        def _divert_analyzer_key(self) -> bool:
            """Give 'a' its host meaning when no flows are loaded; True if diverted.

            Override point for the replay-only viewer (never diverts there).
            MainScreen: outside replay and with no captured flows, 'a' attaches.
            """
            if self._replay_ctrl is None and not self._has_capture_flows():
                self.action_attach()
                return True
            return False

        def _analyzer_flow_ids_and_getter(self):
            """``(flow_ids, get_flow)`` for an analyzer run over the loaded flows.

            Override point for the replay-only viewer. Replay loads full flows
            (with bodies) from disk on demand; capture keeps them in the collector.
            """
            if self._replay_ctrl is not None:
                flow_ids = [s.flow_id for s in self._replay_ctrl.get_summaries()]
                return flow_ids, self._replay_ctrl.get_flow
            collector = self._live_flow_collector()
            flows = list(collector.get_flows()) if collector else []
            flow_map = {f.flow_id: f for f in flows}
            return list(flow_map), flow_map.get

        def _is_capturing(self) -> bool:
            """True while a live capture's SSL logger is running.

            Override point for the replay-only viewer (always False there).
            """
            return bool(self._ssl_logger and self._ssl_logger.running)

        def _escape_running_capture(self) -> None:
            """Esc while capturing: let the capture controller stop the capture.

            Override point for the replay-only viewer (never capturing there).
            """
            self._capture.action_escape_action()

        def _request_close(self) -> None:
            """Esc at the top level: leave the screen.

            Override point for the replay-only viewer, which dismisses itself
            instead. MainScreen asks the app to quit (with confirmation).
            """
            self.app.action_quit()

        def _start_live_tap_recording(self, path: str) -> None:
            """Save a live capture's flows to *path* (.tap) via the collector.

            Override point for the replay-only viewer (never live there).
            """
            self._capture.start_tap_recording(path)

        def _hide_host_panels(self) -> None:
            """Hide host chrome (console log, left menu/status panel) for flow views.

            Override point for the replay-only viewer, which has no such panels.
            """
            self.query_one("#activity-log").display = False
            self.query_one("#left-panel").display = False
            self.query_one("#right-panel").add_class("flow-mode")

        def _flow_title_hints(self) -> list:
            """Host-specific hints appended after "w: save .tap" in the flow title.

            Override point for the replay-only viewer.
            """
            hints = ["[dim]r: restart wizard[/]"]
            if self._replay_ctrl is None:
                hints.append("[dim]f: console view[/]")
            if self._is_capturing():
                hints.append(f"[bold {c('success')}]Esc: stop capture[/]")
            return hints

        def _replay_banner_hints(self) -> str:
            """Key hints closing the initial replay banner (inside its ``[dim]``).

            Override point for the replay-only viewer.
            """
            return (" | Enter: details | /: filter | a: analyzers | w: export"
                    " | r: restart wizard | q: quit")

        def _no_flows_to_save_message(self) -> str:
            """Capture-aware hint (override of the replay-only default)."""
            return "No flows to save.\nStart a capture with flow view first."

        def _update_capture_indicator(self) -> None:
            """Refresh the left-pinned indicator: ▣ TAP / ● CAPTURING / ■ stopped.

            Override point for the replay-only viewer.
            """
            try:
                ind = self.query_one("#capture-indicator", Static)
            except Exception:
                return

            if self._replay_ctrl is not None:
                ind.update(self._tap_indicator_markup(self._replay_filename))
                return

            if self._is_capturing():
                ind.update(f"[bold {c('error')}]● CAPTURING[/]")
            else:
                ind.update("[dim]■ stopped[/]")

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
            # probe_frida_server, not check_connectivity: on frida 17 a
            # server-less USB device still enumerates via the ADB fallback.
            from friTap.server_manager.probe import ServerState, probe_frida_server
            try:
                from friTap.backends import get_backend
                device = get_backend().get_device(mobile=state.device_id)
                server_state = probe_frida_server(device)
            except Exception:
                server_state = ServerState.UNREACHABLE
            self.app.call_from_thread(self._show_server_state, server_state)

        def _show_server_state(self, server_state) -> None:
            """Reflect a probed ServerState in the status bar and menu."""
            from friTap.server_manager.probe import is_attach_capable
            status = self._get_status_bar()
            status.update_device(
                status.device_name, status.device_type, server_state.value,
            )
            self._get_menu_panel().server_running = is_attach_capable(server_state)

        # ----------------------------------------------------------
        # Wizard delegation
        # ----------------------------------------------------------

        def _wizard_guard(self) -> bool:
            """Return True if wizard is active (blocks manual actions)."""
            return self._wizard.guard()

        def _start_wizard(self) -> None:
            """Launch the guided setup wizard."""
            self._wizard.start()

        def _start_pcap_to_tap_wizard(self, pcap_path: str) -> None:
            """Launch the guided pcap-to-tap conversion wizard.

            Mirrors :meth:`_start_wizard` but drives the offline conversion flow:
            confirm the pcap input, choose the output .tap, supply a TLS keylog
            and one or more per-protocol (layered) keylogs, then convert and open
            the result in the replay view.
            """
            self._pcap_to_tap_wizard = PcapToTapWizard(self)
            self._pcap_to_tap_wizard.start(pcap_path)

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
            """Stop capture if one is running. Also cleans up replay. Safe to call from app shutdown.

            Keys off the capture STATE, not ``SSL_Logger.running``: while the
            worker is still building the logger (``_ssl_logger`` is None) the
            capture is already RUNNING and must still be stopped.
            """
            if self._capture.is_running:
                self._capture.action_stop_capture()
            if self._replay_ctrl is not None:
                self._replay_ctrl.close()
                self._replay_ctrl = None

        def action_toggle_capture(self) -> None:
            self._capture.action_toggle_capture()

        def action_restart_wizard(self) -> None:
            """Tear down any live capture or replay and relaunch the setup wizard.

            Reachable via ``r`` from both the capture/console view and the replay
            (.tap) flow-list view, so the user can start a fresh session without
            quitting friTap. Teardown is best-effort: restarting from the replay
            view (where no capture is running) must succeed just the same.

            A capture still in flight (starting, running or tearing down) is
            stopped first and the wizard opens only once it has fully ended —
            otherwise the old worker's late teardown would clobber the wizard's
            new selections or tear down the next capture.
            """
            if self._capture.capture_in_flight:
                self._capture.restart_when_stopped(self._restart_wizard_now)
                return
            self._restart_wizard_now()

        def _restart_wizard_now(self) -> None:
            """Reset to IDLE and launch the wizard (no capture may be in flight)."""
            try:
                self.stop_if_capturing()
            except Exception:
                pass
            try:
                self._capture.reset_capture_state()
            except Exception:
                pass
            try:
                self._activate_legacy_view()
            except Exception:
                pass
            self._start_wizard()

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
            """Per-app (UID) capture: kernel-scoped keys + pcap (Android/Linux)."""
            self._mode_ctrl.set_mode(2)

        def action_set_mode_3(self) -> None:
            """Key extraction only."""
            self._mode_ctrl.set_mode(3)

        def action_set_mode_4(self) -> None:
            """Plaintext pcap."""
            self._mode_ctrl.set_mode(4)

        def action_set_mode_5(self) -> None:
            """Live Wireshark pipe."""
            self._mode_ctrl.set_mode(5)

        def action_set_mode_6(self) -> None:
            """Live Wireshark with auto-decrypt (PCAPNG+DSB)."""
            self._mode_ctrl.set_mode(6)

        def _apply_mode(self, mode_id: str, display: str, config: dict) -> None:
            """Apply a capture mode from the modal result."""
            state = self._get_state()
            state.keylog_path = config.get("keylog", "")
            state.pcap_path = config.get("pcap", "")
            state.live = config.get("live", False)
            state.live_mode = config.get("live_mode", "")
            state.full_capture = config.get("full_capture", False)
            state.owner_capture = config.get("owner_capture", False)

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

                # ensure_running installs/starts as needed and only returns
                # once the server is attach-capable (raises otherwise).
                server_state = mgr.ensure_running(device, callback=_progress)

                def _on_install_success():
                    self._get_activity_log().log_success(
                        f"frida-server is {server_state.value}!"
                    )
                    self._show_server_state(server_state)
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
            from ..protocol_selection import (
                apply_protocol_selection,
                format_protocols,
                select_protocols,
            )

            def _on_done(protocol: str, protocols: list) -> None:
                apply_protocol_selection(state, protocols)
                # Status bar upper-cases this, e.g. "TLS+RC4".
                self._get_status_bar().protocol = "+".join(protocols)
                self._get_activity_log().log_info(f"Protocol: {format_protocols(protocols)}")

            select_protocols(
                self.app,
                on_done=_on_done,
                registry=getattr(self, '_protocol_registry', None),
            )

        # ----------------------------------------------------------
        # Flow view management
        # ----------------------------------------------------------

        # _update_capture_indicator is a host hook (see "Host hooks" above).

        def _activate_legacy_view(self) -> None:
            """Switch right panel to legacy activity log view."""
            self.query_one("#flow-list").display = False
            self.query_one("#flow-detail").display = False
            self.query_one("#filter-bar").display = False
            self._hide_findings_widgets()
            self.query_one("#activity-log").display = True
            self.query_one("#left-panel").display = True
            self.query_one("#right-panel").remove_class("flow-mode")
            self._clear_title_indicators()
            try:
                title = self.query_one("#activity-title", Static)
                capturing = self._is_capturing()
                suffix = f"  [bold {c('success')} on {c('bg-capture')}] CAPTURING [/]" if capturing else ""
                title.update(f"[bold {c('success')}]friTap Console[/]{suffix}  [dim]press f to toggle[/]")
            except Exception:
                pass

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
                else:
                    self._hidden_flow_updates[flow.flow_id] = flow
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
