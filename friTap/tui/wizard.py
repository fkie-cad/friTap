#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Capture wizard -- guided setup flow extracted from MainScreen.

Walks the user through device selection, target mode, process/spawn
selection, capture-mode configuration, and a final confirmation step.
"""

from __future__ import annotations

from typing import Optional


class CaptureWizard:
    """Guided setup wizard for friTap TUI capture sessions."""

    _CAPTURE_MODE_DEFAULTS = {
        "full": ("Full Capture", "full", "keys.log", "capture.pcap", False),
        "keys": ("Key Extraction Only", "keys", "keys.log", "", False),
        "plaintext": ("Plaintext PCAP", "plaintext", "", "plaintext.pcap", False),
        "wireshark": ("Live Wireshark", "wireshark", "keys.log", "", True),
        "live_pcapng": ("Live Wireshark (auto-decrypt)", "live_pcapng", "", "", True),
    }

    def __init__(self, screen) -> None:
        self._screen = screen
        self._active: bool = False
        self._target_mode: str = ""
        self._capture_mode_id: str = ""

    # ----------------------------------------------------------
    # Public API
    # ----------------------------------------------------------

    @property
    def active(self) -> bool:
        return self._active

    @active.setter
    def active(self, value: bool) -> None:
        self._active = value

    @property
    def capture_mode_id(self) -> str:
        return self._capture_mode_id

    def guard(self) -> bool:
        """Return True if wizard is active (blocks manual actions)."""
        return self._active

    def start(self) -> None:
        """Launch the guided setup wizard."""
        self._active = True
        self._screen._get_activity_log().log_info("Starting guided setup wizard...")
        self._step_1_device()

    def finish_cancelled(self) -> None:
        """Cancel the wizard and fall back to normal MainScreen."""
        self._active = False
        self._screen._get_activity_log().log_info(
            "Wizard cancelled. Use keybindings to configure manually."
        )
        # Run normal server check in background
        self._screen.run_worker(self._screen._check_server_status, thread=True)

    # ----------------------------------------------------------
    # Wizard steps
    # ----------------------------------------------------------

    def _step_1_device(self) -> None:
        """Step 1: Select device."""
        from .modals.device_modal import DeviceSelectModal

        state = self._screen._get_state()

        def _on_result(device_id: Optional[str]) -> None:
            if device_id is None:
                self.finish_cancelled()
                return
            self._screen._apply_device_selection(device_id)
            # Step 2 for non-local, otherwise skip to step 3
            if state.device_type != "local":
                self._step_2_server_check()
            else:
                self._step_3_target_mode()

        self._screen.app.push_screen(
            DeviceSelectModal(current_device_id=state.device_id),
            callback=_on_result,
        )

    def _step_2_server_check(self) -> None:
        """Step 2: Check frida-server (non-local devices only)."""
        from .modals.server_check_modal import ServerCheckModal

        state = self._screen._get_state()

        def _on_result(result: Optional[str]) -> None:
            if result is None:
                # Back -> step 1
                self._step_1_device()
                return
            # Update status bar and menu panel with server status
            if result == "ok":
                self._screen._get_status_bar().server_status = "running"
                self._screen._get_menu_panel().server_running = True
            else:
                self._screen._get_status_bar().server_status = "not running"
            # Proceed to next step
            self._step_3_target_mode()

        self._screen.app.push_screen(
            ServerCheckModal(
                device_id=state.device_id,
                device_name=state.device_name,
            ),
            callback=_on_result,
        )

    def _step_3_target_mode(self) -> None:
        """Step 3: Choose attach or spawn."""
        from .modals.target_mode_modal import TargetModeModal

        def _on_result(mode: Optional[str]) -> None:
            if mode is None:
                # Back -> step 1 (skip server check on revisit)
                self._step_1_device()
                return
            self._target_mode = mode
            self._step_4_select_target()

        self._screen.app.push_screen(TargetModeModal(), callback=_on_result)

    def _apply_target(self, display_name: str, frida_target: str, is_spawn: bool) -> None:
        """Apply target selection to state and UI widgets."""
        state = self._screen._get_state()
        mode = "spawn" if is_spawn else "attach"
        mode_tag = mode.upper()

        state.target = frida_target
        state.target_display = display_name
        state.spawn = is_spawn
        self._screen._get_status_bar().update_target(display_name, mode_tag)
        menu = self._screen._get_menu_panel()
        menu.has_target = True
        menu.target_name = display_name
        menu.target_mode = mode
        self._screen._get_activity_log().log_info(
            f"Target: [bold #d4945a]{display_name}[/] [{mode_tag}]"
        )

    def _step_4_select_target(self) -> None:
        """Step 4: Select target (process list or spawn input)."""
        from .modals.process_modal import ProcessSelectModal
        from .modals.spawn_modal import SpawnInputModal

        state = self._screen._get_state()

        if self._target_mode == "attach":
            def _on_attach(result) -> None:
                if result is None:
                    self._step_3_target_mode()
                    return
                display_name, frida_target, is_pid = result
                self._apply_target(display_name, frida_target, is_spawn=False)
                self._step_5_capture_mode()

            self._screen.app.push_screen(
                ProcessSelectModal(
                    device_id=state.device_id,
                    device_type=state.device_type,
                ),
                callback=_on_attach,
            )
        else:
            def _on_spawn(target: Optional[str]) -> None:
                if target is None:
                    self._step_3_target_mode()
                    return
                self._apply_target(target, target, is_spawn=True)
                self._step_5_capture_mode()

            self._screen.app.push_screen(SpawnInputModal(), callback=_on_spawn)

    def _step_5_capture_mode(self) -> None:
        """Step 5: Select capture mode."""
        from .modals.capture_select_modal import CaptureSelectModal

        def _on_result(mode_id: Optional[str]) -> None:
            if mode_id is None:
                # Back -> step 4
                self._step_4_select_target()
                return
            self._capture_mode_id = mode_id
            self._step_5b_protocol()

        self._screen.app.push_screen(CaptureSelectModal(), callback=_on_result)

    def _step_5b_protocol(self) -> None:
        """Step 5b: Select protocol."""
        from .modals.protocol_modal import ProtocolSelectModal

        def _on_result(protocol: Optional[str]) -> None:
            if protocol is None:
                # Back -> step 5
                self._step_5_capture_mode()
                return
            state = self._screen._get_state()
            state.protocol = protocol
            if protocol != "tls":
                self._screen._get_activity_log().log_info(f"Protocol: {protocol.upper()}")
            self._step_6_configure(self._capture_mode_id)

        # Pass protocol registry for dynamic protocol list (custom plugins)
        registry = getattr(self._screen, '_protocol_registry', None)
        self._screen.app.push_screen(
            ProtocolSelectModal(registry=registry), callback=_on_result,
        )

    def _step_6_configure(self, mode_id: str) -> None:
        """Step 6: Configure output paths for the selected mode."""
        from .modals.capture_mode_modal import CaptureModeModal

        display, mid, default_keylog, default_pcap, is_live = (
            self._CAPTURE_MODE_DEFAULTS[mode_id]
        )

        def _on_result(result) -> None:
            if result is None:
                # Back -> step 5
                self._step_5_capture_mode()
                return
            self._screen._apply_mode(mode_id, display, result)
            self._step_7_confirm()

        self._screen.app.push_screen(
            CaptureModeModal(
                mode_id=mid,
                mode_display=display,
                default_keylog=default_keylog,
                default_pcap=default_pcap,
                is_live=is_live,
            ),
            callback=_on_result,
        )

    def _step_7_confirm(self) -> None:
        """Step 7: Show summary and confirm start."""
        from .modals.start_confirm_modal import StartConfirmModal

        state = self._screen._get_state()
        display, *_ = self._CAPTURE_MODE_DEFAULTS.get(
            self._capture_mode_id, ("Custom", "", "", "", False)
        )
        summary = {
            "device_name": state.device_name,
            "device_type": state.device_type,
            "target_name": state.target_display or state.target,
            "target_mode": "spawn" if state.spawn else "attach",
            "capture_mode_display": display,
            "keylog_path": state.keylog_path,
            "pcap_path": state.pcap_path,
            "live": state.live,
            "verbose": state.verbose,
            "protocol": getattr(state, 'protocol', 'tls'),
            "experimental": getattr(state, "_experimental", False),
            "library_scan": getattr(state, "library_scan", False),
        }

        confirm_modal = StartConfirmModal(summary=summary)

        def _on_result(confirmed: Optional[bool]) -> None:
            if confirmed is None:
                # Back -> step 5 (pick different mode, not just re-edit paths)
                self._step_5_capture_mode()
                return
            # Apply verbose/experimental toggles from the confirm screen
            state.verbose = confirm_modal.verbose
            self._screen._get_menu_panel().verbose = state.verbose
            if not hasattr(state, "_experimental"):
                state._experimental = False
            state._experimental = confirm_modal.experimental
            self._screen._get_menu_panel().experimental = state._experimental
            state.library_scan = confirm_modal.library_scan
            self._finish_and_start()

        self._screen.app.push_screen(confirm_modal, callback=_on_result)

    # ----------------------------------------------------------
    # Finish helpers
    # ----------------------------------------------------------

    def _finish_and_start(self) -> None:
        """Complete the wizard and start capture."""
        self._active = False
        state = self._screen._get_state()
        self._screen._get_activity_log().log_success("Wizard complete -- starting capture!")
        self._screen._start_capture(state)
