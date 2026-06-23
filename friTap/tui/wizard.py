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
        "full": ("Full Capture", "full", "keys.log", "capture.pcapng", False),
        "keys": ("Key Extraction Only", "keys", "keys.log", "", False),
        "plaintext": ("Plaintext PCAP", "plaintext", "", "plaintext.pcapng", False),
        "wireshark": ("Live Wireshark", "wireshark", "", "", True),
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
        """Delegate to MainScreen._apply_target()."""
        self._screen._apply_target(display_name, frida_target, is_spawn)

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

            self._screen.app.push_screen(
                SpawnInputModal(
                    device_id=state.device_id,
                    device_type=state.device_type,
                ),
                callback=_on_spawn,
            )

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

    # Protocols whose offline decryption needs an optional crypto backend. Each
    # maps to (offline module, availability fn, hint constant, notify title,
    # import_optional). mtproto and telegram share the MTProto backend.
    # ``import_optional`` is True only for components that may be stripped from a
    # build (signal): a missing module is then swallowed and surfaces no hint.
    # Live key capture works without any of these; this only warns about offline
    # pcap decryption.
    _OFFLINE_BACKEND_WARNINGS = {
        "mtproto": ("friTap.offline.mtproto", "mtproto_backend_available",
                    "MTPROTO_DEPENDENCY_HINT", "MTProto dependency missing", False),
        "telegram": ("friTap.offline.mtproto", "mtproto_backend_available",
                     "MTPROTO_DEPENDENCY_HINT", "Telegram dependency missing", False),
        "signal": ("friTap.offline.signal", "signal_backend_available",
                   "SIGNAL_DEPENDENCY_HINT", "Signal dependency missing", True),
    }

    def _warn_if_offline_backend_missing(self, protocol: str) -> None:
        """Warn (activity log + toast) if a protocol's offline backend is absent.

        No-op for protocols without an optional backend. For an optional build
        component (see ``import_optional``) a missing module surfaces no hint —
        matches MainScreen._warn_if_backend_missing's guarding.
        """
        spec = self._OFFLINE_BACKEND_WARNINGS.get(protocol)
        if spec is None:
            return
        module_name, available_fn, hint_name, title, import_optional = spec
        import importlib
        try:
            module = importlib.import_module(module_name)
        except ImportError:
            if import_optional:
                return
            raise
        hint = getattr(module, hint_name)
        if getattr(module, available_fn)():
            return
        self._screen._get_activity_log().log_warning(hint)
        try:
            self._screen.app.notify(hint, title=title, severity="warning")
        except Exception:
            pass

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
            # Offline decryption of the captured pcap may need an optional crypto
            # backend (MTProto/Telegram/Signal). Warn now if it is missing; live
            # key capture still works without it.
            self._warn_if_offline_backend_missing(protocol)
            # Keys-only mode skips encapsulated protocols and view mode
            if self._capture_mode_id == "keys":
                self._step_6_configure(self._capture_mode_id)
            elif protocol in ("tls", "auto"):
                self._step_5c_encapsulated_protocols()
            elif self._capture_mode_id == "plaintext":
                self._step_5d_view_mode()
            else:
                self._skip_view_mode_to_configure()

        # Pass protocol registry for dynamic protocol list (custom plugins)
        registry = getattr(self._screen, '_protocol_registry', None)
        self._screen.app.push_screen(
            ProtocolSelectModal(registry=registry), callback=_on_result,
        )

    def _step_5c_encapsulated_protocols(self) -> None:
        """Step 5c: Configure encapsulated-protocol decryption (TLS/auto only)."""
        from .modals.encapsulated_protocol_modal import EncapsulatedProtocolModal

        def _on_result(result: Optional[dict]) -> None:
            if result is None:
                # ESC -> back to step 5b
                self._step_5b_protocol()
                return
            state = self._screen._get_state()
            if result:
                state.encapsulated_protocols = result
            if self._capture_mode_id == "plaintext":
                self._step_5c2_quic_capture_mode()
            else:
                self._skip_view_mode_to_configure()

        self._screen.app.push_screen(EncapsulatedProtocolModal(), callback=_on_result)

    def _step_5c2_quic_capture_mode(self) -> None:
        """Step 5c2: Select QUIC capture boundary (TLS/auto + plaintext only)."""
        from .modals.quic_capture_mode_modal import QuicCaptureModeModal

        def _on_result(mode: Optional[str]) -> None:
            if mode is None:
                # ESC -> back to step 5c
                self._step_5c_encapsulated_protocols()
                return
            state = self._screen._get_state()
            state.quic_capture_mode = mode
            if mode != "stream":
                self._screen._get_activity_log().log_info(f"QUIC capture mode: {mode}")
            self._step_5d_view_mode()

        self._screen.app.push_screen(QuicCaptureModeModal(), callback=_on_result)

    def _step_5d_view_mode(self) -> None:
        """Step 5d: Select display mode (legacy vs flow view).

        Skipped for 'keys' capture mode since there is no data to display.
        """
        from .modals.view_mode_modal import ViewModeModal

        def _on_result(view_mode: Optional[str]) -> None:
            state = self._screen._get_state()
            if view_mode is None:
                # Back -> step 5c2 (QUIC mode; tls/auto) or 5b (non-tls protocols).
                # 5d is only reached in plaintext mode, so tls/auto always
                # passed through the QUIC capture-mode step.
                protocol = getattr(state, 'protocol', 'tls')
                if protocol in ("tls", "auto"):
                    self._step_5c2_quic_capture_mode()
                else:
                    self._step_5b_protocol()
                return
            state.view_mode = view_mode
            if view_mode != "legacy":
                self._screen._get_activity_log().log_info(f"Display mode: {view_mode}")
            self._step_6_configure(self._capture_mode_id)

        self._screen.app.push_screen(ViewModeModal(), callback=_on_result)

    def _skip_view_mode_to_configure(self) -> None:
        # Force legacy view for non-plaintext modes; AppState persists across wizard re-runs.
        state = self._screen._get_state()
        state.view_mode = "legacy"
        self._step_6_configure(self._capture_mode_id)

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
            "capture_mode_id": self._capture_mode_id,
            "verbose": state.verbose,
            "protocol": getattr(state, 'protocol', 'tls'),
            "experimental": getattr(state, "_experimental", False),
            "library_scan": getattr(state, "library_scan", False),
            "debug_log": getattr(state, "debug_log", False),
            "encapsulated_protocols": getattr(state, "encapsulated_protocols", {}),
            "quic_capture_mode": getattr(state, "quic_capture_mode", "stream"),
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
            state.debug_log = confirm_modal.debug_log
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


class PcapToTapWizard:
    """Guided pcap-to-tap conversion wizard for the friTap TUI.

    Launched when the user runs ``fritap -r <file>.pcap`` /
    ``fritap <file>.pcapng``. Mirrors :class:`CaptureWizard`'s callback-chained,
    back-navigable step structure but drives the offline conversion flow:

    1. Confirm the pcap input, choose the output ``.tap``, and supply an
       optional TLS keylog (:meth:`_step_1_paths`).
    2. Add one OR MORE per-protocol (layered) keylogs — Signal / MTProto-Telegram
       / plugins — looping until the user is done (:meth:`_step_2_protocol_keylogs`).
    3. Show a summary and confirm (:meth:`_step_3_confirm`).

    On confirm it assembles the ``convert_pcap_to_tap`` kwargs (via
    ``MainScreen._build_convert_args_multi``) and reuses the screen's existing
    decrypt-worker pipeline, which opens the produced ``.tap`` in the replay view.
    """

    def __init__(self, screen) -> None:
        self._screen = screen
        self._active: bool = False
        self._pcap_path: str = ""
        self._tap_path: str = ""
        self._tls_keylog: str = ""
        # protocol_name -> keylog path (one entry per added layered keylog)
        self._protocol_keylogs: dict[str, str] = {}

    # ----------------------------------------------------------
    # Public API
    # ----------------------------------------------------------

    @property
    def active(self) -> bool:
        return self._active

    @active.setter
    def active(self, value: bool) -> None:
        self._active = value

    def guard(self) -> bool:
        """Return True if wizard is active (blocks manual actions)."""
        return self._active

    def start(self, pcap_path: str) -> None:
        """Launch the guided pcap-to-tap conversion wizard."""
        self._active = True
        self._pcap_path = pcap_path or ""
        self._screen._get_activity_log().log_info(
            "Starting pcap-to-tap conversion wizard..."
        )
        self._step_1_paths()

    def finish_cancelled(self) -> None:
        """Cancel the wizard and leave the (empty) flow view in place."""
        self._active = False
        msg = "Conversion wizard cancelled. Use 'o' to open a pcap manually."
        self._screen._get_activity_log().log_info(msg)
        # In ``fritap -r`` mode the activity log is hidden behind the empty flow
        # view, so also surface the cancellation as a toast.
        try:
            self._screen.app.notify(msg, severity="information")
        except Exception:
            pass

    # ----------------------------------------------------------
    # Wizard steps
    # ----------------------------------------------------------

    def _default_tap_for(self, pcap: str) -> str:
        """Default output ``.tap`` path: the pcap path with a ``.tap`` suffix."""
        import os
        if not pcap:
            return ""
        return os.path.splitext(pcap)[0] + ".tap"

    def _offline_protocol_names(self) -> list[str]:
        """Selectable keylog protocols: ``tls`` plus every offline decryptor.

        TLS is offered like any other protocol (its keylog strips the transport
        so TLS-wrapped protocols such as Signal can be decrypted), followed by
        the friTap-owned offline decryptors (signal, mtproto, telegram, ...).
        """
        try:
            from friTap.offline.registry import get_offline_decryptor_registry
            names = get_offline_decryptor_registry().names()
        except Exception:
            names = []
        return ["tls", *names]

    def _step_1_paths(self) -> None:
        """Step 1: confirm the pcap input and the output ``.tap`` path."""
        from .modals.pcap_to_tap_modals import PcapPathsModal

        def _on_result(result: Optional[dict]) -> None:
            if result is None:
                self.finish_cancelled()
                return
            self._pcap_path = result.get("pcap", "") or self._pcap_path
            self._tap_path = result.get("tap", "")
            self._step_2_protocol_keylogs()

        self._screen.app.push_screen(
            PcapPathsModal(
                default_pcap=self._pcap_path,
                default_tap=self._tap_path or self._default_tap_for(self._pcap_path),
            ),
            callback=_on_result,
        )

    def _step_2_protocol_keylogs(self) -> None:
        """Step 2: collect one or more per-protocol (layered) keylogs.

        Re-shows itself after each added entry so several keylogs can be
        supplied. ``Done`` proceeds to confirm; ``Cancel`` (Esc) goes back to
        step 1.
        """
        from .modals.pcap_to_tap_modals import ProtocolKeylogModal

        def _on_result(result: Optional[dict]) -> None:
            if result is None:
                # Back -> step 1
                self._step_1_paths()
                return
            action = result.get("action")
            if action == "add":
                protocol = result.get("protocol", "")
                keylog = result.get("keylog", "")
                if protocol and keylog:
                    self._protocol_keylogs[protocol] = keylog
                    self._screen._get_activity_log().log_info(
                        f"Added {protocol} keylog: {keylog}"
                    )
                # Loop: ask for another keylog.
                self._step_2_protocol_keylogs()
                return
            # action == "done"
            self._step_3_confirm()

        self._screen.app.push_screen(
            ProtocolKeylogModal(
                protocol_names=self._offline_protocol_names(),
                added=self._protocol_keylogs,
            ),
            callback=_on_result,
        )

    def _tls_strip_protocols(self) -> list[str]:
        """Selected protocols (excluding ``tls``) that require a TLS strip.

        These ride inside TLS (e.g. Signal) and so need a TLS keylog in addition
        to their own keylog; read from the offline registry's
        ``requires_tls_strip`` flag.
        """
        try:
            from friTap.offline.registry import get_offline_decryptor_registry
            reg = get_offline_decryptor_registry()
        except Exception:
            return []
        out: list[str] = []
        for name in self._protocol_keylogs:
            if name == "tls":
                continue
            entry = reg.get(name)
            if entry is not None and entry.requires_tls_strip:
                out.append(name)
        return out

    def _capture_has_dsb(self) -> bool:
        """True if the pcap is a pcapng carrying embedded TLS keys (DSB)."""
        try:
            from friTap.offline.tshark import capture_has_dsb
            return capture_has_dsb(self._pcap_path)
        except Exception:
            return False

    def _tls_feedback(self) -> dict:
        """Note/warning for the confirm summary about TLS-key availability.

        Signal (any ``requires_tls_strip`` protocol) needs BOTH a TLS keylog and
        its own keylog. TLS keys may instead be embedded in a pcapng's DSB. When
        a TLS-wrapped protocol is selected but no TLS keys are available, warn
        that it won't decrypt; when they're embedded as a DSB, note that. The
        DSB check only runs when it could matter, to avoid walking a huge pcapng.
        """
        needs_tls = self._tls_strip_protocols()
        if not needs_tls:
            return {}
        if self._protocol_keylogs.get("tls"):
            return {}  # TLS keylog supplied explicitly — nothing to flag.
        if self._capture_has_dsb():
            return {"tls_note": "TLS keys: embedded in capture (DSB)"}

        names = ", ".join(sorted(needs_tls))
        return {
            "warning": (
                f"{names} ride inside TLS and need BOTH a TLS keylog and their "
                f"own keylog. No TLS keys were provided and the capture has no "
                f"embedded DSB keys, so {names} traffic will NOT be decrypted "
                f"— add a 'tls' keylog on the previous screen."
            )
        }

    def _step_3_confirm(self) -> None:
        """Step 3: show a summary and confirm the conversion."""
        from .modals.pcap_to_tap_modals import PcapToTapConfirmModal

        summary = {
            "pcap": self._pcap_path,
            "tap": self._tap_path or self._default_tap_for(self._pcap_path),
            "protocol_keylogs": dict(self._protocol_keylogs),
        }
        summary.update(self._tls_feedback())

        def _on_result(confirmed: Optional[bool]) -> None:
            if confirmed is None:
                # Back -> step 2 (edit the protocol keylogs)
                self._step_2_protocol_keylogs()
                return
            self._finish_and_convert()

        self._screen.app.push_screen(
            PcapToTapConfirmModal(summary=summary), callback=_on_result,
        )

    # ----------------------------------------------------------
    # Finish helpers
    # ----------------------------------------------------------

    def _finish_and_convert(self) -> None:
        """Assemble convert args and launch the decrypt-to-flow worker."""
        self._active = False
        # TLS was collected like any other protocol; split it back out into the
        # dedicated tls_keylog kwarg (TLS rides on keylog_path, not the layered
        # protocol_keylogs map that convert_pcap_to_tap feeds to its decryptors).
        self._tls_keylog = self._protocol_keylogs.get("tls", "")
        protocol_keylogs = {
            name: path for name, path in self._protocol_keylogs.items()
            if name != "tls"
        }
        args = self._screen._build_convert_args_multi(
            pcap=self._pcap_path,
            tls_keylog=self._tls_keylog,
            protocol_keylogs=protocol_keylogs,
            tap=self._tap_path,
        )
        if args is None:
            # Missing pcap was already reported via notify; nothing to convert.
            return
        self._screen._get_activity_log().log_success(
            "Conversion wizard complete -- converting pcap to .tap!"
        )
        self._screen._launch_decrypt_worker(args)
