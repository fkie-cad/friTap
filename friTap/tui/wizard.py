#!/usr/bin/env python3

"""
Capture wizard -- guided setup flow extracted from MainScreen.

Walks the user through device selection, target mode, process/spawn
selection, capture-mode configuration, and a final confirmation step.
"""

from __future__ import annotations

import logging
from typing import Optional

from friTap.offline.keylog_paths import same_keylog_path
from friTap.offline.mtproto.transport import DEFAULT_OBF_MAX_BLOCKS

logger = logging.getLogger(__name__)


def _same_keylog_file(a: str, b: str) -> bool:
    """True when *a* and *b* name the same file (relative vs absolute paths)."""
    return same_keylog_path(a, b)



class CaptureWizard:
    """Guided setup wizard for friTap TUI capture sessions."""

    _CAPTURE_MODE_DEFAULTS = {
        "full": ("Full Capture", "full", "keys.log", "capture.pcapng", False),
        "owner": ("Per-App (UID) Capture","owner", "keys.log", "capture.pcapng", False),
        "keys": ("Key Extraction Only", "keys", "keys.log", "", False),
        "plaintext": ("Plaintext PCAP", "plaintext", "", "plaintext.pcapng", False),
        "wireshark": ("Live Wireshark", "wireshark", "", "", True),
        "live_pcapng": ("Live Wireshark (auto-decrypt)", "live_pcapng", "", "", True),
    }

    # Capture modes whose output is produced by the hooks themselves (decrypted
    # plaintext / live streams), so Intercepting cannot be turned off there.
    _INTERCEPT_REQUIRED_MODES = frozenset({"plaintext", "wireshark", "live_pcapng"})

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
            self._step_5a_extraction_method()

        self._screen.app.push_screen(
            CaptureSelectModal(
                device_platform=self._screen._get_state().device_platform
            ),
            callback=_on_result,
        )

    def _step_5a_extraction_method(self) -> None:
        """Step 5a: Choose the key extraction method (intercepting / memory scan)."""
        from .modals.extraction_method_modal import ExtractionMethodModal

        state = self._screen._get_state()
        intercept_locked = self._capture_mode_id in self._INTERCEPT_REQUIRED_MODES

        def _on_result(result: Optional[dict]) -> None:
            if result is None:
                # Back -> step 5
                self._step_5_capture_mode()
                return
            state.intercept = result["intercept"]
            state.memory_scan = result["memory_scan"]
            self._step_5b_protocol()

        self._screen.app.push_screen(
            ExtractionMethodModal(
                intercept=getattr(state, "intercept", True),
                memory_scan=getattr(state, "memory_scan", False),
                intercept_locked=intercept_locked,
            ),
            callback=_on_result,
        )

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
            from .modals.alert_modal import AlertModal
            self._screen.app.push_screen(
                AlertModal(message=hint, title=title, severity="warning")
            )
        except Exception:
            pass

    def _step_5b_protocol(self) -> None:
        """Step 5b: Select protocol (+ optional custom ciphers, e.g. TLS+RC4)."""
        from .protocol_selection import (
            apply_protocol_selection,
            format_protocols,
            select_protocols,
        )

        def _on_done(protocol: str, protocols: list) -> None:
            state = self._screen._get_state()
            # protocols[0] is the primary protocol that drives the branching below.
            apply_protocol_selection(state, protocols)
            if protocols != ["tls"]:
                self._screen._get_activity_log().log_info(
                    f"Protocol: {format_protocols(protocols)}"
                )
            # Offline decryption of the captured pcap may need an optional crypto
            # backend (MTProto/Telegram/Signal). Warn now if it is missing; live
            # key capture still works without it.
            for selected in protocols:
                self._warn_if_offline_backend_missing(selected)
            # Keys-only mode skips encapsulated protocols and view mode
            if self._capture_mode_id == "keys":
                self._step_6_configure(self._capture_mode_id)
            elif protocol in ("tls", "auto"):
                self._step_5c_encapsulated_protocols()
            elif self._capture_mode_id == "plaintext":
                self._step_5d_view_mode()
            else:
                self._skip_view_mode_to_configure()

        # Pass protocol registry for dynamic protocol list (custom plugins);
        # None -> the modal falls back to the default registry.
        registry = getattr(self._screen, '_protocol_registry', None)
        select_protocols(
            self._screen.app,
            on_done=_on_done,
            on_back=self._step_5a_extraction_method,  # Back -> step 5a
            registry=registry,
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
            # Optional memory-scan pattern file (blank -> use shipped defaults).
            state = self._screen._get_state()
            state.memory_scan_patterns = (
                (result.get("memory_scan_patterns") or "").strip() or None
            )
            self._step_7_confirm()

        self._screen.app.push_screen(
            CaptureModeModal(
                mode_id=mid,
                mode_display=display,
                default_keylog=default_keylog,
                default_pcap=default_pcap,
                is_live=is_live,
                show_memory_scan_patterns=getattr(
                    self._screen._get_state(), "memory_scan", False
                ),
            ),
            callback=_on_result,
        )

    def _step_7_confirm(self) -> None:
        """Step 7: Show summary and confirm start."""
        from .modals.start_confirm_modal import StartConfirmModal
        from .protocol_selection import format_protocols

        state = self._screen._get_state()
        display, *_ = self._CAPTURE_MODE_DEFAULTS.get(
            self._capture_mode_id, ("Custom", "", "", "", False)
        )
        summary = {
            "device_name": state.device_name,
            "device_type": state.device_type,
            "device_platform": state.device_platform,
            "target_name": state.target_display or state.target,
            "target_mode": "spawn" if state.spawn else "attach",
            "capture_mode_display": display,
            "keylog_path": state.keylog_path,
            "pcap_path": state.pcap_path,
            "live": state.live,
            "capture_mode_id": self._capture_mode_id,
            "verbose": state.verbose,
            "protocol": getattr(state, 'protocol', 'tls'),
            "protocols_display": format_protocols(
                getattr(state, "protocols", None) or [getattr(state, "protocol", "tls")]
            ),
            "experimental": getattr(state, "_experimental", False),
            "library_scan": getattr(state, "library_scan", False),
            "pairip_safe": getattr(state, "pairip_safe", False),
            "intercept": getattr(state, "intercept", True),
            "memory_scan": getattr(state, "memory_scan", False),
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
            state.pairip_safe = confirm_modal.pairip_safe
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
        # Advanced: max search depth when re-aligning a mid-stream (obfuscated)
        # transport. Overridable in the confirm modal; defaults to the constant.
        self._resync_search_depth: int = DEFAULT_OBF_MAX_BLOCKS
        # Protocols the user de-selected in the confirm modal. Consulted by
        # ``_prepopulate_from_manifest`` so a deselection sticks even when
        # backing out to step 1 re-runs the manifest pre-fill (whose
        # ``setdefault`` would otherwise silently re-add the removed keylog).
        self._excluded_keylogs: set[str] = set()
        # Capture-TLS cache: one background tshark pass over the pcap (its
        # ClientHellos + DSB presence) feeding the keylog-coverage checks.
        # ``_capture_tls_for`` names the pcap the cache (or pending read) is for.
        self._capture_tls = None  # Optional[CaptureTls]; None until ready/failed
        self._capture_dsb: bool = False
        self._capture_tls_for: str = ""
        self._capture_tls_pending: bool = False
        # The open confirm modal, updated in place by async coverage/re-pair.
        self._confirm_modal = None

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
        self._prepopulate_from_manifest()
        self._load_capture_tls()
        self._step_1_paths()

    def _prepopulate_from_manifest(self) -> None:
        """Pre-fill keylog slots from a ``<pcap>.fritap.json`` sidecar manifest.

        The friTap capture pipeline writes this sidecar next to the pcap,
        recording the base TLS keylog plus each protocol's split keylog -- the
        same manifest ``fritap --from-pcap`` reads (see ``load_manifest`` /
        ``merge_manifest``). Loading it means a keylog captured alongside the
        pcap (e.g. an MTProto keylog) is pre-filled in its own slot instead of
        the user having to re-enter it and risk mis-filing it under TLS. Only
        slots the user has not already filled are populated; failures degrade
        to leaving the slots empty.
        """
        pcap = self._pcap_path
        if not pcap:
            return
        try:
            from friTap.offline.cli import load_manifest
            manifest = load_manifest(pcap)
        except Exception:
            logger.debug("Could not load pcap manifest", exc_info=True)
            return
        if not manifest:
            return
        base = manifest.get("keylog")
        if base:
            # The manifest's base ``keylog`` is NOT necessarily a TLS keylog — a
            # Telegram/MTProto capture writes its combined keylog here too. Sniff
            # the file's actual content and file it under the protocol it really
            # contains; fall back to ``tls`` only when the sniff is inconclusive
            # (an unreadable/typed-but-missing file, or genuinely TLS content).
            # Without this an MTProto keylog lands in the TLS slot and produces
            # the confusing "no TLS sessions / 0 handshakes" coverage warning.
            self._prefill_protocol_keylog(
                self._detect_keylog_protocol("tls", base), base
            )
        for name, path in (manifest.get("keylogs") or {}).items():
            if path:
                self._prefill_protocol_keylog(name, path)
        # Back-compat top-level ``<proto>_keylog`` keys (e.g. mtproto_keylog).
        for key, value in manifest.items():
            if key.endswith("_keylog") and value:
                self._prefill_protocol_keylog(key[: -len("_keylog")], value)

    def _prefill_protocol_keylog(self, protocol: str, path: str) -> None:
        """``setdefault`` a manifest keylog, skipping a de-selected protocol.

        Honours :attr:`_excluded_keylogs` so a keylog the user unchecked in the
        confirm modal is not silently re-added when backing out to step 1
        re-runs :meth:`_prepopulate_from_manifest`.
        """
        if protocol in self._excluded_keylogs:
            return
        self._protocol_keylogs.setdefault(protocol, path)

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
        """Selectable keylog protocols for the step-2 picker.

        ``tls`` first (its keylog strips the transport so TLS-wrapped protocols
        such as Signal can be decrypted), then the standalone offline
        decryptors (mtproto, telegram, signal, ...), then one grouped
        ``custom`` entry for the custom ciphers (rc4, ...). Grouped backends
        such as ``schannel`` are reached through ``tls``.
        """
        # Plugin/registry import failures must not crash the wizard: fall
        # back to TLS only (the pre-picker behavior).
        try:
            from friTap.offline.keylog_picker import picker_protocol_names
            return picker_protocol_names()
        except Exception:
            logger.debug("Keylog picker protocol discovery failed", exc_info=True)
            return ["tls"]

    def _step_1_paths(self) -> None:
        """Step 1: confirm the pcap input and the output ``.tap`` path."""
        from .modals.pcap_to_tap_modals import PcapPathsModal

        def _on_result(result: Optional[dict]) -> None:
            if result is None:
                self.finish_cancelled()
                return
            self._pcap_path = result.get("pcap", "") or self._pcap_path
            self._tap_path = result.get("tap", "")
            # The pcap may have changed at step 1; pull in its manifest too.
            self._prepopulate_from_manifest()
            self._load_capture_tls()
            self._step_2_protocol_keylogs()

        self._screen.app.push_screen(
            PcapPathsModal(
                default_pcap=self._pcap_path,
                default_tap=self._tap_path or self._default_tap_for(self._pcap_path),
            ),
            callback=_on_result,
        )

    def _step_2_protocol_keylogs(
        self,
        initial_protocol: Optional[str] = None,
        initial_keylog: Optional[str] = None,
    ) -> None:
        """Step 2: collect one or more per-protocol (layered) keylogs.

        Re-shows itself after each added entry so several keylogs can be
        supplied. ``Done`` proceeds to confirm; ``Cancel`` (Esc) goes back to
        step 1. ``initial_protocol`` / ``initial_keylog`` restore the picker
        state (e.g. after backing out of the custom-cipher selection).
        """
        from .modals.pcap_to_tap_modals import ProtocolKeylogModal

        def _on_result(result: Optional[dict]) -> None:
            if result is None:
                # Back -> step 1
                self._step_1_paths()
                return
            if result.get("action") == "add":
                self._handle_keylog_added(
                    result.get("protocol", ""), result.get("keylog", "")
                )
                return
            # action == "done"
            self._step_3_confirm()

        # Only suggest before the first add: most users add one keylog, so
        # afterwards Done is the default (and no directory re-scan per re-show).
        suggestion = None
        evidence = None
        if not initial_keylog and not self._protocol_keylogs:
            suggestion, suggested_protocol, evidence = self._suggest_keylog()
            if initial_protocol is None:
                initial_protocol = suggested_protocol

        self._screen.app.push_screen(
            ProtocolKeylogModal(
                protocol_names=self._offline_protocol_names(),
                added=self._protocol_keylogs,
                suggested_keylog=suggestion,
                suggestion_evidence=evidence,
                initial_protocol=initial_protocol,
                initial_keylog=initial_keylog,
            ),
            callback=_on_result,
        )

    def _suggest_keylog(
        self,
    ) -> tuple[Optional[str], Optional[str], Optional[tuple[int, int]]]:
        """``(keylog path, picker protocol, (covered, total))`` for the pcap.

        Ranked by content when the capture-TLS cache is ready (the evidence
        tuple is then set), else by timestamp (evidence ``None``). The
        suggestion is optional: any failure (import, I/O, sniffing) just means
        no suggestion, never a crashed wizard.
        """
        try:
            from friTap.offline.keylog_picker import TLS_PICKER_NAME
            from friTap.offline.keylog_suggest import (
                sniff_keylog_protocol,
                suggest_keylog_with_evidence,
            )
            suggestion = suggest_keylog_with_evidence(
                self._pcap_path, capture_crs=self._capture_client_randoms(),
            )
            if not suggestion:
                return None, None, None
            protocol = sniff_keylog_protocol(suggestion.path) or TLS_PICKER_NAME
            # The evidence tuple is *TLS-session* coverage (ClientHellos the
            # keylog's CLIENT_RANDOMs match); it is meaningless for an MTProto /
            # custom keylog and shows a misleading "matches 0/4 TLS sessions".
            # Only attach it for a TLS suggestion; other protocols fall back to
            # the neutral "matches pcap timestamp" line in the modal.
            evidence = (
                self._suggestion_evidence(suggestion)
                if protocol == TLS_PICKER_NAME
                else None
            )
            return suggestion.path, protocol, evidence
        except Exception:
            logger.debug("Keylog suggestion failed", exc_info=True)
            return None, None, None

    @staticmethod
    def _suggestion_evidence(suggestion) -> Optional[tuple[int, int]]:
        """``(covered, total)`` of a content-ranked suggestion, else ``None``."""
        if suggestion.covered is None or not suggestion.total:
            return None
        return suggestion.covered, suggestion.total

    # ----------------------------------------------------------
    # Capture-TLS cache (background tshark pass)
    # ----------------------------------------------------------

    def _capture_tls_ready(self) -> bool:
        """True once the cache for the CURRENT pcap is loaded (or failed)."""
        return (
            bool(self._pcap_path)
            and self._capture_tls_for == self._pcap_path
            and not self._capture_tls_pending
        )

    def _capture_client_randoms(self):
        """The cached capture's ClientHello randoms, or ``None`` when unknown."""
        if not self._capture_tls_ready() or self._capture_tls is None:
            return None
        return self._capture_tls.client_randoms

    def _load_capture_tls(self) -> None:
        """Start the background capture read unless it is cached for this pcap."""
        pcap = self._pcap_path
        if not pcap or pcap == self._capture_tls_for:
            return
        self._capture_tls = None
        self._capture_dsb = False
        self._capture_tls_for = pcap
        self._capture_tls_pending = True
        try:
            self._screen.app.run_worker(
                lambda: self._capture_tls_worker(pcap),
                thread=True,
                exclusive=True,
                group="pcap-capture-tls",
            )
        except Exception:
            logger.debug("Could not start the capture-TLS worker", exc_info=True)
            self._capture_tls_pending = False

    @staticmethod
    def _read_capture_tls(pcap: str) -> tuple:
        """``(CaptureTls or None, has_dsb)`` for *pcap*; never raises (thread body)."""
        try:
            from friTap.offline.keylog_coverage import read_capture_handshakes
            from friTap.offline.tshark import capture_has_dsb, find_tshark
            capture = read_capture_handshakes(find_tshark(None), pcap)
            return capture, bool(capture_has_dsb(pcap))
        except Exception:
            logger.debug("Reading the capture's TLS handshakes failed", exc_info=True)
            return None, False

    def _capture_tls_worker(self, pcap: str) -> None:
        """Worker thread: read the capture, then hand the result to the UI thread."""
        capture, has_dsb = self._read_capture_tls(pcap)
        self._call_on_ui(self._on_capture_tls_ready, pcap, capture, has_dsb)

    def _call_on_ui(self, fn, *args) -> None:
        """Run *fn(*args)* on the UI thread (from a worker thread)."""
        try:
            self._screen.app.call_from_thread(fn, *args)
        except Exception:
            logger.debug("UI callback from worker failed", exc_info=True)

    def _on_capture_tls_ready(self, pcap: str, capture, has_dsb: bool) -> None:
        """UI thread: store the cache (if still current) and refresh the confirm modal."""
        if pcap != self._capture_tls_for:
            return  # a stale read for a pcap the user has since changed
        self._capture_tls = capture
        self._capture_dsb = has_dsb
        self._capture_tls_pending = False
        self._refresh_confirm_coverage()

    def _handle_keylog_added(self, protocol: str, keylog: str) -> None:
        """Store one step-2 entry, then ask for another keylog."""
        if not (protocol and keylog):
            self._step_2_protocol_keylogs()
            return
        # Content-sniff the file so a keylog is filed under the protocol it
        # actually contains, not merely the highlighted picker row (``tls`` by
        # default). Without this an ``MTPROTO_AUTH_KEY`` keylog added while
        # ``tls`` is highlighted would land in the TLS slot, no MTProto emitter
        # would run, and the conversion would write a 0-flow .tap.
        protocol = self._detect_keylog_protocol(protocol, keylog)
        from friTap.offline.keylog_picker import CUSTOM_PICKER_NAME
        if protocol == CUSTOM_PICKER_NAME:
            self._select_custom_ciphers(keylog)
            return
        self._store_protocol_keylog(protocol, keylog)
        self._step_2_protocol_keylogs()

    def _detect_keylog_protocol(self, picker_name: str, keylog: str) -> str:
        """Prefer the protocol *keylog*'s content identifies over *picker_name*.

        Reuses :func:`sniff_keylog_protocol`, which returns ``tls``/``custom``/
        ``mtproto`` for a recognizable keylog (else ``None``). A definite match
        overrides the highlighted row; an inconclusive sniff (unknown content or
        an unreadable/typed-but-missing file) keeps the user's explicit choice.
        """
        try:
            from friTap.offline.keylog_suggest import sniff_keylog_protocol
            detected = sniff_keylog_protocol(keylog)
        except Exception:
            logger.debug("Keylog protocol sniff failed", exc_info=True)
            detected = None
        return detected or picker_name

    def _store_protocol_keylog(self, picker_name: str, keylog: str) -> None:
        """Store *keylog* under the decryptor its picker choice resolves to.

        When another keylog is already stored for the same protocol the two are
        MERGED (union of de-duplicated key lines) instead of the newcomer
        silently overwriting the first — e.g. an E2E-only ``telegram.keys.log``
        and an auth+E2E+OBF memory-scan keylog both resolve to ``mtproto`` and
        the user needs the union of their key lines. An identical file path is
        left untouched (:meth:`_warn_if_replacing` stays a no-op there).
        """
        from friTap.offline.keylog_picker import (
            keylog_protocol_label,
            resolve_keylog_protocol,
        )
        protocol = resolve_keylog_protocol(picker_name, keylog)
        label = keylog_protocol_label(protocol)
        # A deliberate (re-)add clears any prior deselection of this protocol.
        self._excluded_keylogs.discard(protocol)
        previous = self._protocol_keylogs.get(protocol)
        if previous and not _same_keylog_file(previous, keylog) and self._merge_protocol_keylog(
            protocol, label, previous, keylog
        ):
            return
        self._warn_if_replacing(protocol, label, keylog)
        self._protocol_keylogs[protocol] = keylog
        self._screen._get_activity_log().log_info(
            f"Added {label} keylog: {keylog}"
        )

    def _merge_protocol_keylog(
        self, protocol: str, label: str, previous: str, keylog: str
    ) -> bool:
        """Merge *keylog* into the *previous* keylog stored for *protocol*.

        Points ``_protocol_keylogs[protocol]`` at the combined file and shows a
        "Keylogs merged (N keys)" note. Returns ``True`` on a successful merge;
        ``False`` (leaving the store untouched) when merging is not possible, so
        the caller falls back to the plain overwrite path.
        """
        from friTap.offline.keylog_picker import merge_keylogs
        merged = merge_keylogs([previous, keylog], protocol)
        if merged is None:
            return False
        self._protocol_keylogs[protocol] = merged.path
        msg = (
            f"Merged {label} keylogs ({merged.key_count} keys): "
            f"{previous} + {keylog} -> {merged.path}"
        )
        self._screen._get_activity_log().log_info(msg)
        try:
            from .modals.alert_modal import AlertModal
            self._screen.app.push_screen(
                AlertModal(
                    message=(
                        f"Combined {label} keylogs into one file "
                        f"({merged.key_count} distinct keys)."
                    ),
                    title="Keylogs merged",
                    severity="info",
                )
            )
        except Exception:
            pass
        return True

    def _warn_if_replacing(self, protocol: str, label: str, keylog: str) -> None:
        """Warn when *keylog* replaces a different keylog stored for *protocol*."""
        previous = self._protocol_keylogs.get(protocol)
        if not previous or _same_keylog_file(previous, keylog):
            return
        msg = f"Replaced the previous {label} keylog: {previous} -> {keylog}"
        self._screen._get_activity_log().log_warning(msg)
        try:
            from .modals.alert_modal import AlertModal
            self._screen.app.push_screen(
                AlertModal(message=msg, title="Keylog Replaced", severity="warning")
            )
        except Exception:
            pass

    def _select_custom_ciphers(self, keylog: str) -> None:
        """Ask which custom ciphers *keylog* is for, then store it per cipher.

        Esc returns to step 2 with the custom entry and keylog preserved.
        """
        from friTap.offline.keylog_picker import (
            CUSTOM_PICKER_NAME,
            keylog_protocol_label,
            offline_custom_ciphers,
        )
        from .modals.custom_cipher_modal import (
            CustomCipherModal,
            available_custom_ciphers,
        )

        offline = offline_custom_ciphers()

        def _on_result(ciphers: Optional[list]) -> None:
            if ciphers is None:
                self._step_2_protocol_keylogs(
                    initial_protocol=CUSTOM_PICKER_NAME, initial_keylog=keylog,
                )
                return
            for cipher in ciphers:
                label = keylog_protocol_label(cipher, custom_ciphers=offline)
                self._warn_if_replacing(cipher, label, keylog)
                self._protocol_keylogs[cipher] = keylog
                self._screen._get_activity_log().log_info(
                    f"Added {label} keylog: {keylog}"
                )
            self._step_2_protocol_keylogs()

        entries = [e for e in available_custom_ciphers() if e.name in offline]
        self._screen.app.push_screen(
            CustomCipherModal(required=True, ciphers=entries),
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
        """Confirm-summary feedback: TLS-key availability plus keylog coverage."""
        feedback = self._tls_strip_feedback()
        feedback.update(self._coverage_feedback())
        return feedback

    def _coverage_feedback(self) -> dict:
        """Coverage of the ``tls`` keylog over the capture, for the confirm summary.

        Skipped without a ``tls`` keylog (a routed Schannel sidecar is stored
        as ``schannel``), when the capture embeds its own keys (DSB), or when
        the capture could not be read. While the background capture read is
        still running this returns ``{"coverage_pending": True}``; the modal is
        updated in place once it finishes. Only the cheap keylog parse runs
        here — the tshark pass is the cached part.
        """
        keylog = self._protocol_keylogs.get("tls")
        if not keylog:
            return {}
        if self._capture_tls_pending and self._capture_tls_for == self._pcap_path:
            return {"coverage_pending": True}
        if self._capture_client_randoms() is None or self._capture_dsb:
            return {}
        try:
            from friTap.offline.keylog_coverage import check_keylog_coverage, describe
            coverage = check_keylog_coverage(
                "", self._pcap_path, keylog, capture=self._capture_tls,
            )
            severity, lines = describe(coverage)
        except Exception:
            logger.debug("Keylog coverage check failed", exc_info=True)
            return {}
        return {
            "coverage_severity": severity,
            "coverage_lines": lines,
            "can_repair": self._can_repair(coverage),
        }

    @staticmethod
    def _can_repair(coverage) -> bool:
        """Re-pairing can help: uncovered handshakes AND keylog sessions outside the capture."""
        return bool(coverage.uncovered) and (
            coverage.keylog_sessions > coverage.keylog_sessions_in_capture
        )

    def _refresh_confirm_coverage(self) -> None:
        """Push freshly computed coverage into the open confirm modal, if any."""
        modal = self._confirm_modal
        if modal is None:
            return
        feedback = self._coverage_feedback()
        modal.set_coverage(
            feedback.get("coverage_severity", "info"),
            feedback.get("coverage_lines", []),
            feedback.get("can_repair", False),
        )

    def _tls_strip_feedback(self) -> dict:
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

        def _on_result(result: Optional[dict]) -> None:
            self._confirm_modal = None
            if result is None:
                # Back -> step 2 (edit the protocol keylogs)
                self._step_2_protocol_keylogs()
                return
            self._apply_keylog_selection(result.get("enabled_keylogs"))
            self._resync_search_depth = result.get(
                "resync_search_depth", self._resync_search_depth
            )
            self._finish_and_convert()

        modal = PcapToTapConfirmModal(
            summary=summary,
            on_repair=self._start_repair,
            resync_search_depth=self._resync_search_depth,
        )
        self._confirm_modal = modal
        self._screen.app.push_screen(modal, callback=_on_result)

    def _apply_keylog_selection(self, enabled: Optional[list]) -> None:
        """Drop keylogs the user de-selected in the confirm modal.

        Each dropped protocol is remembered in :attr:`_excluded_keylogs` so
        that backing out to step 1 (which re-runs the manifest pre-fill) does
        not silently re-add it. ``None`` means the modal reported no selection
        (e.g. there were no keylogs) — nothing to drop.
        """
        if enabled is None:
            return
        enabled_set = set(enabled)
        for protocol in list(self._protocol_keylogs):
            if protocol not in enabled_set:
                del self._protocol_keylogs[protocol]
                self._excluded_keylogs.add(protocol)
                self._screen._get_activity_log().log_info(
                    f"Skipping de-selected {protocol} keylog."
                )

    # ----------------------------------------------------------
    # Keylog re-pair (opt-in, from the confirm modal)
    # ----------------------------------------------------------

    def _start_repair(self) -> None:
        """Re-pair the ``tls`` keylog by trial decryption in a thread worker."""
        keylog = self._protocol_keylogs.get("tls")
        modal = self._confirm_modal
        if not keylog or modal is None:
            return
        modal.set_repair_status("Re-pairing keys by trial decryption…", busy=True)
        pcap, capture = self._pcap_path, self._capture_tls
        try:
            self._screen.app.run_worker(
                lambda: self._repair_worker(pcap, keylog, capture),
                thread=True,
                exclusive=True,
                group="pcap-keylog-repair",
            )
        except Exception:
            logger.debug("Could not start the keylog re-pair worker", exc_info=True)
            modal.set_repair_status("Could not start re-pairing.", severity="warning")

    def _repair_worker(self, pcap: str, keylog: str, capture) -> None:
        """Worker thread: run the (slow) re-pair, then report on the UI thread."""
        result = self._run_repair(pcap, keylog, capture)
        self._call_on_ui(self._on_repair_done, keylog, result)

    def _run_repair(self, pcap: str, keylog: str, capture):
        """``relabel_keylog`` with progress relayed to the modal; never raises."""
        from friTap.offline.keylog_coverage import RepairResult, relabel_keylog
        try:
            from friTap.offline.tshark import find_tshark
            return relabel_keylog(
                find_tshark(None), pcap, keylog, capture=capture,
                progress=lambda msg: self._call_on_ui(self._on_repair_progress, msg),
            )
        except Exception as exc:
            logger.debug("Keylog re-pair failed", exc_info=True)
            return RepairResult(None, 0, 0, f"Re-pairing failed: {exc}")

    def _on_repair_progress(self, message: str) -> None:
        """UI thread: show re-pair progress in the open confirm modal."""
        if self._confirm_modal is not None:
            self._confirm_modal.set_repair_status(message, busy=True)

    def _on_repair_done(self, keylog: str, result) -> None:
        """UI thread: swap in a repaired keylog, or report why nothing matched."""
        if result.repaired_path and self._protocol_keylogs.get("tls") == keylog:
            self._adopt_repaired_keylog(result)
            return
        if self._confirm_modal is not None:
            self._confirm_modal.set_repair_status(result.message, severity="warning")

    def _adopt_repaired_keylog(self, result) -> None:
        """Use the repaired keylog as the ``tls`` keylog and re-check coverage."""
        self._protocol_keylogs["tls"] = result.repaired_path
        self._screen._get_activity_log().log_success(result.message)
        try:
            self._screen.app.notify(result.message, severity="information")
        except Exception:
            pass
        modal = self._confirm_modal
        if modal is None:
            return
        modal.set_protocol_keylogs(dict(self._protocol_keylogs))
        modal.set_repair_status(result.message, severity="ok")
        self._refresh_confirm_coverage()

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
            resync_search_depth=self._resync_search_depth,
        )
        if args is None:
            # Missing pcap was already reported via an alert modal; nothing to convert.
            return
        self._screen._get_activity_log().log_success(
            "Conversion wizard complete -- converting pcap to .tap!"
        )
        self._screen._launch_decrypt_worker(args)
