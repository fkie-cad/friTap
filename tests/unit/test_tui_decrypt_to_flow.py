#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Unit tests for the Phase 3 TUI "decrypt-to-flow" feature.

Covers code that previously had no automated coverage:

* :meth:`MainScreen._build_convert_args` -- assembles the kwargs dict passed
  to ``convert_pcap_to_tap``: resolving the per-protocol keylog siblings
  (``split_keylog_path``), defaulting the output ``.tap`` path, and returning
  ``None`` (after notifying) when the pcap is missing.
* :meth:`MainScreen.reload_replay` -- (re)loads a ``.tap`` into the flow view.
* :meth:`MainScreen.action_open_pcap` -- pushes :class:`OpenPcapModal` and wires
  its result back into ``_build_convert_args`` + the decrypt worker.
* The worker handlers ``_on_decrypt_done`` / ``_on_decrypt_error``.
* :meth:`CaptureController._on_session_ended` -- pushes
  :class:`DecryptConfirmModal` ONLY for a full capture that left both a keylog
  and a pcap on disk.
* :class:`DecryptConfirmModal` (returns True/False on its buttons) and
  :class:`OpenPcapModal` (returns a dict on accept / None on cancel).

Two harnessing styles are used, mirroring the established repo patterns:

* The Textual ``App.run_test()`` async harness (see
  ``test_tui_findings_view.py``) for anything that needs a live MainScreen
  with mounted widgets (``reload_replay``, ``action_open_pcap``, the modals).
  The repo configures no async pytest plugin, so each async body is driven via
  ``asyncio.run``.
* Lightweight stubs (see ``test_capture_controller_severity.py``) for the
  ``_on_session_ended`` modal-routing check, which only needs to spy on
  ``app.push_screen``.
"""

from __future__ import annotations

import asyncio
import importlib.util
import os
import types
from unittest.mock import MagicMock

import pytest

_SIGNAL_AVAILABLE = importlib.util.find_spec("friTap.offline.signal") is not None

pytest.importorskip("textual")

from friTap.output.keylog_paths import split_keylog_path
from friTap.tui.app import FriTapApp


# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------

FIXTURES = os.path.join(
    os.path.dirname(os.path.dirname(__file__)), "fixtures"
)
SIGNAL_PCAP = os.path.join(FIXTURES, "signal_h2_ws_modern.pcapng")
SIGNAL_TLS_LOG = os.path.join(FIXTURES, "signal_h2_ws_modern.tls.log")
SIGNAL_SIGNAL_LOG = os.path.join(FIXTURES, "signal_h2_ws_modern.signal.log")

TSHARK = "/Applications/Wireshark.app/Contents/MacOS/tshark"


def _make_signal_keylogs(tmp_path) -> tuple[str, str, str]:
    """Create a base keylog name with realistic ``.tls`` / ``.signal`` siblings.

    The production code resolves per-protocol keylogs from ``split_keylog_path``
    siblings of the base keylog. We recreate that on-disk layout so the
    resolution logic is exercised against real files.

    Returns ``(base_keylog, tls_sibling, signal_sibling)``.
    """
    base = str(tmp_path / "keys.log")
    tls_sib = split_keylog_path(base, "tls")
    signal_sib = split_keylog_path(base, "signal")
    # split_keylog_path("keys.log", "tls") -> "keys.tls.log"
    with open(tls_sib, "w") as f:
        f.write("CLIENT_RANDOM aa bb\n")
    with open(signal_sib, "w") as f:
        f.write("SIGNALKEYLOG dummy\n")
    return base, tls_sib, signal_sib


def _find_main_screen(app):
    """Return the MainScreen from the app's screen stack.

    A fresh (non-replay) FriTapApp launches the setup wizard on mount, which
    pushes a device-select modal on top of MainScreen — so ``app.screen``
    (the topmost screen) is the modal, not MainScreen. We dig MainScreen out
    of the stack instead.
    """
    from friTap.tui.screens.main_screen import MainScreen
    for screen in app.screen_stack:
        if isinstance(screen, MainScreen):
            return screen
    raise AssertionError("MainScreen not found in screen stack")


def _run_with_screen(coro_factory):
    """Run an async test body against a fresh MainScreen under run_test.

    ``coro_factory`` is called with ``(app, screen, pilot)`` where ``screen``
    is the MainScreen (not the wizard modal that sits on top of it).
    """

    async def _run() -> None:
        app = FriTapApp()
        async with app.run_test() as pilot:
            screen = _find_main_screen(app)
            await coro_factory(app, screen, pilot)

    asyncio.run(_run())


# ===========================================================================
# 1. _build_convert_args -- the most unit-testable piece
# ===========================================================================

class TestBuildConvertArgs:
    """Verify the kwargs dict assembled for ``convert_pcap_to_tap``."""

    @pytest.mark.skipif(not _SIGNAL_AVAILABLE, reason="signal protocol is private/stripped in public build")
    def test_resolves_tls_and_signal_siblings(self, tmp_path):
        """Given a pcap + base keylog whose .tls/.signal siblings exist on
        disk, the returned dict points at those siblings and defaults the
        tap path to ``<pcap>.tap``."""
        pcap = str(tmp_path / "capture.pcapng")
        with open(pcap, "wb") as f:
            f.write(b"\x00")  # contents irrelevant; only os.path.isfile matters
        base, tls_sib, signal_sib = _make_signal_keylogs(tmp_path)

        captured: dict = {}

        async def body(app, screen, pilot):
            screen.app.notify = MagicMock()
            args = screen._build_convert_args(
                pcap=pcap, keylog=base, proto_keylog="",
                protocol="tls", tap="",
            )
            captured["args"] = args
            captured["notify"] = screen.app.notify

        _run_with_screen(body)

        args = captured["args"]
        assert args is not None
        assert args["pcap_path"] == pcap
        assert args["keylog_path"] == tls_sib
        assert args["signal_keylog"] == signal_sib
        # No mtproto sibling on disk -> None.
        assert args["mtproto_keylog"] is None
        # Generic map carries every resolved protocol (incl. signal); the named
        # signal_keylog/mtproto_keylog args are derived from it for back-compat
        # (mirrors cli.merge_manifest). So protocol_keylogs holds the signal entry.
        assert args["protocol_keylogs"] == {"signal": signal_sib}
        # Default tap path = pcap stem + .tap
        assert args["tap_path"] == os.path.splitext(pcap)[0] + ".tap"
        # Nothing was missing -> no error notification.
        captured["notify"].assert_not_called()

    def test_decrypt_to_flow_multi_routes_signal_keylog(self, tmp_path):
        """Regression (Signal capture -> 0 messages in the TUI .tap): the
        post-capture decrypt offer passes the AUTHORITATIVE resolved keylog map to
        start_decrypt_to_flow_multi. Signal's keylog must be its own .signal.log —
        never the TLS log — so it decrypts the chat instead of skipping it."""
        pcap = str(tmp_path / "s1capture.pcapng")
        with open(pcap, "wb") as f:
            f.write(b"\x00")
        _base, tls_sib, signal_sib = _make_signal_keylogs(tmp_path)
        keylog_files = {"tls": tls_sib, "signal": signal_sib}

        captured: dict = {}

        async def body(app, screen, pilot):
            screen.app.notify = MagicMock()
            screen._launch_decrypt_worker = MagicMock(
                side_effect=lambda a: captured.update(args=a)
            )
            screen.start_decrypt_to_flow_multi(pcap, keylog_files)

        _run_with_screen(body)
        args = captured["args"]
        assert args["keylog_path"] == tls_sib
        assert args["signal_keylog"] == signal_sib          # NOT the TLS log
        assert args["protocol_keylogs"] == {"signal": signal_sib}

    def test_explicit_tap_path_is_honored(self, tmp_path):
        pcap = str(tmp_path / "capture.pcapng")
        with open(pcap, "wb") as f:
            f.write(b"\x00")
        base, _tls, _sig = _make_signal_keylogs(tmp_path)
        explicit_tap = str(tmp_path / "out" / "result.tap")

        captured: dict = {}

        async def body(app, screen, pilot):
            screen.app.notify = MagicMock()
            captured["args"] = screen._build_convert_args(
                pcap=pcap, keylog=base, proto_keylog="",
                protocol="tls", tap=explicit_tap,
            )

        _run_with_screen(body)
        assert captured["args"]["tap_path"] == explicit_tap

    def test_falls_back_to_base_keylog_when_no_tls_sibling(self, tmp_path):
        """When only the base keylog exists (no .tls sibling), keylog_path
        falls back to the base file itself."""
        pcap = str(tmp_path / "capture.pcapng")
        with open(pcap, "wb") as f:
            f.write(b"\x00")
        base = str(tmp_path / "plain.log")
        with open(base, "w") as f:
            f.write("CLIENT_RANDOM aa bb\n")

        captured: dict = {}

        async def body(app, screen, pilot):
            screen.app.notify = MagicMock()
            captured["args"] = screen._build_convert_args(
                pcap=pcap, keylog=base, proto_keylog="",
                protocol="tls", tap="",
            )

        _run_with_screen(body)
        args = captured["args"]
        assert args["keylog_path"] == base
        # No protocol siblings present.
        assert args["signal_keylog"] is None
        assert args["mtproto_keylog"] is None

    @pytest.mark.skipif(not _SIGNAL_AVAILABLE, reason="signal protocol is private/stripped in public build")
    def test_explicit_proto_keylog_used_for_matching_protocol(self, tmp_path):
        """An explicit per-protocol keylog (proto_keylog) is used when the
        chosen protocol matches its registry name, even without a sibling."""
        pcap = str(tmp_path / "capture.pcapng")
        with open(pcap, "wb") as f:
            f.write(b"\x00")
        # Only a TLS keylog base; signal provided explicitly.
        base = str(tmp_path / "plain.log")
        with open(base, "w") as f:
            f.write("CLIENT_RANDOM aa bb\n")
        explicit_signal = str(tmp_path / "my_signal.keys")
        with open(explicit_signal, "w") as f:
            f.write("SIGNALKEYLOG x\n")

        captured: dict = {}

        async def body(app, screen, pilot):
            screen.app.notify = MagicMock()
            captured["args"] = screen._build_convert_args(
                pcap=pcap, keylog=base, proto_keylog=explicit_signal,
                protocol="signal", tap="",
            )

        _run_with_screen(body)
        assert captured["args"]["signal_keylog"] == explicit_signal

    def test_missing_pcap_returns_none_and_notifies(self, tmp_path):
        """A non-existent pcap yields None and an error notification."""
        captured: dict = {}

        async def body(app, screen, pilot):
            screen.app.notify = MagicMock()
            result = screen._build_convert_args(
                pcap=str(tmp_path / "does_not_exist.pcap"),
                keylog="", proto_keylog="", protocol="tls", tap="",
            )
            captured["result"] = result
            captured["notify"] = screen.app.notify

        _run_with_screen(body)
        assert captured["result"] is None
        captured["notify"].assert_called_once()
        # Error severity on the notification.
        _args, kwargs = captured["notify"].call_args
        assert kwargs.get("severity") == "error"

    def test_empty_pcap_returns_none(self, tmp_path):
        captured: dict = {}

        async def body(app, screen, pilot):
            screen.app.notify = MagicMock()
            captured["result"] = screen._build_convert_args(
                pcap="", keylog="", proto_keylog="", protocol="tls", tap="",
            )

        _run_with_screen(body)
        assert captured["result"] is None


# ===========================================================================
# 2. _on_session_ended -- DecryptConfirmModal trigger gating
# ===========================================================================

def _make_screen_stub():
    """Stub `_screen` rich enough for ``_on_session_ended``'s TUI calls.

    Mirrors the stub in ``test_capture_controller_severity.py`` but exposes
    ``start_decrypt_to_flow`` (a MagicMock) so the controller's callback wiring
    can be inspected, and records ``app.push_screen`` invocations.
    """
    pushed_screens: list = []

    class _ActivityLog:
        def log_error(self, m): pass
        def log_info(self, m): pass
        def log_warning(self, m): pass
        def log_session(self, m): pass

    class _StatusBar:
        capture_mode = ""
        def update_capture(self, *a, **kw): pass
        def update_target(self, *a, **kw): pass

    class _MenuPanel:
        capture_active = False
        has_target = False
        target_name = ""
        target_mode = ""
        current_mode = ""
        keylog_path = ""
        pcap_path = ""
        def batch_update(self):
            class _CM:
                def __enter__(self): return self
                def __exit__(self, *a): return False
            return _CM()

    class _State:
        target = ""
        target_display = ""
        spawn = False
        pcap_path = ""
        keylog_path = ""
        json_path = ""
        live = False
        live_mode = ""
        full_capture = False
        device_type = ""
        protocol = "tls"

    state_obj = _State()

    class _App:
        def push_screen(self, screen, callback=None):
            pushed_screens.append((screen, callback))
        def call_from_thread(self, fn, *a, **kw):
            return fn(*a, **kw)

    screen = types.SimpleNamespace()
    screen.app = _App()
    screen._get_activity_log = lambda: _ActivityLog()
    screen._get_status_bar = lambda: _StatusBar()
    screen._get_menu_panel = lambda: _MenuPanel()
    screen._get_state = lambda: state_obj
    screen._activate_legacy_view = lambda: None
    screen._update_flow_title = lambda: None
    screen.query_one = MagicMock(side_effect=Exception("not in test"))
    screen.run_worker = MagicMock()
    screen.start_decrypt_to_flow = MagicMock()
    screen.start_decrypt_to_flow_multi = MagicMock()

    return screen, pushed_screens, state_obj


def _make_controller():
    from friTap.tui.capture_controller import CaptureController
    screen, pushed, state = _make_screen_stub()
    controller = CaptureController(screen)
    # Null out subsystems _on_session_ended touches but we don't drive.
    controller._tui_handler = None
    controller._flow_collector = None
    controller._tap_writer = None
    controller._ssl_logger = None
    controller._session_error = ""
    return controller, screen, pushed, state


def _decrypt_modals(pushed):
    """Filter pushed screens for DecryptConfirmModal instances."""
    from friTap.tui.modals.decrypt_confirm_modal import DecryptConfirmModal
    return [
        (s, cb) for (s, cb) in pushed if isinstance(s, DecryptConfirmModal)
    ]


def _advance_to_decrypt(pushed):
    """Walk friTap's sequential post-capture modal queue until the
    DecryptConfirmModal is shown. Modals are presented one at a time:
    each is pushed with an ``_advance`` callback that, when invoked
    (simulating the user dismissing it), pushes the next. This simulates
    dismissing the leading modals (e.g. Capture Results) so the decrypt
    prompt — always queued last — is reached. Returns ``(modal, callback)``
    or ``(None, None)`` if no decrypt modal is ever offered."""
    from friTap.tui.modals.decrypt_confirm_modal import DecryptConfirmModal
    i = 0
    while i < len(pushed):
        screen, cb = pushed[i]
        if isinstance(screen, DecryptConfirmModal):
            return screen, cb
        i += 1
        if cb is not None:
            cb(None)  # dismiss this leading modal -> pushes the next in the queue
    return None, None


def _write_nonempty_pcapng(path):
    """Write a minimal valid pcapng containing one packet so the decrypt
    offer's empty-pcap guard (_pcap_has_packets) sees real traffic. A capture
    with no packets is intentionally NOT offered for decrypt."""
    import struct
    shb = (struct.pack("<III", 0x0A0D0D0A, 28, 0x1A2B3C4D)
           + struct.pack("<HHq", 1, 0, -1) + struct.pack("<I", 28))
    idb = struct.pack("<IIHHI", 0x00000001, 20, 1, 0, 0) + struct.pack("<I", 20)
    epb = (struct.pack("<II", 0x00000006, 36)
           + struct.pack("<IIIII", 0, 0, 0, 4, 4) + b"abcd" + struct.pack("<I", 36))
    with open(path, "wb") as f:
        f.write(shb + idb + epb)


class TestSessionEndedDecryptOffer:
    """`_on_session_ended` only offers decrypt for a full capture with both
    a keylog and a pcap present on disk."""

    def test_full_capture_with_keylog_and_pcap_pushes_modal(self, tmp_path):
        keylog = str(tmp_path / "keys.log")
        pcap = str(tmp_path / "capture.pcapng")
        with open(keylog, "w") as f:
            f.write("x")
        _write_nonempty_pcapng(pcap)  # non-empty pcap -> decrypt offered

        controller, screen, pushed, state = _make_controller()
        state.full_capture = True
        state.keylog_path = keylog
        state.pcap_path = pcap
        state.protocol = "tls"

        controller._on_session_ended({})

        # The decrypt prompt is queued last and shown after the Capture Results
        # modal is dismissed; advance the sequential queue to reach it.
        _modal, callback = _advance_to_decrypt(pushed)
        assert _modal is not None, "expected a DecryptConfirmModal"

        # The callback, when invoked with True, must forward the captured pcap
        # and the AUTHORITATIVE resolved keylog map (not the raw base keylog) to
        # start_decrypt_to_flow_multi, so split captures route per-protocol keylogs
        # correctly.
        assert callback is not None
        callback(True)
        screen.start_decrypt_to_flow_multi.assert_called_once_with(pcap, {"tls": keylog})

    def test_callback_skip_does_not_decrypt(self, tmp_path):
        keylog = str(tmp_path / "keys.log")
        pcap = str(tmp_path / "capture.pcapng")
        with open(keylog, "w") as f:
            f.write("x")
        _write_nonempty_pcapng(pcap)  # non-empty pcap -> decrypt offered

        controller, screen, pushed, state = _make_controller()
        state.full_capture = True
        state.keylog_path = keylog
        state.pcap_path = pcap

        controller._on_session_ended({})
        _modal, callback = _advance_to_decrypt(pushed)
        assert _modal is not None, "expected a DecryptConfirmModal"
        callback(False)
        screen.start_decrypt_to_flow_multi.assert_not_called()

    def test_full_capture_empty_pcap_no_modal(self, tmp_path):
        """A full capture that produced an empty pcap (no packets) must NOT
        offer decrypt — decrypting an empty pcap yields 0 flows."""
        keylog = str(tmp_path / "keys.log")
        pcap = str(tmp_path / "capture.pcapng")
        with open(keylog, "w") as f:
            f.write("x")
        with open(pcap, "wb") as f:
            f.write(b"\x00")  # not a valid/non-empty pcap -> treated as empty

        controller, screen, pushed, state = _make_controller()
        state.full_capture = True
        state.keylog_path = keylog
        state.pcap_path = pcap

        controller._on_session_ended({})
        assert _decrypt_modals(pushed) == []

    def test_plaintext_capture_no_keylog_no_modal(self, tmp_path):
        """A plaintext-hook capture (full_capture False, no keylog) must NOT
        get a decrypt prompt."""
        pcap = str(tmp_path / "capture.pcapng")
        with open(pcap, "w") as f:
            f.write("x")

        controller, screen, pushed, state = _make_controller()
        state.full_capture = False
        state.keylog_path = ""
        state.pcap_path = pcap

        controller._on_session_ended({})
        assert _decrypt_modals(pushed) == []

    def test_full_capture_missing_pcap_on_disk_no_modal(self, tmp_path):
        """full_capture True but the pcap path doesn't exist on disk -> no
        modal (the gate checks os.path.isfile)."""
        keylog = str(tmp_path / "keys.log")
        with open(keylog, "w") as f:
            f.write("x")

        controller, screen, pushed, state = _make_controller()
        state.full_capture = True
        state.keylog_path = keylog
        state.pcap_path = str(tmp_path / "missing.pcapng")  # not created

        controller._on_session_ended({})
        assert _decrypt_modals(pushed) == []

    def test_full_capture_missing_keylog_on_disk_no_modal(self, tmp_path):
        pcap = str(tmp_path / "capture.pcapng")
        with open(pcap, "w") as f:
            f.write("x")

        controller, screen, pushed, state = _make_controller()
        state.full_capture = True
        state.keylog_path = str(tmp_path / "missing.log")  # not created
        state.pcap_path = pcap

        controller._on_session_ended({})
        assert _decrypt_modals(pushed) == []


# ===========================================================================
# 3. reload_replay
# ===========================================================================

def _write_minimal_tap(path: str) -> int:
    """Hand-build a tiny .tap with two flows. Returns the flow count."""
    from friTap.flow.models import Flow, FlowState
    from friTap.flow.tap_writer import TapWriter

    writer = TapWriter()
    writer.open(path, target="test")
    for i, port in enumerate((443, 8443)):
        writer.write_flow(
            Flow(
                flow_id=f"flow-{i}",
                connection_id=f"conn-{i}",
                src_addr="10.0.0.1",
                src_port=10000 + i,
                dst_addr="93.184.216.34",
                dst_port=port,
                state=FlowState.COMPLETE,
            )
        )
    writer.close()
    return 2


class TestReloadReplay:
    """`reload_replay` clears any existing flows and repopulates from a .tap."""

    def test_reload_minimal_tap_populates_flow_list(self, tmp_path):
        tap_path = str(tmp_path / "mini.tap")
        expected = _write_minimal_tap(tap_path)

        captured: dict = {}

        async def body(app, screen, pilot):
            from friTap.tui.widgets.flow_list import FlowListWidget
            screen.reload_replay(tap_path)
            await pilot.pause()
            captured["replay_count"] = screen._replay_ctrl.flow_count
            flow_list = screen.query_one("#flow-list", FlowListWidget)
            captured["row_count"] = flow_list.row_count
            captured["filename"] = screen._replay_filename

        _run_with_screen(body)
        assert captured["replay_count"] == expected
        assert captured["row_count"] == expected
        assert captured["filename"] == "mini.tap"

    def test_reload_replaces_previous_flows(self, tmp_path):
        """A second reload_replay replaces (not appends) the flow list."""
        first = str(tmp_path / "first.tap")
        second = str(tmp_path / "second.tap")
        _write_minimal_tap(first)
        _write_minimal_tap(second)

        captured: dict = {}

        async def body(app, screen, pilot):
            from friTap.tui.widgets.flow_list import FlowListWidget
            flow_list = screen.query_one("#flow-list", FlowListWidget)
            screen.reload_replay(first)
            await pilot.pause()
            screen.reload_replay(second)
            await pilot.pause()
            captured["row_count"] = flow_list.row_count
            captured["filename"] = screen._replay_filename

        _run_with_screen(body)
        # Both taps have 2 flows; a replace (not append) keeps it at 2.
        assert captured["row_count"] == 2
        assert captured["filename"] == "second.tap"

    @pytest.mark.skipif(
        not (os.path.isfile(TSHARK) and os.path.isfile(SIGNAL_PCAP)),
        reason="requires tshark + signal fixtures",
    )
    def test_reload_real_decrypted_tap(self, tmp_path):
        """End-to-end: decrypt the Signal fixture into a .tap, then reload it
        into the flow view and assert the flow count matches."""
        from friTap.offline.pcap_to_tap import convert_pcap_to_tap

        tap_path = str(tmp_path / "signal.tap")
        result = convert_pcap_to_tap(
            pcap_path=SIGNAL_PCAP,
            keylog_path=SIGNAL_TLS_LOG,
            signal_keylog=SIGNAL_SIGNAL_LOG,
            tap_path=tap_path,
            tshark_path=TSHARK,
        )
        expected = result.flow_count
        assert expected > 0, "fixture decryption should yield flows"

        captured: dict = {}

        async def body(app, screen, pilot):
            from friTap.tui.widgets.flow_list import FlowListWidget
            screen.reload_replay(tap_path)
            await pilot.pause()
            captured["replay_count"] = screen._replay_ctrl.flow_count
            captured["row_count"] = screen.query_one(
                "#flow-list", FlowListWidget
            ).row_count

        _run_with_screen(body)
        assert captured["replay_count"] == expected
        assert captured["row_count"] == expected


# ===========================================================================
# 4. _on_decrypt_done / _on_decrypt_error worker handlers
# ===========================================================================

class TestDecryptWorkerHandlers:
    """The UI-thread handlers invoked from the decrypt thread worker."""

    def test_on_decrypt_done_reloads_and_notifies(self, tmp_path):
        tap_path = str(tmp_path / "done.tap")
        _write_minimal_tap(tap_path)
        result = types.SimpleNamespace(flow_count=2)

        captured: dict = {}

        async def body(app, screen, pilot):
            screen.app.notify = MagicMock()
            screen.reload_replay = MagicMock()
            screen._on_decrypt_done(tap_path, result)
            captured["reload"] = screen.reload_replay
            captured["notify"] = screen.app.notify

        _run_with_screen(body)
        captured["reload"].assert_called_once_with(tap_path)
        captured["notify"].assert_called_once()
        _a, kw = captured["notify"].call_args
        assert kw.get("severity") == "information"

    def test_on_decrypt_done_partial_warns_on_degraded(self, tmp_path):
        """flows>0 but degraded streams present -> success notify AND a warning.

        Regression for the silent-partial-capture gap: a mid-flow Telegram stream
        (carrying the chat) is skipped while service flows decode, so the bare
        "Decrypted N flows" success message used to hide that messages were lost.
        """
        tap_path = str(tmp_path / "partial.tap")
        _write_minimal_tap(tap_path)
        result = types.SimpleNamespace(
            flow_count=4,
            mtproto_streams_degraded=3,
            signal_streams_degraded=0,
        )

        captured: dict = {}

        async def body(app, screen, pilot):
            screen.app.notify = MagicMock()
            screen.reload_replay = MagicMock()
            screen._on_decrypt_done(tap_path, result)
            captured["reload"] = screen.reload_replay
            captured["notify"] = screen.app.notify

        _run_with_screen(body)
        captured["reload"].assert_called_once_with(tap_path)
        # Two notifies: the success info, then a degraded warning.
        assert captured["notify"].call_count == 2
        severities = [c.kwargs.get("severity") for c in captured["notify"].call_args_list]
        assert "information" in severities and "warning" in severities
        warn_msg = next(
            c.args[0] for c in captured["notify"].call_args_list
            if c.kwargs.get("severity") == "warning"
        )
        assert "mid-connection" in warn_msg and "spawn" in warn_msg

    def test_on_decrypt_done_clean_capture_no_warning(self, tmp_path):
        """flows>0 with zero degraded streams -> exactly one (success) notify."""
        tap_path = str(tmp_path / "clean.tap")
        _write_minimal_tap(tap_path)
        result = types.SimpleNamespace(
            flow_count=4, mtproto_streams_degraded=0, signal_streams_degraded=0
        )

        captured: dict = {}

        async def body(app, screen, pilot):
            screen.app.notify = MagicMock()
            screen.reload_replay = MagicMock()
            screen._on_decrypt_done(tap_path, result)
            captured["notify"] = screen.app.notify

        _run_with_screen(body)
        assert captured["notify"].call_count == 1
        _a, kw = captured["notify"].call_args
        assert kw.get("severity") == "information"

    def test_on_decrypt_done_no_flows_warns(self, tmp_path):
        """When flow_count is 0 and no .tap exists, warn instead of reloading."""
        missing_tap = str(tmp_path / "nope.tap")
        result = types.SimpleNamespace(flow_count=0)

        captured: dict = {}

        async def body(app, screen, pilot):
            screen.app.notify = MagicMock()
            screen.reload_replay = MagicMock()
            screen._on_decrypt_done(missing_tap, result)
            captured["reload"] = screen.reload_replay
            captured["notify"] = screen.app.notify

        _run_with_screen(body)
        captured["reload"].assert_not_called()
        _a, kw = captured["notify"].call_args
        assert kw.get("severity") == "warning"

    def test_on_decrypt_error_notifies_error(self):
        captured: dict = {}

        async def body(app, screen, pilot):
            screen.app.notify = MagicMock()
            screen._on_decrypt_error("boom failure")
            captured["notify"] = screen.app.notify

        _run_with_screen(body)
        _a, kw = captured["notify"].call_args
        assert kw.get("severity") == "error"
        msg = captured["notify"].call_args[0][0]
        assert "boom failure" in msg


# ===========================================================================
# 5. action_open_pcap -> OpenPcapModal wiring
# ===========================================================================

class TestActionOpenPcap:
    """`action_open_pcap` pushes OpenPcapModal and feeds its result into the
    convert-args + decrypt-worker pipeline."""

    def test_pushes_open_pcap_modal(self):
        captured: dict = {}

        async def body(app, screen, pilot):
            from friTap.tui.modals.open_pcap_modal import OpenPcapModal
            pushed = []
            screen.app.push_screen = MagicMock(
                side_effect=lambda s, callback=None: pushed.append((s, callback))
            )
            screen.action_open_pcap()
            captured["pushed"] = pushed

        _run_with_screen(body)
        pushed = captured["pushed"]
        from friTap.tui.modals.open_pcap_modal import OpenPcapModal
        assert len(pushed) == 1
        assert isinstance(pushed[0][0], OpenPcapModal)
        assert pushed[0][1] is not None  # a result callback is wired

    def test_modal_result_launches_decrypt_worker(self, tmp_path):
        """The OpenPcapModal callback builds convert args and launches the
        decrypt worker for a valid pcap."""
        pcap = str(tmp_path / "capture.pcapng")
        with open(pcap, "wb") as f:
            f.write(b"\x00")
        base, _tls, _sig = _make_signal_keylogs(tmp_path)

        captured: dict = {}

        async def body(app, screen, pilot):
            screen.app.notify = MagicMock()
            screen._launch_decrypt_worker = MagicMock()
            cb_holder = {}
            screen.app.push_screen = MagicMock(
                side_effect=lambda s, callback=None: cb_holder.update(cb=callback)
            )
            screen.action_open_pcap()
            # Simulate the modal accepting with these values.
            cb_holder["cb"]({
                "pcap": pcap,
                "keylog": base,
                "proto_keylog": "",
                "protocol": "tls",
                "tap": "",
            })
            captured["launch"] = screen._launch_decrypt_worker

        _run_with_screen(body)
        captured["launch"].assert_called_once()
        args = captured["launch"].call_args[0][0]
        assert args["pcap_path"] == pcap

    def test_modal_cancel_does_not_launch_worker(self):
        captured: dict = {}

        async def body(app, screen, pilot):
            screen._launch_decrypt_worker = MagicMock()
            cb_holder = {}
            screen.app.push_screen = MagicMock(
                side_effect=lambda s, callback=None: cb_holder.update(cb=callback)
            )
            screen.action_open_pcap()
            cb_holder["cb"](None)  # user cancelled
            captured["launch"] = screen._launch_decrypt_worker

        _run_with_screen(body)
        captured["launch"].assert_not_called()


# ===========================================================================
# 6. Modal return values (DecryptConfirmModal / OpenPcapModal)
# ===========================================================================

class TestDecryptConfirmModal:
    """The modal dismisses True on Decrypt, False on Skip/Esc."""

    def _drive(self, action):
        """Mount the modal, run *action(modal)*, return the dismissed value."""
        from friTap.tui.modals.decrypt_confirm_modal import DecryptConfirmModal
        result: dict = {}

        async def _run() -> None:
            app = FriTapApp()
            async with app.run_test() as pilot:
                modal = DecryptConfirmModal()

                def _cb(value):
                    result["value"] = value

                await app.push_screen(modal, callback=_cb)
                await pilot.pause()
                action(modal)
                await pilot.pause()

        asyncio.run(_run())
        return result.get("value")

    def test_decrypt_button_returns_true(self):
        from textual.widgets import Button
        value = self._drive(
            lambda m: m.on_button_pressed(
                types.SimpleNamespace(button=m.query_one("#btn-decrypt", Button))
            )
        )
        assert value is True

    def test_skip_button_returns_false(self):
        from textual.widgets import Button
        value = self._drive(
            lambda m: m.on_button_pressed(
                types.SimpleNamespace(button=m.query_one("#btn-skip", Button))
            )
        )
        assert value is False

    def test_escape_cancel_returns_false(self):
        value = self._drive(lambda m: m.action_cancel())
        assert value is False


class TestOpenPcapModal:
    """OpenPcapModal returns a dict of paths on Accept, None on Cancel, and
    keeps itself open when the pcap field is empty."""

    def test_accept_returns_dict(self):
        from friTap.tui.modals.open_pcap_modal import OpenPcapModal
        from textual.widgets import Input
        result: dict = {}

        async def _run() -> None:
            app = FriTapApp()
            async with app.run_test() as pilot:
                modal = OpenPcapModal()

                def _cb(value):
                    result["value"] = value

                await app.push_screen(modal, callback=_cb)
                await pilot.pause()
                modal.query_one("#pcap-input", Input).value = "/tmp/x.pcap"
                modal.query_one("#keylog-input", Input).value = "/tmp/x.tls.log"
                modal.query_one("#protocol-input", Input).value = "tls"
                modal._submit()
                await pilot.pause()

        asyncio.run(_run())
        value = result["value"]
        assert isinstance(value, dict)
        assert value["pcap"] == "/tmp/x.pcap"
        assert value["keylog"] == "/tmp/x.tls.log"
        assert value["protocol"] == "tls"

    def test_cancel_returns_none(self):
        from friTap.tui.modals.open_pcap_modal import OpenPcapModal
        result: dict = {"value": "sentinel"}

        async def _run() -> None:
            app = FriTapApp()
            async with app.run_test() as pilot:
                modal = OpenPcapModal()

                def _cb(value):
                    result["value"] = value

                await app.push_screen(modal, callback=_cb)
                await pilot.pause()
                modal.dismiss(None)
                await pilot.pause()

        asyncio.run(_run())
        assert result["value"] is None

    def test_empty_pcap_keeps_modal_open(self):
        """Submitting with an empty pcap must NOT dismiss (no result)."""
        from friTap.tui.modals.open_pcap_modal import OpenPcapModal
        from textual.widgets import Input
        result: dict = {"dismissed": False}

        async def _run() -> None:
            app = FriTapApp()
            async with app.run_test() as pilot:
                modal = OpenPcapModal()

                def _cb(value):
                    result["dismissed"] = True

                await app.push_screen(modal, callback=_cb)
                await pilot.pause()
                modal.query_one("#pcap-input", Input).value = ""  # empty
                modal._submit()
                await pilot.pause()

        asyncio.run(_run())
        assert result["dismissed"] is False
