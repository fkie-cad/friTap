#!/usr/bin/env python3

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
import os
import types
from unittest.mock import MagicMock

import pytest

pytest.importorskip("textual")

from friTap.tui.app import FriTapApp  # noqa: E402

# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------


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

    def test_missing_pcap_returns_none_and_alerts(self, tmp_path):
        """A non-existent pcap yields None and a dismissible error alert modal."""
        from friTap.tui.modals.alert_modal import AlertModal
        captured: dict = {}

        async def body(app, screen, pilot):
            pushed: list = []
            screen.app.push_screen = MagicMock(
                side_effect=lambda s, callback=None: pushed.append(s)
            )
            result = screen._build_convert_args(
                pcap=str(tmp_path / "does_not_exist.pcap"),
                keylog="", proto_keylog="", protocol="tls", tap="",
            )
            captured["result"] = result
            captured["pushed"] = pushed

        _run_with_screen(body)
        assert captured["result"] is None
        alerts = [s for s in captured["pushed"] if isinstance(s, AlertModal)]
        assert len(alerts) == 1
        assert alerts[0]._severity == "error"

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

        from friTap.tui.modals.alert_modal import AlertModal
        captured: dict = {}

        async def body(app, screen, pilot):
            screen.app.notify = MagicMock()
            pushed: list = []
            screen.app.push_screen = MagicMock(
                side_effect=lambda s, callback=None: pushed.append(s)
            )
            screen.reload_replay = MagicMock()
            screen._on_decrypt_done(tap_path, result)
            captured["reload"] = screen.reload_replay
            captured["notify"] = screen.app.notify
            captured["pushed"] = pushed

        _run_with_screen(body)
        captured["reload"].assert_called_once_with(tap_path)
        # The success message stays a toast; the degraded-streams warning is now
        # a dismissible modal (not a transient toast).
        captured["notify"].assert_called_once()
        assert captured["notify"].call_args.kwargs.get("severity") == "information"
        alerts = [s for s in captured["pushed"] if isinstance(s, AlertModal)]
        assert len(alerts) == 1
        assert alerts[0]._severity == "warning"
        assert "mid-connection" in alerts[0]._message and "spawn" in alerts[0]._message

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

    def test_on_decrypt_done_no_flows_alerts(self, tmp_path):
        """When flow_count is 0 and no .tap exists, show a dismissible warning
        modal (not a transient toast) instead of reloading."""
        from friTap.tui.modals.alert_modal import AlertModal
        missing_tap = str(tmp_path / "nope.tap")
        result = types.SimpleNamespace(flow_count=0)

        captured: dict = {}

        async def body(app, screen, pilot):
            pushed: list = []
            screen.app.push_screen = MagicMock(
                side_effect=lambda s, callback=None: pushed.append(s)
            )
            screen.reload_replay = MagicMock()
            screen._on_decrypt_done(missing_tap, result)
            captured["reload"] = screen.reload_replay
            captured["pushed"] = pushed

        _run_with_screen(body)
        captured["reload"].assert_not_called()
        alerts = [s for s in captured["pushed"] if isinstance(s, AlertModal)]
        assert len(alerts) == 1
        assert alerts[0]._severity == "warning"

    def test_on_decrypt_error_alerts_error(self):
        from friTap.tui.modals.alert_modal import AlertModal
        captured: dict = {}

        async def body(app, screen, pilot):
            pushed: list = []
            screen.app.push_screen = MagicMock(
                side_effect=lambda s, callback=None: pushed.append(s)
            )
            screen._on_decrypt_error("boom failure")
            captured["pushed"] = pushed

        _run_with_screen(body)
        alerts = [s for s in captured["pushed"] if isinstance(s, AlertModal)]
        assert len(alerts) == 1
        assert alerts[0]._severity == "error"
        assert "boom failure" in alerts[0]._message


# ===========================================================================
# 5. action_open_pcap -> OpenPcapModal wiring
# ===========================================================================

class TestActionOpenPcap:
    """`action_open_pcap` pushes OpenPcapModal and feeds its result into the
    convert-args + decrypt-worker pipeline."""

    def test_pushes_open_pcap_modal(self):
        captured: dict = {}

        async def body(app, screen, pilot):
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
        from textual.widgets import Input

        from friTap.tui.modals.open_pcap_modal import OpenPcapModal
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
        from textual.widgets import Input

        from friTap.tui.modals.open_pcap_modal import OpenPcapModal
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


# ---------------------------------------------------------------------------
# 5. tshark-missing surfaces as a MODAL (not a transient toast), and the
#    decrypt worker is never launched. Both the pre-flight and the reactive
#    safety net funnel into the one shared presenter.
# ---------------------------------------------------------------------------
class TestTsharkMissingModal:
    def test_preflight_shows_modal_and_skips_worker(self, monkeypatch):
        """find_tshark failing in _launch_decrypt_worker -> AlertModal, no worker."""
        from friTap.tui.screens.main_screen import MainScreen
        from friTap.tui.modals.alert_modal import AlertModal
        from friTap.offline import tshark as tshark_mod
        from friTap.offline.tshark import TSHARK_INSTALL_MESSAGE, TsharkNotFoundError

        screen, pushed, _ = _make_screen_stub()
        screen.app.notify = MagicMock()
        # Wire the real presenter onto the stub so the pre-flight exercises it.
        screen._show_tshark_missing_modal = (
            lambda: MainScreen._show_tshark_missing_modal(screen)
        )

        monkeypatch.setattr(
            tshark_mod, "find_tshark",
            lambda *a, **k: (_ for _ in ()).throw(TsharkNotFoundError("missing")),
        )

        MainScreen._launch_decrypt_worker(
            screen, {"tshark_path": None, "tap_path": "out.tap"}
        )

        assert len(pushed) == 1, "expected exactly one modal pushed"
        modal, _cb = pushed[0]
        assert isinstance(modal, AlertModal)
        assert modal._message == TSHARK_INSTALL_MESSAGE  # single-source text
        assert modal._severity == "error"
        # The worker must NOT start, and no "Decrypting..." toast should appear.
        screen.run_worker.assert_not_called()
        screen.app.notify.assert_not_called()

    def test_preflight_launches_worker_when_tshark_present(self, monkeypatch):
        """When tshark resolves, the worker runs behind a progress spinner modal."""
        from friTap.tui.screens.main_screen import MainScreen
        from friTap.tui.modals.decrypt_progress_modal import DecryptProgressModal
        from friTap.offline import tshark as tshark_mod

        screen, pushed, _ = _make_screen_stub()
        screen.app.notify = MagicMock()
        monkeypatch.setattr(tshark_mod, "find_tshark", lambda *a, **k: "/usr/bin/tshark")

        MainScreen._launch_decrypt_worker(
            screen, {"tshark_path": None, "tap_path": "out.tap"}
        )

        # A non-dismissible progress spinner is shown so a long decrypt never
        # looks hung; the worker still starts.
        assert len(pushed) == 1
        assert isinstance(pushed[0][0], DecryptProgressModal)
        screen.run_worker.assert_called_once()

    def test_presenter_pushes_error_modal_and_logs(self):
        """The shared presenter both front-ends/paths funnel into."""
        from friTap.tui.screens.main_screen import MainScreen
        from friTap.tui.modals.alert_modal import AlertModal
        from friTap.offline.tshark import TSHARK_INSTALL_MESSAGE

        screen, pushed, _ = _make_screen_stub()
        logged: list = []
        screen._get_activity_log = lambda: types.SimpleNamespace(
            log_warning=lambda m: logged.append(m)
        )

        MainScreen._show_tshark_missing_modal(screen)

        assert len(pushed) == 1
        modal, _cb = pushed[0]
        assert isinstance(modal, AlertModal)
        assert modal._message == TSHARK_INSTALL_MESSAGE
        assert modal._severity == "error"
        assert modal._title == "tshark not found"
        assert logged and "tshark not found" in logged[0]


# ===========================================================================
# 0-flow keylog-coverage explanation + per_protocol Signal counters
# ===========================================================================

class TestZeroFlowExplanation:
    """_decrypt_worker computes keylog coverage for a 0-flow TLS conversion."""

    _LINES = [
        "TLS keylog matches 0 of 4 TLS handshakes in the capture (a.com TLS 1.3).",
        "None of the keylog's 2 sessions appear in this capture.",
    ]

    def _coverage(self, args, flow_count, **patches):
        from unittest.mock import patch

        from friTap.tui.screens.main_screen import MainScreen
        result = types.SimpleNamespace(flow_count=flow_count)
        with patch("friTap.offline.tshark.find_tshark", return_value="tshark"), patch(
            "friTap.offline.keylog_coverage.check_keylog_coverage", **patches,
        ) as check, patch(
            "friTap.offline.keylog_coverage.describe", return_value=("warning", self._LINES),
        ):
            return MainScreen._zero_flow_coverage(args, result), check

    def test_zero_flows_with_tls_keylog_computes_coverage(self):
        args = {"pcap_path": "c.pcapng", "keylog_path": "k.log", "tshark_path": None}
        coverage, check = self._coverage(args, 0, return_value=object())
        assert coverage == ("warning", self._LINES)
        check.assert_called_once_with("tshark", "c.pcapng", "k.log")

    def test_skipped_with_flows_or_without_tls_keylog(self):
        args = {"pcap_path": "c.pcapng", "keylog_path": "k.log"}
        assert self._coverage(args, 2, return_value=object())[0] is None
        assert self._coverage(dict(args, keylog_path=None), 0, return_value=object())[0] is None

    def test_failure_yields_none(self):
        args = {"pcap_path": "c.pcapng", "keylog_path": "k.log"}
        assert self._coverage(args, 0, side_effect=RuntimeError("boom"))[0] is None

    def test_on_decrypt_done_shows_coverage_lines(self, tmp_path):
        from friTap.tui.modals.alert_modal import AlertModal
        captured: dict = {}

        async def body(app, screen, pilot):
            pushed: list = []
            screen.app.push_screen = MagicMock(
                side_effect=lambda s, callback=None: pushed.append(s)
            )
            screen._on_decrypt_done(
                str(tmp_path / "none.tap"), types.SimpleNamespace(flow_count=0),
                ("warning", self._LINES),
            )
            captured["pushed"] = pushed

        _run_with_screen(body)
        # The multi-sentence coverage explanation is a dismissible modal now
        # (no more transient toast with a long timeout).
        alerts = [s for s in captured["pushed"] if isinstance(s, AlertModal)]
        assert len(alerts) == 1
        msg = alerts[0]._message
        assert msg.startswith("Decrypted 0 flows: TLS keylog matches 0 of 4")
        assert "None of the keylog's 2 sessions" in msg
        assert "Decryption produced no flows" not in msg

    def test_signal_counters_read_from_per_protocol(self):
        from friTap.offline.pcap_to_tap import ConvertResult
        from friTap.tui.screens.main_screen import MainScreen
        result = ConvertResult(tap_path="x.tap")
        result.record_protocol("signal", undecryptable=3, degraded=2)
        result.record_protocol("mtproto", degraded=1)
        assert MainScreen._degraded_stream_count(result) == 3
        assert MainScreen._undecryptable_record_count(result) == 3

    def test_signal_undecryptable_explains_zero_flows(self, tmp_path):
        from friTap.offline.pcap_to_tap import ConvertResult
        result = ConvertResult(tap_path="x.tap")
        result.record_protocol("signal", undecryptable=5)
        from friTap.tui.modals.alert_modal import AlertModal
        captured: dict = {}

        async def body(app, screen, pilot):
            pushed: list = []
            screen.app.push_screen = MagicMock(
                side_effect=lambda s, callback=None: pushed.append(s)
            )
            screen._on_decrypt_done(str(tmp_path / "none.tap"), result)
            captured["pushed"] = pushed

        _run_with_screen(body)
        alerts = [s for s in captured["pushed"] if isinstance(s, AlertModal)]
        assert len(alerts) == 1
        assert "5 records had no matching key" in alerts[0]._message

    def test_telegram_prefix_counters_reach_the_tui_helpers(self):
        """A ``telegram``-prefixed keylog's degraded/undecryptable counts must reach
        the TUI helpers — previously only ``mtproto_*`` legacy attrs were read, so a
        ``telegram`` run's counters were silently dropped."""
        from friTap.offline.pcap_to_tap import ConvertResult
        from friTap.tui.screens.main_screen import MainScreen
        result = ConvertResult(tap_path="x.tap")
        result.record_protocol("telegram", degraded=2, undecryptable=3)
        assert MainScreen._degraded_stream_count(result) == 2
        assert MainScreen._undecryptable_record_count(result) == 3

    def test_short_and_unsupported_framing_not_counted_as_degraded(self):
        """D3/D5 streams (short / unsupported framing) must NOT be reported as
        mid-connection: they never touch the degraded count."""
        from friTap.offline.pcap_to_tap import ConvertResult
        from friTap.tui.screens.main_screen import MainScreen
        result = ConvertResult(tap_path="x.tap")
        result.record_protocol("mtproto", short=4, unsupported_framing=2)
        assert MainScreen._degraded_stream_count(result) == 0

    def test_e2e_only_explains_zero_flows_before_degraded(self, tmp_path):
        """E2E key present but no transport auth key -> the dedicated E2E-only
        message, reported even when degraded streams are ALSO present (it is the
        more specific, true cause and must not be masked)."""
        from friTap.offline.pcap_to_tap import ConvertResult
        from friTap.tui.modals.alert_modal import AlertModal
        result = ConvertResult(tap_path="x.tap")
        # Both signals present: e2e_only must win over the mid-connection fallback.
        result.record_protocol("telegram", e2e_only=True, degraded=1, undecryptable=2)
        captured: dict = {}

        async def body(app, screen, pilot):
            pushed: list = []
            screen.app.push_screen = MagicMock(
                side_effect=lambda s, callback=None: pushed.append(s)
            )
            screen._on_decrypt_done(str(tmp_path / "none.tap"), result)
            captured["pushed"] = pushed

        _run_with_screen(body)
        alerts = [s for s in captured["pushed"] if isinstance(s, AlertModal)]
        assert len(alerts) == 1
        msg = alerts[0]._message
        assert "secret-chat (E2E) key but no" in msg
        assert "transport envelope can't be decrypted" in msg
        assert "-ms" in msg and "-k" in msg
        # NOT the mid-connection wording.
        assert "started mid-connection" not in msg

    def test_unknown_auth_key_ids_are_surfaced(self, tmp_path):
        """Unknown auth_key_ids seen in the clear are named so the user knows which
        transport keys to capture."""
        from friTap.offline.pcap_to_tap import ConvertResult
        from friTap.tui.modals.alert_modal import AlertModal
        result = ConvertResult(tap_path="x.tap")
        result.record_protocol(
            "telegram", undecryptable=2,
            unknown_key_ids={"1122334455667788": 1, "aabbccddeeff0011": 1},
        )
        captured: dict = {}

        async def body(app, screen, pilot):
            pushed: list = []
            screen.app.push_screen = MagicMock(
                side_effect=lambda s, callback=None: pushed.append(s)
            )
            screen._on_decrypt_done(str(tmp_path / "none.tap"), result)
            captured["pushed"] = pushed

        _run_with_screen(body)
        alerts = [s for s in captured["pushed"] if isinstance(s, AlertModal)]
        assert len(alerts) == 1
        msg = alerts[0]._message
        assert "1122334455667788" in msg
        assert "aabbccddeeff0011" in msg
        assert "Unknown auth_key_id" in msg

    def test_recovered_via_obf_counter_reads_per_protocol(self):
        """Mid-stream streams recovered from memory-scanned obfuscation keys are
        summed generically across messaging prefixes."""
        from friTap.offline.pcap_to_tap import ConvertResult
        from friTap.tui.screens.main_screen import MainScreen
        result = ConvertResult(tap_path="x.tap")
        result.record_protocol("mtproto", recovered_via_obf=2)
        result.record_protocol("telegram", recovered_via_obf=3)
        assert MainScreen._recovered_via_obf_count(result) == 5

    def test_degraded_unrecovered_counter_reads_per_protocol(self):
        """Streams where obfuscation-key recovery was attempted but no key aligned
        are counted separately from plain degraded streams."""
        from friTap.offline.pcap_to_tap import ConvertResult
        from friTap.tui.screens.main_screen import MainScreen
        result = ConvertResult(tap_path="x.tap")
        result.record_protocol("mtproto", degraded=1, degraded_unrecovered=4)
        assert MainScreen._degraded_unrecovered_count(result) == 4
        # ...and it does NOT leak into the mid-connection degraded figure.
        assert MainScreen._degraded_stream_count(result) == 1

    def test_short_stream_counter_reads_per_protocol(self):
        """Short streams are surfaced on their own, never as degraded."""
        from friTap.offline.pcap_to_tap import ConvertResult
        from friTap.tui.screens.main_screen import MainScreen
        result = ConvertResult(tap_path="x.tap")
        result.record_protocol("mtproto", short=6)
        assert MainScreen._short_stream_count(result) == 6
        assert MainScreen._degraded_stream_count(result) == 0

    def test_on_decrypt_done_reports_recovered_via_obf_as_positive_note(self, tmp_path):
        """flows>0 with ONLY recovered_via_obf streams -> an informational note
        (not a warning): those mid-stream streams were a success, recovered from
        memory-scanned obfuscation keys."""
        from friTap.offline.pcap_to_tap import ConvertResult
        from friTap.tui.modals.alert_modal import AlertModal
        tap_path = str(tmp_path / "recovered.tap")
        _write_minimal_tap(tap_path)
        result = ConvertResult(tap_path=tap_path)
        result.flow_count = 4
        result.record_protocol("telegram", recovered_via_obf=2)
        captured: dict = {}

        async def body(app, screen, pilot):
            screen.app.notify = MagicMock()
            pushed: list = []
            screen.app.push_screen = MagicMock(
                side_effect=lambda s, callback=None: pushed.append(s)
            )
            screen.reload_replay = MagicMock()
            screen._on_decrypt_done(tap_path, result)
            captured["pushed"] = pushed

        _run_with_screen(body)
        alerts = [s for s in captured["pushed"] if isinstance(s, AlertModal)]
        assert len(alerts) == 1
        assert alerts[0]._severity == "information"
        msg = alerts[0]._message
        assert "recovered from memory-scanned obfuscation key" in msg
        assert "2 mid-stream" in msg

    def test_on_decrypt_done_reports_degraded_unrecovered_and_short(self, tmp_path):
        """flows>0 with degraded_unrecovered AND short streams -> one warning modal
        that itemizes both buckets (additively, alongside the degraded note)."""
        from friTap.offline.pcap_to_tap import ConvertResult
        from friTap.tui.modals.alert_modal import AlertModal
        tap_path = str(tmp_path / "buckets.tap")
        _write_minimal_tap(tap_path)
        result = ConvertResult(tap_path=tap_path)
        result.flow_count = 4
        result.record_protocol(
            "mtproto", degraded=1, degraded_unrecovered=2, short=3
        )
        captured: dict = {}

        async def body(app, screen, pilot):
            screen.app.notify = MagicMock()
            pushed: list = []
            screen.app.push_screen = MagicMock(
                side_effect=lambda s, callback=None: pushed.append(s)
            )
            screen.reload_replay = MagicMock()
            screen._on_decrypt_done(tap_path, result)
            captured["pushed"] = pushed

        _run_with_screen(body)
        alerts = [s for s in captured["pushed"] if isinstance(s, AlertModal)]
        assert len(alerts) == 1
        assert alerts[0]._severity == "warning"
        msg = alerts[0]._message
        # The existing mid-connection wording is preserved...
        assert "started mid-connection" in msg and "spawn" in msg
        # ...and the two new buckets are itemized.
        assert "no key aligned" in msg
        assert "2 stream" in msg
        assert "3 short stream" in msg
