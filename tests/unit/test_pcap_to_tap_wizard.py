#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Unit tests for the guided pcap-to-tap wizard (Work Item 4).

Covers three layers, none of which touches a device or launches the
interactive TUI:

* :func:`friTap.friTap._dispatch_special_mode` now routes ``.pcap`` / ``.pcapng``
  inputs (via ``-r``/``--replay`` or the bare trailing-path form) to the new
  ``"pcap-wizard"`` mode while keeping ``.tap`` on the existing replay path.
* :meth:`MainScreen._build_convert_args_multi` assembles the
  ``convert_pcap_to_tap`` kwargs from a pcap plus an explicit TLS keylog and a
  map of several per-protocol (layered) keylogs.
* :class:`friTap.tui.wizard.PcapToTapWizard` drives the callback-chained step
  flow, accumulates multiple protocol keylogs across step-2 loops, and hands the
  assembled kwargs to the screen's decrypt worker on confirm.

The wizard tests use a lightweight stub screen (mirroring
``test_capture_controller_severity.py``) that records ``app.push_screen`` calls
and exposes the convert/launch hooks the wizard depends on — so the step chain
is exercised without a live Textual app.
"""

from __future__ import annotations

import importlib.util
import types
from unittest.mock import MagicMock

import pytest

_signal_spec = importlib.util.find_spec("friTap.offline.signal")
# `.loader is not None` guards against a stale __pycache__ leftover turning the
# stripped signal dir into an importable namespace package (false positive).
_SIGNAL_AVAILABLE = _signal_spec is not None and _signal_spec.loader is not None

from friTap.friTap import _dispatch_special_mode, _looks_like_pcap_input  # noqa: E402


def _argv(*rest):
    """Build an argv vector with a synthetic program name in slot 0."""
    return ["fritap", *rest]


# ---------------------------------------------------------------------------
# 1. dispatch routing for pcap / pcapng -> pcap-wizard
# ---------------------------------------------------------------------------

class TestDispatchPcapWizard:
    def test_dash_r_pcap_routes_to_pcap_wizard(self):
        assert _dispatch_special_mode(_argv("-r", "cap.pcap")) == (
            "pcap-wizard", "cap.pcap")

    def test_dash_r_pcapng_routes_to_pcap_wizard(self):
        assert _dispatch_special_mode(_argv("--replay", "cap.pcapng")) == (
            "pcap-wizard", "cap.pcapng")

    def test_bare_pcap_path_routes_to_pcap_wizard(self):
        assert _dispatch_special_mode(_argv("cap.pcap")) == (
            "pcap-wizard", "cap.pcap")
        assert _dispatch_special_mode(_argv("capture.pcapng")) == (
            "pcap-wizard", "capture.pcapng")

    def test_tap_still_routes_to_replay(self):
        # The .tap replay path must be untouched by the new pcap handling.
        assert _dispatch_special_mode(_argv("-r", "cap.tap")) == (
            "replay", "cap.tap")
        assert _dispatch_special_mode(_argv("cap.tap")) == ("replay", "cap.tap")

    def test_dash_r_without_file_still_replay_none(self):
        assert _dispatch_special_mode(_argv("-r")) == ("replay", None)

    def test_from_pcap_takes_precedence_over_pcap_wizard(self):
        # --from-pcap is matched earlier and must keep winning for a pcap arg.
        assert _dispatch_special_mode(
            _argv("--from-pcap", "cap.pcapng"))[0] == "from-pcap"

    def test_looks_like_pcap_input(self):
        assert _looks_like_pcap_input("foo.pcap") is True
        assert _looks_like_pcap_input("foo.pcapng") is True
        assert _looks_like_pcap_input("foo.tap") is False
        assert _looks_like_pcap_input("-m") is False
        assert _looks_like_pcap_input("") is False
        assert _looks_like_pcap_input(None) is False


# ---------------------------------------------------------------------------
# 2. MainScreen._build_convert_args_multi
# ---------------------------------------------------------------------------

pytest.importorskip("textual")

from friTap.tui.app import FriTapApp  # noqa: E402


def _find_main_screen(app):
    from friTap.tui.screens.main_screen import MainScreen
    for screen in app.screen_stack:
        if isinstance(screen, MainScreen):
            return screen
    raise AssertionError("MainScreen not found in screen stack")


def _run_with_screen(coro_factory):
    import asyncio

    async def _run() -> None:
        app = FriTapApp()
        async with app.run_test() as pilot:
            screen = _find_main_screen(app)
            await coro_factory(app, screen, pilot)

    asyncio.run(_run())


class TestBuildConvertArgsMulti:
    def test_assembles_tls_and_multiple_protocol_keylogs(self, tmp_path):
        """A pcap + TLS keylog + several layered keylogs map straight through to
        the convert kwargs (named back-compat args derived from the map)."""
        pcap = str(tmp_path / "capture.pcapng")
        tls = str(tmp_path / "tls.log")
        sig = str(tmp_path / "signal.log")
        tg = str(tmp_path / "telegram.log")
        for p, body in ((pcap, b"\x00"), (tls, b"x"), (sig, b"x"), (tg, b"x")):
            with open(p, "wb") as f:
                f.write(body)

        captured: dict = {}

        async def body(app, screen, pilot):
            screen.app.notify = MagicMock()
            captured["args"] = screen._build_convert_args_multi(
                pcap=pcap,
                tls_keylog=tls,
                protocol_keylogs={"signal": sig, "mtproto": tg},
                tap="",
            )
            captured["notify"] = screen.app.notify

        _run_with_screen(body)
        args = captured["args"]
        assert args is not None
        assert args["pcap_path"] == pcap
        assert args["keylog_path"] == tls
        assert args["signal_keylog"] == sig
        assert args["mtproto_keylog"] == tg
        assert args["protocol_keylogs"] == {"signal": sig, "mtproto": tg}
        # Default tap path = pcap stem + .tap
        import os
        assert args["tap_path"] == os.path.splitext(pcap)[0] + ".tap"
        captured["notify"].assert_not_called()

    def test_explicit_tap_path_is_honored(self, tmp_path):
        pcap = str(tmp_path / "capture.pcapng")
        with open(pcap, "wb") as f:
            f.write(b"\x00")
        explicit = str(tmp_path / "out" / "result.tap")

        captured: dict = {}

        async def body(app, screen, pilot):
            screen.app.notify = MagicMock()
            captured["args"] = screen._build_convert_args_multi(
                pcap=pcap, tls_keylog="", protocol_keylogs={}, tap=explicit,
            )

        _run_with_screen(body)
        assert captured["args"]["tap_path"] == explicit
        # No keylogs supplied -> all None / no map.
        assert captured["args"]["keylog_path"] is None
        assert captured["args"]["protocol_keylogs"] is None

    def test_drops_keylogs_that_do_not_exist_on_disk(self, tmp_path):
        """Only keylogs pointing at an existing file are kept."""
        pcap = str(tmp_path / "capture.pcapng")
        sig = str(tmp_path / "signal.log")
        with open(pcap, "wb") as f:
            f.write(b"\x00")
        with open(sig, "wb") as f:
            f.write(b"x")

        captured: dict = {}

        async def body(app, screen, pilot):
            screen.app.notify = MagicMock()
            captured["args"] = screen._build_convert_args_multi(
                pcap=pcap,
                tls_keylog=str(tmp_path / "missing-tls.log"),  # absent
                protocol_keylogs={
                    "signal": sig,
                    "mtproto": str(tmp_path / "missing.log"),  # absent
                },
                tap="",
            )

        _run_with_screen(body)
        args = captured["args"]
        assert args["keylog_path"] is None
        assert args["signal_keylog"] == sig
        assert args["mtproto_keylog"] is None
        assert args["protocol_keylogs"] == {"signal": sig}

    def test_missing_pcap_returns_none_and_notifies(self, tmp_path):
        captured: dict = {}

        async def body(app, screen, pilot):
            screen.app.notify = MagicMock()
            captured["result"] = screen._build_convert_args_multi(
                pcap=str(tmp_path / "nope.pcap"),
                tls_keylog="", protocol_keylogs={}, tap="",
            )
            captured["notify"] = screen.app.notify

        _run_with_screen(body)
        assert captured["result"] is None
        _a, kw = captured["notify"].call_args
        assert kw.get("severity") == "error"


# ---------------------------------------------------------------------------
# 3. PcapToTapWizard step flow
# ---------------------------------------------------------------------------

from friTap.tui.wizard import PcapToTapWizard  # noqa: E402


def _make_wizard_screen():
    """Stub screen recording push_screen + exposing the wizard's hooks."""
    pushed: list = []

    class _ActivityLog:
        def log_info(self, m): pass
        def log_success(self, m): pass
        def log_warning(self, m): pass

    class _App:
        def push_screen(self, screen, callback=None):
            pushed.append((screen, callback))

    screen = types.SimpleNamespace()
    screen.app = _App()
    screen._get_activity_log = lambda: _ActivityLog()
    # The wizard delegates the final kwargs build + launch to the screen.
    screen._build_convert_args_multi = MagicMock(
        return_value={"pcap_path": "cap.pcap", "tap_path": "cap.tap"}
    )
    screen._launch_decrypt_worker = MagicMock()
    return screen, pushed


def _last_callback(pushed):
    return pushed[-1][1]


def _last_modal(pushed):
    return pushed[-1][0]


class TestPcapToTapWizardFlow:
    def test_full_flow_with_multiple_keylogs_launches_worker(self):
        """start -> paths -> add signal -> add mtproto -> done -> confirm
        assembles all keylogs and launches the decrypt worker once."""
        screen, pushed = _make_wizard_screen()
        wiz = PcapToTapWizard(screen)
        wiz.start("cap.pcap")

        # Step 1: paths modal pushed; answer it (no TLS keylog here anymore).
        assert wiz.active is True
        _last_callback(pushed)({"pcap": "cap.pcap", "tap": "out.tap"})

        # Step 2 (loops): TLS is now picked here like any other protocol.
        _last_callback(pushed)({
            "action": "add", "protocol": "tls", "keylog": "tls.log",
        })
        _last_callback(pushed)({
            "action": "add", "protocol": "signal", "keylog": "sig.log",
        })
        _last_callback(pushed)({
            "action": "add", "protocol": "mtproto", "keylog": "tg.log",
        })
        # Done -> confirm.
        _last_callback(pushed)({"action": "done"})

        # Step 3: confirm -> convert.
        _last_callback(pushed)(True)

        # TLS is split back out into tls_keylog; the layered map carries the rest.
        screen._build_convert_args_multi.assert_called_once()
        _a, kwargs = screen._build_convert_args_multi.call_args
        assert kwargs["pcap"] == "cap.pcap"
        assert kwargs["tap"] == "out.tap"
        assert kwargs["tls_keylog"] == "tls.log"
        assert kwargs["protocol_keylogs"] == {
            "signal": "sig.log", "mtproto": "tg.log",
        }
        assert "tls" not in kwargs["protocol_keylogs"]
        screen._launch_decrypt_worker.assert_called_once()
        assert wiz.active is False

    def test_cancel_at_paths_step_finishes_without_convert(self):
        screen, pushed = _make_wizard_screen()
        wiz = PcapToTapWizard(screen)
        wiz.start("cap.pcap")
        _last_callback(pushed)(None)  # cancel the paths modal

        assert wiz.active is False
        screen._launch_decrypt_worker.assert_not_called()

    def test_confirm_back_returns_to_protocol_step(self):
        from friTap.tui.modals.pcap_to_tap_modals import (
            PcapToTapConfirmModal, ProtocolKeylogModal,
        )
        screen, pushed = _make_wizard_screen()
        wiz = PcapToTapWizard(screen)
        wiz.start("cap.pcap")
        _last_callback(pushed)({"pcap": "cap.pcap", "tap": ""})
        _last_callback(pushed)({"action": "done"})  # -> confirm
        assert isinstance(_last_modal(pushed), PcapToTapConfirmModal)
        _last_callback(pushed)(None)  # Back from confirm -> step 2
        assert isinstance(_last_modal(pushed), ProtocolKeylogModal)
        screen._launch_decrypt_worker.assert_not_called()

    def test_no_keylogs_still_converts(self):
        """A pcap with no keylogs at all (already-plaintext capture) still
        proceeds to conversion."""
        screen, pushed = _make_wizard_screen()
        wiz = PcapToTapWizard(screen)
        wiz.start("plain.pcap")
        _last_callback(pushed)({"pcap": "plain.pcap", "tap": ""})
        _last_callback(pushed)({"action": "done"})
        _last_callback(pushed)(True)

        _a, kwargs = screen._build_convert_args_multi.call_args
        assert kwargs["protocol_keylogs"] == {}
        screen._launch_decrypt_worker.assert_called_once()

    def test_build_args_none_skips_worker(self):
        """When the screen's arg builder returns None (missing pcap), the wizard
        does not launch the worker."""
        screen, pushed = _make_wizard_screen()
        screen._build_convert_args_multi = MagicMock(return_value=None)
        screen._launch_decrypt_worker = MagicMock()
        wiz = PcapToTapWizard(screen)
        wiz.start("cap.pcap")
        _last_callback(pushed)({"pcap": "cap.pcap", "tap": ""})
        _last_callback(pushed)({"action": "done"})
        _last_callback(pushed)(True)
        screen._launch_decrypt_worker.assert_not_called()


# ---------------------------------------------------------------------------
# 4. Modal return values
# ---------------------------------------------------------------------------

class TestPcapToTapModals:
    def test_paths_modal_accept_returns_dict(self):
        import asyncio
        from friTap.tui.modals.pcap_to_tap_modals import PcapPathsModal
        from textual.widgets import Input
        result: dict = {}

        async def _run() -> None:
            app = FriTapApp()
            async with app.run_test() as pilot:
                modal = PcapPathsModal()

                def _cb(value):
                    result["value"] = value

                await app.push_screen(modal, callback=_cb)
                await pilot.pause()
                modal.query_one("#pcap-input", Input).value = "/tmp/x.pcap"
                modal.query_one("#tap-input", Input).value = "/tmp/x.tap"
                modal._submit()
                await pilot.pause()

        asyncio.run(_run())
        value = result["value"]
        # TLS keylog is no longer collected here — it's a step-2 protocol now.
        assert value == {
            "pcap": "/tmp/x.pcap",
            "tap": "/tmp/x.tap",
        }

    def test_paths_modal_empty_pcap_keeps_open(self):
        import asyncio
        from friTap.tui.modals.pcap_to_tap_modals import PcapPathsModal
        from textual.widgets import Input
        result: dict = {"dismissed": False}

        async def _run() -> None:
            app = FriTapApp()
            async with app.run_test() as pilot:
                modal = PcapPathsModal()

                def _cb(value):
                    result["dismissed"] = True

                await app.push_screen(modal, callback=_cb)
                await pilot.pause()
                modal.query_one("#pcap-input", Input).value = ""
                modal._submit()
                await pilot.pause()

        asyncio.run(_run())
        assert result["dismissed"] is False

    def test_protocol_keylog_modal_done_returns_action_done(self):
        import asyncio
        from friTap.tui.modals.pcap_to_tap_modals import ProtocolKeylogModal
        result: dict = {}

        async def _run() -> None:
            app = FriTapApp()
            async with app.run_test() as pilot:
                modal = ProtocolKeylogModal(protocol_names=["signal", "mtproto"])

                def _cb(value):
                    result["value"] = value

                await app.push_screen(modal, callback=_cb)
                await pilot.pause()
                modal.on_button_pressed(
                    types.SimpleNamespace(
                        button=types.SimpleNamespace(id="btn-done")
                    )
                )
                await pilot.pause()

        asyncio.run(_run())
        assert result["value"] == {"action": "done"}

    def test_confirm_modal_convert_returns_true(self):
        import asyncio
        from friTap.tui.modals.pcap_to_tap_modals import PcapToTapConfirmModal
        result: dict = {}

        async def _run() -> None:
            app = FriTapApp()
            async with app.run_test() as pilot:
                modal = PcapToTapConfirmModal(summary={
                    "pcap": "c.pcap", "tap": "c.tap",
                    "protocol_keylogs": {"tls": "t.log", "signal": "s.log"},
                })

                def _cb(value):
                    result["value"] = value

                await app.push_screen(modal, callback=_cb)
                await pilot.pause()
                modal.on_button_pressed(
                    types.SimpleNamespace(
                        button=types.SimpleNamespace(id="btn-convert")
                    )
                )
                await pilot.pause()

        asyncio.run(_run())
        assert result["value"] is True


# ---------------------------------------------------------------------------
# 5. Confirm summary rendering — TLS is just another keylog, no dead line
# ---------------------------------------------------------------------------

class TestConfirmSummaryText:
    def _summary_text(self, summary: dict) -> str:
        from friTap.tui.modals.pcap_to_tap_modals import PcapToTapConfirmModal
        return PcapToTapConfirmModal(summary=summary)._build_summary_text()

    def test_no_dead_tls_keylog_line_and_tls_listed_as_keylog(self):
        text = self._summary_text({
            "pcap": "c.pcap", "tap": "c.tap",
            "protocol_keylogs": {"tls": "t.log", "signal": "s.log"},
        })
        # The dedicated "TLS keylog:" line is gone; TLS shows under Keylogs.
        assert "TLS keylog" not in text
        assert "- tls: t.log" in text
        assert "- signal: s.log" in text

    def test_warning_and_tls_note_render_when_present(self):
        text = self._summary_text({
            "pcap": "c.pcap", "tap": "c.tap",
            "protocol_keylogs": {"signal": "s.log"},
            "warning": "signal needs TLS keys",
            "tls_note": "TLS keys: embedded in capture (DSB)",
        })
        assert "signal needs TLS keys" in text
        assert "embedded in capture (DSB)" in text


# ---------------------------------------------------------------------------
# 6. Wizard TLS-availability feedback (Signal needs both keys; DSB counts)
# ---------------------------------------------------------------------------

class TestWizardTlsFeedback:
    def _wizard(self, protocol_keylogs, *, tls_strip, dsb):
        screen, _pushed = _make_wizard_screen()
        wiz = PcapToTapWizard(screen)
        wiz._pcap_path = "cap.pcapng"
        wiz._protocol_keylogs = dict(protocol_keylogs)
        wiz._tls_strip_protocols = lambda: list(tls_strip)
        wiz._capture_has_dsb = lambda: dsb
        return wiz

    def test_warns_when_signal_lacks_tls_keys_and_no_dsb(self):
        wiz = self._wizard({"signal": "s.log"}, tls_strip=["signal"], dsb=False)
        fb = wiz._tls_feedback()
        assert "warning" in fb
        assert "signal" in fb["warning"]
        assert "tls_note" not in fb

    def test_dsb_supplies_tls_keys_so_note_not_warning(self):
        wiz = self._wizard({"signal": "s.log"}, tls_strip=["signal"], dsb=True)
        fb = wiz._tls_feedback()
        assert "warning" not in fb
        assert "DSB" in fb["tls_note"]

    def test_explicit_tls_keylog_clears_feedback(self):
        wiz = self._wizard(
            {"signal": "s.log", "tls": "t.log"}, tls_strip=["signal"], dsb=False,
        )
        assert wiz._tls_feedback() == {}

    def test_no_tls_strip_protocol_means_no_feedback(self):
        wiz = self._wizard({"mtproto": "m.log"}, tls_strip=[], dsb=False)
        assert wiz._tls_feedback() == {}

    def test_offline_protocol_names_lead_with_tls(self):
        screen, _ = _make_wizard_screen()
        names = PcapToTapWizard(screen)._offline_protocol_names()
        # TLS is offered first, like any other selectable protocol.
        assert names[0] == "tls"
        if _SIGNAL_AVAILABLE:
            assert "signal" in names


# ---------------------------------------------------------------------------
# 7. `fritap -r <pcap>` shows an empty flow view (not the live-hooking console)
# ---------------------------------------------------------------------------

class TestPcapReadShowsEmptyFlowView:
    def test_empty_flow_view_backdrop_and_paths_modal_without_tls_field(self):
        import asyncio
        from textual.widgets import Input
        from friTap.tui.modals.pcap_to_tap_modals import PcapPathsModal

        async def _run() -> None:
            app = FriTapApp(pcap_to_tap_file="capt.pcap")
            async with app.run_test() as pilot:
                await pilot.pause()
                screen = _find_main_screen(app)
                # Backdrop is the (empty) flow view, not the live console.
                assert screen.query_one("#flow-list").display is True
                assert screen.query_one("#activity-log").display is False
                assert screen.query_one("#left-panel").display is False
                assert screen.query_one("#flow-list").row_count == 0
                # Step-1 modal is on top and has no TLS keylog input anymore.
                modal = app.screen
                assert isinstance(modal, PcapPathsModal)
                assert [i for i in modal.query(Input) if i.id == "keylog-input"] == []

        asyncio.run(_run())
