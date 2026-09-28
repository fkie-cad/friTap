#!/usr/bin/env python3

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
from unittest.mock import MagicMock, patch

import pytest

_SIGNAL_AVAILABLE = importlib.util.find_spec("friTap.offline.signal") is not None

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
from friTap.offline.mtproto.transport import DEFAULT_OBF_MAX_BLOCKS  # noqa: E402


def _find_main_screen(app):
    from friTap.tui.screens.main_screen import MainScreen
    for screen in app.screen_stack:
        if isinstance(screen, MainScreen):
            return screen
    raise AssertionError("MainScreen not found in screen stack")


def _run_with_screen(coro_factory, size=None, modal=None) -> dict:
    """Run ``coro_factory(app, screen, pilot)`` on a headless test app.

    With *modal*, it is pushed first and its dismiss value is returned as
    ``result["value"]``. *size* overrides the default 80x24 terminal.
    """
    import asyncio

    result: dict = {}

    async def _run() -> None:
        app = FriTapApp()
        async with app.run_test(size=size) as pilot:
            screen = _find_main_screen(app)
            if modal is not None:
                await app.push_screen(
                    modal, callback=lambda value: result.__setitem__("value", value)
                )
                await pilot.pause()
            await coro_factory(app, screen, pilot)
            await pilot.pause()

    asyncio.run(_run())
    return result


class TestBuildConvertArgsMulti:
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

    def test_missing_pcap_returns_none_and_alerts(self, tmp_path):
        from friTap.tui.modals.alert_modal import AlertModal
        captured: dict = {}

        async def body(app, screen, pilot):
            pushed: list = []
            screen.app.push_screen = MagicMock(
                side_effect=lambda s, callback=None: pushed.append(s)
            )
            captured["result"] = screen._build_convert_args_multi(
                pcap=str(tmp_path / "nope.pcap"),
                tls_keylog="", protocol_keylogs={}, tap="",
            )
            captured["pushed"] = pushed

        _run_with_screen(body)
        assert captured["result"] is None
        alerts = [s for s in captured["pushed"] if isinstance(s, AlertModal)]
        assert len(alerts) == 1
        assert alerts[0]._severity == "error"


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

        # Step 3: confirm -> convert (all keylogs left checked).
        _last_callback(pushed)(
            {"enabled_keylogs": ["tls", "signal", "mtproto"]}
        )

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
            PcapToTapConfirmModal,
            ProtocolKeylogModal,
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
        _last_callback(pushed)({"enabled_keylogs": []})

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
        _last_callback(pushed)({"enabled_keylogs": []})
        screen._launch_decrypt_worker.assert_not_called()


# ---------------------------------------------------------------------------
# 4. Modal return values
# ---------------------------------------------------------------------------

class TestPcapToTapModals:
    def test_paths_modal_accept_returns_dict(self):
        import asyncio

        from textual.widgets import Input

        from friTap.tui.modals.pcap_to_tap_modals import PcapPathsModal
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

        from textual.widgets import Input

        from friTap.tui.modals.pcap_to_tap_modals import PcapPathsModal
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

    def test_confirm_modal_convert_returns_enabled_keylogs(self):
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
        # Convert returns the still-checked keylogs (all by default) plus the
        # mid-stream resync search depth (default when left untouched).
        assert result["value"] == {
            "enabled_keylogs": ["tls", "signal"],
            "resync_search_depth": DEFAULT_OBF_MAX_BLOCKS,
        }

    def test_confirm_modal_convert_returns_user_entered_resync_depth(self):
        import asyncio

        from textual.widgets import Input

        from friTap.tui.modals.pcap_to_tap_modals import PcapToTapConfirmModal
        result: dict = {}

        async def _run() -> None:
            app = FriTapApp()
            async with app.run_test() as pilot:
                modal = PcapToTapConfirmModal(summary={
                    "pcap": "c.pcap", "tap": "c.tap",
                    "protocol_keylogs": {"tls": "t.log"},
                })

                def _cb(value):
                    result["value"] = value

                await app.push_screen(modal, callback=_cb)
                await pilot.pause()
                modal.query_one("#resync-depth-input", Input).value = "20000"
                await pilot.pause()
                modal.on_button_pressed(
                    types.SimpleNamespace(
                        button=types.SimpleNamespace(id="btn-convert")
                    )
                )
                await pilot.pause()

        asyncio.run(_run())
        assert result["value"]["resync_search_depth"] == 20000


# ---------------------------------------------------------------------------
# 5. Confirm summary rendering — TLS is just another keylog, no dead line
# ---------------------------------------------------------------------------

class TestConfirmSummaryText:
    def _summary_text(self, summary: dict) -> str:
        from friTap.tui.modals.pcap_to_tap_modals import PcapToTapConfirmModal
        return PcapToTapConfirmModal(summary=summary)._build_summary_text()

    def _selection_prompts(self, summary: dict) -> list:
        """``"label: path"`` for each keylog selection row (order preserved)."""
        from friTap.tui.modals.pcap_to_tap_modals import PcapToTapConfirmModal
        modal = PcapToTapConfirmModal(summary=summary)
        protocol_keylogs = summary.get("protocol_keylogs", {})
        return [str(sel.prompt) for sel in modal._keylog_selections(protocol_keylogs)]

    def test_no_dead_tls_keylog_line_and_tls_listed_as_keylog(self):
        summary = {
            "pcap": "c.pcap", "tap": "c.tap",
            "protocol_keylogs": {"tls": "t.log", "signal": "s.log"},
        }
        text = self._summary_text(summary)
        # The dedicated "TLS keylog:" line is gone, and the keylog rows moved
        # out of the summary text into the checkable selection list.
        assert "TLS keylog" not in text
        prompts = self._selection_prompts(summary)
        assert "tls: t.log" in prompts
        assert "signal: s.log" in prompts

    def test_keylogs_use_step_2_labels(self):
        summary = {
            "pcap": "c.pcap", "tap": "c.tap",
            "protocol_keylogs": {"schannel": "y.unpaired", "rc4": "x.log"},
        }
        prompts = self._selection_prompts(summary)
        assert "tls (schannel): y.unpaired" in prompts
        assert "custom encryption (rc4): x.log" in prompts

    def test_no_keylogs_shows_dash_line(self):
        text = self._summary_text({
            "pcap": "c.pcap", "tap": "c.tap", "protocol_keylogs": {},
        })
        assert "Keylogs:" in text and "—" in text

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


# ---------------------------------------------------------------------------
# 8. Step-2 picker rework: custom ciphers, Schannel routing, keylog suggestion
# ---------------------------------------------------------------------------

_CLIENT_RANDOM_LINE = f"CLIENT_RANDOM {'aa' * 32} {'bb' * 48}\n"


def _wizard_at_step_2(pcap: str = "cap.pcap"):
    """A wizard whose step-2 modal is the last pushed screen."""
    screen, pushed = _make_wizard_screen()
    wiz = PcapToTapWizard(screen)
    wiz.start(pcap)
    _last_callback(pushed)({"pcap": pcap, "tap": ""})
    return wiz, pushed


class TestStep2PickerWizard:
    def test_offline_protocol_names_delegate_to_picker(self):
        from friTap.offline.keylog_picker import picker_protocol_names

        screen, _ = _make_wizard_screen()
        names = PcapToTapWizard(screen)._offline_protocol_names()
        assert names == picker_protocol_names()

    def test_custom_pushes_cipher_modal_and_stores_per_cipher(self):
        from friTap.tui.modals.custom_cipher_modal import CustomCipherModal
        from friTap.tui.modals.pcap_to_tap_modals import ProtocolKeylogModal

        wiz, pushed = _wizard_at_step_2()
        _last_callback(pushed)({
            "action": "add", "protocol": "custom", "keylog": "rc4.log",
        })
        modal = _last_modal(pushed)
        assert isinstance(modal, CustomCipherModal)
        assert modal._required is True
        assert [e.name for e in modal._entries] == ["rc4"]

        _last_callback(pushed)(["rc4"])
        assert wiz._protocol_keylogs == {"rc4": "rc4.log"}
        assert isinstance(_last_modal(pushed), ProtocolKeylogModal)

    def test_custom_cipher_back_reshows_step_2_with_keylog(self):
        from friTap.tui.modals.pcap_to_tap_modals import ProtocolKeylogModal

        wiz, pushed = _wizard_at_step_2()
        _last_callback(pushed)({
            "action": "add", "protocol": "custom", "keylog": "rc4.log",
        })
        _last_callback(pushed)(None)  # Esc in the cipher modal

        modal = _last_modal(pushed)
        assert isinstance(modal, ProtocolKeylogModal)
        assert modal._initial_protocol == "custom"
        assert modal._initial_keylog == "rc4.log"
        assert wiz._protocol_keylogs == {}

    def test_tls_schannel_sidecar_stored_as_schannel(self, tmp_path):
        sidecar = str(tmp_path / "lsass.schannel.unpaired")
        wiz, pushed = _wizard_at_step_2()
        _last_callback(pushed)({
            "action": "add", "protocol": "tls", "keylog": sidecar,
        })
        assert wiz._protocol_keylogs == {"schannel": sidecar}

    def test_mtproto_keylog_added_under_tls_routes_to_mtproto(self, tmp_path):
        """An ``MTPROTO_AUTH_KEY`` keylog added while the default ``tls`` row is
        highlighted is content-sniffed and filed under ``mtproto`` — so the
        MTProto emitter runs instead of the keylog silently landing in the TLS
        slot and producing a 0-flow .tap."""
        keylog = tmp_path / "keys.log"
        # format: MTPROTO_AUTH_KEY <dc_id> <auth_key_id_hex16> <auth_key_hex512> <key_type>
        keylog.write_text(
            f"MTPROTO_AUTH_KEY 2 {'ab' * 8} {'cd' * 256} perm\n"
        )
        wiz, pushed = _wizard_at_step_2()
        _last_callback(pushed)({
            "action": "add", "protocol": "tls", "keylog": str(keylog),
        })
        assert wiz._protocol_keylogs == {"mtproto": str(keylog)}

    def test_manifest_sidecar_prepopulates_mtproto_keylog(self, tmp_path):
        """A ``<pcap>.fritap.json`` sidecar recording an mtproto keylog pre-fills
        the mtproto slot when the wizard starts (reusing ``load_manifest``), so a
        keylog captured alongside the pcap is not lost or mis-filed under TLS."""
        import json

        pcap = tmp_path / "cap.pcapng"
        pcap.write_bytes(b"\x00")
        mtproto_log = tmp_path / "keys.mtproto.log"
        mtproto_log.write_text(f"MTPROTO_AUTH_KEY 2 {'ab' * 8} {'cd' * 256} perm\n")
        (tmp_path / "cap.pcapng.fritap.json").write_text(
            json.dumps({"keylogs": {"mtproto": str(mtproto_log)}})
        )

        screen, _pushed = _make_wizard_screen()
        wiz = PcapToTapWizard(screen)
        wiz.start(str(pcap))
        assert wiz._protocol_keylogs.get("mtproto") == str(mtproto_log)

    def test_manifest_base_keylog_is_sniffed_not_forced_to_tls(self, tmp_path):
        """Regression: a manifest whose base ``keylog`` is actually a Telegram/
        MTProto keylog (e.g. an E2E-only ``keys_mtprot.log``) must be filed under
        the protocol it CONTAINS, never blindly under ``tls`` — otherwise the
        wizard shows a phantom TLS entry and a misleading "no TLS sessions"
        coverage warning (the friTap#… report)."""
        import json
        from friTap.protocols.mtproto_keylog_spec import format_e2e_line

        pcap = tmp_path / "cap.pcapng"
        pcap.write_bytes(b"\x00")
        e2e = tmp_path / "keys_mtprot.log"
        line = format_e2e_line(key_fingerprint="11" * 8, shared_key="22" * 256, chat_id=-1)
        e2e.write_text(f"# friTap MTProto keylog\n{line}\n")
        # Original-capture shape: base keylog + telegram_keylog both point at it.
        (tmp_path / "cap.pcapng.fritap.json").write_text(
            json.dumps({"keylog": str(e2e), "telegram_keylog": str(e2e)})
        )

        screen, _pushed = _make_wizard_screen()
        wiz = PcapToTapWizard(screen)
        wiz.start(str(pcap))
        # Sniffed to mtproto (base) + explicit telegram slot; NOT tls.
        assert wiz._protocol_keylogs.get("tls") is None
        assert wiz._protocol_keylogs.get("mtproto") == str(e2e)
        assert wiz._protocol_keylogs.get("telegram") == str(e2e)

    def test_suggested_keylog_passed_to_modal(self, tmp_path):
        pcap = tmp_path / "cap_20240131_120000.pcap"
        pcap.write_bytes(b"")
        keylog = tmp_path / "keys_20240131_120010.log"
        keylog.write_text(_CLIENT_RANDOM_LINE)

        _wiz, pushed = _wizard_at_step_2(str(pcap))
        modal = _last_modal(pushed)
        assert modal._suggested_keylog == str(keylog)
        assert modal._initial_protocol == "tls"

    def test_added_suggestion_is_not_suggested_again(self, tmp_path):
        pcap = tmp_path / "cap_20240131_120000.pcap"
        pcap.write_bytes(b"")
        keylog = tmp_path / "keys_20240131_120010.log"
        keylog.write_text(_CLIENT_RANDOM_LINE)

        _wiz, pushed = _wizard_at_step_2(str(pcap))
        with patch(
            "friTap.offline.keylog_suggest.suggest_keylog_with_evidence"
        ) as suggest:
            _last_callback(pushed)({
                "action": "add", "protocol": "tls", "keylog": str(keylog),
            })
        suggest.assert_not_called()  # no suggestion (nor dir scan) after an add
        modal = _last_modal(pushed)
        assert modal._suggested_keylog == ""
        assert modal._input_value == ""

    def test_restored_keylog_skips_suggestion(self):
        wiz, pushed = _wizard_at_step_2()
        with patch(
            "friTap.offline.keylog_suggest.suggest_keylog_with_evidence"
        ) as suggest:
            wiz._step_2_protocol_keylogs(
                initial_protocol="custom", initial_keylog="rc4.log",
            )
        suggest.assert_not_called()

    def test_suggestion_failure_means_no_suggestion(self):
        screen, pushed = _make_wizard_screen()
        wiz = PcapToTapWizard(screen)
        wiz.start("cap.pcap")
        with patch(
            "friTap.offline.keylog_suggest.suggest_keylog_with_evidence",
            side_effect=RuntimeError("boom"),
        ):
            _last_callback(pushed)({"pcap": "cap.pcap", "tap": ""})
        modal = _last_modal(pushed)
        assert modal._suggested_keylog == ""
        assert modal._initial_protocol is None

    def test_offline_protocol_names_fall_back_to_tls(self):
        screen, _ = _make_wizard_screen()
        with patch(
            "friTap.offline.keylog_picker.picker_protocol_names",
            side_effect=ImportError("broken plugin"),
        ):
            assert PcapToTapWizard(screen)._offline_protocol_names() == ["tls"]

    def test_replacing_keylog_warns(self):
        from friTap.tui.modals.alert_modal import AlertModal

        def _alerts():
            return [s for (s, _cb) in pushed if isinstance(s, AlertModal)]

        wiz, pushed = _wizard_at_step_2()
        _last_callback(pushed)({"action": "add", "protocol": "tls", "keylog": "a.log"})
        _last_callback(pushed)({"action": "add", "protocol": "tls", "keylog": "a.log"})
        assert _alerts() == []  # same path: no warning

        _last_callback(pushed)({"action": "add", "protocol": "tls", "keylog": "b.log"})
        assert wiz._protocol_keylogs == {"tls": "b.log"}
        # The replaced-keylog warning is now a dismissible modal, not a toast.
        alerts = _alerts()
        assert len(alerts) == 1
        assert "tls" in alerts[0]._message and "a.log -> b.log" in alerts[0]._message
        assert alerts[0]._severity == "warning"

    def test_replacing_custom_cipher_keylog_warns(self):
        from friTap.tui.modals.alert_modal import AlertModal
        wiz, pushed = _wizard_at_step_2()
        for keylog in ("r1.log", "r2.log"):
            _last_callback(pushed)({
                "action": "add", "protocol": "custom", "keylog": keylog,
            })
            _last_callback(pushed)(["rc4"])
        assert wiz._protocol_keylogs == {"rc4": "r2.log"}
        alerts = [s for (s, _cb) in pushed if isinstance(s, AlertModal)]
        assert len(alerts) == 1
        assert "custom encryption (rc4)" in alerts[0]._message
        assert "r1.log -> r2.log" in alerts[0]._message


# Tall enough that the whole modal (incl. the keylog input) is visible: at the
# default 80x24 the input is clipped and pilot clicks miss it.
_MODAL_SIZE = (100, 50)


class TestStep2PickerModal:
    def test_focus_done_after_an_add(self):
        from friTap.tui.modals.pcap_to_tap_modals import ProtocolKeylogModal
        seen: dict = {}

        async def interact(app, screen, pilot):
            seen["focused"] = app.focused.id
            seen["hints"] = str(modal.query_one("#proto-key-hints").render())
            await pilot.press("enter")

        modal = ProtocolKeylogModal(
            protocol_names=["tls", "custom"], added={"rc4": "/x/rc4.log"},
        )
        result = _run_with_screen(interact, size=_MODAL_SIZE, modal=modal)
        assert seen["focused"] == "btn-done"
        assert "Enter: Done" in seen["hints"]
        assert result["value"] == {"action": "done"}

    def test_restored_keylog_focuses_add_even_after_an_add(self):
        from friTap.tui.modals.pcap_to_tap_modals import ProtocolKeylogModal
        seen: dict = {}

        async def interact(app, screen, pilot):
            seen["focused"] = app.focused.id

        modal = ProtocolKeylogModal(
            protocol_names=["tls", "custom"], added={"tls": "/a/keys.log"},
            initial_protocol="custom", initial_keylog="/e/rc4.log",
        )
        _run_with_screen(interact, size=_MODAL_SIZE, modal=modal)
        assert seen["focused"] == "btn-add"

    def test_after_add_hints_and_shift_tab_reaches_add(self):
        from friTap.tui.modals.pcap_to_tap_modals import ProtocolKeylogModal
        seen: dict = {}

        async def interact(app, screen, pilot):
            seen["hints"] = str(modal.query_one("#proto-key-hints").render())
            seen["start"] = app.focused.id
            await pilot.press("shift+tab")
            seen["first"] = app.focused.id
            await pilot.press("shift+tab")
            seen["second"] = app.focused.id

        modal = ProtocolKeylogModal(
            protocol_names=["tls", "custom"], added={"tls": "/a/keys.log"},
        )
        _run_with_screen(interact, size=_MODAL_SIZE, modal=modal)
        assert "Shift+Tab: add another" in seen["hints"]
        assert "Tab: add another" not in seen["hints"].replace("Shift+Tab", "")
        assert seen["start"] == "btn-done"
        assert seen["first"] == "btn-add"
        assert seen["second"] == "proto-keylog-input"

    def test_added_summary_is_readable(self):
        from friTap.tui.modals.pcap_to_tap_modals import ProtocolKeylogModal
        modal = ProtocolKeylogModal(
            protocol_names=["tls"],
            added={"tls": "/a/keys.log", "rc4": "/b/x.log",
                   "schannel": "/c/y.unpaired"},
        )
        assert modal._added_summary() == (
            "tls: keys.log, custom encryption (rc4): x.log, "
            "tls (schannel): y.unpaired"
        )

    def test_suggestion_prefilled_add_focused_and_returned(self):
        from textual.widgets import Input

        from friTap.tui.modals.pcap_to_tap_modals import ProtocolKeylogModal
        seen: dict = {}

        async def interact(app, screen, pilot):
            seen["value"] = modal.query_one("#proto-keylog-input", Input).value
            seen["focused"] = app.focused.id
            seen["hint"] = str(modal.query_one("#keylog-suggestion-hint").render())
            await pilot.press("enter")

        modal = ProtocolKeylogModal(
            protocol_names=["tls", "custom"],
            suggested_keylog="/d/keys_1.log",
            initial_protocol="tls",
        )
        result = _run_with_screen(interact, size=_MODAL_SIZE, modal=modal)
        assert seen["value"] == "/d/keys_1.log"
        assert seen["focused"] == "btn-add"
        assert "keys_1.log" in seen["hint"]
        assert result["value"] == {
            "action": "add", "protocol": "tls", "keylog": "/d/keys_1.log",
        }

    def test_initial_protocol_highlighted(self):
        from textual.widgets import OptionList

        from friTap.tui.modals.pcap_to_tap_modals import ProtocolKeylogModal
        seen: dict = {}

        async def interact(app, screen, pilot):
            seen["idx"] = modal.query_one("#proto-list", OptionList).highlighted

        modal = ProtocolKeylogModal(
            protocol_names=["tls", "signal", "custom"],
            initial_protocol="custom", initial_keylog="/e/rc4.log",
        )
        _run_with_screen(interact, size=_MODAL_SIZE, modal=modal)
        assert seen["idx"] == 2

    def test_click_clears_untouched_suggestion(self):
        from textual.widgets import Input

        from friTap.tui.modals.pcap_to_tap_modals import ProtocolKeylogModal
        seen: dict = {}

        async def interact(app, screen, pilot):
            await pilot.click("#proto-keylog-input")
            await pilot.pause()
            field = modal.query_one("#proto-keylog-input", Input)
            seen["after_click"] = field.value
            await pilot.press(*"/f/other.log")
            await pilot.click("#proto-keylog-input")
            await pilot.pause()
            seen["after_second_click"] = field.value

        modal = ProtocolKeylogModal(
            protocol_names=["tls"], suggested_keylog="/d/keys_1.log",
        )
        _run_with_screen(interact, size=_MODAL_SIZE, modal=modal)
        assert seen["after_click"] == ""
        assert seen["after_second_click"] == "/f/other.log"

    def test_click_clearing_suggestion_hides_hint(self):
        from friTap.tui.modals.pcap_to_tap_modals import ProtocolKeylogModal
        seen: dict = {}

        async def interact(app, screen, pilot):
            hint = modal.query_one("#keylog-suggestion-hint")
            seen["before"] = hint.display
            await pilot.click("#proto-keylog-input")
            await pilot.pause()
            seen["after"] = hint.display

        modal = ProtocolKeylogModal(
            protocol_names=["tls"], suggested_keylog="/d/keys_1.log",
        )
        _run_with_screen(interact, size=_MODAL_SIZE, modal=modal)
        assert seen["before"] is True
        assert seen["after"] is False

    def test_typing_after_focus_replaces_suggestion(self):
        from friTap.tui.modals.pcap_to_tap_modals import ProtocolKeylogModal

        async def interact(app, screen, pilot):
            modal.query_one("#proto-keylog-input").focus()
            await pilot.pause()
            await pilot.press(*"/g/k.log", "enter")

        modal = ProtocolKeylogModal(
            protocol_names=["tls"], suggested_keylog="/d/keys_1.log",
        )
        result = _run_with_screen(interact, size=_MODAL_SIZE, modal=modal)
        assert result["value"]["keylog"] == "/g/k.log"


# ---------------------------------------------------------------------------
# 9. Keylog coverage: capture-TLS cache, suggestion evidence, confirm, re-pair
# ---------------------------------------------------------------------------

from friTap.offline.keylog_coverage import (  # noqa: E402
    NO_REPAIR_HITS_MESSAGE,
    CaptureTls,
    RepairResult,
    TlsHandshake,
)

_CR_IN_CAPTURE = "11" * 32
_CR_ELSEWHERE = "22" * 32
_CAPTURE = CaptureTls(handshakes=(
    TlsHandshake("0", _CR_IN_CAPTURE, "example.com", "TLS 1.3"),
))


def _tls13_keylog(path, client_random: str) -> str:
    path.write_text(f"CLIENT_TRAFFIC_SECRET_0 {client_random} {'cc' * 32}\r\n")
    return str(path)


def _make_worker_screen():
    """Stub screen whose app runs thread workers / UI callbacks synchronously."""
    screen, pushed = _make_wizard_screen()
    screen.app.run_worker = MagicMock(side_effect=lambda fn, **_kw: fn())
    screen.app.call_from_thread = lambda fn, *args: fn(*args)
    screen.app.notify = MagicMock()
    return screen, pushed


def _patch_capture_read(capture=_CAPTURE, *, side_effect=None, dsb=False):
    """Patch the tshark-backed pieces the capture-TLS worker uses."""
    from contextlib import ExitStack
    stack = ExitStack()
    stack.enter_context(patch("friTap.offline.tshark.find_tshark", return_value="tshark"))
    stack.enter_context(patch("friTap.offline.tshark.capture_has_dsb", return_value=dsb))
    stack.enter_context(patch(
        "friTap.offline.keylog_coverage.read_capture_handshakes",
        return_value=capture, side_effect=side_effect,
    ))
    return stack


def _wizard_with_capture(capture=_CAPTURE, pcap: str = "cap.pcapng"):
    """Started wizard (step 1 shown) whose capture cache holds *capture*."""
    screen, pushed = _make_worker_screen()
    wiz = PcapToTapWizard(screen)
    with _patch_capture_read(capture):
        wiz.start(pcap)
    return wiz, screen, pushed


class TestCaptureTlsCache:
    def test_start_reads_capture_in_a_thread_worker(self):
        wiz, screen, _ = _wizard_with_capture()
        _args, kwargs = screen.app.run_worker.call_args
        assert kwargs["thread"] is True
        assert kwargs["group"] == "pcap-capture-tls"
        assert wiz._capture_tls is _CAPTURE
        assert wiz._capture_tls_ready() is True
        assert wiz._capture_client_randoms() == {_CR_IN_CAPTURE}

    def test_read_failure_caches_none(self):
        screen, _ = _make_worker_screen()
        wiz = PcapToTapWizard(screen)
        with _patch_capture_read(side_effect=RuntimeError("tshark died")):
            wiz.start("cap.pcapng")
        assert wiz._capture_tls is None
        assert wiz._capture_tls_ready() is True
        assert wiz._capture_client_randoms() is None

    def test_changed_pcap_rereads_and_ignores_stale_result(self):
        wiz, screen, pushed = _wizard_with_capture()
        other = CaptureTls()
        with _patch_capture_read(other):
            _last_callback(pushed)({"pcap": "other.pcapng", "tap": ""})
        assert screen.app.run_worker.call_count == 2
        assert wiz._capture_tls is other
        wiz._on_capture_tls_ready("cap.pcapng", _CAPTURE, False)  # stale
        assert wiz._capture_tls is other

    def test_same_pcap_is_not_reread(self):
        wiz, screen, pushed = _wizard_with_capture()
        _last_callback(pushed)({"pcap": "cap.pcapng", "tap": ""})
        assert screen.app.run_worker.call_count == 1

    def test_app_without_workers_degrades_to_no_cache(self):
        screen, _ = _make_wizard_screen()  # its app has no run_worker
        wiz = PcapToTapWizard(screen)
        wiz.start("cap.pcapng")
        assert wiz._capture_tls_pending is False
        assert wiz._capture_client_randoms() is None


class TestSuggestionEvidence:
    def _hint(self, evidence):
        from friTap.tui.modals.pcap_to_tap_modals import ProtocolKeylogModal
        return ProtocolKeylogModal(
            protocol_names=["tls"], suggested_keylog="/d/keys_power.log",
            suggestion_evidence=evidence,
        )._suggestion_hint()

    def test_hint_reports_matching_sessions(self):
        assert "Suggested: keys_power.log — matches 2/2 TLS sessions" in self._hint((2, 2))

    def test_zero_coverage_hint_is_amber(self):
        from friTap.tui.themes import c
        hint = self._hint((0, 4))
        assert "matches 0/4 TLS sessions" in hint
        assert c("warning-amber") in hint

    def test_unknown_coverage_keeps_timestamp_hint(self):
        assert "matches pcap timestamp" in self._hint(None)

    def test_wizard_passes_capture_randoms_and_evidence(self):
        from friTap.offline.keylog_suggest import Suggestion
        wiz, _screen, pushed = _wizard_with_capture()
        with patch(
            "friTap.offline.keylog_suggest.suggest_keylog_with_evidence",
            return_value=Suggestion("/d/keys_power.log", 1, 1),
        ) as suggest:
            _last_callback(pushed)({"pcap": "cap.pcapng", "tap": ""})
        assert suggest.call_args.kwargs["capture_crs"] == {_CR_IN_CAPTURE}
        modal = _last_modal(pushed)
        assert modal._suggested_keylog == "/d/keys_power.log"
        assert modal._suggestion_evidence == (1, 1)

    def test_no_cache_means_timestamp_only_suggestion(self):
        from friTap.offline.keylog_suggest import Suggestion
        screen, pushed = _make_wizard_screen()
        wiz = PcapToTapWizard(screen)
        wiz.start("cap.pcapng")
        with patch(
            "friTap.offline.keylog_suggest.suggest_keylog_with_evidence",
            return_value=Suggestion("/d/keys.log"),
        ) as suggest:
            _last_callback(pushed)({"pcap": "cap.pcapng", "tap": ""})
        assert suggest.call_args.kwargs["capture_crs"] is None
        assert _last_modal(pushed)._suggestion_evidence is None

    def test_non_tls_suggestion_drops_tls_session_evidence(self, tmp_path):
        """The '(covered, total)' evidence is TLS-session coverage; for an MTProto
        suggestion it is meaningless, so it must be dropped (the modal then shows
        the neutral timestamp hint instead of 'matches 0/4 TLS sessions')."""
        from friTap.offline.keylog_suggest import Suggestion
        from friTap.protocols.mtproto_keylog_spec import format_line as mtproto_format_line
        mk = tmp_path / "keys.mtproto.log"
        mk.write_text(
            mtproto_format_line(dc_id=2, auth_key_id="ab" * 8, auth_key="cd" * 256) + "\n"
        )
        wiz, _screen, pushed = _wizard_with_capture()
        with patch(
            "friTap.offline.keylog_suggest.suggest_keylog_with_evidence",
            # Evidence present, but the file sniffs as mtproto so it must be dropped.
            return_value=Suggestion(str(mk), 0, 4),
        ):
            _last_callback(pushed)({"pcap": "cap.pcapng", "tap": ""})
        modal = _last_modal(pushed)
        assert modal._suggested_keylog == str(mk)
        assert modal._suggestion_evidence is None


class TestConfirmCoverage:
    def _confirm(self, wiz, pushed, keylogs):
        wiz._protocol_keylogs = dict(keylogs)
        wiz._step_3_confirm()
        return _last_modal(pushed)

    def test_uncovered_keylog_warns_and_offers_repair(self, tmp_path):
        wiz, _screen, pushed = _wizard_with_capture()
        keylog = _tls13_keylog(tmp_path / "k.log", _CR_ELSEWHERE)
        modal = self._confirm(wiz, pushed, {"tls": keylog})
        assert modal._summary["coverage_severity"] == "warning"
        assert "matches 0 of 1 TLS handshake" in modal._summary["coverage_lines"][0]
        assert modal._summary["can_repair"] is True
        assert "example.com" in modal._build_summary_text()

    def test_full_coverage_is_ok_without_repair(self, tmp_path):
        wiz, _screen, pushed = _wizard_with_capture()
        keylog = _tls13_keylog(tmp_path / "k.log", _CR_IN_CAPTURE)
        modal = self._confirm(wiz, pushed, {"tls": keylog})
        assert modal._summary["coverage_severity"] == "ok"
        assert "covers 1/1" in modal._build_summary_text()
        assert modal._summary["can_repair"] is False

    def test_skipped_for_schannel_dsb_and_no_tls(self, tmp_path):
        keylog = _tls13_keylog(tmp_path / "k.log", _CR_ELSEWHERE)
        wiz, _screen, pushed = _wizard_with_capture()
        for keylogs in ({"schannel": keylog}, {"mtproto": keylog}):
            assert "coverage_lines" not in self._confirm(wiz, pushed, keylogs)._summary
        wiz._capture_dsb = True
        assert "coverage_lines" not in self._confirm(wiz, pushed, {"tls": keylog})._summary

    def test_pending_then_updated_in_place(self, tmp_path):
        screen, pushed = _make_wizard_screen()
        screen.app.run_worker = MagicMock()  # never runs: the read stays pending
        wiz = PcapToTapWizard(screen)
        wiz.start("cap.pcapng")
        keylog = _tls13_keylog(tmp_path / "k.log", _CR_ELSEWHERE)
        modal = self._confirm(wiz, pushed, {"tls": keylog})
        assert modal._summary.get("coverage_pending") is True
        assert "Checking keylog coverage" in modal._build_summary_text()

        wiz._on_capture_tls_ready("cap.pcapng", _CAPTURE, False)
        assert "coverage_pending" not in modal._summary
        assert modal._summary["coverage_severity"] == "warning"
        assert "Checking keylog coverage" not in modal._build_summary_text()

    def test_failed_read_clears_pending_note(self, tmp_path):
        screen, pushed = _make_wizard_screen()
        screen.app.run_worker = MagicMock()
        wiz = PcapToTapWizard(screen)
        wiz.start("cap.pcapng")
        modal = self._confirm(wiz, pushed, {"tls": _tls13_keylog(tmp_path / "k.log", _CR_ELSEWHERE)})
        wiz._on_capture_tls_ready("cap.pcapng", None, False)
        assert modal._summary["coverage_lines"] == []
        assert "Checking keylog coverage" not in modal._build_summary_text()

    def test_closed_modal_is_not_updated(self, tmp_path):
        wiz, _screen, pushed = _wizard_with_capture()
        self._confirm(wiz, pushed, {"tls": _tls13_keylog(tmp_path / "k.log", _CR_ELSEWHERE)})
        _last_callback(pushed)(None)  # Back
        assert wiz._confirm_modal is None


class TestConfirmModalCoverageUi:
    def _summary(self, **extra):
        summary = {"pcap": "c.pcapng", "tap": "c.tap", "protocol_keylogs": {"tls": "k.log"}}
        summary.update(extra)
        return summary

    def test_set_coverage_updates_text_and_repair_button(self):
        from textual.widgets import Button, Static

        from friTap.tui.modals.pcap_to_tap_modals import PcapToTapConfirmModal
        seen: dict = {}

        async def interact(app, screen, pilot):
            button = modal.query_one("#btn-repair", Button)
            seen["hidden_before"] = not button.display
            modal.set_coverage("warning", ["TLS keylog matches 0 of 4 TLS handshakes."], True)
            await pilot.pause()
            seen["text"] = str(modal.query_one("#summary-block", Static).render())
            seen["shown_after"] = button.display
            await pilot.click("#btn-repair")
            await pilot.pause()

        on_repair = MagicMock()
        modal = PcapToTapConfirmModal(
            summary=self._summary(coverage_pending=True), on_repair=on_repair,
        )
        _run_with_screen(interact, size=_MODAL_SIZE, modal=modal)
        assert seen["hidden_before"] is True
        assert "matches 0 of 4" in seen["text"]
        assert "Checking keylog coverage" not in seen["text"]
        assert seen["shown_after"] is True
        on_repair.assert_called_once()

    def test_repair_status_disables_button_but_convert_still_works(self):
        from textual.widgets import Button

        from friTap.tui.modals.pcap_to_tap_modals import PcapToTapConfirmModal
        seen: dict = {}

        async def interact(app, screen, pilot):
            modal.set_repair_status("Re-pairing keys by trial decryption…", busy=True)
            await pilot.pause()
            seen["disabled"] = modal.query_one("#btn-repair", Button).disabled
            await pilot.click("#btn-convert")
            await pilot.pause()

        modal = PcapToTapConfirmModal(
            summary=self._summary(can_repair=True), on_repair=MagicMock(),
        )
        result = _run_with_screen(interact, size=_MODAL_SIZE, modal=modal)
        assert seen["disabled"] is True
        assert "Re-pairing keys" in modal._build_summary_text()
        # Convert now returns the still-checked keylogs rather than a bare True.
        assert result["value"] == {
            "enabled_keylogs": ["tls"],
            "resync_search_depth": DEFAULT_OBF_MAX_BLOCKS,
        }

    def test_no_repair_callback_never_shows_button(self):
        from friTap.tui.modals.pcap_to_tap_modals import PcapToTapConfirmModal
        modal = PcapToTapConfirmModal(summary=self._summary(can_repair=True))
        assert modal._repair_visible() is False


class TestKeylogRepair:
    def _at_confirm(self, tmp_path):
        wiz, screen, pushed = _wizard_with_capture()
        keylog = _tls13_keylog(tmp_path / "k.log", _CR_ELSEWHERE)
        wiz._protocol_keylogs = {"tls": keylog}
        wiz._step_3_confirm()
        return wiz, screen, _last_modal(pushed), keylog

    def test_success_swaps_in_repaired_keylog_and_rechecks(self, tmp_path):
        wiz, screen, modal, _keylog = self._at_confirm(tmp_path)
        repaired = _tls13_keylog(tmp_path / "k.repaired.keylog", _CR_IN_CAPTURE)
        result = RepairResult(repaired, 1, 1, "Relabeled 1 session by trial decryption; wrote k.relabeled.keylog.")
        with patch("friTap.offline.tshark.find_tshark", return_value="tshark"), patch(
            "friTap.offline.keylog_coverage.relabel_keylog", return_value=result,
        ) as repair:
            modal.on_button_pressed(types.SimpleNamespace(button=types.SimpleNamespace(id="btn-repair")))
        assert repair.call_args.kwargs["capture"] is _CAPTURE
        assert wiz._protocol_keylogs["tls"] == repaired
        assert modal._summary["protocol_keylogs"]["tls"] == repaired
        assert modal._summary["coverage_severity"] == "ok"
        assert modal._summary["repair_severity"] == "ok"
        screen.app.notify.assert_called_once()

    def test_no_hits_reports_message_and_keeps_keylog(self, tmp_path):
        wiz, _screen, modal, keylog = self._at_confirm(tmp_path)
        result = RepairResult(None, 0, 1, NO_REPAIR_HITS_MESSAGE)
        with patch("friTap.offline.tshark.find_tshark", return_value="tshark"), patch(
            "friTap.offline.keylog_coverage.relabel_keylog", return_value=result,
        ):
            wiz._start_repair()
        assert wiz._protocol_keylogs["tls"] == keylog
        assert modal._summary["repair_message"] == NO_REPAIR_HITS_MESSAGE
        assert modal._summary["repair_severity"] == "warning"

    def test_repair_crash_is_reported_not_raised(self, tmp_path):
        wiz, _screen, modal, _keylog = self._at_confirm(tmp_path)
        with patch("friTap.offline.tshark.find_tshark", side_effect=RuntimeError("no tshark")):
            wiz._start_repair()
        assert "Re-pairing failed" in modal._summary["repair_message"]

    def test_progress_is_relayed_to_the_modal(self, tmp_path):
        wiz, _screen, modal, _keylog = self._at_confirm(tmp_path)
        wiz._on_repair_progress("Trying 1 secret against the capture…")
        assert modal._summary["repair_message"].startswith("Trying 1 secret")
        assert modal._summary["repair_severity"] == "busy"


# ---------------------------------------------------------------------------
# 8. Same-protocol merge + deselect + exclusion persistence (Part C)
# ---------------------------------------------------------------------------

class TestSameProtocolMerge:
    def _mtproto_keylog(self, path, *, e2e=True, auth=False, obf=False, comment=""):
        from friTap.protocols.mtproto_keylog_spec import (
            format_e2e_line,
            format_line,
            format_obf_line,
        )
        lines = []
        if comment:
            lines.append(comment)
        if e2e:
            lines.append(
                format_e2e_line(key_fingerprint="11" * 8, shared_key="22" * 256, chat_id=-1)
            )
        if auth:
            lines.append(format_line(dc_id=2, auth_key_id="ab" * 8, auth_key="cd" * 256, key_type="perm"))
        if obf:
            lines.append(
                format_obf_line(
                    key_out="aa" * 32, iv_out="bb" * 16,
                    key_in="cc" * 32, iv_in="dd" * 16,
                )
            )
        path.write_text("\n".join(lines) + "\n")
        return str(path)

    def test_same_protocol_store_merges_not_overwrites(self, tmp_path):
        """Storing a second keylog under an already-filled protocol MERGES the
        two (union of key lines) instead of silently overwriting the first."""
        screen, pushed = _make_wizard_screen()
        wiz = PcapToTapWizard(screen)

        e2e_only = self._mtproto_keylog(
            tmp_path / "telegram.keys.log", e2e=True, comment="# e2e"
        )
        full = self._mtproto_keylog(
            tmp_path / "Telegram_memscan.mtproto.keylog",
            e2e=True, auth=True, obf=True, comment="# memscan",
        )

        wiz._store_protocol_keylog("mtproto", e2e_only)
        assert wiz._protocol_keylogs["mtproto"] == e2e_only

        wiz._store_protocol_keylog("mtproto", full)
        merged_path = wiz._protocol_keylogs["mtproto"]
        # The dict now points at a NEW combined file, not either input.
        assert merged_path not in (e2e_only, full)
        with open(merged_path, "r", encoding="utf-8") as fh:
            content = fh.read()
        assert "MTPROTO_AUTH_KEY" in content
        assert "MTPROTO_E2E_KEY" in content
        assert "MTPROTO_OBF_KEY" in content
        # A merged note (not the old "Keylog Replaced" alert) is surfaced.
        from friTap.tui.modals.alert_modal import AlertModal
        alerts = [s for (s, _cb) in pushed if isinstance(s, AlertModal)]
        assert len(alerts) == 1
        assert alerts[0]._title == "Keylogs merged"
        assert alerts[0]._severity == "info"

    def test_deselect_drops_keylog_from_convert_args(self):
        """Unchecking a keylog in the confirm modal drops it from the kwargs the
        conversion worker receives and records it as excluded."""
        screen, pushed = _make_wizard_screen()
        wiz = PcapToTapWizard(screen)
        wiz.start("cap.pcap")
        _last_callback(pushed)({"pcap": "cap.pcap", "tap": "out.tap"})
        _last_callback(pushed)({"action": "add", "protocol": "tls", "keylog": "tls.log"})
        _last_callback(pushed)({"action": "add", "protocol": "signal", "keylog": "sig.log"})
        _last_callback(pushed)({"action": "done"})
        # Confirm with signal unchecked (only tls enabled).
        _last_callback(pushed)({"enabled_keylogs": ["tls"]})

        _a, kwargs = screen._build_convert_args_multi.call_args
        assert kwargs["tls_keylog"] == "tls.log"
        assert kwargs["protocol_keylogs"] == {}  # signal was dropped
        assert "signal" in wiz._excluded_keylogs

    def test_exclusion_persists_across_reprepopulate(self, tmp_path):
        """A de-selected manifest keylog is not silently re-added when backing
        out to step 1 re-runs the manifest pre-fill (its ``setdefault``)."""
        import json

        pcap = tmp_path / "cap.pcapng"
        pcap.write_bytes(b"\x00")
        mtproto_log = self._mtproto_keylog(tmp_path / "keys.mtproto.log", e2e=True)
        (tmp_path / "cap.pcapng.fritap.json").write_text(
            json.dumps({"keylogs": {"mtproto": mtproto_log}})
        )

        screen, _pushed = _make_wizard_screen()
        wiz = PcapToTapWizard(screen)
        wiz.start(str(pcap))
        assert wiz._protocol_keylogs.get("mtproto") == mtproto_log

        # User de-selects mtproto at the confirm step.
        wiz._apply_keylog_selection([])
        assert "mtproto" not in wiz._protocol_keylogs
        assert "mtproto" in wiz._excluded_keylogs

        # Backing out to step 1 re-runs the manifest pre-fill; the exclusion
        # must stick (the keylog is NOT re-added).
        wiz._prepopulate_from_manifest()
        assert "mtproto" not in wiz._protocol_keylogs

    def test_readding_excluded_protocol_clears_exclusion(self, tmp_path):
        """Explicitly adding a keylog again for an excluded protocol un-excludes
        it (a deliberate re-add wins over the prior deselection)."""
        screen, _pushed = _make_wizard_screen()
        wiz = PcapToTapWizard(screen)
        wiz._excluded_keylogs.add("signal")
        wiz._store_protocol_keylog("signal", "sig.log")
        assert wiz._protocol_keylogs.get("signal") == "sig.log"
        assert "signal" not in wiz._excluded_keylogs
