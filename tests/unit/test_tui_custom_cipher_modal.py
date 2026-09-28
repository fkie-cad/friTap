"""Tests for the TUI "Custom Encryption" flow: the option-B cipher selection
helper, the CustomCipherModal, the protocol picker entries, the shared
select_protocols() chain, and the capture-controller wiring."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest

from friTap.protocols.registry import custom_cipher_names
from friTap.tui.modals.custom_cipher_modal import (
    CipherSelection,
    available_custom_ciphers,
)

# ---------------------------------------------------------------------------
# 1. Pure option-B toggle helper (no Textual)
# ---------------------------------------------------------------------------

class TestCipherSelection:
    def test_default_is_all_ciphers(self):
        sel = CipherSelection(["aes", "rc4"])
        assert sel.all_selected is True
        assert sel.result() == ["aes", "rc4"]

    def test_all_off_start_is_empty_and_toggles(self):
        """The optional modal's starting state: nothing selected."""
        sel = CipherSelection(["aes", "rc4"], all_selected=False)
        assert sel.result() == []
        sel.set_cipher("rc4", True)
        assert sel.all_selected is False
        assert sel.result() == ["rc4"]
        sel.set_all(True)
        assert sel.checked == set()
        assert sel.result() == ["aes", "rc4"]

    def test_checking_cipher_turns_all_off(self):
        sel = CipherSelection(["aes", "rc4"])
        sel.set_cipher("rc4", True)
        assert sel.all_selected is False
        assert sel.result() == ["rc4"]

    def test_rechecking_all_clears_rows(self):
        sel = CipherSelection(["aes", "rc4"])
        sel.set_cipher("rc4", True)
        sel.set_cipher("aes", True)
        sel.set_all(True)
        assert sel.checked == set()
        assert sel.result() == ["aes", "rc4"]

    def test_nothing_checked_is_empty(self):
        sel = CipherSelection(["aes", "rc4"])
        sel.set_all(False)
        assert sel.result() == []
        sel.set_cipher("rc4", True)
        sel.set_cipher("rc4", False)
        assert sel.result() == []

    def test_result_keeps_registry_order(self):
        sel = CipherSelection(["aes", "chacha", "rc4"])
        sel.set_cipher("rc4", True)
        sel.set_cipher("aes", True)
        assert sel.result() == ["aes", "rc4"]


def test_available_custom_ciphers_matches_registry():
    entries = available_custom_ciphers()
    assert [e.name for e in entries] == custom_cipher_names()
    rc4 = next(e for e in entries if e.name == "rc4")
    assert rc4.display_name == "RC4"
    assert rc4.description


def test_combine_protocols():
    from friTap.tui.protocol_selection import combine_protocols, format_protocols

    assert combine_protocols("tls", ["rc4"]) == ["tls", "rc4"]
    assert combine_protocols("tls", []) == ["tls"]
    assert combine_protocols("custom", ["rc4"]) == ["rc4"]
    assert combine_protocols("rc4", ["rc4"]) == ["rc4"]
    assert format_protocols(["tls", "rc4"]) == "TLS+RC4"


def test_apply_protocol_selection_sets_primary_and_set():
    from friTap.tui.protocol_selection import apply_protocol_selection

    state = SimpleNamespace(protocol="tls", protocols=["tls"])
    apply_protocol_selection(state, ["ssh", "rc4"])
    assert state.protocol == "ssh"
    assert state.protocols == ["ssh", "rc4"]


def test_menu_label():
    from friTap.tui.modals.custom_cipher_modal import menu_label

    assert menu_label("RC4", "stream cipher") == "RC4 — stream cipher"
    assert menu_label("RC4", "") == "RC4"
    assert menu_label("Foo", "", "Foo (plugin)") == "Foo (plugin)"


# ---------------------------------------------------------------------------
# 2. Capture-controller wiring (no Textual app needed)
# ---------------------------------------------------------------------------

def test_selected_protocols_prefers_state_list():
    from friTap.tui.capture_controller import _selected_protocols

    assert _selected_protocols(SimpleNamespace(protocol="tls", protocols=["tls", "rc4"])) == ["tls", "rc4"]
    # Out of sync (only the primary was set) -> fall back to the primary.
    assert _selected_protocols(SimpleNamespace(protocol="ssh", protocols=["tls"])) == ["ssh"]
    assert _selected_protocols(SimpleNamespace(protocol="auto")) == ["auto"]


def test_custom_cipher_selection_does_not_force_modern_agent():
    """The TUI runs the legacy agent by default, like the CLI: no protocol
    selection (e.g. RC4 / custom ciphers) switches the SSL_Logger to modern."""
    import inspect

    from friTap.tui import capture_controller

    assert not hasattr(capture_controller, "_selection_requires_modern_agent")
    assert "use_modern = True" not in inspect.getsource(capture_controller)


# ---------------------------------------------------------------------------
# 3. Textual pilot tests
# ---------------------------------------------------------------------------

pytest.importorskip("textual")

from friTap.tui.app import FriTapApp  # noqa: E402
from friTap.tui.modals.custom_cipher_modal import CustomCipherModal  # noqa: E402
from friTap.tui.modals.protocol_modal import ProtocolSelectModal  # noqa: E402
from friTap.tui.protocol_selection import select_protocols  # noqa: E402


def _run(body, size=(80, 24)):
    async def _main() -> None:
        app = FriTapApp()
        async with app.run_test(size=size) as pilot:
            await body(app, pilot)

    asyncio.run(_main())


def test_cipher_modal_required_default_enter_is_all_ciphers():
    from textual.widgets import Switch
    result = {}

    async def body(app, pilot):
        modal = CustomCipherModal(required=True)
        await app.push_screen(modal, callback=lambda v: result.setdefault("v", v))
        await pilot.pause()
        assert modal.query_one("#switch-all", Switch).value is True
        assert modal.query_one("#row-rc4").has_class("-dimmed")
        await pilot.press("enter")
        await pilot.pause()

    _run(body)
    assert result["v"] == custom_cipher_names()


def test_cipher_modal_optional_default_enter_is_skip():
    """Optional follow-up: All starts off, focus is on it, Enter dismisses []."""
    from textual.widgets import Switch
    result = {}

    async def body(app, pilot):
        modal = CustomCipherModal(required=False)
        await app.push_screen(modal, callback=lambda v: result.setdefault("v", v))
        await pilot.pause()
        all_switch = modal.query_one("#switch-all", Switch)
        assert all_switch.value is False
        assert modal.focused is all_switch
        assert not modal.query_one("#row-rc4").has_class("-dimmed")
        await pilot.press("enter")
        await pilot.pause()

    _run(body)
    assert result["v"] == []


def test_cipher_modal_optional_space_on_all_then_enter_is_all_ciphers():
    from textual.widgets import Switch
    result = {}

    async def body(app, pilot):
        modal = CustomCipherModal(required=False)
        await app.push_screen(modal, callback=lambda v: result.setdefault("v", v))
        await pilot.pause()
        await pilot.press("space")
        await pilot.pause()
        assert modal.query_one("#switch-all", Switch).value is True
        assert modal.query_one("#row-rc4").has_class("-dimmed")
        await pilot.press("enter")
        await pilot.pause()

    _run(body)
    assert result["v"] == custom_cipher_names()


def test_cipher_modal_checking_row_turns_all_off():
    from textual.widgets import Switch
    result = {}

    async def body(app, pilot):
        modal = CustomCipherModal(required=False)
        await app.push_screen(modal, callback=lambda v: result.setdefault("v", v))
        await pilot.pause()
        assert modal.query_one("#switch-all", Switch).value is False
        assert not modal.query_one("#row-rc4").has_class("-dimmed")
        modal.query_one("#switch-cipher-rc4", Switch).value = True
        await pilot.pause()
        assert modal.query_one("#switch-all", Switch).value is False
        assert not modal.query_one("#row-rc4").has_class("-dimmed")
        # Re-checking All clears the row again.
        modal.query_one("#switch-all", Switch).value = True
        await pilot.pause()
        assert modal.query_one("#switch-cipher-rc4", Switch).value is False
        assert modal.query_one("#row-rc4").has_class("-dimmed")
        modal.query_one("#switch-cipher-rc4", Switch).value = True
        await pilot.pause()
        modal._confirm()
        await pilot.pause()

    _run(body)
    assert result["v"] == ["rc4"]


def test_cipher_modal_optional_skip_and_escape():
    results = []

    async def body(app, pilot):
        modal = CustomCipherModal(required=False)
        await app.push_screen(modal, callback=results.append)
        await pilot.pause()
        await pilot.click("#btn-skip")
        await pilot.pause()
        modal2 = CustomCipherModal(required=False)
        await app.push_screen(modal2, callback=results.append)
        await pilot.pause()
        await pilot.press("escape")
        await pilot.pause()

    _run(body)
    assert results == [[], None]


def test_cipher_modal_required_guard():
    from textual.widgets import Button, Switch
    results = []

    async def body(app, pilot):
        modal = CustomCipherModal(required=True)
        await app.push_screen(modal, callback=results.append)
        await pilot.pause()
        assert not modal.query("#btn-skip")  # no Skip in required mode
        assert modal.query_one("#btn-confirm", Button)
        modal.query_one("#switch-all", Switch).value = False
        await pilot.pause()
        modal._confirm()
        await pilot.pause()
        # Nothing selected in required mode: the cipher modal is NOT dismissed;
        # a dismissible AlertModal is shown on top (not a transient toast).
        from friTap.tui.modals.alert_modal import AlertModal
        assert isinstance(app.screen, AlertModal)
        assert modal in app.screen_stack  # underlying cipher modal still open
        assert results == []

    _run(body)


def test_protocol_modal_lists_custom_encryption_and_hides_rc4():
    async def body(app, pilot):
        modal = ProtocolSelectModal()  # registry=None -> default registry
        await app.push_screen(modal)
        await pilot.pause()
        entries = dict(modal._protocol_entries)
        names = [name for name, _ in modal._protocol_entries]
        assert "custom" in entries
        assert entries["custom"] == "Custom Encryption — custom cipher key extraction"
        assert "(RC4)" not in entries["custom"]
        assert "rc4" not in names
        assert names[-1] == "auto"
        assert names.index("custom") == len(names) - 2
        from friTap.protocols.registry import available_protocol_names
        if "signal" in available_protocol_names():
            assert "signal" in names
            assert " — " in entries["signal"]

    _run(body)


def _drive_selection(first_choice, cipher_action):
    """Run select_protocols, answer the protocol modal with *first_choice*, and
    let *cipher_action(modal)* answer the cipher modal (if one opens)."""
    done = []
    opened = []

    async def body(app, pilot):
        select_protocols(app, on_done=lambda p, ps: done.append((p, ps)))
        await pilot.pause()
        assert isinstance(app.screen, ProtocolSelectModal)
        app.screen.dismiss(first_choice)
        await pilot.pause()
        if isinstance(app.screen, CustomCipherModal):
            opened.append(app.screen._required)
            cipher_action(app.screen)
            await pilot.pause()

    _run(body)
    return done, opened


def _select_all_and_confirm(modal):
    modal._selection.set_all(True)
    modal._confirm()


def test_select_protocols_tls_default_confirm_is_tls_only():
    done, opened = _drive_selection("tls", lambda m: m._confirm())
    assert opened == [False]
    assert done == [("tls", ["tls"])]


def test_select_protocols_tls_with_all_ciphers():
    done, opened = _drive_selection("tls", _select_all_and_confirm)
    assert opened == [False]
    assert done == [("tls", ["tls"] + custom_cipher_names())]


def test_select_protocols_tls_skip():
    done, opened = _drive_selection("tls", lambda m: m.dismiss([]))
    assert opened == [False]
    assert done == [("tls", ["tls"])]


def test_select_protocols_custom_is_required():
    done, opened = _drive_selection("custom", lambda m: m._confirm())
    assert opened == [True]
    ciphers = custom_cipher_names()
    assert done == [(ciphers[0], ciphers)]


def test_select_protocols_auto_skips_cipher_modal():
    done, opened = _drive_selection("auto", lambda m: None)
    assert opened == []
    assert done == [("auto", ["auto"])]


def test_select_protocols_escape_in_cipher_modal_reopens_protocol_modal():
    reopened = []

    async def body(app, pilot):
        select_protocols(app, on_done=lambda p, ps: None)
        await pilot.pause()
        app.screen.dismiss("ssh")
        await pilot.pause()
        assert isinstance(app.screen, CustomCipherModal)
        app.screen.dismiss(None)
        await pilot.pause()
        reopened.append(isinstance(app.screen, ProtocolSelectModal))

    _run(body)
    assert reopened == [True]


def test_select_protocols_escape_in_protocol_modal_calls_on_back():
    back = []

    async def body(app, pilot):
        select_protocols(app, on_done=lambda p, ps: None, on_back=lambda: back.append(True))
        await pilot.pause()
        await pilot.press("escape")
        await pilot.pause()

    _run(body)
    assert back == [True]


def test_wizard_step_5b_sets_state_protocols():
    """Headless: TLS then Enter on the optional cipher modal stores TLS only."""
    from friTap.tui.screens.main_screen import MainScreen
    from friTap.tui.wizard import CaptureWizard

    captured = {}

    async def body(app, pilot):
        screen = next(s for s in app.screen_stack if isinstance(s, MainScreen))
        wizard = CaptureWizard(screen)
        wizard._capture_mode_id = "keys"
        wizard._step_6_configure = lambda mode: captured.setdefault("next", mode)
        wizard._step_5b_protocol()
        await pilot.pause()
        assert isinstance(app.screen, ProtocolSelectModal)
        app.screen.dismiss("tls")
        await pilot.pause()
        assert isinstance(app.screen, CustomCipherModal)
        await pilot.press("enter")
        await pilot.pause()
        state = screen._get_state()
        captured["protocol"] = state.protocol
        captured["protocols"] = list(state.protocols)

    _run(body)
    assert captured["next"] == "keys"
    assert captured["protocol"] == "tls"
    assert captured["protocols"] == ["tls"]


def test_protocol_hotkey_updates_state_and_status_bar():
    """The `p` hotkey path uses the same chain and shows e.g. TLS+RC4."""
    from friTap.tui.screens.main_screen import MainScreen

    captured = {}

    async def body(app, pilot):
        screen = next(s for s in app.screen_stack if isinstance(s, MainScreen))
        screen._wizard_guard = lambda: False  # the startup wizard is running
        screen.action_protocol_select()
        await pilot.pause()
        assert isinstance(app.screen, ProtocolSelectModal)
        app.screen.dismiss("tls")
        await pilot.pause()
        assert isinstance(app.screen, CustomCipherModal)
        _select_all_and_confirm(app.screen)
        await pilot.pause()
        state = screen._get_state()
        captured["protocols"] = list(state.protocols)
        captured["status"] = screen._get_status_bar().protocol

    _run(body)
    assert captured["protocols"] == ["tls"] + custom_cipher_names()
    assert captured["status"].upper() == "+".join(["tls"] + custom_cipher_names()).upper()


def test_select_protocols_computes_ciphers_once(monkeypatch):
    from friTap.tui.modals import custom_cipher_modal

    real = custom_cipher_modal.available_custom_ciphers
    calls = []

    def _counting():
        calls.append(1)
        return real()

    monkeypatch.setattr(custom_cipher_modal, "available_custom_ciphers", _counting)
    done, opened = _drive_selection("tls", lambda m: m._confirm())
    assert done and done[0][0] == "tls"
    assert len(calls) == 1, "both modals must share one cipher list"


def test_wizard_confirm_summary_shows_full_protocol_selection():
    from friTap.tui.modals.start_confirm_modal import StartConfirmModal
    from friTap.tui.protocol_selection import apply_protocol_selection
    from friTap.tui.screens.main_screen import MainScreen
    from friTap.tui.wizard import CaptureWizard

    captured = {}

    async def body(app, pilot):
        screen = next(s for s in app.screen_stack if isinstance(s, MainScreen))
        apply_protocol_selection(screen._get_state(), ["tls", "rc4"])
        wizard = CaptureWizard(screen)
        wizard._capture_mode_id = "keys"
        wizard._step_7_confirm()
        await pilot.pause()
        assert isinstance(app.screen, StartConfirmModal)
        captured["summary"] = dict(app.screen._summary)

    _run(body)
    assert captured["summary"]["protocols_display"] == "TLS+RC4"
    assert captured["summary"]["protocol"] == "tls"
