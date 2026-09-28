#!/usr/bin/env python3

"""Tests for the wizard's "Key Extraction Method" step (intercept / memory scan)."""

from __future__ import annotations

import asyncio

import pytest

from friTap.tui.modals.extraction_method_modal import ExtractionMethodSelection

# ---------------------------------------------------------------------------
# 1. Pure selection logic
# ---------------------------------------------------------------------------


def test_selection_defaults_to_intercepting_only():
    selection = ExtractionMethodSelection()
    assert selection.result() == {"intercept": True, "memory_scan": False}
    assert selection.is_valid()


def test_selection_both_and_memory_only():
    selection = ExtractionMethodSelection()
    selection.set_memory_scan(True)
    assert selection.result() == {"intercept": True, "memory_scan": True}
    selection.set_intercept(False)
    assert selection.result() == {"intercept": False, "memory_scan": True}
    assert selection.is_valid()


def test_selection_none_is_invalid():
    selection = ExtractionMethodSelection()
    selection.set_intercept(False)
    assert not selection.is_valid()


def test_selection_locked_keeps_intercept_on():
    selection = ExtractionMethodSelection(intercept=False, intercept_locked=True)
    assert selection.intercept is True
    selection.set_intercept(False)
    assert selection.intercept is True


# ---------------------------------------------------------------------------
# 2. Textual pilot tests
# ---------------------------------------------------------------------------

pytest.importorskip("textual")

from friTap.tui.app import FriTapApp  # noqa: E402
from friTap.tui.modals.alert_modal import AlertModal  # noqa: E402
from friTap.tui.modals.extraction_method_modal import ExtractionMethodModal  # noqa: E402


def _run(body, size=(80, 24)):
    async def _main() -> None:
        app = FriTapApp()
        async with app.run_test(size=size) as pilot:
            await body(app, pilot)

    asyncio.run(_main())


def _drive(keys, **modal_kwargs):
    """Push the modal, press *keys*, return (result dict, final screen type)."""
    result = {}

    async def body(app, pilot):
        modal = ExtractionMethodModal(**modal_kwargs)
        await app.push_screen(modal, callback=lambda v: result.setdefault("v", v))
        await pilot.pause()
        for key in keys:
            await pilot.press(key)
            await pilot.pause()
        result["screen"] = type(app.screen)
        result["modal"] = modal

    _run(body)
    return result


def test_modal_enter_with_defaults_is_intercepting_only():
    result = _drive(["enter"])
    assert result["v"] == {"intercept": True, "memory_scan": False}


def test_modal_enter_on_confirm_button_is_intercepting_only():
    result = _drive(["tab", "tab", "enter"])
    assert result["v"] == {"intercept": True, "memory_scan": False}


def test_modal_both_methods():
    result = _drive(["tab", "space", "enter"])
    assert result["v"] == {"intercept": True, "memory_scan": True}


def test_modal_memory_scan_only():
    result = _drive(["space", "tab", "space", "enter"])
    assert result["v"] == {"intercept": False, "memory_scan": True}


def test_modal_none_selected_shows_alert_and_stays_open():
    result = _drive(["space", "enter"])
    assert "v" not in result
    assert result["screen"] is AlertModal


def test_modal_locked_cannot_disable_intercept():
    from textual.widgets import Switch

    result = {}

    async def body(app, pilot):
        modal = ExtractionMethodModal(intercept=False, intercept_locked=True)
        await app.push_screen(modal, callback=lambda v: result.setdefault("v", v))
        await pilot.pause()
        intercept_switch = modal.query_one("#switch-intercept", Switch)
        assert intercept_switch.disabled is True
        assert intercept_switch.value is True
        # Focus starts on the memory switch; Space toggles it, not Intercepting.
        assert modal.focused is modal.query_one("#switch-memory-scan", Switch)
        await pilot.press("space")
        await pilot.pause()
        await pilot.press("enter")
        await pilot.pause()

    _run(body)
    assert result["v"] == {"intercept": True, "memory_scan": True}


def test_modal_prefills_initial_values():
    result = _drive(["enter"], intercept=False, memory_scan=True)
    assert result["v"] == {"intercept": False, "memory_scan": True}


def test_modal_escape_is_none():
    result = _drive(["escape"])
    assert result["v"] is None


# ---------------------------------------------------------------------------
# 3. Wizard ordering: step 5 -> 5a -> 5b with state propagation
# ---------------------------------------------------------------------------


def _wizard_through_step_5a(mode_id, keys):
    from friTap.tui.modals.capture_select_modal import CaptureSelectModal
    from friTap.tui.screens.main_screen import MainScreen
    from friTap.tui.wizard import CaptureWizard

    captured = {}

    async def body(app, pilot):
        screen = next(s for s in app.screen_stack if isinstance(s, MainScreen))
        wizard = CaptureWizard(screen)
        wizard._step_5b_protocol = lambda: captured.setdefault("next", "5b")
        wizard._step_5_capture_mode()
        await pilot.pause()
        assert isinstance(app.screen, CaptureSelectModal)
        app.screen.dismiss(mode_id)
        await pilot.pause()
        assert isinstance(app.screen, ExtractionMethodModal)
        captured["locked"] = app.screen._selection.intercept_locked
        for key in keys:
            await pilot.press(key)
            await pilot.pause()
        state = screen._get_state()
        captured["intercept"] = state.intercept
        captured["memory_scan"] = state.memory_scan
        captured["mode"] = wizard.capture_mode_id

    _run(body)
    return captured


def test_wizard_step_5_then_5a_then_5b_sets_state():
    captured = _wizard_through_step_5a("keys", ["space", "tab", "space", "enter"])
    assert captured["next"] == "5b"
    assert captured["mode"] == "keys"
    assert captured["locked"] is False
    assert captured["intercept"] is False
    assert captured["memory_scan"] is True


def test_wizard_step_5a_locks_intercept_for_plaintext():
    captured = _wizard_through_step_5a("plaintext", ["space", "enter"])
    assert captured["next"] == "5b"
    assert captured["locked"] is True
    assert captured["intercept"] is True
    assert captured["memory_scan"] is True


def test_wizard_step_5a_escape_returns_to_capture_mode():
    from friTap.tui.modals.capture_select_modal import CaptureSelectModal
    from friTap.tui.screens.main_screen import MainScreen
    from friTap.tui.wizard import CaptureWizard

    captured = {}

    async def body(app, pilot):
        screen = next(s for s in app.screen_stack if isinstance(s, MainScreen))
        wizard = CaptureWizard(screen)
        wizard._capture_mode_id = "full"
        wizard._step_5a_extraction_method()
        await pilot.pause()
        await pilot.press("escape")
        await pilot.pause()
        captured["screen"] = type(app.screen)

    _run(body)
    assert captured["screen"] is CaptureSelectModal
