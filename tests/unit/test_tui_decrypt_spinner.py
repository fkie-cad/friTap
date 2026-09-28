#!/usr/bin/env python3

"""Regression tests for the decrypt spinner's lifetime (T3).

``Screen.dismiss`` pops the app's TOP screen. The spinner used to be closed
with ``modal.dismiss(None)``, so when another screen (quit confirmation, an
alert) had been pushed above it, the wrong screen closed and the spinner,
which ignores Esc, stayed forever. A cancelled decrypt worker also never
closed its spinner.
"""

from __future__ import annotations

import asyncio
import types
from unittest.mock import MagicMock

import pytest

pytest.importorskip("textual")

from friTap.tui.app import FriTapApp  # noqa: E402
from friTap.tui.modals.alert_modal import AlertModal  # noqa: E402
from friTap.tui.modals.decrypt_progress_modal import DecryptProgressModal  # noqa: E402
from friTap.tui.modals.quit_modal import QuitConfirmModal  # noqa: E402
from friTap.tui.screens.main_screen import MainScreen  # noqa: E402


def _main_screen(app):
    for screen in app.screen_stack:
        if isinstance(screen, MainScreen):
            return screen
    raise AssertionError("MainScreen not found in screen stack")


def _run(body):
    async def _go() -> None:
        app = FriTapApp()
        async with app.run_test() as pilot:
            await body(app, pilot)

    asyncio.run(_go())


class TestSpinnerDismissal:

    def test_finish_when_on_top_closes_spinner(self):
        async def body(app, pilot):
            spinner = DecryptProgressModal()
            app.push_screen(spinner)
            await pilot.pause()
            spinner.finish()
            await pilot.pause()
            assert spinner not in app.screen_stack

        _run(body)

    def test_covered_spinner_does_not_close_screen_above(self):
        """ctrl+q's quit modal on top must survive the spinner finishing."""
        async def body(app, pilot):
            screen = _main_screen(app)
            spinner = DecryptProgressModal()
            screen._decrypt_progress = spinner
            app.push_screen(spinner)
            await pilot.pause()
            quit_modal = QuitConfirmModal()
            app.push_screen(quit_modal)
            await pilot.pause()

            screen._dismiss_decrypt_progress()
            await pilot.pause()

            assert app.screen is quit_modal, "the quit modal was closed instead"
            assert spinner in app.screen_stack
            assert screen._decrypt_progress is None

            # Once the covering screen goes away the spinner closes itself.
            quit_modal.dismiss(None)
            await pilot.pause()
            await pilot.pause()
            assert spinner not in app.screen_stack
            assert quit_modal not in app.screen_stack

        _run(body)

    def test_alert_pushed_after_finish_is_kept(self):
        """_on_decrypt_error closes the spinner, then alerts: alert must stay."""
        async def body(app, pilot):
            spinner = DecryptProgressModal()
            app.push_screen(spinner)
            await pilot.pause()
            alert = AlertModal("boom", title="Decrypt Failed", severity="error")
            app.push_screen(alert)
            spinner.finish()
            await pilot.pause()
            assert app.screen is alert
            alert.dismiss(None)
            await pilot.pause()
            await pilot.pause()
            assert spinner not in app.screen_stack

        _run(body)

    def test_finish_is_idempotent(self):
        async def body(app, pilot):
            spinner = DecryptProgressModal()
            app.push_screen(spinner)
            await pilot.pause()
            below = app.screen_stack[-2]
            spinner.finish()
            spinner.finish()
            await pilot.pause()
            assert spinner not in app.screen_stack
            assert below in app.screen_stack, "a second finish popped another screen"

        _run(body)


class TestCancelledWorkerClosesSpinner:

    def _stub_screen(self):
        calls: list = []

        class _App:
            def call_from_thread(self, fn, *a, **kw):
                calls.append((fn, a))
                return fn(*a, **kw)

        screen = types.SimpleNamespace(app=_App())
        screen._decrypt_progress = None
        screen._dismiss_decrypt_progress = (
            lambda modal=None: MainScreen._dismiss_decrypt_progress(screen, modal)
        )
        screen._close_cancelled_spinner = (
            lambda progress: MainScreen._close_cancelled_spinner(screen, progress)
        )
        screen._on_decrypt_done = MagicMock()
        screen._on_decrypt_error = MagicMock()
        return screen, calls

    def _run_worker(self, monkeypatch, screen, progress, pcap_to_tap):
        import textual.worker as worker_mod
        import friTap.offline.pcap_to_tap as p2t

        monkeypatch.setattr(
            worker_mod, "get_current_worker",
            lambda: types.SimpleNamespace(is_cancelled=True),
        )
        monkeypatch.setattr(p2t, "pcap_to_tap", pcap_to_tap)
        MainScreen._decrypt_worker(screen, {"tap_path": "x.tap"}, progress)

    def test_cancelled_after_success_finishes_own_spinner(self, monkeypatch):
        screen, _ = self._stub_screen()
        progress = MagicMock()
        newer = MagicMock()
        screen._decrypt_progress = newer  # a newer run's spinner is current
        self._run_worker(monkeypatch, screen, progress, lambda **k: object())
        progress.finish.assert_called_once()
        newer.finish.assert_not_called()
        assert screen._decrypt_progress is newer
        screen._on_decrypt_done.assert_not_called()

    def test_cancelled_after_failure_finishes_spinner(self, monkeypatch):
        screen, _ = self._stub_screen()
        progress = MagicMock()
        screen._decrypt_progress = progress

        def _boom(**k):
            raise RuntimeError("fail")

        self._run_worker(monkeypatch, screen, progress, _boom)
        progress.finish.assert_called_once()
        assert screen._decrypt_progress is None
        screen._on_decrypt_error.assert_not_called()
