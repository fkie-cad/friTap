#!/usr/bin/env python3

"""
Pilot tests: swapping the loaded ``.tap`` (``reload_replay``) in both viewers.

``MainScreen`` (``fritap -r a.tap`` = ``FriTapApp(replay_file=...)``) and the
embeddable ``TapViewerScreen`` reload a second ``.tap`` after a pcap->tap
conversion / decrypted-tap swap. The swap must:

* open and load the NEW file first; a failure only shows the alert and leaves
  the shown file (rows, banner, controller, file name) untouched;
* close the previous controller exactly once (MainScreen always owns it; the
  viewer only one it opened itself), after the new one is swapped in;
* forget the previous file's findings (cache, findings list, analyzer
  dashboard) and drop a late completion of an analyzer run started before
  the swap (run id bumped, "analyzer" worker group cancelled, "decrypt" not);
* return an open detail view to the flow list, and never read through the
  closed controller afterwards.

Each async body is driven with ``asyncio.run`` (no async pytest plugin).
"""

from __future__ import annotations

import asyncio
import threading

import pytest

pytest.importorskip("textual")

from textual.app import App  # noqa: E402
from textual.widgets import Static  # noqa: E402

from friTap.analysis import Finding, Severity  # noqa: E402
from friTap.flow.tap_writer import TapWriter  # noqa: E402
from friTap.tui.app import FriTapApp  # noqa: E402
from friTap.tui.screens.tap_viewer import TapViewerScreen  # noqa: E402
from tests.unit._tui_flow_helpers import make_flow, write_tap  # noqa: E402

# Controller members that read the .tap (properties cannot be wrapped).
_READ_METHODS = (
    "get_flow", "get_flows", "get_summaries", "read_all_findings",
    "read_request_contexts", "store_reparse", "has_findings",
)


# ---------------------------------------------------------------------------
# .tap fixtures
# ---------------------------------------------------------------------------

def _finding(flow_id: str, title: str) -> Finding:
    return Finding(
        severity=Severity.HIGH, title=title, description=f"{title} description",
        source="credentials", flow_id=flow_id,
    )


def _write_tap_with_findings(path: str, flow_ids: list, title: str) -> None:
    writer = TapWriter()
    writer.open(path, target="test")
    for index, flow_id in enumerate(flow_ids):
        writer.write_flow(make_flow(flow_id, 443 + index))
    writer.write_findings(flow_ids[0], [_finding(flow_ids[0], title)])
    writer.close()


@pytest.fixture
def taps(tmp_path) -> dict:
    """a.tap (2 flows, 1 finding), b.tap (1 flow, 1 finding), b_plain.tap (no findings)."""
    paths = {name: str(tmp_path / f"{name}.tap") for name in ("a", "b", "b_plain")}
    _write_tap_with_findings(paths["a"], ["flow-a1", "flow-a2"], "A finding")
    _write_tap_with_findings(paths["b"], ["flow-b1"], "B finding")
    write_tap(paths["b_plain"], [make_flow("flow-b1", 443)])
    paths["missing"] = str(tmp_path / "missing.tap")
    paths["corrupt"] = str(tmp_path / "corrupt.tap")
    with open(paths["corrupt"], "wb") as handle:
        handle.write(b"this is not a tap file" * 8)
    return paths


# ---------------------------------------------------------------------------
# Hosts: fritap -r (FriTapApp + MainScreen) and an app hosting TapViewerScreen
# ---------------------------------------------------------------------------

class _ViewerHost(App):
    """Minimal host app for the embeddable viewer."""


def _run_main(tap_path: str, body) -> None:
    async def _go() -> None:
        app = FriTapApp(replay_file=tap_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            await body(app, pilot, app.screen)

    asyncio.run(_go())


def _run_viewer(tap_path: str, body) -> None:
    async def _go() -> None:
        app = _ViewerHost()
        async with app.run_test() as pilot:
            await pilot.pause()
            viewer = TapViewerScreen(tap_path)
            app.push_screen(viewer)
            await pilot.pause()
            await pilot.pause()
            await body(app, pilot, viewer)

    asyncio.run(_go())


@pytest.fixture(params=["main_screen", "tap_viewer"])
def run_host(request):
    return {"main_screen": _run_main, "tap_viewer": _run_viewer}[request.param]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

class _ControllerWatch:
    """Counts ``close()`` calls and records reads made after the first close."""

    def __init__(self, ctrl) -> None:
        self.closes: list = []
        self.reads_after_close: list = []
        for name in _READ_METHODS:
            self._wrap_read(ctrl, name)
        original_close = ctrl.close

        def close() -> None:
            self.closes.append(True)
            original_close()

        ctrl.close = close

    def _wrap_read(self, ctrl, name: str) -> None:
        original = getattr(ctrl, name)

        def read(*args, **kwargs):
            if self.closes:
                self.reads_after_close.append(name)
            return original(*args, **kwargs)

        setattr(ctrl, name, read)


def _row_ids(screen) -> list:
    return [key.value for key in screen.query_one("#flow-list").rows]


def _rendered(screen, selector: str) -> str:
    return str(screen.query_one(selector, Static).render())


def _finding_titles(screen) -> list:
    findings_list = screen.query_one("#findings-list")
    return [f.title for f in findings_list._all_findings]


async def _settle(pilot, rounds: int = 2) -> None:
    for _ in range(rounds):
        await pilot.pause()


async def _wait_for(pilot, event: threading.Event) -> None:
    for _ in range(200):  # the worker thread is started by the event loop
        if event.is_set():
            return
        await pilot.pause(0.05)
    raise AssertionError("worker thread did not start")


# ---------------------------------------------------------------------------
# Controller lifecycle
# ---------------------------------------------------------------------------

def test_reload_closes_previous_controller_once_and_keeps_new_open(taps, run_host):
    async def body(app, pilot, screen):
        old = screen._replay_ctrl
        old_watch = _ControllerWatch(old)
        screen.reload_replay(taps["b"])
        await _settle(pilot)

        new = screen._replay_ctrl
        assert new is not old
        assert old_watch.closes == [True]
        assert new.get_flow("flow-b1") is not None  # the new reader is open
        assert old.header is None  # the old reader was released
        assert _row_ids(screen) == ["flow-b1"]
        assert screen._replay_file == taps["b"]
        assert screen._replay_filename == "b.tap"

        new_watch = _ControllerWatch(new)
        screen.reload_replay(taps["a"])
        await _settle(pilot)
        assert new_watch.closes == [True]
        assert old_watch.closes == [True]  # never closed twice
        assert _row_ids(screen) == ["flow-a1", "flow-a2"]

    run_host(taps["a"], body)


def test_first_load_closes_nothing_and_shows_rows(taps, run_host):
    async def body(app, pilot, screen):
        assert _row_ids(screen) == ["flow-a1", "flow-a2"]
        assert screen._replay_ctrl.get_flow("flow-a1") is not None
        assert screen._findings_cache is None
        assert screen._detail_origin == "flow"

    run_host(taps["a"], body)


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("second, expected", [("b", ["B finding"]), ("b_plain", [])])
def test_findings_view_shows_the_new_files_findings(taps, run_host, second, expected):
    async def body(app, pilot, screen):
        await pilot.press("shift+f")
        await _settle(pilot)
        assert _finding_titles(screen) == ["A finding"]
        assert screen._findings_cache is not None

        screen.reload_replay(taps[second])  # reloaded while in the findings view
        await _settle(pilot)
        assert screen._findings_cache is None
        assert screen.query_one("#findings-list").total_count == 0
        assert screen.query_one("#findings-list").display is False
        assert screen.query_one("#flow-list").display is True

        await pilot.press("shift+f")
        await _settle(pilot)
        assert _finding_titles(screen) == expected

    run_host(taps["a"], body)


def test_stale_analyzer_completion_is_dropped(taps, run_host):
    async def body(app, pilot, screen):
        # A finished run on a.tap fills the findings list and the dashboard.
        screen._analyzer_run_id += 1
        screen._on_analyzers_complete(
            [_finding("flow-a1", "A analyzer")], screen._analyzer_run_id)
        await _settle(pilot)
        assert screen._findings_cache and screen._findings_cache[0].title == "A analyzer"
        assert screen.query_one("#analyzer-dashboard").display is True

        # Another run starts on a.tap; the reload happens before it completes.
        screen._analyzer_run_id += 1
        stale_run = screen._analyzer_run_id
        screen.reload_replay(taps["b"])
        await _settle(pilot)
        assert screen._analyzer_run_id != stale_run
        assert screen._findings_cache is None
        assert screen.query_one("#findings-list").total_count == 0
        assert screen.query_one("#analyzer-dashboard").display is False
        assert screen.query_one("#analyzer-chooser").display is True

        screen._on_analyzers_complete([_finding("flow-a1", "A late")], stale_run)
        await _settle(pilot)
        assert screen._findings_cache is None
        assert screen.query_one("#findings-list").total_count == 0

        await pilot.press("shift+f")
        await _settle(pilot)
        assert _finding_titles(screen) == ["B finding"]

    run_host(taps["a"], body)


def test_reload_cancels_analyzer_worker_but_not_decrypt(taps, run_host):
    analyzer_started, decrypt_started = threading.Event(), threading.Event()
    release = threading.Event()

    async def body(app, pilot, screen):
        from friTap.tui.widgets.analyzer_panel import AnalyzerPanel

        old = screen._replay_ctrl

        def slow_get_flow(flow_id):
            analyzer_started.set()
            release.wait(10)
            return old.get_flow(flow_id)

        def decrypt_job():
            decrypt_started.set()
            release.wait(10)

        screen._analyzer_flow_ids_and_getter = lambda: (["flow-a1", "flow-a2"], slow_get_flow)
        screen.on_analyzer_panel_run_requested(
            AnalyzerPanel.RunRequested(["credentials"], None))
        screen.run_worker(decrypt_job, thread=True, group="decrypt")
        await _wait_for(pilot, analyzer_started)
        await _wait_for(pilot, decrypt_started)
        by_group = {w.group: w for w in screen.workers if w.node is screen}

        screen.reload_replay(taps["b"])
        await _settle(pilot)
        assert by_group["analyzer"].is_cancelled
        assert not by_group["decrypt"].is_cancelled

        release.set()
        for _ in range(10):
            await pilot.pause(0.05)
        assert screen._findings_cache is None
        assert screen.query_one("#findings-list").total_count == 0
        assert screen.query_one("#analyzer-dashboard").display is False

    try:
        run_host(taps["a"], body)
    finally:
        release.set()


# ---------------------------------------------------------------------------
# Failed reload
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("bad", ["missing", "corrupt"])
def test_failed_reload_keeps_the_shown_file(taps, run_host, bad):
    async def body(app, pilot, screen):
        old = screen._replay_ctrl
        watch = _ControllerWatch(old)
        before = (
            _row_ids(screen), _rendered(screen, "#activity-title"),
            _rendered(screen, "#capture-indicator"), screen._replay_file,
            screen._replay_filename, screen._analyzer_run_id,
        )

        screen.reload_replay(taps[bad])
        await _settle(pilot)

        assert type(app.screen).__name__ == "AlertModal"
        assert app.screen._title == "Replay Error"
        assert f"{bad}.tap" in str(app.screen.query_one("#alert-message", Static).render())
        assert screen._replay_ctrl is old
        assert watch.closes == []
        assert old.get_flow("flow-a1") is not None
        after = (
            _row_ids(screen), _rendered(screen, "#activity-title"),
            _rendered(screen, "#capture-indicator"), screen._replay_file,
            screen._replay_filename, screen._analyzer_run_id,
        )
        assert after == before

        await pilot.press("escape")  # dismiss the alert
        await _settle(pilot)
        assert app.screen is screen
        assert _row_ids(screen) == ["flow-a1", "flow-a2"]

    run_host(taps["a"], body)


# ---------------------------------------------------------------------------
# Detail pane
# ---------------------------------------------------------------------------

def test_reload_with_open_flow_detail_never_reads_the_closed_controller(taps, run_host):
    async def body(app, pilot, screen):
        watch = _ControllerWatch(screen._replay_ctrl)
        detail = screen.query_one("#flow-detail")
        await pilot.press("enter")
        await _settle(pilot)
        assert detail.display is True
        assert detail._current_flow.flow_id == "flow-a1"

        screen.reload_replay(taps["b"])
        await _settle(pilot)
        assert watch.closes == [True]
        assert detail.display is False
        assert screen.query_one("#flow-list").display is True
        assert app.focused is screen.query_one("#flow-list")
        assert screen._detail_origin == "flow"

        # Everything that loads flow content now reads the NEW controller.
        assert screen._lookup_flow("flow-a1") is None
        await pilot.press("enter")
        await _settle(pilot)
        assert detail.display is True
        assert detail._current_flow.flow_id == "flow-b1"
        await pilot.press("escape")
        await _settle(pilot)
        assert detail.display is False
        await pilot.press("shift+f")
        await _settle(pilot)
        await pilot.press("shift+f")
        await _settle(pilot)
        assert watch.reads_after_close == []

    run_host(taps["a"], body)


def test_reload_from_finding_opened_detail_resets_origin(taps, run_host):
    async def body(app, pilot, screen):
        await pilot.press("shift+f")
        await _settle(pilot)
        await pilot.press("enter")  # finding -> analyzer finding detail
        await _settle(pilot)
        assert screen.query_one("#finding-detail").display is True
        await pilot.press("d")  # -> full flow detail, opened from a finding
        await _settle(pilot)
        assert screen._detail_origin == "finding"
        assert screen.query_one("#flow-detail").display is True

        screen.reload_replay(taps["b"])
        await _settle(pilot)
        assert screen._detail_origin == "flow"
        for selector in ("#flow-detail", "#finding-detail", "#findings-list"):
            assert screen.query_one(selector).display is False
        assert screen.query_one("#flow-list").display is True
        assert _row_ids(screen) == ["flow-b1"]

    run_host(taps["a"], body)


# ---------------------------------------------------------------------------
# Real trigger: the decrypt worker's completion swaps in the decrypted .tap
# ---------------------------------------------------------------------------

def test_decrypt_completion_swap_forgets_old_findings(taps, run_host):
    import types

    async def body(app, pilot, screen):
        old_watch = _ControllerWatch(screen._replay_ctrl)
        await pilot.press("shift+f")
        await _settle(pilot)
        assert _finding_titles(screen) == ["A finding"]

        screen._on_decrypt_done(taps["b"], types.SimpleNamespace(flow_count=1))
        await _settle(pilot)
        assert old_watch.closes == [True]
        assert _row_ids(screen) == ["flow-b1"]
        assert screen._findings_cache is None

        await pilot.press("shift+f")
        await _settle(pilot)
        assert _finding_titles(screen) == ["B finding"]
        assert old_watch.reads_after_close == []

    run_host(taps["a"], body)
