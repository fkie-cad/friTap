#!/usr/bin/env python3

"""
Pilot tests for the embeddable replay-only ``TapViewerScreen`` (task 4.1).

The viewer is pushed into a FOREIGN host app: its own theme (no ``$fritap-*``
variables), a priority ``escape`` binding that drives ``go_back()``, a global
``DataTable`` rule and a host widget whose id collides with ``#flow-list``.

Each async body is driven with ``asyncio.run`` (no async pytest plugin).
"""

from __future__ import annotations

import asyncio
import re
import subprocess
import sys
import threading
from pathlib import Path

import pytest

pytest.importorskip("textual")

from textual.app import App  # noqa: E402
from textual.binding import Binding  # noqa: E402
from textual.color import Color  # noqa: E402
from textual.screen import Screen  # noqa: E402
from textual.theme import Theme  # noqa: E402
from textual.widgets import DataTable, Static  # noqa: E402

from friTap.tui.screens.tap_viewer import NullActivityLog, TapViewerScreen  # noqa: E402
from tests.unit._tui_flow_helpers import make_flow, write_tap  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[2]
HOST_TITLE = "Host App"


# ---------------------------------------------------------------------------
# Fixtures: a .tap file and a foreign host app
# ---------------------------------------------------------------------------

def _write_tap(path: str) -> None:
    write_tap(path, [make_flow("flow-aaaa", 443), make_flow("flow-bbbb", 8443)])


def _row_cells(flow_list, flow_id: str) -> list:
    for key in flow_list.rows:
        if key.value == flow_id:
            return [str(cell) for cell in flow_list.get_row(key)]
    raise AssertionError(f"row {flow_id} not found")


class HostScreen(Screen):
    def compose(self):
        yield Static("host flow list", id="flow-list")
        yield DataTable(id="host-table")


class HostApp(App):
    CSS = "DataTable { background: red; }"
    TITLE = HOST_TITLE
    BINDINGS = [Binding("escape", "host_escape", "Back", priority=True)]

    def __init__(self) -> None:
        super().__init__()
        self.closed_messages: list = []
        self.host_escapes = 0

    def on_mount(self) -> None:
        self.register_theme(Theme(name="host-theme", primary="#336699", dark=True))
        self.theme = "host-theme"
        self.push_screen(HostScreen())

    def action_host_escape(self) -> None:
        self.host_escapes += 1
        screen = self.screen
        if isinstance(screen, TapViewerScreen):
            if not screen.go_back():
                screen.dismiss()
        elif not isinstance(screen, HostScreen):
            self.pop_screen()

    def on_tap_viewer_screen_closed(self, message: TapViewerScreen.Closed) -> None:
        self.closed_messages.append(message)


def _run(tmp_path, body, **viewer_kwargs) -> HostApp:
    tap_path = str(tmp_path / "replay.tap")
    _write_tap(tap_path)
    app = HostApp()

    async def _go() -> None:
        async with app.run_test() as pilot:
            await pilot.pause()
            viewer = TapViewerScreen(tap_path, **viewer_kwargs)
            app.push_screen(viewer)
            await pilot.pause()
            await pilot.pause()
            await body(app, pilot, viewer)

    asyncio.run(_go())
    return app


def _stack_names(app) -> list[str]:
    return [type(s).__name__ for s in app.screen_stack]


# ---------------------------------------------------------------------------
# Loading / rendering
# ---------------------------------------------------------------------------

def test_viewer_shows_rows_banner_and_indicator(tmp_path):
    async def body(app, pilot, viewer):
        from friTap.tui.widgets.flow_list import FlowListWidget

        assert app.screen is viewer
        flow_list = viewer.query_one("#flow-list", FlowListWidget)
        assert [k.value for k in flow_list.rows] == ["flow-aaaa", "flow-bbbb"]
        for flow_id, num, port in (("flow-aaaa", "1", 443), ("flow-bbbb", "2", 8443)):
            cells = _row_cells(flow_list, flow_id)
            assert cells[0] == num
            assert re.fullmatch(r"\d\d:\d\d:\d\d", cells[1])
            assert cells[2:4] == ["???", "-"]
            assert cells[4] == f"10.0.0.1:12345 \u2192 93.184.216.34:{port}"
            assert cells[5:7] == ["...", "-"]
            assert re.fullmatch(r"\d+ms", cells[7])
        banner = str(viewer.query_one("#activity-title", Static).render())
        assert banner == (
            "friTap Replay  replay.tap (2 flows) | Enter: details | /: filter"
            " | a: analyzers | w: export | q: close"
        )
        indicator = str(viewer.query_one("#capture-indicator", Static).render())
        assert indicator == "▣ TAP: replay.tap"
        assert app.focused is flow_list

    _run(tmp_path, body)


def test_title_applies_to_screen_not_app(tmp_path):
    async def body(app, pilot, viewer):
        assert viewer.title == "My Capture"
        assert viewer.sub_title == "embedded"
        assert app.title == HOST_TITLE

    _run(tmp_path, body, title="My Capture", sub_title="embedded")


def test_missing_tap_shows_alert_inside_host(tmp_path):
    app = HostApp()

    async def _go() -> None:
        async with app.run_test() as pilot:
            await pilot.pause()
            app.push_screen(TapViewerScreen(str(tmp_path / "missing.tap")))
            await pilot.pause()
            await pilot.pause()
            assert type(app.screen).__name__ == "AlertModal"
            assert "missing.tap" in str(app.screen.query_one("#alert-message", Static).render())
            await pilot.press("escape")  # host priority escape pops the modal
            await pilot.pause()
            assert isinstance(app.screen, TapViewerScreen)

    asyncio.run(_go())


def test_prebuilt_source_is_used_and_not_closed(tmp_path):
    """A host-passed source belongs to the host: the viewer never closes it."""
    from friTap.flow.replay import ReplayController

    tap_path = str(tmp_path / "replay.tap")
    _write_tap(tap_path)
    ctrl = ReplayController(tap_path)
    ctrl.load()
    closed = []
    ctrl.close = lambda: closed.append(True)  # type: ignore[method-assign]
    app = HostApp()

    async def _go() -> None:
        async with app.run_test() as pilot:
            await pilot.pause()
            viewer = TapViewerScreen(tap_path, source=ctrl)
            app.push_screen(viewer)
            await pilot.pause()
            assert viewer._replay_ctrl is ctrl
            assert len(viewer.query_one("#flow-list").rows) == 2
            await pilot.press("q")
            await pilot.pause()
            assert closed == []

    asyncio.run(_go())


# ---------------------------------------------------------------------------
# Navigation and keys
# ---------------------------------------------------------------------------

def test_enter_opens_detail_and_host_escape_goes_back(tmp_path):
    async def body(app, pilot, viewer):
        detail = viewer.query_one("#flow-detail")
        await pilot.press("enter")
        await pilot.pause()
        assert detail.display is True

        await pilot.press("escape")  # host priority binding -> go_back()
        await pilot.pause()
        assert app.host_escapes == 1
        assert detail.display is False
        assert app.screen is viewer
        assert app.focused.id == "flow-list"

        await pilot.press("escape")  # top level: go_back() False -> host closes
        await pilot.pause()
        assert _stack_names(app) == ["Screen", "HostScreen"]
        assert [m.tap_path for m in app.closed_messages] == [str(tmp_path / "replay.tap")]

    _run(tmp_path, body)


def test_backspace_goes_back_from_detail(tmp_path):
    async def body(app, pilot, viewer):
        detail = viewer.query_one("#flow-detail")
        await pilot.press("enter")
        await pilot.pause()
        assert detail.display is True
        # The detail widget focuses its tabs; backspace bubbles to the screen.
        await pilot.press("backspace")
        await pilot.pause()
        assert detail.display is False
        assert app.screen is viewer

    _run(tmp_path, body)


def test_go_back_returns_false_at_top_level_and_does_not_close(tmp_path):
    async def body(app, pilot, viewer):
        assert viewer.go_back() is False
        await pilot.pause()
        assert app.screen is viewer
        assert app.closed_messages == []

    _run(tmp_path, body)


def test_go_back_steps_out_of_findings_and_analyzer_panel(tmp_path):
    async def body(app, pilot, viewer):
        await pilot.press("shift+f")
        await pilot.pause()
        assert viewer.query_one("#findings-list").display is True
        assert viewer.go_back() is True
        await pilot.pause()
        assert viewer.query_one("#findings-list").display is False
        assert viewer.query_one("#flow-list").display is True

        await pilot.press("a")
        await pilot.pause()
        assert viewer._analyzer_panel().display is True
        assert viewer.go_back() is True
        await pilot.pause()
        assert viewer._analyzer_panel().display is False
        assert viewer.go_back() is False

    _run(tmp_path, body)


def test_go_back_clears_active_flow_filter(tmp_path):
    async def body(app, pilot, viewer):
        from friTap.tui.widgets.filter_bar import FilterBar

        from friTap.filter import FilterEngine

        bar = viewer.query_one("#filter-bar", FilterBar)
        bar.apply_result(text="tcp.port == 443", text_engine=FilterEngine("tcp.port == 443"),
                         toggle_engine=None, active_toggles=set())
        await pilot.pause()
        assert bar.has_active_filter is True
        assert viewer.go_back() is True
        await pilot.pause()
        assert bar.has_active_filter is False
        assert viewer.go_back() is False

    _run(tmp_path, body)


def test_slash_opens_filter_modal(tmp_path):
    async def body(app, pilot, viewer):
        await pilot.press("slash")
        await pilot.pause()
        assert type(app.screen).__name__ == "FilterModal"
        await pilot.press("escape")  # host priority escape pops the modal
        await pilot.pause()
        assert app.screen is viewer

    _run(tmp_path, body)


def test_a_toggles_analyzer_panel(tmp_path):
    async def body(app, pilot, viewer):
        panel = viewer._analyzer_panel()
        await pilot.press("a")
        await pilot.pause()
        assert panel.display is True
        assert app.screen is viewer
        await pilot.press("a")
        await pilot.pause()
        assert panel.display is False
        assert app.focused.id == "flow-list"

    _run(tmp_path, body)


def test_w_opens_save_tap_modal(tmp_path):
    async def body(app, pilot, viewer):
        await pilot.press("w")
        await pilot.pause()
        assert type(app.screen).__name__ == "SaveTapModal"
        assert _stack_names(app) == ["Screen", "HostScreen", "TapViewerScreen", "SaveTapModal"]

    _run(tmp_path, body)


def test_shift_f_toggles_findings_view(tmp_path):
    async def body(app, pilot, viewer):
        findings = viewer.query_one("#findings-list")
        await pilot.press("shift+f")
        await pilot.pause()
        assert findings.display is True
        assert app.focused.id == "findings-list"
        await pilot.press("shift+f")
        await pilot.pause()
        assert findings.display is False
        assert app.focused.id == "flow-list"

    _run(tmp_path, body)


def test_r_and_t_do_nothing(tmp_path):
    async def body(app, pilot, viewer):
        before = (app.theme, _stack_names(app), viewer.query_one("#flow-list").display)
        await pilot.press("r")
        await pilot.press("t")
        await pilot.pause()
        assert (app.theme, _stack_names(app), viewer.query_one("#flow-list").display) == before
        assert app.screen is viewer
        assert not any(b.key in ("r", "t") for b in TapViewerScreen.BINDINGS)

    _run(tmp_path, body)


def test_q_closes_viewer_and_host_survives(tmp_path):
    async def body(app, pilot, viewer):
        await pilot.press("q")
        await pilot.pause()
        assert app.is_running
        assert _stack_names(app) == ["Screen", "HostScreen"]
        host_flow_list = app.screen.query_one("#flow-list", Static)
        assert str(host_flow_list.render()) == "host flow list"
        assert len(app.closed_messages) == 1
        assert app.closed_messages[0].tap_path == str(tmp_path / "replay.tap")
        assert app.closed_messages[0].viewer is viewer
        assert viewer._replay_ctrl is None  # controller closed on unmount

    _run(tmp_path, body)


# ---------------------------------------------------------------------------
# Host isolation: CSS, title, modals
# ---------------------------------------------------------------------------

def test_host_styles_and_title_unchanged(tmp_path):
    async def body(app, pilot, viewer):
        await pilot.press("q")
        await pilot.pause()
        host_table = app.screen.query_one("#host-table", DataTable)
        assert host_table.styles.background == Color.parse("red")
        assert app.title == HOST_TITLE
        assert app.theme == "host-theme"

    _run(tmp_path, body)


def test_alert_modal_renders_inside_host(tmp_path):
    async def body(app, pilot, viewer):
        viewer._alert("something [bold]happened[/]", title="Heads up", severity="info")
        await pilot.pause()
        assert type(app.screen).__name__ == "AlertModal"
        rendered = str(app.screen.query_one("#alert-message", Static).render())
        assert "something happened" in rendered
        await pilot.press("escape")  # host priority escape pops the modal
        await pilot.pause()
        assert app.screen is viewer

    _run(tmp_path, body)


# ---------------------------------------------------------------------------
# Lifecycle
# ---------------------------------------------------------------------------

def test_unmount_mid_analyzer_run_does_not_crash(tmp_path):
    release = threading.Event()
    started = threading.Event()

    async def body(app, pilot, viewer):
        ctrl = viewer._replay_ctrl

        def slow_get_flow(flow_id):
            started.set()
            release.wait(10)
            return ctrl.get_flow(flow_id)

        viewer._analyzer_flow_ids_and_getter = lambda: (["flow-aaaa", "flow-bbbb"], slow_get_flow)
        from friTap.tui.widgets.analyzer_panel import AnalyzerPanel

        viewer.on_analyzer_panel_run_requested(AnalyzerPanel.RunRequested(["credentials"], None))
        for _ in range(200):  # the worker thread is started by the event loop
            if started.is_set():
                break
            await pilot.pause(0.05)
        assert started.is_set()
        run_id = viewer._analyzer_run_id
        await pilot.press("q")
        await pilot.pause()
        assert viewer._analyzer_run_id == run_id + 1
        release.set()
        for _ in range(10):
            await pilot.pause(0.05)
        assert app.is_running
        assert _stack_names(app) == ["Screen", "HostScreen"]

    try:
        _run(tmp_path, body)
    finally:
        release.set()


def test_request_close_when_not_active_is_ignored(tmp_path):
    async def body(app, pilot, viewer):
        viewer._alert("on top")
        await pilot.pause()
        viewer._request_close()
        await pilot.pause()
        assert type(app.screen).__name__ == "AlertModal"
        assert app.closed_messages == []

    _run(tmp_path, body)


def test_reload_replay_replaces_controller_and_findings_cache(tmp_path):
    other = str(tmp_path / "other.tap")
    write_tap(other, [make_flow("flow-cccc", 443)])

    async def body(app, pilot, viewer):
        old_ctrl = viewer._replay_ctrl
        viewer._findings_cache = ["stale"]
        viewer.reload_replay(other)
        await pilot.pause()
        assert viewer._replay_ctrl is not old_ctrl
        assert viewer._findings_cache is None
        assert viewer._replay_file == other
        assert [k.value for k in viewer.query_one("#flow-list").rows] == ["flow-cccc"]

    _run(tmp_path, body)


# ---------------------------------------------------------------------------
# Host hooks (pure)
# ---------------------------------------------------------------------------

def test_replay_only_host_hooks_without_controller():
    viewer = TapViewerScreen("x.tap")
    assert viewer._is_capturing() is False
    assert viewer._live_flow_collector() is None
    assert viewer._divert_analyzer_key() is False
    assert viewer._has_flows() is False
    ids, getter = viewer._analyzer_flow_ids_and_getter()
    assert ids == [] and getter("x") is None
    assert viewer._flow_title_hints() == ["[dim]q: close[/]"]
    assert viewer._hide_host_panels() is None
    assert viewer._escape_running_capture() is None
    assert viewer._start_live_tap_recording("y.tap") is None
    assert isinstance(viewer._get_activity_log(), NullActivityLog)
    assert viewer._output_dir is None


def test_constructor_stores_output_dir_and_state():
    viewer = TapViewerScreen("x.tap", output_dir="/tmp/out")
    assert viewer._output_dir == "/tmp/out"
    assert viewer._replay_file == "x.tap"
    assert viewer._replay_ctrl is None
    assert viewer._findings_cache is None
    assert viewer._analyzer_run_id == 0
    assert viewer._detail_origin == "flow"


def test_null_activity_log_methods_are_noops():
    log = NullActivityLog()
    for name in ("log_info", "log_error", "log_warning", "log_success", "log_key",
                 "log_secret", "log_data", "log_library", "log_session", "log_detach",
                 "log_live", "show_welcome", "clear"):
        assert getattr(log, name)("x", markup=True) is None
    assert log.show_welcome() is None
    assert log.get_plain_text() == ""
    assert log.get_line_count() == 0


def test_null_activity_log_rejects_other_names():
    log = NullActivityLog()
    for name in ("write", "flush", "clear_all", "_private"):
        with pytest.raises(AttributeError):
            getattr(log, name)
    assert not hasattr(log, "log")


# ---------------------------------------------------------------------------
# ViewerHostDefaults (replay-only hook defaults the viewer inherits)
# ---------------------------------------------------------------------------

class _FakeReplayController:
    def __init__(self, flow_ids):
        self._flow_ids = list(flow_ids)

    @property
    def flow_count(self) -> int:
        return len(self._flow_ids)

    def get_summaries(self):
        from types import SimpleNamespace

        return [SimpleNamespace(flow_id=flow_id) for flow_id in self._flow_ids]

    def get_flow(self, flow_id):
        return f"flow:{flow_id}" if flow_id in self._flow_ids else None


def test_default_hooks_follow_the_replay_controller():
    viewer = TapViewerScreen("x.tap")
    viewer._replay_ctrl = _FakeReplayController(["f1", "f2"])
    assert viewer._has_flows() is True
    ids, getter = viewer._analyzer_flow_ids_and_getter()
    assert ids == ["f1", "f2"]
    assert getter("f2") == "flow:f2"

    viewer._replay_ctrl = _FakeReplayController([])
    assert viewer._has_flows() is False
    assert viewer._analyzer_flow_ids_and_getter()[0] == []


def test_default_output_dir_is_a_class_level_none():
    from friTap.tui.screens.viewer_mixins import ViewerHostDefaults

    assert ViewerHostDefaults._output_dir is None
    assert TapViewerScreen("x.tap", output_dir="/tmp/o")._output_dir == "/tmp/o"


def test_shared_title_markup():
    from friTap.tui.screens.viewer_mixins import ViewerHostDefaults
    from friTap.tui.themes import c

    assert ViewerHostDefaults._replay_banner_markup("a.tap", 1, " | q") == (
        f"[bold {c('primary')}]friTap Replay[/]  [dim]a.tap (1 flow) | q[/]"
    )
    assert ViewerHostDefaults._replay_banner_markup("a.tap", 0, "") == (
        f"[bold {c('primary')}]friTap Replay[/]  [dim]a.tap (0 flows)[/]"
    )
    assert ViewerHostDefaults._tap_indicator_markup("a.tap") == f"[bold {c('info')}]▣ TAP: a.tap[/]"
    assert ViewerHostDefaults._tap_indicator_markup(None) == f"[bold {c('info')}]▣ TAP: tap[/]"


def test_replay_filename_is_derived_and_escaped():
    viewer = TapViewerScreen("/some/dir/[odd].tap")
    assert viewer._replay_filename == "\\[odd].tap"
    viewer._replay_file = None
    assert viewer._replay_filename == "tap"


# ---------------------------------------------------------------------------
# _escape_step (FlowNavigationMixin): one nested-view step, never closes
# ---------------------------------------------------------------------------

def test_escape_step_leaves_flow_detail_and_is_false_at_top(tmp_path):
    async def body(app, pilot, viewer):
        await pilot.press("enter")
        await pilot.pause()
        assert viewer.query_one("#flow-detail").display is True
        assert viewer._escape_step() is True
        await pilot.pause()
        assert viewer.query_one("#flow-detail").display is False
        assert viewer.query_one("#flow-list").display is True
        assert viewer._escape_step() is False
        await pilot.pause()
        assert app.screen is viewer
        assert app.closed_messages == []

    _run(tmp_path, body)


def test_escape_step_ignores_analyzer_panel(tmp_path):
    """The analyzer panel is a viewer-only go_back() step, not an Esc-hierarchy one."""
    async def body(app, pilot, viewer):
        await pilot.press("a")
        await pilot.pause()
        assert viewer._analyzer_panel().display is True
        assert viewer._escape_step() is False
        assert viewer._analyzer_panel().display is True

    _run(tmp_path, body)


def test_constructor_loads_extensions(monkeypatch):
    import friTap.tui.screens.tap_viewer as tap_viewer

    calls = []
    monkeypatch.setattr(tap_viewer, "load_extensions", lambda **kw: calls.append(kw))
    TapViewerScreen("x.tap")
    assert calls == [{"offline_decryptors": False}]


def test_viewer_never_quits_the_app():
    """No code reference (docstrings aside) to quitting the host or CSS_PATH."""
    import ast

    source = (REPO_ROOT / "friTap" / "tui" / "screens" / "tap_viewer.py").read_text(encoding="utf-8")
    names = {
        node.attr if isinstance(node, ast.Attribute) else node.id
        for node in ast.walk(ast.parse(source))
        if isinstance(node, (ast.Attribute, ast.Name))
    }
    assert not names & {"action_quit", "exit", "CSS_PATH"}


def test_import_isolation_subprocess():
    code = (
        "import sys\n"
        "import friTap.tui.screens.tap_viewer\n"
        "bad = ('frida', 'friTap.tui.capture_controller', 'friTap.tui.wizard',"
        " 'friTap.tui.screens.main_screen')\n"
        "print([m for m in bad if m in sys.modules])\n"
        "from friTap.tui.screens import MainScreen, SCREENS_AVAILABLE\n"
        "print(MainScreen.__name__, SCREENS_AVAILABLE)\n"
    )
    out = subprocess.run(
        [sys.executable, "-c", code],
        cwd=REPO_ROOT, capture_output=True, text=True, timeout=120,
    )
    assert out.returncode == 0, out.stderr
    assert out.stdout.strip().splitlines()[-2:] == ["[]", "MainScreen True"]


class PlainHostApp(App):
    """A host with no bindings of its own: the viewer's escape handles itself."""

    def __init__(self) -> None:
        super().__init__()
        self.closed_messages: list = []

    def on_tap_viewer_screen_closed(self, message: TapViewerScreen.Closed) -> None:
        self.closed_messages.append(message)


def test_viewer_escape_closes_at_top_level_without_host_binding(tmp_path):
    tap_path = str(tmp_path / "replay.tap")
    _write_tap(tap_path)
    app = PlainHostApp()

    async def _go() -> None:
        async with app.run_test() as pilot:
            viewer = TapViewerScreen(tap_path)
            app.push_screen(viewer)
            await pilot.pause()
            await pilot.press("enter")
            await pilot.pause()
            await pilot.press("escape")  # flow detail's own escape -> list
            await pilot.pause()
            assert app.screen is viewer
            await pilot.press("escape")  # top level -> viewer closes itself
            await pilot.pause()
            assert app.is_running
            assert not isinstance(app.screen, TapViewerScreen)
            assert len(app.closed_messages) == 1

    asyncio.run(_go())


def test_ctrl_l_clears_flow_filter(tmp_path):
    async def body(app, pilot, viewer):
        from friTap.filter import FilterEngine
        from friTap.tui.widgets.filter_bar import FilterBar

        bar = viewer.query_one("#filter-bar", FilterBar)
        bar.apply_result(text="tcp.port == 443", text_engine=FilterEngine("tcp.port == 443"),
                         toggle_engine=None, active_toggles=set())
        await pilot.pause()
        assert bar.has_active_filter is True
        await pilot.press("ctrl+l")
        await pilot.pause()
        assert bar.has_active_filter is False

    _run(tmp_path, body)


# ---------------------------------------------------------------------------
# Code-review fixes: TapSource contract, source ownership, MODES close,
# late decrypt completion
# ---------------------------------------------------------------------------

class _MinimalSource:
    """Implements EXACTLY the TapSource protocol members, nothing else."""

    def __init__(self, ctrl) -> None:
        self._ctrl = ctrl

    @property
    def header(self):
        return self._ctrl.header

    @property
    def flow_count(self) -> int:
        return self._ctrl.flow_count

    def get_summaries(self):
        return self._ctrl.get_summaries()

    def get_flow(self, flow_id):
        return self._ctrl.get_flow(flow_id)

    def get_flows(self):
        return self._ctrl.get_flows()

    def store_reparse(self, flow_id, request, response, clear_trailing=False):
        self._ctrl.store_reparse(flow_id, request, response, clear_trailing)

    def read_all_findings(self):
        return self._ctrl.read_all_findings()

    def read_request_contexts(self):
        return self._ctrl.read_request_contexts()


def _public_members(cls) -> set[str]:
    return {name for name in vars(cls) if not name.startswith("_")}


def _loaded_controller(tmp_path):
    from friTap.flow.replay import ReplayController

    tap_path = str(tmp_path / "replay.tap")
    _write_tap(tap_path)
    ctrl = ReplayController(tap_path)
    ctrl.load()
    return tap_path, ctrl


def test_minimal_protocol_source_mounts_and_exports(tmp_path):
    from friTap.flow.replay import TapSource
    from friTap.flow.tap_reader import TapReader

    assert _public_members(_MinimalSource) == _public_members(TapSource)
    tap_path, ctrl = _loaded_controller(tmp_path)
    source = _MinimalSource(ctrl)
    assert isinstance(source, TapSource)
    out_path = str(tmp_path / "exported.tap")
    app = HostApp()

    async def _go() -> None:
        async with app.run_test() as pilot:
            await pilot.pause()
            viewer = TapViewerScreen(tap_path, source=source)
            app.push_screen(viewer)
            await pilot.pause()
            await pilot.pause()
            assert app.screen is viewer
            rows = [k.value for k in viewer.query_one("#flow-list").rows]
            assert rows == ["flow-aaaa", "flow-bbbb"]
            assert viewer._has_flows() is True
            viewer._export_replay_to_tap(out_path)
            await pilot.pause()
            assert type(app.screen).__name__ == "AlertModal"
            assert "Exported 2 flows" in str(
                app.screen.query_one("#alert-message", Static).render())

    asyncio.run(_go())
    reader = TapReader(out_path)
    reader.open()
    assert sorted(s.flow_id for s in reader.read_flow_summaries()) == ["flow-aaaa", "flow-bbbb"]
    reader.close()


def test_host_passed_source_is_never_closed_and_is_reusable(tmp_path):
    tap_path, ctrl = _loaded_controller(tmp_path)
    app = HostApp()

    async def _go() -> None:
        async with app.run_test() as pilot:
            await pilot.pause()
            viewer = TapViewerScreen(tap_path, source=ctrl)
            app.push_screen(viewer)
            await pilot.pause()
            await pilot.press("q")
            await pilot.pause()
            assert _stack_names(app) == ["Screen", "HostScreen"]
            # The host's controller survives the viewer.
            assert ctrl.get_summaries()
            assert ctrl.get_flow("flow-aaaa") is not None
            second = TapViewerScreen(tap_path, source=ctrl)
            app.push_screen(second)
            await pilot.pause()
            await pilot.pause()
            rows = [k.value for k in second.query_one("#flow-list").rows]
            assert rows == ["flow-aaaa", "flow-bbbb"]

    asyncio.run(_go())
    assert ctrl.get_flow("flow-bbbb") is not None
    ctrl.close()


def test_source_swap_closes_only_viewer_owned_controllers(tmp_path):
    tap_path, ctrl = _loaded_controller(tmp_path)
    other = str(tmp_path / "other.tap")
    write_tap(other, [make_flow("flow-cccc", 443)])
    app = HostApp()

    async def _go() -> None:
        async with app.run_test() as pilot:
            await pilot.pause()
            viewer = TapViewerScreen(tap_path, source=ctrl)
            app.push_screen(viewer)
            await pilot.pause()
            viewer.reload_replay(other)  # swap: the host source stays open
            await pilot.pause()
            assert ctrl.get_flow("flow-aaaa") is not None
            owned = viewer._replay_ctrl
            closed = []
            owned.close = lambda: closed.append(True)  # type: ignore[method-assign]
            await pilot.press("q")
            await pilot.pause()
            assert closed == [True]  # a controller the viewer opened IS closed

    asyncio.run(_go())
    ctrl.close()


class ModesHostApp(App):
    """A host that uses the viewer as the base screen of a mode."""

    def __init__(self, tap_path: str) -> None:
        self.MODES = {"tap": lambda: TapViewerScreen(tap_path)}
        super().__init__()
        self.closed_messages: list = []

    def on_mount(self) -> None:
        self.switch_mode("tap")

    def on_tap_viewer_screen_closed(self, message: TapViewerScreen.Closed) -> None:
        self.closed_messages.append(message)


def test_close_as_mode_base_screen_posts_closed_without_dismiss(tmp_path):
    tap_path = str(tmp_path / "replay.tap")
    _write_tap(tap_path)
    app = ModesHostApp(tap_path)
    errors: list = []

    async def _go() -> None:
        async with app.run_test() as pilot:
            await pilot.pause()
            await pilot.pause()
            viewer = app.screen
            assert isinstance(viewer, TapViewerScreen)
            assert len(app.screen_stack) == 1
            await pilot.press("q")
            await pilot.pause()
            await pilot.press("escape")  # a second request posts nothing new
            await pilot.pause()
            assert app.is_running
            assert app.screen is viewer
            assert len(app.closed_messages) == 1
            assert app.closed_messages[0].viewer is viewer

    try:
        asyncio.run(_go())
    except Exception as e:  # pragma: no cover - reported below
        errors.append(e)
    assert errors == []
    assert app.return_code in (None, 0)


def test_decrypt_done_after_unmount_is_ignored(tmp_path):
    import types

    other = str(tmp_path / "other.tap")
    write_tap(other, [make_flow("flow-cccc", 443)])
    opened: list = []

    async def body(app, pilot, viewer):
        viewer._open_controller = lambda path: opened.append(path)  # type: ignore[method-assign]
        await pilot.press("q")
        await pilot.pause()
        assert _stack_names(app) == ["Screen", "HostScreen"]
        # A pcap decrypt finishing late queues these via call_from_thread.
        viewer._on_decrypt_done(other, types.SimpleNamespace(flow_count=1))
        viewer._on_decrypt_error("late failure")
        await pilot.pause()
        assert opened == []
        assert viewer._replay_ctrl is None
        assert _stack_names(app) == ["Screen", "HostScreen"]
        assert app.is_running

    _run(tmp_path, body)


def test_decrypt_done_while_mounted_still_reloads(tmp_path):
    import types

    other = str(tmp_path / "other.tap")
    write_tap(other, [make_flow("flow-cccc", 443)])

    async def body(app, pilot, viewer):
        viewer._on_decrypt_done(other, types.SimpleNamespace(flow_count=1))
        await pilot.pause()
        assert viewer._replay_file == other
        assert [k.value for k in viewer.query_one("#flow-list").rows] == ["flow-cccc"]

    _run(tmp_path, body)
