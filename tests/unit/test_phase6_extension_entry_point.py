"""Phase 6 phase-check: one fake ``fritap.ui_extensions`` entry point drives
every extension surface in BOTH viewer hosts.

Hosts: (a) ``fritap -r`` = ``FriTapApp(replay_file=...)``; (b) a minimal host
``App`` pushing the embeddable ``TapViewerScreen``. The entry point's zero-arg
callable registers a detail tab, a flow column, a body decoder and a filter
field; the tests then check each surface inside the running app.

Body decoder: asserted by pushing ``BodyProcessingModal`` inside the running
host app (the modal has no key binding in the viewer screens) and reading its
buttons. Filter field: the filter is applied through the screen's real filter
path (``FilterBar.apply_result`` -> ``FilterChanged`` -> ``FlowListWidget``).
"""

from __future__ import annotations

import asyncio

import pytest

pytest.importorskip("textual")

from textual.app import App  # noqa: E402
from textual.widgets import Button  # noqa: E402

from friTap import extensions as ext  # noqa: E402
from friTap.filter import FilterEngine  # noqa: E402
from friTap.filter.layer_fields import LayerFieldSpec  # noqa: E402
from friTap.flow.layers import TlsLayer  # noqa: E402
from tests.unit._ext_helpers import FakeEntryPoint  # noqa: E402
from tests.unit._tui_flow_helpers import make_flow, write_tap  # noqa: E402

COLUMN_LABEL = "Phase6Col"
TAB_ID = "p6tab"
TAB_TEXT = "phase6 tab content"
DECODER_NAME = "p6dec"
LIBS = {"flow-aaaa": "BoringSSL", "flow-bbbb": "OpenSSL"}


def _register_all() -> None:
    ext.register_detail_tab(ext.DetailTabSpec(
        id=TAB_ID, label="P6 Tab", render=lambda flow: TAB_TEXT))
    ext.register_flow_column(ext.FlowColumnSpec(
        key="p6", label=COLUMN_LABEL, width=14,
        value=lambda row: "col-" + row.flow_id))
    ext.register_body_decoder(ext.BodyDecoderSpec(
        name=DECODER_NAME, label="P6 Decoder", decode=lambda body, headers: ["x"]))
    ext.register_filter_field(
        LayerFieldSpec("p6.lib", ("tls",), "library", "str", "P6 lib"))


@pytest.fixture(autouse=True)
def _extension_env(monkeypatch):
    monkeypatch.delenv(ext.DISABLE_ENV_VAR, raising=False)
    monkeypatch.setattr(ext.discovery_base, "get_entry_points",
                        lambda *a, **kw: [FakeEntryPoint("phase6", _register_all)])


def _tap(tmp_path) -> str:
    flows = []
    for flow_id, lib in LIBS.items():
        flow = make_flow(flow_id)
        flow.layers.append(TlsLayer(library=lib))
        flows.append(flow)
    path = tmp_path / "phase6.tap"
    write_tap(path, flows)
    return str(path)


class _ViewerHost(App):
    def __init__(self, tap_path: str) -> None:
        super().__init__()
        self._tap_path = tap_path

    def on_mount(self) -> None:
        from friTap.tui.screens.tap_viewer import TapViewerScreen
        from friTap.tui.theme_install import install_theme
        install_theme(self)
        self.push_screen(TapViewerScreen(self._tap_path))


def _make_app(host: str, tap_path: str):
    if host == "replay":
        from friTap.tui.app import FriTapApp
        return FriTapApp(replay_file=tap_path)
    return _ViewerHost(tap_path)


def _run_host(host: str, tmp_path, body) -> None:
    app = _make_app(host, _tap(tmp_path))

    async def _go() -> None:
        async with app.run_test(size=(200, 50)) as pilot:
            for _ in range(4):
                await pilot.pause()
            await body(app, pilot)

    asyncio.run(_go())


def _flow_list(app):
    from friTap.tui.widgets.flow_list import FlowListWidget
    return app.screen.query_one("#flow-list", FlowListWidget)


def _row_by_flow(flow_list, flow_id: str) -> list:
    for key in flow_list.rows:
        if key.value == flow_id:
            return [str(c) for c in flow_list.get_row(key)]
    raise AssertionError(f"row {flow_id} missing")


HOSTS = pytest.mark.parametrize("host", ["replay", "viewer"])


@HOSTS
def test_column_header_and_cell_value(host, tmp_path):
    async def body(app, pilot) -> None:
        table = _flow_list(app)
        assert COLUMN_LABEL in [str(c.label) for c in table.columns.values()]
        for flow_id in LIBS:
            assert _row_by_flow(table, flow_id)[-1] == "col-" + flow_id

    _run_host(host, tmp_path, body)


@HOSTS
def test_extension_tab_pane_visible_with_content_after_enter(host, tmp_path):
    from friTap.tui.widgets.flow_detail import FlowDetailWidget

    async def body(app, pilot) -> None:
        table = _flow_list(app)
        table.focus()
        await pilot.pause()
        await pilot.press("enter")
        for _ in range(4):
            await pilot.pause()
        detail = app.screen.query_one("#flow-detail", FlowDetailWidget)
        pane_id = f"tab-ext-{TAB_ID}"
        assert detail.query(f"#{pane_id}"), "extension TabPane not composed"
        assert not detail._tabs.get_tab(pane_id).has_class("-hidden")
        detail._tabs.active = pane_id
        for _ in range(4):
            await pilot.pause()
        assert detail._ext_content[pane_id] == TAB_TEXT
        assert detail.query_one(f"#{pane_id}").display

    _run_host(host, tmp_path, body)


@HOSTS
def test_body_processing_modal_lists_decoder(host, tmp_path):
    from friTap.tui.modals.body_processing_modal import BodyProcessingModal

    async def body(app, pilot) -> None:
        app.push_screen(BodyProcessingModal())
        await pilot.pause()
        labels = {b.id: str(b.label) for b in app.screen.query(Button)}
        assert any("P6 Decoder" in label for label in labels.values())

    _run_host(host, tmp_path, body)


@HOSTS
def test_filter_field_parses_and_filters_rows(host, tmp_path):
    from friTap.tui.widgets.filter_bar import FilterBar

    async def body(app, pilot) -> None:
        table = _flow_list(app)
        assert table.total_count == 2
        engine = FilterEngine('p6.lib == "BoringSSL"')
        assert table.count_matches(engine) == 1
        app.screen.query_one("#filter-bar", FilterBar).apply_result(
            text='p6.lib == "BoringSSL"', text_engine=engine,
            toggle_engine=None, active_toggles=set())
        for _ in range(4):
            await pilot.pause()
        assert table.visible_count == 1
        assert [k.value for k in table.rows] == ["flow-aaaa"]

    _run_host(host, tmp_path, body)
