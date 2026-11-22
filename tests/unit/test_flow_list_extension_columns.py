"""Extension (FlowColumnSpec) columns in the flow list widget."""

import asyncio

from friTap import extensions as ext
from tests.unit._tui_flow_helpers import make_flow

BASE = ["#", "Time", "Proto", "Method", "Connection", "Status", "Size", "Duration"]


def _run(body):
    from textual.app import App

    from friTap.tui.widgets.flow_list import FlowListWidget

    class _App(App):
        def compose(self):
            yield FlowListWidget()

    async def go():
        app = _App()
        async with app.run_test() as pilot:
            table = app.query_one(FlowListWidget)
            await pilot.pause()
            return body(table)

    return asyncio.run(go())


def _labels(table):
    return [str(col.label) for col in table.columns.values()]


def _first_row(table):
    table.add_or_update_flow(make_flow("f1"))
    return list(table.get_row_at(0))


def test_no_registration_keeps_existing_columns():
    assert _run(_labels) == BASE


def test_column_header_value_and_width():
    ext.register_flow_column(ext.FlowColumnSpec("k", "My[Col]", 12, lambda r: "v[1]"))
    ext.register_flow_column(ext.FlowColumnSpec("a", "Auto", 0, lambda r: "x"))

    def body(table):
        row = _first_row(table)
        widths = [col.width for col in table.columns.values()]
        return _labels(table), row, widths

    labels, row, widths = _run(body)
    assert labels == BASE + ["My[Col]", "Auto"]
    assert row[-2:] == ["v[1]", "x"]
    assert widths[8] == 12
    assert getattr(ext.get_flow_columns()[1], "width") == 0


def test_raising_value_gives_empty_cell(fritap_log_records):
    from friTap.tui.widgets import flow_list

    records = fritap_log_records(flow_list.__name__)
    def boom(row):
        raise RuntimeError("nope")

    ext.register_flow_column(ext.FlowColumnSpec("b", "Bad", 8, boom))
    assert _run(_first_row)[-1] == ""
    assert any("value() failed" in r.getMessage() for r in records)


def test_unchanged_extension_value_skips_update_cell():
    ext.register_flow_column(ext.FlowColumnSpec("k", "K", 8, lambda r: "same"))

    def body(table):
        table.add_or_update_flow(make_flow("f1"))
        calls = []
        real = table.update_cell
        table.update_cell = lambda *a, **k: (calls.append(a), real(*a, **k))[1]
        table.add_or_update_flow(make_flow("f1"))
        return [c for c in calls if c[1] == list(table.columns.keys())[-1]]

    assert _run(body) == []


def test_changed_extension_value_updates_cell():
    state = {"v": "one"}
    ext.register_flow_column(ext.FlowColumnSpec("k", "K", 8, lambda r: state["v"]))

    def body(table):
        table.add_or_update_flow(make_flow("f1"))
        state["v"] = "two"
        table.add_or_update_flow(make_flow("f1"))
        return list(table.get_row_at(0))[-1]

    assert _run(body) == "two"
