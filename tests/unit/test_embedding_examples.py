"""The three embedding examples under ``example/`` actually work.

Mode A (launch script), mode B (host Textual app) and mode C (extension
package). Async bodies are driven with ``asyncio.run`` under an outer timeout.
"""

from __future__ import annotations

import asyncio
import importlib.util
import logging
import sys
from pathlib import Path

import pytest

pytest.importorskip("textual")

from tests.unit._tui_flow_helpers import make_flow, write_tap  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[2]
EXAMPLE_DIR = REPO_ROOT / "example"
OUTER_TIMEOUT_S = 60


def _load_script(name: str):
    spec = importlib.util.spec_from_file_location(f"_example_{name}", EXAMPLE_DIR / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _drive(body):
    async def _go():
        await asyncio.wait_for(body(), OUTER_TIMEOUT_S)
    asyncio.run(_go())


# --- mode A ---------------------------------------------------------------

def test_launch_script_missing_file_is_a_clean_error(tmp_path, capsys):
    launch = _load_script("tap_viewer_launch")
    root = logging.getLogger()
    handlers_before = list(root.handlers)
    try:
        code = launch.main([str(tmp_path / "missing.tap")])
    finally:
        for handler in list(root.handlers):
            if handler not in handlers_before:
                root.removeHandler(handler)
    assert code == launch.EXIT_FILE_NOT_FOUND
    err = capsys.readouterr().err
    assert "error:" in err and "missing.tap" in err
    assert "Traceback" not in err


# --- mode B ---------------------------------------------------------------

def test_host_app_survives_viewer_escape_and_quit(tmp_path):
    host_mod = _load_script("tap_viewer_host_app")
    from friTap.ui import TapViewerScreen

    tap = tmp_path / "c.tap"
    write_tap(tap, [make_flow("flow-aaaa", 443), make_flow("flow-bbbb", 8443)])
    app = host_mod.HostApp(str(tap), output_dir=str(tmp_path))

    async def body():
        async with app.run_test() as pilot:
            await pilot.pause()
            assert isinstance(app.screen, host_mod.HomeScreen)

            await pilot.press("escape")  # no viewer: the host handles it
            assert app.escape_presses_on_home == 1

            await pilot.press("v")
            await pilot.pause()
            await pilot.pause()
            viewer = app.screen
            assert isinstance(viewer, TapViewerScreen)

            await pilot.press("enter")
            await pilot.pause()
            assert viewer.query_one("#flow-detail").display is True
            await pilot.press("escape")  # reaches the viewer, not the host
            await pilot.pause()
            assert app.screen is viewer
            assert viewer.query_one("#flow-detail").display is False
            assert app.escape_presses_on_home == 1

            await pilot.press("q")
            await pilot.pause()
            await pilot.pause()
            assert isinstance(app.screen, host_mod.HomeScreen)
            assert app.is_running

            before = app.theme
            await pilot.press("t")
            await pilot.pause()
            assert app.theme != before

    _drive(body)


# --- mode C ---------------------------------------------------------------

@pytest.fixture
def demo_package(monkeypatch):
    monkeypatch.syspath_prepend(str(EXAMPLE_DIR / "fritap_ui_extension_demo"))
    sys.modules.pop("fritap_ui_extension_demo", None)
    yield __import__("fritap_ui_extension_demo")
    from friTap.analysis import registry
    registry._DISCOVERED.pop("demo-large-body", None)
    sys.modules.pop("fritap_ui_extension_demo", None)


def test_extension_demo_registers_everything(demo_package):
    from friTap.extensions import (
        get_body_decoders, get_detail_tabs, get_filter_fields, get_flow_columns,
    )
    from friTap.analysis import registry
    from friTap.filter.layer_fields import extract_filter_attrs

    demo_package.register()

    assert [s.id for s in get_detail_tabs()] == ["demo"]
    assert [s.key for s in get_flow_columns()] == ["demo_bytes"]
    assert [s.name for s in get_body_decoders()] == ["demo_length"]
    assert [s.field for s in get_filter_fields()] == ["demo.tls_version"]
    assert "demo-large-body" in registry.available_analyzers()

    attrs = extract_filter_attrs([{"name": "tls", "version": "TLSv1.3"}])
    assert attrs["demo.tls_version"] == ("TLSv1.3",)

    flow = make_flow("f1")
    assert demo_package.render_demo_tab(flow) is None
    assert demo_package.decode_length_summary(b"hello", {})[0].startswith("5 bytes")
    assert registry._build("demo-large-body").analyze_flow(flow) == []

    # The column callback receives a friTap.flow.models.FlowSummary (total_bytes).
    from friTap.flow.models import FlowSummary
    data_flow = make_flow("f2")
    data_flow._total_bytes = 1234
    row = FlowSummary.from_flow(data_flow)
    assert get_flow_columns()[0].value(row) == "1234"
